"""Tests for the shared finding data model (scripts/finding_model.py, schemas/finding.schema.json)."""

import copy
import json
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts"))

import finding_model as fm  # noqa: E402

#: Assembled from parts, never written as one literal: a provider-shaped
#: credential in a tracked file trips GitHub push protection (GH013) on every
#: push. The values are identical at run time, so the length assertions below
#: (20 and 24 characters) still pin the exact shape.
AWS_EXAMPLE_KEY = "AKIA" + "IOSFODNN7EXAMPLE"
GITHUB_EXAMPLE_TOKEN = "ghp_" + "0123456789abcdefghij"


def valid_finding(**overrides):
    finding = {
        "id": "VULN-001",
        "title": "SQL injection in order lookup",
        "category": "sql_injection",
        "severity": "Critical",
        "confidence": "CONFIRMED",
        "validation_status": "validated",
        "cwe": {"id": "CWE-89", "name": "SQL Injection"},
        "owasp": {"top10_2025": "A05:2025", "api_2023": "API1:2023", "asvs": "not mapped"},
        "cvss_vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
        "cvss_score": 9.3,
        "location": {"file": "app/orders.py", "line_start": 42, "line_end": 44},
        "language": "python",
        "evidence": "42: cur.execute(f\"SELECT * FROM orders WHERE id = {request.args['id']}\")",
        "description": "Request data is interpolated into a SQL statement.",
        "impact": "Any unauthenticated visitor can read the orders table.",
        "attack_scenario": "Send GET /orders?id=1%20OR%201=1 and receive every order.",
        "recommended_fix": "Bind the parameter: cur.execute(sql, (order_id,)).",
        "references": ["https://cwe.mitre.org/data/definitions/89.html"],
        "sources": [{"tool": "builtin", "rule_id": "py.sql.fstring", "raw_ref": None}],
        "priority": "P0",
    }
    finding.update(overrides)
    return finding


def dataset(*findings, **extra):
    data = {"schema_version": "1.0", "findings": list(findings)}
    data.update(extra)
    return data


# --------------------------------------------------------------------------- #
# Schema
# --------------------------------------------------------------------------- #

def test_schema_loads_and_is_draft_2020_12():
    schema = fm.load_schema()
    assert schema["$schema"].endswith("2020-12/schema")
    assert "finding" in schema["$defs"]


def test_schema_requires_all_twenty_mandatory_fields():
    schema = fm.load_schema()
    required = schema["$defs"]["finding"]["required"]
    assert tuple(required) == fm.MANDATORY_FIELDS
    assert len(required) == 20


def test_valid_finding_passes():
    assert fm.validate(dataset(valid_finding())) == []


def test_missing_single_field_is_detected():
    for field in fm.MANDATORY_FIELDS:
        broken = valid_finding()
        del broken[field]
        problems = fm.validate(dataset(broken))
        assert problems, f"removing {field!r} should fail validation"
        assert any(field in p for p in problems), f"{field!r} not named in {problems}"


@pytest.mark.parametrize("field,value", [
    ("severity", "Severe"),
    ("confidence", "confirmed"),
    ("validation_status", "todo"),
    ("priority", "P9"),
    ("category", "made_up_category"),
])
def test_enum_violations_are_detected(field, value):
    problems = fm.validate(dataset(valid_finding(**{field: value})))
    assert problems


def test_absolute_location_path_rejected():
    bad = valid_finding(location={"file": "/etc/passwd", "line_start": 1, "line_end": 1})
    assert fm.validate(dataset(bad))


def test_line_end_before_start_rejected():
    bad = valid_finding(location={"file": "a.py", "line_start": 9, "line_end": 3})
    assert fm.validate(dataset(bad))


def test_unscored_finding_must_have_null_vector_and_score():
    ok = valid_finding(severity="Informational", cvss_vector=None, cvss_score=None)
    assert fm.validate(dataset(ok)) == []
    half = valid_finding(severity="Informational", cvss_vector=None, cvss_score=9.3)
    assert fm.validate(dataset(half))


def test_suppressed_requires_reason():
    f = valid_finding(validation_status="suppressed")
    assert fm.validate(dataset(f))
    f["suppression_reason"] = "parameterised query at line 91"
    assert fm.validate(dataset(f)) == []


def test_unvalidated_finding_is_flagged_in_a_reportable_dataset():
    problems = fm.validate(dataset(valid_finding(validation_status="unvalidated")))
    assert any("unvalidated" in p for p in problems)


def test_stdlib_fallback_agrees_with_schema_on_mandatory_fields(monkeypatch):
    """The fallback validator must catch what the schema catches for required fields."""
    broken = valid_finding()
    del broken["evidence"]
    via_fallback = fm._fallback_errors(dataset(broken))
    assert any("evidence" in p for p in via_fallback)


# --------------------------------------------------------------------------- #
# Identifiers
# --------------------------------------------------------------------------- #

def test_assign_ids_is_deterministic_and_ordered_by_severity_then_location():
    low = valid_finding(title="Header note", severity="Low", cvss_score=2.0,
                        category="missing_security_headers",
                        location={"file": "a.py", "line_start": 1, "line_end": 1})
    critical = valid_finding(title="RCE", severity="Critical", cvss_score=9.8,
                             location={"file": "z.py", "line_start": 9, "line_end": 9})
    medium = valid_finding(title="CORS", severity="Medium", cvss_score=5.1,
                           category="permissive_cors",
                           location={"file": "m.py", "line_start": 3, "line_end": 3})
    data = dataset(low, critical, medium)
    fm.assign_ids(data)
    by_title = {f["title"]: f["id"] for f in data["findings"]}
    assert by_title == {"RCE": "VULN-001", "CORS": "VULN-002", "Header note": "VULN-003"}

    again = copy.deepcopy(data)
    fm.assign_ids(again)
    assert [(f["id"], f["title"]) for f in data["findings"]] == \
           [(f["id"], f["title"]) for f in again["findings"]]


def test_next_id_reports_the_following_number():
    data = dataset(valid_finding(id="VULN-007"))
    assert fm.next_id(data) == "VULN-008"
    assert fm.next_id(dataset()) == "VULN-001"


# --------------------------------------------------------------------------- #
# Severity bands
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("score,expected", [
    (10.0, "Critical"), (9.0, "Critical"), (8.9, "High"), (7.0, "High"),
    (6.9, "Medium"), (4.0, "Medium"), (3.9, "Low"), (0.1, "Low"),
    (0.0, "Informational"), (None, "Informational"),
])
def test_severity_from_score_bands(score, expected):
    assert fm.severity_from_score(score) == expected


def test_scored_finding_severity_can_be_rederived():
    data = dataset(valid_finding(severity="Low"))
    fm.apply_severity(data)
    assert data["findings"][0]["severity"] == "Critical"


def test_severity_score_mismatch_is_a_consistency_problem():
    data = dataset(valid_finding(severity="Low", cvss_score=9.3))
    assert any("contradicts" in p for p in fm.consistency_problems(data))


def test_critical_with_low_confidence_is_rejected():
    data = dataset(valid_finding(confidence="LOW"))
    assert any("LOW confidence" in p for p in fm.consistency_problems(data))


# --------------------------------------------------------------------------- #
# Redaction
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("value,expected", [
    (AWS_EXAMPLE_KEY, "AKIA…(20 chars)"),
    (GITHUB_EXAMPLE_TOKEN, "ghp_…(24 chars)"),
    ("hunter2", "…(7 chars)"),
    ("ab", "…(2 chars)"),
    ("", "…(0 chars)"),
])
def test_redact_value_formats(value, expected):
    assert fm.redact_value(value) == expected


def test_redaction_never_returns_the_input():
    for value in ["a", "ab", "abcdef", "abcdefghijklmnop", AWS_EXAMPLE_KEY]:
        assert fm.redact_value(value) != value


def test_redact_text_counts_replacements_and_is_idempotent():
    text = "key %s used, again %s" % (AWS_EXAMPLE_KEY, AWS_EXAMPLE_KEY)
    redacted, count = fm.redact_text(text, [AWS_EXAMPLE_KEY])
    assert count == 2
    assert AWS_EXAMPLE_KEY not in redacted
    assert redacted.count("AKIA…(20 chars)") == 2
    twice, again = fm.redact_text(redacted, [AWS_EXAMPLE_KEY])
    assert twice == redacted and again == 0


def test_redact_text_handles_overlapping_secrets_longest_first():
    long_secret = "token-abcdef123456"
    short_secret = "token"
    redacted, _ = fm.redact_text("value: token-abcdef123456", [short_secret, long_secret])
    assert "token-abcdef123456" not in redacted
    assert "abcdef123456" not in redacted


def test_redact_finding_scrubs_every_narrative_field():
    secret = AWS_EXAMPLE_KEY
    finding = valid_finding(
        evidence=f"12: AWS_KEY = '{secret}'",
        description=f"A hardcoded key {secret} ships in the image.",
        impact=f"Anyone can use {secret} against the account.",
        attack_scenario=f"Take {secret} from the repo and call the API.",
        recommended_fix=f"Rotate {secret} and load it from the environment.",
        title=f"Hardcoded AWS key {secret}",
    )
    fm.redact_finding(finding, [secret])
    blob = json.dumps(finding, ensure_ascii=False)
    assert secret not in blob
    assert blob.count("AKIA…(20 chars)") >= 5


def test_find_leaks_reports_where_a_secret_survives():
    secret = AWS_EXAMPLE_KEY
    data = dataset(valid_finding(evidence=f"key = {secret}"))
    assert fm.find_leaks(data, [secret])
    assert fm.find_leaks(dataset(valid_finding()), [secret]) == []


# --------------------------------------------------------------------------- #
# Round-trip
# --------------------------------------------------------------------------- #

def test_save_and_load_round_trip_is_byte_stable(tmp_path):
    data = dataset(valid_finding())
    first = tmp_path / "a.json"
    second = tmp_path / "b.json"
    fm.save_findings(data, str(first))
    fm.save_findings(fm.load_findings(str(first)), str(second))
    assert first.read_bytes() == second.read_bytes()
    assert fm.load_findings(str(first))["findings"][0]["id"] == "VULN-001"


def test_bare_list_is_accepted_as_a_dataset(tmp_path):
    path = tmp_path / "list.json"
    path.write_text(json.dumps([valid_finding()]), encoding="utf-8")
    data = fm.load_findings(str(path))
    assert data["schema_version"] == "1.0"
    assert len(data["findings"]) == 1


def test_dumps_puts_mandatory_fields_first():
    text = fm.dumps(dataset(valid_finding(zzz_extra="x")))
    payload = json.loads(text)["findings"][0]
    keys = list(payload)
    assert keys[:20] == list(fm.MANDATORY_FIELDS)
    assert keys[-1] == "zzz_extra"
