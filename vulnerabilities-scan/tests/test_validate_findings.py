#!/usr/bin/env python3
"""Tests for stage-5 validation.

Each test pins one promise from references/validation-methodology.md and
references/severity-scoring.md: evidence comes from the snapshot, a control that
is present but bypassable does not mitigate, a pattern-only hit is never sold as
a confirmed Critical, secrets are gone before the dataset is written, and every
emitted dataset passes the shared schema.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import sys

import pytest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPTS = os.path.join(REPO, "scripts")
if SCRIPTS not in sys.path:
    sys.path.insert(0, SCRIPTS)

import finding_model as fm  # noqa: E402
import validate_findings as vf  # noqa: E402

SCRATCH_ROOT = os.path.join(REPO, ".scratch", "tests")


@pytest.fixture()
def target(request):
    digest = hashlib.sha1(request.node.name.encode("utf-8")).hexdigest()[:12]
    path = os.path.join(SCRATCH_ROOT, "v" + digest)
    shutil.rmtree(path, ignore_errors=True)
    os.makedirs(path)
    yield path
    shutil.rmtree(path, ignore_errors=True)


def write(root, rel, content):
    path = os.path.join(root, rel)
    os.makedirs(os.path.dirname(path) or root, exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(content)


def finding(file="app/orders.py", line=5, category="sql_injection", cwe="CWE-89",
            tool="semgrep", **extra):
    record = {
        "title": "SQL injection in order lookup",
        "category": category,
        "severity": "High",
        "confidence": "MEDIUM",
        "validation_status": "unvalidated",
        "cwe": {"id": cwe, "name": ""},
        "owasp": {"top10_2025": "A05:2025", "api_2023": "not mapped", "asvs": "not mapped"},
        "cvss_vector": None,
        "cvss_score": None,
        "scoring": "unscored",
        "location": {"file": file, "line_start": line, "line_end": line},
        "language": "python",
        "evidence": "placeholder from the scanner",
        "description": "A query is assembled by string concatenation.",
        "impact": "The whole orders table can be read.",
        "attack_scenario": "A client sends a quote in the id parameter.",
        "recommended_fix": "Bind the parameter.",
        "references": [],
        "sources": [{"tool": tool, "rule_id": "r1", "raw_ref": None}],
        "priority": "P1",
    }
    record.update(extra)
    return record


VULN_SQL = """import sqlite3
from flask import request

def handler(request):
    uid = request.args["id"]
    cur.execute("SELECT * FROM orders WHERE id = " + uid)
    return cur.fetchall()
"""

SAFE_SQL = """import sqlite3
from flask import request

def handler(request):
    uid = request.args["id"]
    cur.execute("SELECT * FROM orders WHERE id = " + uid)
    cur.execute("SELECT 1 FROM audit WHERE actor = ?", (uid,))
    return cur.fetchall()
"""

NO_SOURCE_SQL = """import sqlite3

def run(q):
    cur = sqlite3.connect("db").cursor()
    cur.execute("SELECT * FROM orders WHERE id = " + q)
    return cur.fetchall()
"""


def validate(root, findings, **kwargs):
    dataset = {"schema_version": fm.SCHEMA_VERSION, "findings": findings}
    return vf.validate_dataset(root, dataset, **kwargs)


# --------------------------------------------------------------------------- #
# Evidence capture
# --------------------------------------------------------------------------- #

def test_evidence_is_reread_from_the_snapshot_not_copied_from_the_scanner(target):
    write(target, "app/orders.py", VULN_SQL)
    result, _ = validate(target, [finding(line=5)])
    evidence = result["findings"][0]["evidence"]
    assert 'cur.execute("SELECT * FROM orders WHERE id = " + uid)' in evidence
    assert "    5 | " in evidence
    assert "placeholder from the scanner" not in evidence


def test_evidence_numbers_are_one_based_and_bounded(target):
    write(target, "app/orders.py", VULN_SQL)
    result, _ = validate(target, [finding(line=1)])
    evidence = result["findings"][0]["evidence"]
    assert evidence.splitlines()[0].strip().startswith("1 |")
    assert len(evidence.splitlines()) <= vf.MAX_EVIDENCE_LINES


def test_line_past_the_end_of_the_file_is_reported_not_papered_over(target):
    write(target, "app/orders.py", VULN_SQL)
    result, transcript = validate(target, [finding(line=400)])
    record = result["findings"][0]
    assert "evidence unavailable" in record["evidence"]
    assert "past the end of the file" in record["evidence"]
    assert record["confidence"] == "LOW"
    assert record["validation_status"] == "needs_review"
    assert record["scoring"] in ("scored", "unscored")
    assert record["severity"] not in ("Critical",)
    assert transcript["findings"][0]["status"] == "needs_review"


@pytest.mark.parametrize("path", ["/etc/passwd", "../../etc/passwd", ""])
def test_paths_outside_the_root_are_never_read(target, path):
    write(target, "app/orders.py", VULN_SQL)
    result, _ = validate(target, [finding(file=path, line=1)])
    record = result["findings"][0]
    assert "evidence unavailable" in record["evidence"]
    assert "passwd" not in record["evidence"]


def test_missing_file_is_a_clean_capture_failure(target):
    result, _ = validate(target, [finding(file="app/ghost.py", line=3)])
    record = result["findings"][0]
    assert "file not present" in record["evidence"]
    assert record["confidence"] == "LOW"


# --------------------------------------------------------------------------- #
# Controls and false positives
# --------------------------------------------------------------------------- #

def test_parameterised_sibling_line_suppresses_the_injection(target):
    write(target, "app/orders.py", SAFE_SQL)
    result, transcript = validate(target, [finding(line=5)])
    record = result["findings"][0]
    assert record["validation_status"] == "suppressed"
    assert "bound parameter" in record["suppression_reason"]
    assert result["suppressions"][0]["rule"] == "compensating-control"
    # The suppression is carried by the status, not by falsifying the severity:
    # the record must stay consistent with its own CVSS score.
    assert record["severity"] == fm.severity_from_score(record["cvss_score"])
    assert fm.validate(result) == []
    assert result["summary"]["suppressed"] == 1
    assert result["summary"]["by_severity_reportable"] == {}


def test_unparameterised_query_is_confirmed_with_the_tainted_value(target):
    write(target, "app/orders.py", VULN_SQL)
    result, transcript = validate(target, [finding(line=5)])
    record = result["findings"][0]
    assert record["validation_status"] == "validated"
    assert record["confidence"] == "CONFIRMED"
    assert transcript["findings"][0]["dataflow"] == "same-function"


def test_bypassable_control_does_not_mitigate(target):
    write(target, "app/files.py", """import os
from flask import request

def read(request):
    name = request.args["f"]
    name = name.replace("../", "")
    return open(os.path.join("/srv", name)).read()
""")
    result, transcript = validate(target, [finding(file="app/files.py", line=6,
                                                    category="path_traversal", cwe="CWE-22")])
    record = result["findings"][0]
    assert record["validation_status"] != "suppressed"
    assert transcript["findings"][0]["controls"][0]["strength"] == "bypassable"
    assert "bypassable" in record["validation"]


def test_partial_control_lowers_confidence_one_step(target):
    write(target, "app/redirect.py", """from flask import request, redirect

def go(request):
    nxt = request.args["next"]
    if nxt.startswith("/"):
        return redirect(nxt)
    return redirect("/")
""")
    result, transcript = validate(target, [finding(file="app/redirect.py", line=6,
                                                    category="open_redirect", cwe="CWE-601")])
    record = result["findings"][0]
    assert record["confidence"] == "HIGH"  # CONFIRMED lowered by the fragile control
    assert transcript["findings"][0]["controls"][0]["strength"] == "partial"
    assert record["validation_status"] != "suppressed"


def test_untouched_code_still_records_what_was_searched(target):
    write(target, "app/orders.py", VULN_SQL)
    result, _ = validate(target, [finding(line=5)])
    assert "nothing found on the path" in result["findings"][0]["validation"]


# --------------------------------------------------------------------------- #
# Confidence ladder and scoring
# --------------------------------------------------------------------------- #

def test_pattern_only_hit_is_low_confidence_and_never_critical(target):
    write(target, "app/orders.py", NO_SOURCE_SQL)
    result, transcript = validate(target, [finding(line=5)])
    record = result["findings"][0]
    assert record["confidence"] == "LOW"
    assert transcript["findings"][0]["dataflow"] == "pattern-only"
    assert record["severity"] in ("Medium", "Low", "Informational")
    assert record["cvss_score"] is None or record["cvss_score"] < 7.0


def test_no_critical_finding_can_be_low_confidence(target):
    write(target, "app/fetch.py", """import requests
def fetch(u):
    return requests.get(u)
""")
    result, _ = validate(target, [finding(file="app/fetch.py", line=3, category="ssrf",
                                          cwe="CWE-918")])
    record = result["findings"][0]
    assert not (record["severity"] == "Critical" and record["confidence"] == "LOW")
    assert fm.consistency_problems(result) == []


def test_scores_come_from_the_class_vector_and_are_recorded(target):
    write(target, "app/orders.py", VULN_SQL)
    record = validate(target, [finding(line=5)])[0]["findings"][0]
    assert record["scoring"] == "scored"
    assert record["cvss_score"] == 8.7
    assert record["cvss_vector"].startswith("CVSS:4.0/AV:N/")
    assert record["severity"] == fm.severity_from_score(record["cvss_score"])


def test_a_stored_number_is_recomputed_from_its_vector(target):
    write(target, "app/orders.py", VULN_SQL)
    stored = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N"
    record = validate(target, [finding(line=5, cvss_score=9.9, cvss_vector=stored,
                                       scoring="scored")])[0]["findings"][0]
    assert record["cvss_score"] != 9.9
    assert record["cvss_vector"] == stored


def test_invalid_stored_vector_falls_back_to_the_class_vector(target):
    write(target, "app/orders.py", VULN_SQL)
    record = validate(target, [finding(line=5, cvss_vector="CVSS:4.0/AV:Q",
                                       scoring="scored")])[0]["findings"][0]
    assert record["cvss_vector"].startswith("CVSS:4.0/AV:N/")
    assert "stored vector rejected" in record["validation"]


def test_unknown_category_is_explicitly_unscored(target):
    write(target, "app/orders.py", VULN_SQL)
    record = validate(target, [finding(line=5, category="unclassified",
                                       cwe="CWE-693")])[0]["findings"][0]
    assert record["scoring"] == "unscored"
    assert record["cvss_score"] is None and record["cvss_vector"] is None
    assert record["severity"] == "Informational"
    assert "no defensible default vector" in record["validation"]


def test_no_score_switch_marks_everything_unscored(target):
    write(target, "app/orders.py", VULN_SQL)
    record = validate(target, [finding(line=5)], no_score=True)[0]["findings"][0]
    assert record["scoring"] == "unscored"
    assert record["severity"] == "Informational"
    assert "--no-score" in record["validation"]


@pytest.mark.parametrize("severity,confidence,expected", [
    ("Critical", "CONFIRMED", "P0"), ("Critical", "MEDIUM", "P1"),
    ("High", "CONFIRMED", "P1"), ("High", "LOW", "P1"),
    ("Medium", "CONFIRMED", "P2"), ("Medium", "LOW", "P3"),
    ("Low", "CONFIRMED", "P3"), ("Informational", "HIGH", "P3"),
])
def test_priority_table(severity, confidence, expected):
    assert vf.priority_for(severity, confidence, False, []) == expected


def test_test_paths_are_demoted_and_labelled(target):
    write(target, "tests/fixtures/vulnerable.py", VULN_SQL)
    record = validate(target, [finding(file="tests/fixtures/vulnerable.py", line=5)]
                      )[0]["findings"][0]
    assert record["in_test_path"] is True
    assert record["priority"] == "P3"
    assert "test/fixture" in record["validation"]


def test_path_policy_suppress_turns_fixture_findings_into_suppressions(target):
    write(target, "tests/fixtures/vulnerable.py", VULN_SQL)
    result, _ = validate(target, [finding(file="tests/fixtures/vulnerable.py", line=5)],
                         path_policy="suppress")
    record = result["findings"][0]
    assert record["validation_status"] == "suppressed"
    assert "path-based suppression" in record["suppression_reason"]


# --------------------------------------------------------------------------- #
# Redaction
# --------------------------------------------------------------------------- #

def test_planted_secret_is_redacted_in_evidence_and_impact(target):
    secret = "AKIAIOSFODNN7EXAMPLE"
    write(target, "app/config.py", 'AWS_KEY = "%s"\nOTHER = 1\n' % secret)
    planted = finding(file="app/config.py", line=1, category="hardcoded_secret",
                      cwe="CWE-798",
                      impact="Anyone with the key %s can read the bucket." % secret)
    result, transcript = validate(target, [planted], secrets=[secret])
    record = result["findings"][0]
    blob = json.dumps(record)
    assert secret not in blob
    assert "REDACTED" in record["evidence"] or "…" in record["evidence"]
    assert fm.find_leaks(result, [secret]) == []
    assert transcript["redactions_applied"] >= 1


def test_secret_files_never_leak_through_validation_text(target):
    secret = "s3cr3t-value-0123456789"
    write(target, "app/config.py", 'TOKEN = "%s"\n' % secret)
    result, _ = validate(target, [finding(file="app/config.py", line=1,
                                          category="hardcoded_secret", cwe="CWE-798")],
                         secrets=[secret])
    assert secret not in json.dumps(result)


# --------------------------------------------------------------------------- #
# Dataset contract and CLI
# --------------------------------------------------------------------------- #

def test_output_dataset_is_schema_valid_and_has_no_unvalidated_findings(target):
    write(target, "app/orders.py", VULN_SQL)
    write(target, "app/no_source.py", NO_SOURCE_SQL)
    result, _ = validate(target, [finding(line=5),
                                  finding(file="app/no_source.py", line=5)])
    assert fm.validate(result) == []
    assert all(f["validation_status"] != "unvalidated" for f in result["findings"])
    assert result["summary"]["findings"] == 2
    assert len({f["id"] for f in result["findings"]}) == 2


def test_validation_is_deterministic(target):
    write(target, "app/orders.py", VULN_SQL)
    first = fm.dumps(validate(target, [finding(line=5)])[0])
    second = fm.dumps(validate(target, [finding(line=5)])[0])
    assert first == second


def test_cli_writes_dataset_and_transcript(target, tmp_path, capsys):
    write(target, "app/orders.py", VULN_SQL)
    source = tmp_path / "deduped.json"
    source.write_text(json.dumps({"schema_version": fm.SCHEMA_VERSION,
                                  "findings": [finding(line=5)]}))
    out, transcript = tmp_path / "findings.json", tmp_path / "validation.json"
    assert vf.main([str(source), "--root", target, "--out", str(out),
                    "--transcript", str(transcript)]) == 0
    payload = json.loads(out.read_text())
    assert payload["stage"] == "validation"
    assert json.loads(transcript.read_text())["findings"][0]["file"] == "app/orders.py"
    assert json.loads(capsys.readouterr().out)["written"] == str(out)


def test_cli_refuses_to_write_when_a_secret_survives(target, tmp_path, capsys):
    secret = "AKIAIOSFODNN7EXAMPLE"
    write(target, "app/config.py", 'K = "%s"\n' % secret)
    source = tmp_path / "deduped.json"
    # The secret is hidden inside a field redaction never touches (references),
    # so the leak check must fail and nothing may be written.
    source.write_text(json.dumps({"findings": [
        finding(file="app/config.py", line=1, category="hardcoded_secret",
                cwe="CWE-798", references=[secret])]}))
    out = tmp_path / "findings.json"
    secrets = tmp_path / "secrets.txt"
    secrets.write_text(secret + "\n")
    assert vf.main([str(source), "--root", target, "--out", str(out),
                    "--secrets-file", str(secrets)]) == 1
    assert not out.exists()

def test_control_catalogue_matches_the_stage_three_vocabulary():
    """Stage 5 must not call a stage-3 guard a vulnerability."""
    import builtin_analyzers as ba
    for category in ("sql_injection", "xss_reflected", "path_traversal", "ssrf"):
        labels = " ".join(c.label for c in vf.CONTROLS[category])
        assert labels.strip()
        assert category in ba.GUARDS
