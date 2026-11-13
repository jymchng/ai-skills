#!/usr/bin/env python3
"""The finding taxonomy: verdict first, then urgency, then why it was closed.

These tests exist because the previous layout answered two different questions
with one directory name. "Is this a vulnerability?" (validated, needs review,
never assessed, suppressed) and "what should we do, and when?" (fix it now, fix
it later) are separate axes, and flattening them let a validated Critical sit
under ``review-required/`` while an unassessed pattern match sat under
``optional-hardening/`` -- a directory that promises a discretionary fix for
something nobody had confirmed was real.

What is asserted here:

* the mapping is **total** -- every ``validation_status`` the schema allows
  reaches a bucket, and that bucket exists in ``FINDING_BUCKETS``;
* it is **mutually exclusive** -- one bucket per finding, decided by the first
  matching rule and nothing else;
* it is **deterministic** -- the same fields always give the same answer, and a
  finding with no verdict is filed as unassessed rather than guessed at;
* the generator writes every bucket on every run, and the register's
  ``by_disposition`` totals agree with the files on disk;
* the validator notices a file that sits in the wrong bucket, which is the
  failure mode a directory layout invites: a correct file in the wrong place.
"""

from __future__ import annotations

import json
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                                "scripts"))

import finding_model as fm  # noqa: E402
import generate_json  # noqa: E402
import report_model as rm  # noqa: E402
import validate_reports  # noqa: E402


# --------------------------------------------------------------------------- #
# The mapping
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("severity,priority,expected", [
    ("Critical", "P0", "validated/remediate-now"),
    ("Critical", "P3", "validated/remediate-now"),
    ("High", "P2", "validated/remediate-now"),
    ("Medium", "P1", "validated/remediate-now"),
    # A Medium finding on a P3 priority: the severity axis wins, so it is filed
    # as owing action. Filing it under schedule/ would let a confirmed Medium
    # vulnerability be read as a discretionary tidy-up.
    ("Medium", "P3", "validated/remediate-now"),
    ("Low", "P3", "validated/schedule"),
    ("Low", "P2", "validated/remediate-now"),     # P2 outranks a Low severity
    ("Informational", "P3", "validated/schedule"),
])
def test_a_validated_finding_is_filed_by_urgency(severity, priority, expected):
    finding = {"validation_status": "validated", "severity": severity, "priority": priority}
    assert rm.finding_bucket(finding) == expected


def test_a_medium_p3_is_filed_by_severity_not_priority():
    """The precedence rule the old three-bucket scheme left open."""
    finding = {"validation_status": "validated", "severity": "Medium", "priority": "P3"}
    assert rm.finding_bucket(finding) == "validated/remediate-now"
    # ...and a Low finding promoted to P1 owes action too: priority is not ignored.
    promoted = {"validation_status": "validated", "severity": "Low", "priority": "P1"}
    assert rm.finding_bucket(promoted) == "validated/remediate-now"


@pytest.mark.parametrize("status,expected", [
    ("needs_review", "needs-review"),
    ("unvalidated", "unvalidated"),
])
def test_a_finding_without_a_confirmed_verdict_is_never_filed_as_actionable(status, expected):
    finding = {"validation_status": status, "severity": "Critical", "priority": "P0"}
    bucket = rm.finding_bucket(finding)
    assert bucket == expected
    assert not rm.bucket_is_validated(bucket)
    assert rm.bucket_reason(bucket)


@pytest.mark.parametrize("kind,expected", [
    ("false_positive", "suppressed/false-positive"),
    ("not_exploitable", "suppressed/not-exploitable"),
    ("accepted_risk", "suppressed/accepted-risk"),
])
def test_a_suppressed_finding_is_filed_by_why_it_was_closed(kind, expected):
    finding = {"validation_status": "suppressed", "suppression_kind": kind,
               "suppression_reason": "recorded"}
    assert rm.finding_bucket(finding) == expected


def test_a_suppressed_finding_with_no_recorded_kind_is_not_guessed_at():
    finding = {"validation_status": "suppressed", "suppression_reason": "recorded"}
    assert rm.finding_bucket(finding) == "suppressed/unspecified"
    # An unrecognised kind is a dataset bug, not a reason to invent a bucket.
    unknown = {"validation_status": "suppressed", "suppression_kind": "we-were-tired",
               "suppression_reason": "recorded"}
    assert rm.finding_bucket(unknown) == "suppressed/unspecified"


@pytest.mark.parametrize("finding", [
    {},
    {"validation_status": ""},
    {"validation_status": "validated-but-not-really"},
    {"severity": "Critical", "priority": "P0"},
])
def test_a_finding_with_no_usable_verdict_is_filed_as_unassessed(finding):
    assert rm.finding_bucket(finding) == "unvalidated"


def test_the_mapping_is_total_and_mutually_exclusive():
    """Every status the schema allows reaches exactly one bucket that exists."""
    for status in fm.VALIDATION_STATUSES:
        for severity in fm.SEVERITIES:
            for priority in fm.PRIORITIES:
                finding = {"validation_status": status, "severity": severity,
                           "priority": priority}
                bucket = rm.finding_bucket(finding)
                assert bucket in rm.FINDING_BUCKETS, (status, severity, priority, bucket)
                # Deterministic: same fields, same answer, every time.
                assert rm.finding_bucket(dict(finding)) == bucket


def test_every_bucket_in_the_layout_is_reachable():
    """No bucket is decoration: each one is the answer for some finding."""
    reachable = set()
    for status in fm.VALIDATION_STATUSES:
        for severity in fm.SEVERITIES:
            for priority in fm.PRIORITIES:
                for kind in (None,) + fm.SUPPRESSION_KINDS:
                    finding = {"validation_status": status, "severity": severity,
                               "priority": priority}
                    if kind:
                        finding["suppression_kind"] = kind
                    reachable.add(rm.finding_bucket(finding))
    assert reachable == set(rm.FINDING_BUCKETS), sorted(set(rm.FINDING_BUCKETS) - reachable)


def test_the_suppression_vocabulary_matches_the_model_and_the_schema():
    assert set(rm.SUPPRESSION_KINDS) == set(fm.SUPPRESSION_KINDS)
    schema = json.load(open(os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "schemas", "finding.schema.json"), encoding="utf-8"))
    declared = schema["$defs"]["finding"]["properties"]["suppression_kind"]["enum"]
    assert {value for value in declared if value is not None} == set(fm.SUPPRESSION_KINDS)


def test_only_a_validated_bucket_is_ticketable():
    for bucket in rm.FINDING_BUCKETS:
        reason = rm.bucket_reason(bucket)
        assert (reason == "") is rm.bucket_is_validated(bucket), bucket


# --------------------------------------------------------------------------- #
# What gets written
# --------------------------------------------------------------------------- #

def _finding(**overrides):
    finding = {
        "id": "VULN-001",
        "title": "SQL injection in order lookup",
        "category": "Injection",
        "cwe": {"id": "CWE-89", "name": "SQL Injection"},
        "owasp": {"top10_2025": "A03 Injection"},
        "severity": "Critical",
        "confidence": "HIGH",
        "priority": "P0",
        "validation_status": "validated",
        "cvss_score": 9.3,
        "cvss_vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
        "location": {"file": "app/orders.py", "line_start": 42, "line_end": 44},
        "description": "User input is concatenated into SQL.",
        "impact": "Full read of the orders table.",
        "attack_scenario": "Send `1 OR 1=1` in the id parameter.",
        "evidence": "42 | q = 'SELECT * FROM orders WHERE id=' + uid",
        "recommended_fix": "Use a parameterised query.",
        "references": ["https://cwe.mitre.org/data/definitions/89.html"],
        "sources": [{"tool": "builtin", "rule_id": "sql-injection"}],
    }
    finding.update(overrides)
    return finding


def _model(findings):
    """The real view model, so the tests exercise the pipeline and not a stub."""
    dataset = {
        "schema_version": "1.0",
        "generated_by": {"name": "validate_findings.py", "version": "1.0.0"},
        "findings": list(findings),
        "summary": {"findings": len(findings)},
        "validation_policy": {"policy": "test"},
    }
    return rm.build_report(dataset)


def test_generate_writes_every_bucket_even_when_empty(tmp_path):
    result = generate_json.generate(_model([_finding()]), str(tmp_path))
    for bucket in rm.FINDING_BUCKETS:
        assert os.path.isdir(os.path.join(result["findings_dir"], *bucket.split("/"))), bucket
    assert os.path.isfile(os.path.join(result["findings_dir"], "validated",
                                       "remediate-now", "VULN-001.json"))


def test_generate_files_each_finding_where_its_own_fields_say(tmp_path):
    model = _model([
        _finding(),
        _finding(id="VULN-002", severity="Low", priority="P3", title="Low",
                 cvss_score=2.0,
                 cvss_vector="CVSS:4.0/AV:N/AC:H/AT:N/PR:H/UI:P/VC:L/VI:N/VA:N"
                             "/SC:N/SI:N/SA:N"),
        _finding(id="VULN-003", validation_status="needs_review", title="Inconclusive"),
        _finding(id="VULN-004", validation_status="suppressed",
                 suppression_reason="accepted by the owner",
                 suppression_kind="accepted_risk", title="Accepted"),
        # Straight into the findings list, the way a skipped validation stage
        # would leave it: the generator has to notice, not just pass it through.
        _finding(id="VULN-005", validation_status="unvalidated", title="Never assessed"),
    ])
    result = generate_json.generate(model, str(tmp_path))
    index = json.load(open(os.path.join(str(tmp_path), "findings-index.json"),
                           encoding="utf-8"))
    by_id = {entry["id"]: entry for entry in index["findings"]}
    assert by_id["VULN-001"]["disposition"] == "validated/remediate-now"
    assert by_id["VULN-002"]["disposition"] == "validated/schedule"
    assert by_id["VULN-003"]["disposition"] == "needs-review"
    assert by_id["VULN-004"]["disposition"] == "suppressed/accepted-risk"
    assert by_id["VULN-005"]["disposition"] == "unvalidated"
    assert [by_id[key]["ticketable"] for key in
            ("VULN-001", "VULN-002", "VULN-003", "VULN-004", "VULN-005")] == \
           [True, True, False, False, False]
    for key, entry in by_id.items():
        assert os.path.isfile(entry["json"]["path"]), key
        assert entry["json"]["sha256"]
    assert result["by_disposition"]["unvalidated"] == 1
    assert sum(index["totals"]["by_disposition"].values()) == 5


def test_the_file_repeats_the_bucket_the_index_states(tmp_path):
    result = generate_json.generate(_model([_finding()]), str(tmp_path))
    path = os.path.join(result["findings_dir"], "validated", "remediate-now",
                        "VULN-001.json")
    document = json.load(open(path, encoding="utf-8"))
    assert document["disposition"] == "validated/remediate-now"
    assert document["ticketable"] is True
    assert document["ticketable_reason"] == ""


def test_an_unassessed_finding_is_never_ticketable():
    """The bug the split fixes: a straggler in the findings list used to be filed
    as a ticketable vulnerability merely because of which list it arrived in."""
    ticket = generate_json.build_ticket(
        _model([]), _finding(validation_status="unvalidated"))
    assert ticket["ticketable"] is False
    assert ticket["disposition"] == "unvalidated"
    assert ticket["ticketable_reason"]


def test_the_aggregate_report_keeps_unassessed_findings_out_of_the_findings_list(tmp_path):
    model = _model([_finding(id="VULN-001"),
                    _finding(id="VULN-009", validation_status="unvalidated")])
    generate_json.generate(model, str(tmp_path))
    document = json.load(open(os.path.join(str(tmp_path), "SECURITY-AUDIT-REPORT.json"),
                              encoding="utf-8"))
    assert [entry["finding_id"] for entry in document["findings"]] == ["VULN-001"]
    assert [entry["finding_id"] for entry in document["unvalidated"]] == ["VULN-009"]


# --------------------------------------------------------------------------- #
# The validator's half of the promise
# --------------------------------------------------------------------------- #

def test_a_file_in_the_wrong_bucket_is_caught(tmp_path):
    """A directory layout invites one specific failure: correct file, wrong place.

    The file is untouched -- same bytes, same digest, same finding -- and only
    its bucket is wrong, which is exactly what a hand-sorted or half-migrated
    report set looks like. The validator has to notice.
    """
    result = generate_json.generate(_model([_finding()]), str(tmp_path))
    documents = os.path.join(result["findings_dir"], "validated", "remediate-now")
    moved = os.path.join(result["findings_dir"], "validated", "schedule",
                         "VULN-001.json")
    os.replace(os.path.join(documents, "VULN-001.json"), moved)
    report = validate_reports.validate(str(tmp_path))
    assert not report["ok"]
    assert any("filed under" in problem for problem in report["problems"]), \
        report["problems"]


def test_a_file_at_the_root_of_findings_is_not_in_any_bucket(tmp_path):
    result = generate_json.generate(_model([_finding()]), str(tmp_path))
    source = os.path.join(result["findings_dir"], "validated", "remediate-now",
                          "VULN-001.json")
    os.replace(source, os.path.join(result["findings_dir"], "VULN-001.json"))
    report = validate_reports.validate(str(tmp_path))
    assert not report["ok"]
    assert any("not in any known bucket" in problem for problem in report["problems"]), \
        report["problems"]


def test_a_suppression_with_no_recorded_kind_is_reported_as_a_dataset_gap(tmp_path):
    model = _model([_finding(validation_status="suppressed",
                             suppression_reason="closed without saying why")])
    generate_json.generate(model, str(tmp_path))
    report = validate_reports.validate(str(tmp_path))
    assert any("no suppression_kind" in warning for warning in report["warnings"]), \
        report["warnings"]


def test_regenerating_removes_a_file_the_run_no_longer_produces(tmp_path):
    """A finding that changes bucket must not survive in its old directory.

    Re-running an audit into the same directory is the normal case, and a
    downgraded finding would otherwise sit in ``remediate-now/`` for ever while
    its replacement sits in ``schedule/``: two files, one id, opposite advice.
    """
    first = generate_json.generate(_model([_finding()]), str(tmp_path))
    stale = os.path.join(first["findings_dir"], "validated", "remediate-now",
                         "VULN-001.json")
    assert os.path.isfile(stale)
    downgraded = _finding(severity="Low", priority="P3", cvss_score=2.0,
                          cvss_vector="CVSS:4.0/AV:N/AC:H/AT:N/PR:H/UI:P/VC:L/VI:N/VA:N"
                                      "/SC:N/SI:N/SA:N")
    second = generate_json.generate(_model([downgraded]), str(tmp_path))
    assert not os.path.exists(stale), "the previous filing must not linger"
    assert second["pruned"] == [stale]
    on_disk = sorted(path.name for path in (tmp_path / "findings").rglob("*.json"))
    assert on_disk == ["VULN-001.json"], on_disk
    assert os.path.isfile(os.path.join(second["findings_dir"], "validated", "schedule",
                                       "VULN-001.json"))
