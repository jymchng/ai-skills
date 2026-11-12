#!/usr/bin/env python3
"""Tests for stage-4 consolidation.

The properties that matter: one real issue becomes one finding, no provenance is
lost, the specific CWE survives alongside its umbrella class, and the output is
deterministic (same inputs -> byte-identical dataset).
"""

from __future__ import annotations

import json
import os
import sys

import pytest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPTS = os.path.join(REPO, "scripts")
if SCRIPTS not in sys.path:
    sys.path.insert(0, SCRIPTS)

import deduplicate_findings as dd  # noqa: E402
import finding_model as fm  # noqa: E402


def finding(file="app/orders.py", line=10, cwe="CWE-89", category="sql_injection",
            tool="semgrep", rule=None, severity="High", evidence="db.execute(sql + uid)",
            fix="Use a bound parameter.", title="SQL injection", **extra):
    record = {
        "title": title,
        "category": category,
        "severity": severity,
        "confidence": "MEDIUM",
        "validation_status": "unvalidated",
        "cwe": {"id": cwe, "name": ""},
        "owasp": {"top10_2025": "not mapped", "api_2023": "not mapped", "asvs": "not mapped"},
        "cvss_vector": None,
        "cvss_score": None,
        "scoring": "unscored",
        "location": {"file": file, "line_start": line, "line_end": line},
        "language": "python",
        "evidence": "  %d | %s" % (line, evidence),
        "description": "A query is built by concatenation.",
        "impact": "Data disclosure.",
        "attack_scenario": "An attacker supplies a quote.",
        "recommended_fix": fix,
        "references": [],
        "sources": [{"tool": tool, "rule_id": rule or "rule-1", "raw_ref": None}],
        "priority": "P1",
    }
    record.update(extra)
    return record


def run(findings, **kwargs):
    dataset = {"schema_version": fm.SCHEMA_VERSION, "findings": findings}
    return dd.deduplicate(dataset, **kwargs)


# --------------------------------------------------------------------------- #
# Same site
# --------------------------------------------------------------------------- #

def test_same_site_same_cwe_merges_and_keeps_both_sources():
    result = run([finding(tool="semgrep", rule="py.sqli"),
                  finding(line=12, tool="bandit", rule="B608")])
    assert len(result["findings"]) == 1
    merged = result["findings"][0]
    assert [s["tool"] for s in merged["sources"]] == ["bandit", "semgrep"]
    assert merged["corroborating_tools"] == ["bandit", "semgrep"]
    assert result["dedupe"]["duplicates_removed"] == 1
    assert merged["merge_notes"]


def test_same_cwe_outside_the_window_stays_separate():
    result = run([finding(line=10), finding(line=30)])
    assert len(result["findings"]) == 2


def test_window_is_configurable():
    assert len(run([finding(line=10), finding(line=30)], line_window=25)["findings"]) == 1


def test_different_files_are_not_same_site():
    result = run([finding(file="a.py"), finding(file="b.py")], cross_file=False)
    assert len(result["findings"]) == 2


def test_different_categories_are_not_merged_even_on_one_line():
    result = run([finding(category="sql_injection", cwe="CWE-89"),
                  finding(category="xss_reflected", cwe="CWE-79")])
    assert len(result["findings"]) == 2


# --------------------------------------------------------------------------- #
# CWE specificity
# --------------------------------------------------------------------------- #

def test_specific_cwe_wins_over_umbrella_class():
    result = run([
        finding(cwe="CWE-20", category="code_injection", tool="checkov", evidence="one"),
        finding(cwe="CWE-89", category="sql_injection", tool="semgrep", evidence="two"),
    ])
    assert len(result["findings"]) == 1
    winner = result["findings"][0]
    assert winner["cwe"]["id"] == "CWE-89"
    assert {s["tool"] for s in winner["sources"]} == {"checkov", "semgrep"}
    assert any("less specific CWE" in note for note in winner["merge_notes"])


# --------------------------------------------------------------------------- #
# Cross-file root cause
# --------------------------------------------------------------------------- #

COPIED = 'cur.execute("SELECT * FROM orders WHERE id = " + request.args["id"])'


def test_copy_pasted_helper_merges_into_one_finding_with_locations():
    result = run([finding(file="app/orders.py", line=10, evidence=COPIED),
                  finding(file="app/admin.py", line=42, evidence=COPIED)])
    assert len(result["findings"]) == 1
    merged = result["findings"][0]
    assert merged["location"]["file"] == "app/admin.py"  # sorted first
    assert [loc["file"] for loc in merged["locations"]] == ["app/orders.py"]


def test_cross_file_merge_is_skipped_when_the_fix_differs():
    result = run([
        finding(file="app/a.py", evidence=COPIED, fix="Bind the parameter in a.py."),
        finding(file="app/b.py", evidence=COPIED, fix="Use the ORM in b.py."),
    ])
    assert len(result["findings"]) == 2


def test_short_generic_evidence_never_merges_across_files():
    result = run([finding(file="a.py", evidence="return result"),
                  finding(file="b.py", evidence="return result")])
    assert len(result["findings"]) == 2


def test_no_cross_file_flag_disables_copy_paste_merging():
    result = run([finding(file="a.py", evidence=COPIED),
                  finding(file="b.py", evidence=COPIED)], cross_file=False)
    assert len(result["findings"]) == 2


def test_comments_do_not_prevent_a_fingerprint_match():
    result = run([finding(file="a.py", evidence=COPIED + "  # unsafe"),
                  finding(file="b.py", evidence=COPIED)])
    assert len(result["findings"]) == 1


# --------------------------------------------------------------------------- #
# Severity, suppression, determinism
# --------------------------------------------------------------------------- #

def test_higher_severity_survives_the_merge():
    result = run([finding(severity="Medium"), finding(line=11, severity="High")])
    assert result["findings"][0]["severity"] == "High"


def test_higher_cvss_score_wins_when_both_are_scored():
    high = finding(line=10, severity="High", cvss_score=8.7,
                   cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
                   scoring="scored")
    low = finding(line=11, severity="Medium", cvss_score=5.3,
                  cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N",
                  scoring="scored")
    merged = run([low, high])["findings"][0]
    assert merged["cvss_score"] == 8.7
    assert merged["severity"] == "High"


def test_a_suppression_from_one_engine_is_carried_over():
    result = run([finding(tool="semgrep"),
                  finding(line=11, tool="bandit", validation_status="suppressed",
                          suppression_reason="parameterised at line 91")])
    merged = result["findings"][0]
    assert merged["validation_status"] == "suppressed"
    assert "parameterised" in merged["suppression_reason"]


def test_ids_are_assigned_and_unique():
    result = run([finding(line=10), finding(line=40), finding(file="z.py")])
    ids = [f["id"] for f in result["findings"]]
    assert len(ids) == len(set(ids)) == 3
    assert all(fm._ID_RE.match(i) for i in ids)


def test_output_is_deterministic():
    findings = [finding(line=10, tool="semgrep"), finding(line=11, tool="bandit"),
                finding(file="b.py", line=3)]
    first = fm.dumps(run(json.loads(json.dumps(findings))))
    second = fm.dumps(run(json.loads(json.dumps(findings))))
    assert first == second


def test_merge_log_records_what_happened():
    result = run([finding(line=10, tool="semgrep"), finding(line=11, tool="bandit")])
    merges = result["dedupe"]["merges"]
    assert merges and merges[0]["merged"][0]["line"] == 11
    assert "same site" in merges[0]["reason"]


# --------------------------------------------------------------------------- #
# Input shapes and CLI
# --------------------------------------------------------------------------- #

def test_bare_array_input_is_accepted(tmp_path):
    path = tmp_path / "bare.json"
    path.write_text(json.dumps([finding(), finding(line=11)]))
    documents = dd.load_documents([str(path)])
    assert len(documents[0][1]["findings"]) == 2


def test_directory_input_expands_json_files(tmp_path):
    (tmp_path / "a.json").write_text(json.dumps({"findings": [finding()]}))
    (tmp_path / "b.json").write_text(json.dumps({"findings": [finding(line=11)]}))
    (tmp_path / "notes.txt").write_text("ignore me")
    assert len(dd._iter_json_inputs([str(tmp_path)])) == 2


def test_cli_writes_a_dataset(tmp_path, capsys):
    source = tmp_path / "in.json"
    source.write_text(json.dumps({"stage": "analysis", "findings": [finding(), finding(line=11)]}))
    out = tmp_path / "out.json"
    assert dd.main([str(source), "--out", str(out)]) == 0
    payload = json.loads(out.read_text())
    assert payload["dedupe"]["duplicates_removed"] == 1
    assert payload["stage"] == "dedupe"
    assert json.loads(capsys.readouterr().out)["written"] == str(out)


def test_missing_input_is_a_clean_failure(tmp_path):
    with pytest.raises(SystemExit):
        dd.load_documents([str(tmp_path / "nope.json")])
