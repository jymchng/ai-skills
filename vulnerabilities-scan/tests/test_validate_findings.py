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
import subprocess
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


# --------------------------------------------------------------------------- #
# Redaction parity with the analyzers
#
# capture_evidence re-quotes the audited file, so any credential shape the
# analyzer can detect must also be redactable here. When a Stripe key was missing
# from this table, stage 5 restored the value the analyzer had already redacted
# and the reports printed it in full.
# --------------------------------------------------------------------------- #

#: ``secret id -> (text containing the secret, the part that must not survive)``.
#: Every id in ``builtin_analyzers.SECRET_PATTERNS`` needs an entry; the coverage
#: assertion below turns a new analyzer pattern into a test failure instead of a
#: silent redaction gap.
SECRET_SAMPLES = {
    "aws-access-key": ("AKIA" + "Q" * 16, "AKIA" + "Q" * 16),
    "private-key-block": ("-----BEGIN RSA PRIVATE KEY-----\nMIIEow\n-----END RSA PRIVATE KEY-----",
                          "MIIEow"),
    "github-token": ("ghp_" + "Ab1" * 12, "ghp_" + "Ab1" * 12),
    "slack-token": ("xoxb-" + "1234567890-abcdefghijkl", "1234567890-abcdefghijkl"),
    "stripe-key": ("sk_live_" + "Z" * 24, "sk_live_" + "Z" * 24),
    "google-api-key": ("AIza" + "A" * 35, "AIza" + "A" * 35),
    "jwt-token": ("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0." + "x" * 43, "x" * 43),
    "generic-assignment": ('client_secret = "abc123def456"', "abc123def456"),
    "connection-string": ("postgresql://app:S3cretPassw0rd@db.internal:5432/app",
                          "S3cretPassw0rd"),
}


def test_every_analyzer_secret_shape_is_also_redactable_here():
    import builtin_analyzers as ba

    analyzer_ids = {secret_id for secret_id, _pattern, _label in ba.SECRET_PATTERNS}
    assert analyzer_ids == set(SECRET_SAMPLES), analyzer_ids ^ set(SECRET_SAMPLES)

    for secret_id, (text, sensitive) in SECRET_SAMPLES.items():
        redacted, count = vf.redact_text("  4 | " + text)
        assert count >= 1, secret_id
        assert sensitive not in redacted, (secret_id, redacted)
        assert "[REDACTED" in redacted, (secret_id, redacted)


def test_redaction_is_idempotent_and_leaves_placeholders_alone():
    text = 'api_key = "your-api-key-here"'
    assert vf.redact_text(text) == (text, 0)

    once, count = vf.redact_text(" 4 | key = " + "sk_live_" + "Z" * 24)
    twice, again = vf.redact_text(once)
    assert count == 1 and again == 0
    assert once == twice


def test_capture_evidence_never_restores_a_redacted_secret(target):
    """The evidence is re-read from disk: that copy must be redacted too."""
    secret = "sk_live_" + "Z" * 24
    write(target, "docs/keys.md", "# Keys\n\nbilling key: " + secret + "\n")
    with open(os.path.join(target, "docs/keys.md"), encoding="utf-8") as handle:
        lines = handle.read().splitlines()

    evidence, problem = vf.capture_evidence(
        lines, {"file": "docs/keys.md", "line_start": 3, "line_end": 3})
    assert problem is None
    assert secret not in evidence
    assert "[REDACTED STRIPE KEY]" in evidence


#: A repo whose documents carry two live-shaped credentials, driven through all
#: four stages. Stripe and AWS are both here on purpose: the AWS shape was always
#: redacted, the Stripe shape was not, and a test that only used AWS passed while
#: the report printed ``sk_live_…`` in full.
def _secret_corpus(target):
    stripe = "sk_live_" + "Z" * 24
    aws = "AKIA" + "Q" * 16
    write(target, "docs/onboarding.rst",
          "Onboarding\n==========\n\nBilling key: " + stripe + "\n")
    write(target, "notes.txt", "stripe: " + stripe + "\naws: " + aws + "\n")
    write(target, "app/query.py",
          "from flask import request\n\n\ndef handler(request):\n"
          "    return db.execute(\"SELECT * FROM t WHERE id=\" + request.args['id'])\n")
    return stripe, aws


def _run_pipeline(target, tmp_path):
    """builtin_analyzers -> deduplicate_findings -> validate_findings -> reports."""
    import builtin_analyzers as ba
    import deduplicate_findings as df
    import generate_reports as gr

    analysis = tmp_path / "analysis.json"
    analysis.write_text(json.dumps(ba.analyze(target)))
    deduped = tmp_path / "deduped.json"
    deduped.write_text(json.dumps(df.deduplicate(json.loads(analysis.read_text()))))
    validated = tmp_path / "findings.json"
    assert vf.main([str(deduped), "--root", target, "--out", str(validated)]) == 0
    return validated, gr


def test_a_document_secret_never_reaches_a_deliverable(target, tmp_path):
    """The end-to-end guarantee: no deliverable prints the value stage 3 redacted.

    Stage 5 re-quotes the audited file, so its shape table has to know every
    shape stage 3 can redact. When it did not, the Stripe key below came back in
    full in every report format and in the ticket file.
    """
    stripe, aws = _secret_corpus(target)
    validated, gr = _run_pipeline(target, tmp_path)

    outdir = tmp_path / "report"
    assert gr.main(["--dataset", str(validated), "--outdir", str(outdir),
                    "--formats", "markdown,html,json"]) == 0

    written = sorted(p for p in outdir.rglob("*")
                     if p.is_file() and p.suffix in (".md", ".html", ".json"))
    assert written, "no report files were written"
    names = {p.relative_to(outdir).as_posix() for p in written}
    assert "SECURITY-AUDIT-REPORT.md" in names
    assert any(name.startswith("tickets/VULN-") for name in names), names
    for path in written:
        text = path.read_text(encoding="utf-8", errors="replace")
        assert stripe not in text, path
        assert aws not in text, path
    assert any("[REDACTED" in p.read_text(encoding="utf-8", errors="replace")
               for p in written), "redaction markers should be visible"

    # The ticket is the file that used to print the key: check it on its own.
    dataset = json.loads(validated.read_text())
    expected = {f["id"] + ".json" for f in dataset["findings"]}
    tickets = sorted((outdir / "tickets").glob("VULN-*.json"))
    assert {t.name for t in tickets} == expected, [t.name for t in tickets]
    assert len(expected) >= 2, "the corpus should produce a secret finding per document"
    for ticket in tickets:
        text = ticket.read_text(encoding="utf-8", errors="replace")
        assert stripe not in text, ticket
        assert aws not in text, ticket
    secret_tickets = [t for t in tickets
                      if t.stem in {f["id"] for f in dataset["findings"]
                                    if f["category"] == "hardcoded_secret"}]
    assert len(secret_tickets) >= 2, [t.name for t in tickets]
    for ticket in secret_tickets:
        assert "[REDACTED" in ticket.read_text(encoding="utf-8", errors="replace"), ticket


def test_no_pdf_carries_a_redacted_secret(target, tmp_path):
    """The same guarantee for the PDF, which is rendered text and easy to miss."""
    for tool in ("pandoc", "xelatex", "pdftotext"):
        if not shutil.which(tool):
            pytest.skip("%s is not installed: the PDF branch cannot be checked here" % tool)

    stripe, aws = _secret_corpus(target)
    validated, gr = _run_pipeline(target, tmp_path)

    outdir = tmp_path / "report"
    assert gr.main(["--dataset", str(validated), "--outdir", str(outdir),
                    "--formats", "markdown,html,json,pdf"]) == 0
    pdf = outdir / "SECURITY-AUDIT-REPORT.pdf"
    assert pdf.exists(), "the PDF toolchain was present but no PDF was written"

    text = subprocess.run(["pdftotext", str(pdf), "-"],
                          capture_output=True, text=True, check=True).stdout
    assert stripe not in text
    assert aws not in text
    assert "REDACTED" in text, "the PDF should show the redaction marker, not nothing"


# --------------------------------------------------------------------------- #
# The leak guard must know the shapes, not only the values
#
# finding_model.find_leaks searches for values it was handed, so without a
# --secrets-file it had nothing to search for at all: the Stripe key went through
# a guard that reported no leaks. The shape guard closes that hole.
# --------------------------------------------------------------------------- #

#: One value per unambiguous shape the guard has to recognise. The relaxed
#: ``password=…`` assignment is absent on purpose: a finding may legitimately
#: describe a password rule, so the guard stays quiet about it.
GUARDED_SHAPES = {
    "AWS access key id": "AKIA" + "Q" * 16,
    "GitHub token": "ghp_" + "Ab1" * 12,
    "GitHub fine-grained token": "github_pat_" + "A" * 24,
    "Slack token": "xoxb-" + "1234567890-abcdefghijkl",
    "API key": "sk-" + "A" * 24,
    "Stripe key": "sk_live_" + "Z" * 24,
    "Google API key": "AIza" + "A" * 35,
    "JWT": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0." + "x" * 43,
    "private key": "-----BEGIN RSA " + "PRIVATE KEY-----",
    "password in a connection string": "postgresql://app:S3cretPassw0rd@db.internal:5432/app",
}


def test_every_guarded_shape_is_reported_wherever_it_sits():
    for name, value in GUARDED_SHAPES.items():
        dataset = {"schema_version": fm.SCHEMA_VERSION,
                   "findings": [finding(references=["see " + value])]}
        leaks = vf.find_shape_leaks(dataset)
        assert leaks, name
        assert name in leaks[0], leaks


def test_the_leak_guard_accepts_markers_placeholders_and_documented_examples():
    """A guard that fires on its own markers would be switched off within a day."""
    clean = finding(references=[
        "aws documentation: AKIAIOSFODNN7EXAMPLE",
        "postgresql://app:[REDACTED]@db.internal:5432/app",
        "postgresql://app:${DB_PASS}@db.internal:5432/app",
        "billing key: [REDACTED STRIPE KEY]",
        "token truncated as ghp_\u2026(40 chars)",
    ])
    dataset = {"schema_version": fm.SCHEMA_VERSION, "findings": [clean]}
    assert vf.find_shape_leaks(dataset) == []


def test_the_leak_guard_needs_no_secrets_file(target, tmp_path, capsys):
    """The reported leak: no known-value list, so nothing was checked at all."""
    stripe = "sk_live_" + "Z" * 24
    write(target, "app/config.py", "K = 1\n")
    source = tmp_path / "deduped.json"
    # ``references`` is not a redacted field, so the value survives validation and
    # the shape guard is the only thing between it and findings.json.
    source.write_text(json.dumps({"findings": [
        finding(file="app/config.py", line=1,
                references=["https://dashboard.example.com/keys/" + stripe])]}))
    out = tmp_path / "findings.json"

    assert vf.main([str(source), "--root", target, "--out", str(out)]) == 1
    assert not out.exists(), "a dataset with a live-shaped key must not be written"
    assert "Stripe key" in capsys.readouterr().err


# --------------------------------------------------------------------------- #
# A secret beside an unrelated finding
#
# Evidence quotes a ±1 window, so a credential on the neighbouring line is part
# of the excerpt of a finding that has nothing to do with it. It must be
# redacted there too, or it reaches findings.json and every report through a
# finding nobody would look at for a secret.
# --------------------------------------------------------------------------- #

def test_a_missing_snapshot_does_not_reuse_the_scanners_unredacted_evidence(target):
    """The fallback path must not fall back to the scanner's raw excerpt."""
    stripe = "sk_live_" + "Z" * 24
    planted = finding(file="app/gone.py", line=3,
                      evidence="    3 | billing key: " + stripe)
    result, _ = validate(target, [planted])
    record = result["findings"][0]

    assert stripe not in json.dumps(result)
    assert "evidence unavailable" in record["evidence"], record["evidence"]


def test_an_adjacent_secret_never_reaches_any_deliverable(target, tmp_path):
    """SQL injection at line 4, a Stripe key at line 3: no format may show it."""
    import builtin_analyzers as ba
    import deduplicate_findings as df
    import generate_reports as gr

    stripe = "sk_live_" + "Z" * 24
    write(target, "app/orders.py",
          "from flask import request\n"
          "def handler(request):\n"
          "    # billing key: " + stripe + "\n"
          "    return db.execute(\"SELECT * FROM orders WHERE id=\" + request.args['id'])\n")

    analysis = tmp_path / "analysis.json"
    analysis.write_text(json.dumps(ba.analyze(target)))
    # The stage-3 document is itself a deliverable a reader may open.
    assert stripe not in analysis.read_text()

    deduped = tmp_path / "deduped.json"
    deduped.write_text(json.dumps(df.deduplicate(json.loads(analysis.read_text()))))
    validated = tmp_path / "findings.json"
    assert vf.main([str(deduped), "--root", target, "--out", str(validated)]) == 0
    payload = validated.read_text()
    assert stripe not in payload

    sql = [f for f in json.loads(payload)["findings"] if f["category"] == "sql_injection"]
    assert sql, "the corpus should produce the SQL injection finding"
    assert "SELECT * FROM orders WHERE id=" in sql[0]["evidence"], sql[0]["evidence"]

    formats = "markdown,html,json"
    for tool in ("pandoc", "xelatex"):
        if not shutil.which(tool):
            break
    else:
        formats += ",pdf"

    outdir = tmp_path / "report"
    assert gr.main(["--dataset", str(validated), "--outdir", str(outdir),
                    "--formats", formats]) == 0

    written = [p for p in outdir.rglob("*") if p.is_file()
               and p.suffix in (".md", ".html", ".json", ".pdf")]
    assert written
    for path in written:
        if path.suffix == ".pdf":
            text = subprocess.run(["pdftotext", str(path), "-"],
                                  capture_output=True, text=True, check=True).stdout
        else:
            text = path.read_text(encoding="utf-8", errors="replace")
        assert stripe not in text, path
    rendered = "\n".join(p.read_text(encoding="utf-8", errors="replace")
                         for p in written if p.suffix in (".md", ".html", ".json"))
    assert "sk_l\u2026(32 chars)" in rendered or "REDACTED" in rendered, \
        "the report should show a marker, not silently drop the line"
