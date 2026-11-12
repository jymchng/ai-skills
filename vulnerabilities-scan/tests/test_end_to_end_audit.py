#!/usr/bin/env python3
"""End-to-end audit over both fixture corpora, plus the corpus expectations.

This is the test that would have caught every defect found while writing it: it
runs the real stages in the real order (inventory → technologies → attack surface
→ analyzers → dedupe → validate → reports → verify), then inspects the artefacts
rather than the intermediate objects. Three things are asserted that unit tests
cannot see: that the vulnerable corpus still yields all 20 required classes, that
the secure look-alikes yield nothing beyond the recorded false positives, and that
the delivered report set is internally consistent and secret-free.

The pipeline runs once per corpus per session (~2s each, no PDF toolchain) and is
cached in ``_PIPELINE``; the directories live under ``.scratch`` which is ignored.
"""

from __future__ import annotations

import collections
import hashlib
import json
import os
import subprocess
import sys

import pytest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPTS = os.path.join(REPO, "scripts")
if SCRIPTS not in sys.path:
    sys.path.insert(0, SCRIPTS)

import finding_model as fm  # noqa: E402

FIXTURES = os.path.join(REPO, "tests", "fixtures")
SCRATCH = os.path.join(REPO, ".scratch", "tests", "e2e")
EXPECTATIONS = os.path.join(FIXTURES, "expected_findings.json")

_PIPELINE: dict = {}


def _run(script, *args, timeout=300):
    result = subprocess.run([sys.executable, os.path.join(SCRIPTS, script), *args],
                            capture_output=True, text=True, timeout=timeout)
    assert result.returncode == 0, "%s failed:\n%s\n%s" % (script, result.stdout[-2000:],
                                                           result.stderr[-2000:])
    return result


def pipeline(corpus: str) -> dict:
    """Run stages 1-6 over a fixture corpus once per session and cache the paths."""
    if corpus in _PIPELINE:
        return _PIPELINE[corpus]
    root = os.path.join(FIXTURES, corpus)
    out = os.path.join(SCRATCH, corpus)
    os.makedirs(out, exist_ok=True)
    reports = os.path.join(out, "reports")
    paths = {
        "root": root, "out": out, "reports": reports,
        "inventory": os.path.join(out, "inventory.json"),
        "technologies": os.path.join(out, "technologies.json"),
        "attack_surface": os.path.join(out, "attack-surface.json"),
        "analysis": os.path.join(out, "analysis.json"),
        "deduped": os.path.join(out, "deduped.json"),
        "findings": os.path.join(out, "findings.json"),
        "transcript": os.path.join(out, "transcript.json"),
        "verify": os.path.join(out, "verify-reports.json"),
    }
    _run("repository_inventory.py", "--root", root, "--out", paths["inventory"])
    _run("detect_technologies.py", "--root", root, "--inventory", paths["inventory"],
         "--out", paths["technologies"])
    _run("attack_surface.py", "--root", root, "--inventory", paths["inventory"],
         "--technologies", paths["technologies"], "--out", paths["attack_surface"])
    _run("builtin_analyzers.py", "--root", root, "--inventory", paths["inventory"],
         "--technologies", paths["technologies"], "--attack-surface", paths["attack_surface"],
         "--out", paths["analysis"], "--quiet")
    _run("deduplicate_findings.py", paths["analysis"], "--out", paths["deduped"])
    _run("validate_findings.py", paths["deduped"], "--root", root,
         "--out", paths["findings"], "--transcript", paths["transcript"])
    _run("generate_reports.py", "--dataset", paths["findings"], "--outdir", reports,
         "--analysis", paths["analysis"], "--inventory", paths["inventory"],
         "--formats", "markdown,html,json")
    result = _run("validate_reports.py", "--outdir", reports, "--dataset", paths["findings"])
    with open(paths["verify"], "w") as handle:
        handle.write(result.stdout)
    _PIPELINE[corpus] = paths
    return paths


def load(path):
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def expectations():
    return load(EXPECTATIONS)


# --- the corpus expectations are met, and met honestly --------------------- #


def test_all_twenty_required_classes_are_still_detected():
    doc = pipeline("vulnerable-app")
    analysis = load(doc["analysis"])
    by_category = collections.Counter(finding["category"] for finding in analysis["findings"])
    expected = expectations()
    assert expected["totals"]["required_classes"] == 20
    for entry in expected["classes"]:
        assert by_category[entry["id"]] > 0, entry["id"]
        assert by_category[entry["id"]] == entry["vulnerable"]["findings"], entry["id"]
    assert len(by_category) >= 20
    assert expected["totals"]["classes_detected"] == 20


def test_every_declared_file_exists_and_carries_its_class():
    doc = pipeline("vulnerable-app")
    analysis = load(doc["analysis"])
    seen = collections.defaultdict(set)
    for finding in analysis["findings"]:
        seen[finding["category"]].add(finding["location"]["file"])
    for entry in expectations()["classes"]:
        for declared in entry["vulnerable"]["files"]:
            path = os.path.join(doc["root"], declared["path"])
            assert os.path.isfile(path), (entry["id"], declared["path"])
            assert declared["path"] in seen[entry["id"]], (entry["id"], declared["path"])


def test_secure_look_alikes_produce_only_the_recorded_false_positives():
    doc = pipeline("secure-app")
    analysis = load(doc["analysis"])

    def key(finding):
        return (finding["category"], finding["location"]["file"],
                finding["location"]["line_start"],
                (finding.get("sources") or [{}])[0].get("rule_id"))

    actual = collections.Counter(key(finding) for finding in analysis["findings"])
    recorded = collections.Counter(
        (item["category"], item["file"], item["line"], item["rule_id"])
        for item in expectations()["known_false_positives"])
    assert actual == recorded
    # Every recorded false positive has to explain itself: an unexplained one is
    # an unowned precision gap.
    for item in expectations()["known_false_positives"]:
        assert item["reason"] and item["reason"] != "unclassified precision gap", item
        assert item["status"] == "open", item


# --- the delivered report set --------------------------------------------- #


def test_the_report_set_passes_its_own_verifier():
    for corpus in ("vulnerable-app", "secure-app"):
        doc = pipeline(corpus)
        report = load(doc["verify"])
        assert report["ok"] is True, report["problems"]
        assert report["problems"] == []
        # The PDF toolchain is intentionally not exercised here: no PDF is
        # requested, and the verifier must say so rather than pass silently.
        assert report["checked"]["pdf_state"] == "absent"
        assert any("no PDF" in warning for warning in report["warnings"])


def test_every_finding_has_its_own_json_and_the_index_describes_them_all():
    doc = pipeline("vulnerable-app")
    dataset = load(doc["findings"])
    index = load(os.path.join(doc["reports"], "findings-index.json"))
    assert index["kind"] == "security-audit-findings-index"
    ids = [finding["id"] for finding in dataset["findings"]]
    indexed = [entry["id"] for entry in index["findings"]]
    # The report reorders findings by severity, so the register is compared as a
    # set against the dataset and in order against the JSON report.
    assert set(indexed) == set(ids)
    assert index["totals"]["findings"] == len(ids)
    assert index["totals"]["ticketable"] == sum(
        1 for entry in index["findings"] if entry["ticketable"])
    ticket_dir = os.path.join(doc["reports"], "tickets")
    on_disk = sorted(name for name in os.listdir(ticket_dir) if name.endswith(".json"))
    assert len(on_disk) == len(ids)
    by_id = {entry["id"]: entry for entry in index["findings"]}
    for finding in dataset["findings"]:
        entry = by_id[finding["id"]]
        ticket_path = os.path.join(ticket_dir, "%s.json" % finding["id"])
        assert os.path.isfile(ticket_path), ticket_path
        ticket = load(ticket_path)
        assert ticket["finding_id"] == finding["id"]
        assert entry["ticket"]["sha256"] == hashlib.sha256(
            open(ticket_path, "rb").read()).hexdigest()
        assert entry["category"] == finding["category"]
        assert entry["ticketable"] is (finding["validation_status"] == "validated")
        if not entry["ticketable"]:
            assert entry["ticketable_reason"]


def test_needs_investigation_findings_get_a_file_but_are_not_ticketable():
    doc = pipeline("vulnerable-app")
    index = load(os.path.join(doc["reports"], "findings-index.json"))
    review = [entry for entry in index["findings"]
              if entry["validation_status"] == "needs_review"]
    assert review, "the corpus produces findings that need a human decision"
    for entry in review:
        assert entry["ticketable"] is False
        assert entry["ticketable_reason"]
        assert os.path.isfile(entry["ticket"]["path"])


def test_every_finding_conforms_to_the_published_schema():
    doc = pipeline("vulnerable-app")
    dataset = load(doc["findings"])
    problems = fm.validate(dataset) + fm.consistency_problems(dataset)
    assert problems == [], problems[:5]


def test_ids_and_totals_agree_across_the_formats():
    doc = pipeline("vulnerable-app")
    dataset = load(doc["findings"])
    report = load(os.path.join(doc["reports"], "SECURITY-AUDIT-REPORT.json"))
    ids = [finding["id"] for finding in dataset["findings"]]
    validated = sorted(finding["id"] for finding in dataset["findings"]
                       if finding["validation_status"] == "validated")
    # The report orders by severity and carries only the validated findings; the
    # dataset orders by location and carries every finding. Same set of validated ids.
    assert sorted(ticket["finding_id"] for ticket in report["findings"]) == validated
    counts = report["counts"]
    assert counts["total"] == len(ids)
    assert sum(counts["by_severity"].values()) == len(ids)
    assert counts["validated"] + counts["needs_investigation"] + counts["suppressed"] == len(ids)
    markdown = open(os.path.join(doc["reports"], "SECURITY-AUDIT-REPORT.md")).read()
    html = open(os.path.join(doc["reports"], "SECURITY-AUDIT-REPORT.html")).read()
    for finding_id in ids:
        assert finding_id in markdown
        assert finding_id in html


def test_no_raw_fixture_secret_reaches_any_deliverable():
    """The corpus hardcodes three credentials; none may survive to delivery."""
    doc = pipeline("vulnerable-app")
    config = open(os.path.join(doc["root"], "python", "orders", "config.py")).read()
    raw_values = [line.split("=", 1)[1].strip().strip('"')
                  for line in config.splitlines()
                  if "=" in line and not line.lstrip().startswith("#")]
    raw_values = [value for value in raw_values if value and value.isascii()]
    assert raw_values, "the fixture is expected to hardcode credentials"
    reports = doc["reports"]
    deliverables = [os.path.join(reports, name) for name in
                    ("SECURITY-AUDIT-REPORT.md", "SECURITY-AUDIT-REPORT.html",
                     "SECURITY-AUDIT-REPORT.json", "findings-index.json",
                     "report-manifest.json")]
    deliverables += [os.path.join(reports, "tickets", name)
                     for name in os.listdir(os.path.join(reports, "tickets"))]
    for path in deliverables:
        text = open(path, encoding="utf-8", errors="replace").read()
        for value in raw_values:
            assert value not in text, (os.path.basename(path), value)


def test_validation_reports_that_it_redacted_the_evidence_it_re_quoted():
    """Regression: the run said "0 redactions applied" while redacting evidence."""
    doc = pipeline("vulnerable-app")
    transcript = load(doc["transcript"])
    assert transcript["redactions_applied"] > 0
    dataset = load(doc["findings"])
    secret_finding = next(finding for finding in dataset["findings"]
                          if finding["category"] == "hardcoded_secret"
                          and "postgres" in json.dumps(finding.get("evidence")))
    evidence = secret_finding["evidence"]
    if isinstance(evidence, dict):
        evidence = evidence.get("text") or ""
    assert "postgres://" in evidence
    password = evidence.split("postgres://", 1)[1].split("@", 1)[0].split(":", 1)[1]
    assert fm.is_placeholder(password), password


def test_a_redacted_connection_string_is_not_reported_as_a_leak():
    """Regression: the shape-only leak guard failed a correct report set."""
    import validate_reports as vr
    problems, warnings = [], []
    vr._scan_secret_shapes("a report",  # noqa: SLF001 - the guard is the unit here
                           "DATABASE_URL = \"postgres://app:[REDACTED]@db.internal:5432/app\"\n"
                           "API_KEY = [REDACTED]\n", problems, warnings)
    assert problems == []
    problems, warnings = [], []
    vr._scan_secret_shapes("a report",
                           "DATABASE_URL = \"postgres://app:hunter2hunter2@db.internal/app\"\n",
                           problems, warnings)
    assert problems and "connection-string" in problems[0]


def test_the_html_article_expectation_counts_needs_investigation_sections():
    """Regression: every report set with one needs-review finding failed the gate."""
    doc = pipeline("vulnerable-app")
    report = load(doc["verify"])
    index = load(os.path.join(doc["reports"], "findings-index.json"))
    # Suppressed findings are deliberately not rendered as articles, so the
    # article count is the delivered set minus the suppressed ones.
    rendered = index["totals"]["validated"] + index["totals"]["needs_investigation"]
    assert report["checked"]["html"]["articles"] == rendered
    assert report["checked"]["html"]["articles"] < index["totals"]["findings"]
