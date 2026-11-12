"""Tests for the report layer: one dataset, three formats, one set of numbers.

These tests exist because of specific defects found while building the
generator, each of which would have shipped silently:

* a dataset without ``id`` made every finding render as ``unassigned``, which
  collapsed 57 per-finding tickets onto one file name and made the cross-format
  id check compare the same placeholder 57 times;
* the summary table printed an em dash in the validated / under-investigation /
  suppressed columns, which a reader cannot tell apart from a zero;
* pandoc's ``\\maketitle`` produced a near-empty first page ahead of the real
  cover page;
* an ``impact`` given as an array reached the client as a Python repr;
* a PDF deliberately not requested was reported by the validator as a failure.

The tests also prove the properties the report is *claimed* to have: untrusted
content is escaped, the HTML is self-contained, and the validator really does
catch a format that disagrees with the others or a leaked credential.
"""

from __future__ import annotations

import json
import os
import re
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts"))

import generate_html  # noqa: E402
import generate_json  # noqa: E402
import generate_markdown  # noqa: E402
import generate_pdf  # noqa: E402
import report_model as rm  # noqa: E402
import validate_reports  # noqa: E402


# --------------------------------------------------------------------------- #
# Fixtures
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
        "preconditions": ["A valid session."],
        "evidence": "42 | q = 'SELECT * FROM orders WHERE id=' + uid",
        "root_cause": "String concatenation instead of a bound parameter.",
        "recommended_fix": "Use a parameterised query.",
        "references": ["https://cwe.mitre.org/data/definitions/89.html"],
        "sources": [{"tool": "builtin", "rule_id": "sql-injection"}],
    }
    finding.update(overrides)
    return finding


def _dataset(findings):
    return {
        "schema_version": "1.0",
        "generated_by": {"name": "validate_findings.py", "version": "1.0.0"},
        "findings": findings,
        "summary": {"findings": len(findings)},
        "validation_policy": {"policy": "test"},
    }


@pytest.fixture()
def model():
    return rm.build_report(_dataset([_finding()]))


# --------------------------------------------------------------------------- #
# Finding identifiers
# --------------------------------------------------------------------------- #

class TestIdentifiers:
    def test_missing_ids_are_assigned_not_called_unassigned(self):
        dataset = _dataset([_finding(id=None), _finding(title="Second", id=None)])
        built = rm.build_report(dataset)
        ids = [f["id"] for f in built["findings"]]
        assert len(set(ids)) == 2
        assert all(re.match(r"^VULN-\d{3}$", value) for value in ids)
        assert "unassigned" not in ids

    def test_assignment_is_deterministic_and_ordered_by_severity(self):
        low = _finding(id=None, title="Low one", severity="Low",
                       location={"file": "a.py", "line_start": 1})
        critical = _finding(id=None, title="Critical one", severity="Critical",
                            location={"file": "z.py", "line_start": 9})
        first = rm.build_report(_dataset([low, critical]))
        second = rm.build_report(_dataset([critical, low]))
        by_title_first = {f["title"]: f["id"] for f in first["findings"]}
        by_title_second = {f["title"]: f["id"] for f in second["findings"]}
        assert by_title_first == by_title_second
        assert by_title_first["Critical one"] == "VULN-001"

    def test_duplicate_ids_are_renumbered(self):
        built = rm.build_report(_dataset([_finding(), _finding(title="Twin")]))
        ids = [f["id"] for f in built["findings"]]
        assert len(set(ids)) == 2, "duplicate ids would overwrite each other's ticket"

    def test_existing_valid_ids_are_preserved(self):
        built = rm.build_report(_dataset([_finding(id="VULN-042")]))
        assert built["findings"][0]["id"] == "VULN-042"

    def test_anchors_follow_the_ids(self):
        built = rm.build_report(_dataset([_finding(id="VULN-007")]))
        assert built["anchors"] == ["vuln-007"]


# --------------------------------------------------------------------------- #
# Counts
# --------------------------------------------------------------------------- #

class TestCounts:
    def test_severity_detail_sums_to_the_totals(self):
        findings = [
            _finding(id="VULN-001", severity="Critical"),
            _finding(id="VULN-002", severity="Critical", validation_status="needs_review"),
            _finding(id="VULN-003", severity="High", validation_status="suppressed"),
            _finding(id="VULN-004", severity="Low"),
        ]
        counts = rm.build_report(_dataset(findings))["counts"]
        detail = counts["by_severity_detail"]
        assert sum(row["count"] for row in detail) == counts["total"] == 4
        assert sum(row["validated"] for row in detail) == counts["validated"] == 2
        assert sum(row["needs_investigation"] for row in detail) == 1
        assert sum(row["suppressed"] for row in detail) == 1
        critical = [row for row in detail if row["name"] == "Critical"][0]
        assert critical == {"name": "Critical", "count": 2, "validated": 1,
                            "needs_investigation": 1, "suppressed": 0}

    def test_every_band_is_present_even_at_zero(self):
        detail = rm.build_report(_dataset([_finding()]))["counts"]["by_severity_detail"]
        assert [row["name"] for row in detail] == list(rm.SEVERITIES)


# --------------------------------------------------------------------------- #
# Untrusted content
# --------------------------------------------------------------------------- #

class TestUntrustedContent:
    HOSTILE = _finding(
        id="VULN-001",
        title='<script>alert("xss")</script> | pipe',
        description="desc </script><img src=x onerror=alert(1)>",
        location={"file": "app/<b>evil</b>.py", "line_start": 10, "line_end": 12},
    )

    def test_html_escapes_every_substituted_field(self, tmp_path):
        built = rm.build_report(_dataset([self.HOSTILE]))
        written = generate_html.generate(built, str(tmp_path))
        text = open(written["path"], encoding="utf-8").read()
        assert "<script>alert" not in text
        assert "</script><img" not in text
        assert "&lt;script&gt;" in text
        assert "&lt;img src=x onerror" in text

    def test_html_is_self_contained(self, tmp_path):
        built = rm.build_report(_dataset([self.HOSTILE]))
        written = generate_html.generate(built, str(tmp_path))
        text = open(written["path"], encoding="utf-8").read()
        assert not re.search(r"<script[^>]*\bsrc=", text, re.I)
        assert not re.search(r"<link[^>]*\bhref=", text, re.I)
        assert "@import" not in text
        assert not re.search(r"url\(\s*['\"]?https?:", text, re.I)
        assert text.count("<style") == 1 and text.count("<script") == 1

    def test_markdown_escapes_pipes_inside_table_cells(self, tmp_path):
        hostile = _finding(evidence="42 | q = 'x'", cwe={"id": "CWE-89", "name": "a|b"})
        built = rm.build_report(_dataset([hostile]))
        written = generate_markdown.generate(built, str(tmp_path))
        text = open(written["path"], encoding="utf-8").read()
        row = [line for line in text.splitlines() if line.startswith("| CWE |")][0]
        assert r"\|" in row, "the pipe in the CWE name must be escaped: %r" % row
        cells = re.split(r"(?<!\\)\|", row.strip().strip("|"))
        assert len(cells) == 2, "an unescaped pipe would split the cell: %r" % row

    def test_list_valued_prose_does_not_leak_a_python_repr(self, tmp_path):
        listed = _finding(impact=["First impact.", "Second impact."])
        built = rm.build_report(_dataset([listed]))
        assert built["findings"][0]["impact"] == "First impact.; Second impact."
        for module in (generate_markdown, generate_html):
            written = module.generate(built, str(tmp_path / module.__name__))
            text = open(written["path"], encoding="utf-8").read()
            # The rendered prose must contain the joined text, never the list
            # repr the raw value would have produced.
            assert "First impact.; Second impact." in text
            assert "['First impact." not in text
            assert "Second impact.']" not in text

    def test_scalar_reference_is_kept(self):
        built = rm.build_report(_dataset([_finding(references="https://example.test/x")]))
        assert built["findings"][0]["references"] == ["https://example.test/x"]


# --------------------------------------------------------------------------- #
# PDF
# --------------------------------------------------------------------------- #

class TestPdf:
    def test_cover_page_and_headers_are_emitted(self, model):
        cover = generate_pdf.cover_tex(model)
        assert r"\begin{titlepage}" in cover
        assert "Security Audit Report" in cover
        header = generate_pdf.header_tex(model)
        assert r"\fancyhead" in header
        assert r"\fancyfoot" in header
        assert r"\pageref{LastPage}" in header

    def test_maketitle_is_neutralised_so_no_blank_page_precedes_the_cover(self, model):
        # pandoc answers the title metadata with \maketitle; left alone it prints
        # a near-empty page 1 and pushes the cover to page 2.
        assert r"\renewcommand{\maketitle}{}" in generate_pdf.header_tex(model)

    def test_missing_toolchain_is_a_documented_failure(self, model, tmp_path, monkeypatch):
        monkeypatch.setattr(generate_pdf, "PANDOC", "pandoc-not-installed-here")
        result = generate_pdf.generate(model, str(tmp_path))
        assert result["status"] == "unavailable"
        assert "pandoc-not-installed-here" in result["reason"]
        assert not os.path.exists(os.path.join(str(tmp_path), "SECURITY-AUDIT-REPORT.pdf"))

    def test_latex_special_characters_are_escaped(self):
        for raw, escaped in (("a_b", r"a\_b"), ("50%", r"50\%"), ("&", r"\&"),
                             ("{x}", r"\{x\}")):
            assert generate_pdf.escape_latex(raw) == escaped


# --------------------------------------------------------------------------- #
# The verifier
# --------------------------------------------------------------------------- #

def _generate_set(dataset, directory, formats="markdown,html,json"):
    """Write a report set to *directory* using the real generators."""
    model = rm.build_report(dataset)
    out = str(directory)
    os.makedirs(out, exist_ok=True)
    html = generate_html.generate(model, out)
    markdown = generate_markdown.generate(model, out)
    json_result = generate_json.generate(model, out)
    manifest = {
        "formats": {
            "html": {"status": "generated", "path": html["path"]},
            "markdown": {"status": "generated", "path": markdown["path"]},
            "json": {"status": "generated", "path": json_result["path"]},
        },
        "failed": [],
    }
    with open(os.path.join(out, "report-manifest.json"), "w", encoding="utf-8") as handle:
        json.dump(manifest, handle)
    return model


class TestValidateReports:
    def test_a_consistent_set_passes(self, tmp_path):
        _generate_set(_dataset([_finding()]), tmp_path)
        result = validate_reports.validate(str(tmp_path))
        assert result["ok"], result["problems"]

    def test_a_wrong_total_is_caught(self, tmp_path):
        _generate_set(_dataset([_finding()]), tmp_path)
        path = os.path.join(str(tmp_path), "SECURITY-AUDIT-REPORT.md")
        text = open(path, encoding="utf-8").read()
        text = re.sub(r"\*\*Total\*\* \| \*\*1\*\*", "**Total** | **2**", text)
        open(path, "w", encoding="utf-8").write(text)
        result = validate_reports.validate(str(tmp_path))
        assert not result["ok"]
        assert any("total" in problem.lower() for problem in result["problems"])

    def test_a_missing_finding_id_is_caught(self, tmp_path):
        _generate_set(_dataset([_finding()]), tmp_path)
        path = os.path.join(str(tmp_path), "SECURITY-AUDIT-REPORT.html")
        text = open(path, encoding="utf-8").read().replace("VULN-001", "VULN-999")
        open(path, "w", encoding="utf-8").write(text)
        result = validate_reports.validate(str(tmp_path))
        assert not result["ok"]
        assert any("VULN-001" in problem for problem in result["problems"])

    def test_a_wrong_severity_count_is_caught(self, tmp_path):
        _generate_set(_dataset([_finding()]), tmp_path)
        path = os.path.join(str(tmp_path), "SECURITY-AUDIT-REPORT.html")
        text = open(path, encoding="utf-8").read()
        text = text.replace('<span class="card-count">1</span>',
                            '<span class="card-count">7</span>', 1)
        open(path, "w", encoding="utf-8").write(text)
        result = validate_reports.validate(str(tmp_path))
        assert not result["ok"]
        assert any("severity" in problem.lower() for problem in result["problems"])

    def test_a_leaked_secret_fails_every_format(self, tmp_path):
        # Assembled at run time, not written as a literal: a fixture that reads
        # like a live Stripe key is exactly what push protection and a secret
        # scanner are supposed to block, and this skill should not ship one.
        secret = "sk_" + "live_" + "FAKEFIXTURE0123456789abcd"
        leaked = _finding(evidence="42 | api_key = '%s'" % secret)
        _generate_set(_dataset([leaked]), tmp_path)
        result = validate_reports.validate(str(tmp_path), None, [secret])
        assert not result["ok"]
        joined = " ".join(result["problems"])
        assert "Markdown" in joined and "HTML" in joined and "JSON" in joined

    def test_a_pdf_that_was_not_requested_is_a_warning_not_a_failure(self, tmp_path):
        _generate_set(_dataset([_finding()]), tmp_path)
        result = validate_reports.validate(str(tmp_path))
        assert result["ok"], result["problems"]
        assert any("no PDF" in warning for warning in result["warnings"])

    def test_a_required_pdf_that_is_absent_fails(self, tmp_path):
        _generate_set(_dataset([_finding()]), tmp_path)
        result = validate_reports.validate(str(tmp_path), require_pdf=True)
        assert not result["ok"]
        assert any("--require-pdf" in problem for problem in result["problems"])


# --------------------------------------------------------------------------- #
# One dataset behind every format
# --------------------------------------------------------------------------- #

class TestOneDataset:
    def test_every_format_carries_the_same_findings(self, tmp_path):
        dataset = _dataset([_finding(id="VULN-001"),
                            _finding(id="VULN-002", title="Second issue", severity="Low")])
        _generate_set(dataset, tmp_path)
        html = open(os.path.join(str(tmp_path), "SECURITY-AUDIT-REPORT.html"), encoding="utf-8").read()
        markdown = open(os.path.join(str(tmp_path), "SECURITY-AUDIT-REPORT.md"), encoding="utf-8").read()
        document = json.load(open(os.path.join(str(tmp_path), "SECURITY-AUDIT-REPORT.json"),
                                  encoding="utf-8"))
        for finding_id in ("VULN-001", "VULN-002"):
            assert finding_id in html and finding_id in markdown
        assert [ticket["finding_id"] for ticket in document["findings"]] == \
               ["VULN-001", "VULN-002"]

    def test_each_finding_gets_its_own_ticket(self, tmp_path):
        dataset = _dataset([_finding(id=None), _finding(id=None, title="Second")])
        _generate_set(dataset, tmp_path)
        tickets = os.listdir(os.path.join(str(tmp_path), "tickets"))
        assert sorted(tickets) == ["VULN-001.json", "VULN-002.json"]
