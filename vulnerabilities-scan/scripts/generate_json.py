#!/usr/bin/env python3
"""Stage 6 \u2014 emit the machine-readable report and one JSON file per vulnerability.

The Markdown, HTML and PDF reports are for people. This format is for the agent
or pipeline that comes next: a deterministic, ticket-ready record for every
validated vulnerability, so an issue tracker (Jira, GitHub Issues, Linear, a
spreadsheet) can be populated without parsing prose or re-deriving severity.

Two artefacts are written, from the same view model as the human reports:

``SECURITY-AUDIT-REPORT.json``
    The whole audit: provenance, counts, verdict, coverage and limitations,
    methodology, every finding, plus the items still under investigation and the
    suppressed findings \u2014 so a consumer can see what was *not* reported as a
    vulnerability and why.

``tickets/VULN-NNN.json``
    One self-contained file per validated finding. Written so each file can be
    posted to a tracker on its own, with no cross-references to resolve.

Ticket fields
-------------
Each ticket carries the finding verbatim, a ``fingerprint`` that is stable
across re-runs, and a ``jira`` block that maps the finding onto issue-tracker
fields:

``summary``       ``[High] SQL injection in order lookup (VULN-003)``
``issuetype``     ``Bug``
``priority``      P0\u2192Highest, P1\u2192High, P2\u2192Medium, P3\u2192Low
``labels``        ``security``, the severity, the category, the CWE id, ``audit``
``components``    the top-level directory of the affected file, when there is one
``description``   Markdown with impact, attack scenario, evidence, remediation
``acceptance_criteria``  what has to be true before the ticket may be closed

Every finding in the dataset gets exactly one JSON file in ``tickets/`` \u2014
validated, needs-investigation and suppressed alike \u2014 so no finding is
reachable only by parsing the aggregate report. Actionability is carried
*inside* the file: ``ticketable`` is true only for a validated finding, and
``ticketable_reason`` says why the others are not, because filing an unvalidated
pattern match as a defect is exactly the false-positive behaviour this skill
exists to avoid. ``findings-index.json`` is the metadata document over the whole
set: one entry per finding with its path, digest and status, plus the totals.

The fingerprint exists for idempotency: a downstream agent can create the issue
with the fingerprint as a label and skip tickets whose fingerprint it has seen,
so re-running the audit does not duplicate the backlog.

Usage::

    python3 scripts/generate_json.py --dataset findings.json --outdir audit/

Prints a JSON description of the written files.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from typing import Any, Dict, List, Mapping, Optional, Sequence

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

import report_model as rm  # noqa: E402

TOOL_NAME = "generate_json.py"

#: Directory, under ``--outdir``, holding one file per validated finding.
TICKET_DIRNAME = "tickets"

#: The severity ladder is not the priority ladder: priority also accounts for
#: reachability and business context, and the dataset records both.
JIRA_PRIORITY = {"P0": "Highest", "P1": "High", "P2": "Medium", "P3": "Low"}
JIRA_ISSUE_TYPE = "Bug"


def fingerprint(finding: Mapping[str, Any]) -> str:
    """A stable identifier for "this issue, here", independent of scanner order.

    Built from the location, the weakness class and the category, never from the
    assigned ``VULN-NNN`` id: ids shift when a finding is added or dismissed,
    and a ticket that reopens because an unrelated finding was added would be
    worse than no fingerprint at all.
    """
    location = rm._as_dict(finding.get("location"))  # noqa: SLF001 - same package
    parts = [
        str(location.get("file") or "").lstrip("./"),
        str(location.get("line_start") or ""),
        str(finding.get("cwe") or ""),
        str(finding.get("category") or ""),
        " ".join(str(finding.get("title") or "").lower().split()),
    ]
    seed = "\x1f".join(parts)
    return "sha256:" + hashlib.sha256(seed.encode("utf-8")).hexdigest()[:32]


def _component(finding: Mapping[str, Any]) -> List[str]:
    """The top-level directory of the affected file, used as a Jira component."""
    where = str(rm._as_dict(finding.get("location")).get("file") or "")  # noqa: SLF001
    where = where.lstrip("./")
    if "/" not in where:
        return []
    return [where.split("/")[0]]


def _labels(finding: Mapping[str, Any]) -> List[str]:
    labels = ["security", "audit", str(finding.get("severity") or "").lower()]
    category = str(finding.get("category") or "").strip()
    if category:
        labels.append(category)
    cwe = str(finding.get("cwe") or "").split(",")[0].strip()
    if cwe:
        labels.append(cwe.lower())
    if finding.get("in_test_path"):
        labels.append("test-path")
    return [label for label in labels if label]


def _description_markdown(model: Mapping[str, Any], finding: Mapping[str, Any]) -> str:
    """A ticket body that stands alone, ready for an issue tracker."""
    meta = model.get("meta") or {}
    evidence = finding.get("evidence") or {}
    lines: List[str] = [
        "## Summary",
        "",
        str(finding.get("description") or "Not recorded."),
        "",
        "## Impact",
        "",
        str(finding.get("impact") or "Not recorded."),
        "",
        "## Attack scenario",
        "",
        str(finding.get("attack_scenario") or "Not recorded."),
        "",
    ]
    if finding.get("preconditions"):
        lines += ["## Preconditions", ""]
        lines += ["- %s" % item for item in finding["preconditions"]]
        lines += [""]
    lines += [
        "## Location",
        "",
        "- File: `%s`" % finding.get("where"),
        "- Language: %s" % finding.get("language"),
        "- Severity: %s (CVSS v4.0 %s)" % (finding.get("severity"),
                                           (finding.get("cvss") or {}).get("display")),
    ]
    vector = (finding.get("cvss") or {}).get("vector")
    if vector:
        lines.append("- Vector: `%s`" % vector)
    if finding.get("cwe"):
        lines.append("- CWE: %s" % finding.get("cwe"))
    if finding.get("owasp"):
        lines.append("- OWASP: %s" % finding.get("owasp"))
    lines += [""]
    text = str(evidence.get("text") or "")
    if text.strip():
        lines += ["## Evidence", "", "%s" % evidence.get("fence", "```") + "text",
                  text, str(evidence.get("fence", "```")), ""]
    lines += [
        "## Remediation",
        "",
        str(finding.get("recommended_fix") or "Not recorded."),
        "",
    ]
    if finding.get("references"):
        lines += ["## References", ""]
        lines += ["- %s" % item for item in finding["references"]]
        lines += [""]
    if finding.get("validation"):
        lines += ["## Validation", "", str(finding.get("validation")), ""]
    lines += [
        "---",
        "",
        "Audit provenance: commit `%s` (%s), audited %s, generated by %s %s."
        % (meta.get("commit_short"), meta.get("dirty_display"), meta.get("audit_date"),
           (model.get("tool") or {}).get("name"), (model.get("tool") or {}).get("version")),
        "Line numbers refer to that snapshot.",
        "",
    ]
    return "\n".join(lines)


def _acceptance_criteria(finding: Mapping[str, Any]) -> List[str]:
    where = str(finding.get("where") or "the affected code")
    criteria = [
        "The weakness at %s no longer reproduces under the attack scenario above."
        % where,
        "A regression test or a documented manual check covers the fix.",
        "The remediation below is applied, or a compensating control with a recorded "
        "owner and expiry is in place.",
    ]
    fix = str(finding.get("recommended_fix") or "").strip()
    if fix:
        criteria.append("Remediation applied: %s" % " ".join(fix.split()))
    return criteria


def build_ticket(model: Mapping[str, Any], finding: Mapping[str, Any],
                 ticketable: bool = True,
                 ticketable_reason: str = "") -> Dict[str, Any]:
    """One ticket-ready record for one finding."""
    return {
        "schema_version": "1.0",
        "kind": "security-finding-ticket",
        "generator": {
            "name": (model.get("tool") or {}).get("name"),
            "version": (model.get("tool") or {}).get("version"),
            "generated_at": model.get("generated_at"),
        },
        "audit": {
            "repository": (model.get("meta") or {}).get("repository"),
            "commit": (model.get("meta") or {}).get("commit"),
            "commit_short": (model.get("meta") or {}).get("commit_short"),
            "branch": (model.get("meta") or {}).get("branch"),
            "dirty": (model.get("meta") or {}).get("dirty"),
            "audit_date": (model.get("meta") or {}).get("audit_date"),
            "scope": (model.get("meta") or {}).get("scope"),
        },
        "finding_id": finding.get("id"),
        "fingerprint": fingerprint(finding),
        "ticketable": ticketable,
        "ticketable_reason": ticketable_reason,
        "finding": finding,
        "jira": {
            "summary": "[%s] %s (%s)" % (finding.get("severity"), finding.get("title"),
                                         finding.get("id")),
            "issuetype": {"name": JIRA_ISSUE_TYPE},
            "priority": {"name": JIRA_PRIORITY.get(str(finding.get("priority")), "Medium")},
            "labels": _labels(finding),
            "components": [{"name": name} for name in _component(finding)],
            "description_markdown": _description_markdown(model, finding),
            "acceptance_criteria": _acceptance_criteria(finding),
            "custom_fields": {
                "finding_id": finding.get("id"),
                "fingerprint": fingerprint(finding),
                "severity": finding.get("severity"),
                "confidence": finding.get("confidence"),
                "validation_status": finding.get("validation_status"),
                "priority": finding.get("priority"),
                "cvss_score": (finding.get("cvss") or {}).get("display"),
                "cvss_vector": (finding.get("cvss") or {}).get("vector"),
                "cwe": finding.get("cwe"),
                "owasp": finding.get("owasp"),
                "category": finding.get("category"),
                "location": finding.get("where"),
                "language": finding.get("language"),
                "reported_by": finding.get("sources"),
            },
        },
    }


def build_document(model: Mapping[str, Any]) -> Dict[str, Any]:
    """The aggregate machine-readable report."""
    findings = [entry for entry in rm._as_list(model.get("findings"))  # noqa: SLF001
                if isinstance(entry, dict)]
    return {
        "schema_version": "1.0",
        "kind": "security-audit-report",
        "generator": {
            "name": (model.get("tool") or {}).get("name"),
            "version": (model.get("tool") or {}).get("version"),
            "generated_at": model.get("generated_at"),
            "source": "one shared findings dataset",
        },
        "meta": model.get("meta"),
        "counts": model.get("counts"),
        "verdict": model.get("verdict"),
        "coverage": model.get("coverage"),
        "methodology": model.get("methodology"),
        "dataset_policy": model.get("dataset_policy"),
        "integrity": model.get("integrity"),
        "findings": [build_ticket(model, entry) for entry in findings],
        "needs_investigation": [
            build_ticket(model, entry, False,
                         "not validated as a vulnerability; needs a human decision")
            for entry in rm._as_list(model.get("needs_investigation"))  # noqa: SLF001
            if isinstance(entry, dict)],
        "suppressed": [
            build_ticket(model, entry, False,
                         "dismissed as a false positive by a compensating control")
            for entry in rm._as_list(model.get("suppressed"))  # noqa: SLF001
            if isinstance(entry, dict)],
        "negative_findings": model.get("negative_findings"),
        "suppressions": model.get("suppressions"),
    }


def ticket_filename(finding_id: Any) -> str:
    """A filesystem-safe, sortable file name for a finding id."""
    safe = re.sub(r"[^A-Za-z0-9._-]+", "-", str(finding_id or "unassigned")).strip("-")
    return "%s.json" % (safe or "unassigned")


def build_index(model: Mapping[str, Any], document: Mapping[str, Any],
                ticket_dir: str, tickets: Sequence[Mapping[str, Any]]) -> Dict[str, Any]:
    """Metadata for every finding, with a pointer to that finding's own JSON.

    The aggregate report is prose-shaped: it is built for a reader. This document
    is the machine-readable register of the same set, so a consumer can enumerate
    findings and fetch one file each without parsing the report.
    """
    by_id = {str(ticket.get("finding_id")): ticket for ticket in tickets}
    entries: List[Dict[str, Any]] = []
    for section, status in (("findings", "validated"),
                            ("needs_investigation", "needs_review"),
                            ("suppressed", "suppressed")):
        for entry in rm._as_list(document.get(section)):  # noqa: SLF001
            if not isinstance(entry, dict):
                continue
            ticket = by_id.get(str(entry.get("finding_id")), {})
            entries.append({
                "id": entry.get("finding_id"),
                "kind": entry.get("kind"),
                "file": (entry.get("finding") or {}).get("location", {}).get("file"),
                "line_start": (entry.get("finding") or {}).get("location", {}).get("line_start"),
                "line_end": (entry.get("finding") or {}).get("location", {}).get("line_end"),
                "category": (entry.get("finding") or {}).get("category"),
                "title": (entry.get("finding") or {}).get("title"),
                "severity": (entry.get("finding") or {}).get("severity"),
                "confidence": (entry.get("finding") or {}).get("confidence"),
                "priority": (entry.get("finding") or {}).get("priority"),
                "validation_status": status,
                "ticketable": entry.get("ticketable"),
                "ticketable_reason": entry.get("ticketable_reason"),
                "ticket": {"path": ticket.get("path"), "sha256": ticket.get("sha256"),
                           "bytes": ticket.get("bytes"),
                           "fingerprint": ticket.get("fingerprint")},
            })
    return {
        "schema_version": "1.0",
        "kind": "security-audit-findings-index",
        "generator": {"name": (model.get("tool") or {}).get("name"),
                      "version": (model.get("tool") or {}).get("version"),
                      "generated_at": model.get("generated_at")},
        "meta": model.get("meta"),
        "counts": model.get("counts"),
        "ticket_dir": ticket_dir,
        "totals": {"findings": len(entries),
                   "ticketable": sum(1 for entry in entries if entry["ticketable"]),
                   "validated": sum(1 for entry in entries
                                    if entry["validation_status"] == "validated"),
                   "needs_investigation": sum(1 for entry in entries
                                              if entry["validation_status"] == "needs_review"),
                   "suppressed": sum(1 for entry in entries
                                     if entry["validation_status"] == "suppressed")},
        "findings": entries,
    }


def generate(model: Mapping[str, Any], outdir: str, out: Optional[str] = None,
             ticket_dir: Optional[str] = None,
             write_tickets: bool = True) -> Dict[str, Any]:
    """Write the aggregate report and one file per validated finding."""
    rm.ensure_outdir(outdir)
    document = build_document(model)
    target = out or os.path.join(outdir, rm.OUTPUT_NAMES["json"])
    written = rm.write_report(target, json.dumps(document, indent=2, ensure_ascii=False) + "\n")
    result = rm.format_result(model, written, "json")

    directory = ticket_dir or os.path.join(outdir, TICKET_DIRNAME)
    tickets: List[Dict[str, Any]] = []
    index_record: Dict[str, Any] = {}
    if write_tickets:
        rm.ensure_outdir(directory)
        # One file per finding, not one per *validated* finding: a finding the
        # report shows as "needs investigation" is still a finding with its own
        # evidence, and a reviewer must be able to open it. Actionability is
        # carried by ``ticketable`` inside the file, so the set of files and the
        # set of findings stay the same size.
        for entry in (document["findings"] + document["needs_investigation"]
                      + document["suppressed"]):
            path = os.path.join(directory, ticket_filename(entry["finding_id"]))
            record = rm.write_report(path, json.dumps(entry, indent=2, ensure_ascii=False) + "\n")
            tickets.append({"finding_id": entry["finding_id"], "path": path,
                            "sha256": record["sha256"], "bytes": record["bytes"],
                            "fingerprint": entry["fingerprint"],
                            "jira_summary": entry["jira"]["summary"],
                            "jira_priority": entry["jira"]["priority"]["name"]})
        index = build_index(model, document, directory, tickets)
        index_record = rm.write_report(
            os.path.join(outdir, rm.OUTPUT_NAMES["index"]),
            json.dumps(index, indent=2, ensure_ascii=False) + "\n")
    result.update({"document": target, "ticket_dir": directory if write_tickets else None,
                   "tickets": tickets, "needs_investigation": len(document["needs_investigation"]),
                   "suppressed": len(document["suppressed"]),
                   "index": index_record})
    return result


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Emit the machine-readable audit report and one JSON ticket per "
                    "validated vulnerability.",
        epilog="Tickets are written only for validated findings, so an issue tracker "
               "never receives an unvalidated pattern match. Each ticket carries a "
               "stable fingerprint so re-runs do not duplicate the backlog.")
    rm.add_common_arguments(parser)
    parser.add_argument("--ticket-dir", help="directory for per-finding files "
                                             "(default: <outdir>/%s)" % TICKET_DIRNAME)
    parser.add_argument("--no-tickets", dest="write_tickets", action="store_false",
                        help="write only the aggregate report")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    model = rm.model_from_args(args)
    result = generate(model, args.outdir, args.out, args.ticket_dir, args.write_tickets)
    rm.emit(result, args.indent)
    return 0


if __name__ == "__main__":
    sys.exit(main())
