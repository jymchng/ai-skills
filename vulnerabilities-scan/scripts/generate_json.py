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

``findings/<verdict>/[<action>/]VULN-NNN.json``
    One self-contained file per finding. Written so each file can be posted to a
    tracker on its own, with no cross-references to resolve.

Where a file is filed is not decoration: the directory is the finding's verdict
and, when it is a confirmed vulnerability, its urgency. The taxonomy has two
axes because one was not enough. "Is this a vulnerability?" and "what should be
done about it, and when?" are different questions, and answering both in a
single name is how a validated Critical came to sit under a label that said
"review required" while an unassessed pattern match sat under one that said
"optional hardening". See :func:`report_model.finding_bucket` for the rules and
:func:`report_model.bucket_reason` for why a file is not ticketable.

Ticket fields
-------------
Each ticket carries the finding verbatim, the ``disposition`` it was filed
under, a ``fingerprint`` that is stable across re-runs, and a ``jira`` block
that maps the finding onto issue-tracker fields:

``summary``       ``[High] SQL injection in order lookup (VULN-003)``
``issuetype``     ``Bug``
``priority``      P0\u2192Highest, P1\u2192High, P2\u2192Medium, P3\u2192Low
``labels``        ``security``, the severity, the category, the CWE id, ``audit``
``components``    the top-level directory of the affected file, when there is one
``description``   Markdown with impact, attack scenario, evidence, remediation
``acceptance_criteria``  what has to be true before the ticket may be closed

Every finding in the dataset gets exactly one JSON file under ``findings/``
\u2014 validated, needs-investigation, unassessed and suppressed alike \u2014 so
no finding is reachable only by parsing the aggregate report. Actionability is
carried *inside* the file: ``ticketable`` is true only for a validated finding,
and ``ticketable_reason`` says why the others are not, because filing an
unvalidated pattern match as a defect is exactly the false-positive behaviour
this skill exists to avoid. ``findings-index.json`` is the metadata document
over the whole set: one entry per finding with its bucket, path, digest and
status, plus the totals.

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

#: Directory, under ``--outdir``, holding one file per finding. The bucket path
#: below it (``validated/remediate-now``, ``needs-review``, ...) comes from
#: :func:`report_model.finding_bucket`, so the generator, the validator and the
#: documented layout cannot drift apart.
FINDINGS_DIRNAME = rm.FINDINGS_DIRNAME

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
    evidence = finding.get("evidence")
    if not isinstance(evidence, dict):
        # A hand-written dataset, or one from before the display layer existed,
        # carries evidence as a plain string. Rendering it as a dict used to be
        # an AttributeError, which is a poor way to learn that.
        evidence = {"text": str(evidence or "")}
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
                 ticketable: Optional[bool] = None,
                 ticketable_reason: Optional[str] = None) -> Dict[str, Any]:
    """One ticket-ready record for one finding, filed under its verdict."""
    bucket = rm.finding_bucket(finding)
    if ticketable is None:
        # Never inferred from the section a finding arrived in: only a validated
        # finding may reach an issue tracker, whatever list it was found in.
        ticketable = rm.bucket_is_validated(bucket)
    if ticketable_reason is None:
        ticketable_reason = rm.bucket_reason(bucket)
    return {
        "schema_version": "1.0",
        "kind": "security-finding-ticket",
        "disposition": bucket,
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


def _sections_by_bucket(model: Mapping[str, Any]) -> Dict[str, List[Dict[str, Any]]]:
    """Every finding in the dataset, grouped by the bucket it will be filed in.

    The model already exposes three lists (validated, needs-investigation,
    suppressed), but they are not the taxonomy: they say where a finding sits in
    the report, not what was decided about it. Grouping by
    :func:`report_model.finding_bucket` means the JSON sections, the directories
    on disk and the ``disposition`` in the index all come from one function, and
    a finding that arrived in the wrong list is filed where its own fields say it
    belongs rather than where the pipeline happened to leave it.
    """
    sections: Dict[str, List[Dict[str, Any]]] = {
        "findings": [], "needs_investigation": [], "unvalidated": [], "suppressed": [],
    }
    ordered = (list(rm._as_list(model.get("findings")))          # noqa: SLF001
               + list(rm._as_list(model.get("needs_investigation")))  # noqa: SLF001
               + list(rm._as_list(model.get("unvalidated")))     # noqa: SLF001
               + list(rm._as_list(model.get("suppressed"))))     # noqa: SLF001
    for entry in ordered:
        if not isinstance(entry, dict):
            continue
        bucket = rm.finding_bucket(entry)
        if rm.bucket_is_validated(bucket):
            sections["findings"].append(entry)
        elif bucket.startswith("suppressed/"):
            sections["suppressed"].append(entry)
        elif bucket == "needs-review":
            sections["needs_investigation"].append(entry)
        else:
            # ``unvalidated``: the validation stage never reached this finding.
            # It is not a vulnerability and must not be presented as one, but it
            # is still a finding with evidence, so it is filed and named.
            sections["unvalidated"].append(entry)
    return sections


def build_document(model: Mapping[str, Any]) -> Dict[str, Any]:
    """The aggregate machine-readable report."""
    sections = _sections_by_bucket(model)
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
        "findings": [build_ticket(model, entry) for entry in sections["findings"]],
        "needs_investigation": [build_ticket(model, entry)
                                for entry in sections["needs_investigation"]],
        "unvalidated": [build_ticket(model, entry) for entry in sections["unvalidated"]],
        "suppressed": [build_ticket(model, entry) for entry in sections["suppressed"]],
        "negative_findings": model.get("negative_findings"),
        "suppressions": model.get("suppressions"),
    }


def ticket_filename(finding_id: Any) -> str:
    """A filesystem-safe, sortable file name for a finding id."""
    safe = re.sub(r"[^A-Za-z0-9._-]+", "-", str(finding_id or "unassigned")).strip("-")
    return "%s.json" % (safe or "unassigned")


def build_index(model: Mapping[str, Any], document: Mapping[str, Any],
                findings_dir: str, records: Sequence[Mapping[str, Any]]) -> Dict[str, Any]:
    """Metadata for every finding, with the bucket and the pointer to its JSON.

    The aggregate report is prose-shaped: it is built for a reader. This document
    is the machine-readable register of the same set, so a consumer can enumerate
    findings and fetch one file each without parsing the report. It repeats the
    ``disposition`` for the same reason the per-finding file does: a consumer
    should never have to infer a decision from a directory name.
    """
    by_id = {str(record.get("finding_id")): record for record in records}
    entries: List[Dict[str, Any]] = []
    for section, status in (("findings", "validated"),
                            ("needs_investigation", "needs_review"),
                            ("unvalidated", "unvalidated"),
                            ("suppressed", "suppressed")):
        for entry in rm._as_list(document.get(section)):  # noqa: SLF001
            if not isinstance(entry, dict):
                continue
            record = by_id.get(str(entry.get("finding_id")), {})
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
                "disposition": entry.get("disposition") or rm.finding_bucket(
                    entry.get("finding") or {}),
                "ticketable": entry.get("ticketable"),
                "ticketable_reason": entry.get("ticketable_reason"),
                "json": {"path": record.get("path"), "sha256": record.get("sha256"),
                         "bytes": record.get("bytes"),
                         "fingerprint": record.get("fingerprint")},
            })
    by_disposition = {bucket: 0 for bucket in rm.FINDING_BUCKETS}
    for entry in entries:
        bucket = str(entry.get("disposition") or "")
        by_disposition[bucket] = by_disposition.get(bucket, 0) + 1
    return {
        "schema_version": "1.0",
        "kind": "security-audit-findings-index",
        "generator": {"name": (model.get("tool") or {}).get("name"),
                      "version": (model.get("tool") or {}).get("version"),
                      "generated_at": model.get("generated_at")},
        "meta": model.get("meta"),
        "counts": model.get("counts"),
        "findings_dir": findings_dir,
        "totals": {"findings": len(entries),
                   "ticketable": sum(1 for entry in entries if entry["ticketable"]),
                   "validated": sum(1 for entry in entries
                                    if entry["validation_status"] == "validated"),
                   "needs_investigation": sum(1 for entry in entries
                                              if entry["validation_status"] == "needs_review"),
                   "suppressed": sum(1 for entry in entries
                                     if entry["validation_status"] == "suppressed"),
                   "unvalidated": sum(1 for entry in entries
                                      if entry["validation_status"] == "unvalidated"),
                   "by_disposition": by_disposition},
        "findings": entries,
    }


def _prune_stale_files(directory: str, keep: Sequence[str]) -> List[str]:
    """Delete per-finding JSON files this run did not write.

    A report directory is regenerated in place, so a finding that changed bucket
    -- or was fixed and no longer reported -- would otherwise leave its old file
    behind. The next reader cannot tell that file from a current one, and the
    validator counts it as an unexplained extra. Only ``*.json`` is touched, so a
    directory that also holds notes or extracted evidence is left alone.
    """
    keep_set = {os.path.abspath(path) for path in keep}
    removed: List[str] = []
    for root, _dirs, names in os.walk(directory):
        for name in names:
            if not name.endswith(".json"):
                continue
            path = os.path.join(root, name)
            if os.path.abspath(path) not in keep_set:
                try:
                    os.remove(path)
                except OSError:
                    continue
                removed.append(path)
    return removed


def generate(model: Mapping[str, Any], outdir: str, out: Optional[str] = None,
             findings_dir: Optional[str] = None,
             write_findings: bool = True) -> Dict[str, Any]:
    """Write the aggregate report and one file per finding, under its bucket."""
    rm.ensure_outdir(outdir)
    document = build_document(model)
    target = out or os.path.join(outdir, rm.OUTPUT_NAMES["json"])
    written = rm.write_report(target, json.dumps(document, indent=2, ensure_ascii=False) + "\n")
    result = rm.format_result(model, written, "json")

    directory = findings_dir or os.path.join(outdir, FINDINGS_DIRNAME)
    records: List[Dict[str, Any]] = []
    pruned: List[str] = []
    index_record: Dict[str, Any] = {}
    if write_findings:
        # Every bucket exists on every run, empty or not: a missing directory
        # would read as "this stage did not run", an empty one reads as a zero.
        for bucket in rm.FINDING_BUCKETS:
            rm.ensure_outdir(os.path.join(directory, *bucket.split("/")))
        # One file per finding, not one per *validated* finding: a finding the
        # report shows as "needs investigation" is still a finding with its own
        # evidence, and a reviewer must be able to open it. Actionability is
        # carried by ``ticketable`` inside the file, so the set of files and the
        # set of findings stay the same size.
        for section in ("findings", "needs_investigation", "unvalidated", "suppressed"):
            for entry in document[section]:
                bucket = str(entry.get("disposition") or rm.finding_bucket(entry))
                path = os.path.join(directory, *bucket.split("/"),
                                    ticket_filename(entry["finding_id"]))
                record = rm.write_report(path, json.dumps(entry, indent=2,
                                                          ensure_ascii=False) + "\n")
                records.append({"finding_id": entry["finding_id"], "disposition": bucket,
                                "path": path,
                                "sha256": record["sha256"], "bytes": record["bytes"],
                                "fingerprint": entry["fingerprint"],
                                "jira_summary": entry["jira"]["summary"],
                                "jira_priority": entry["jira"]["priority"]["name"]})
        # The tree must describe this run, not this run plus everything that came
        # before it: a finding that moved bucket would otherwise exist twice.
        pruned = _prune_stale_files(directory, [record["path"] for record in records])
        index = build_index(model, document, directory, records)
        index_record = rm.write_report(
            os.path.join(outdir, rm.OUTPUT_NAMES["index"]),
            json.dumps(index, indent=2, ensure_ascii=False) + "\n")
    by_disposition = {bucket: 0 for bucket in rm.FINDING_BUCKETS}
    for record in records:
        bucket = str(record.get("disposition") or "")
        by_disposition[bucket] = by_disposition.get(bucket, 0) + 1
    result.update({"document": target, "findings_dir": directory if write_findings else None,
                   "findings": records, "by_disposition": by_disposition,
                   "pruned": pruned,
                   "needs_investigation": len(document["needs_investigation"]),
                   "unvalidated": len(document["unvalidated"]),
                   "suppressed": len(document["suppressed"]),
                   "index": index_record})
    return result


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Emit the machine-readable audit report and one JSON file per "
                    "finding, filed under findings/<verdict>/<action>/.",
        epilog="Only findings in the validated/ buckets are ticketable, so an issue "
               "tracker never receives an unvalidated pattern match. Each ticket "
               "carries a stable fingerprint so re-runs do not duplicate the backlog.")
    rm.add_common_arguments(parser)
    parser.add_argument("--findings-dir", "--ticket-dir", dest="findings_dir",
                        help="directory for the per-finding files "
                             "(default: <outdir>/%s)" % FINDINGS_DIRNAME)
    parser.add_argument("--no-findings", "--no-tickets", dest="write_findings",
                        action="store_false",
                        help="write only the aggregate report")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    model = rm.model_from_args(args)
    result = generate(model, args.outdir, args.out, args.findings_dir, args.write_findings)
    rm.emit(result, args.indent)
    return 0


if __name__ == "__main__":
    sys.exit(main())
