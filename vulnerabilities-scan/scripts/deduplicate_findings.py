#!/usr/bin/env python3
"""Stage 4 — consolidate findings from every engine into one dataset.

Deduplication happens **before** validation (references/validation-methodology.md
§5): the same real issue is then examined once, with all of its provenance
attached, instead of being validated three times and reported three times.

Merge rules, in the order they are applied
------------------------------------------
1. **Same site** — same ``cwe``, same ``file``, ``line_start`` within
   ``--line-window`` (default 3). Scanners disagree about which line of a
   multi-line call to blame, so an exact line match is too strict.
2. **Same root cause across files** — same ``cwe`` and identical normalised
   evidence (comments, whitespace and line-number prefixes removed), at least
   ``--min-fingerprint`` characters long. This is the copy-pasted-helper case:
   one finding, several ``locations``. It is skipped when the two findings
   recommend *different* fixes, because then the work to fix them differs.
3. **Different CWEs on the same line** — the more specific CWE wins
   (``CWE-89`` over ``CWE-20``), and the loser is recorded in ``merge_notes``.
4. **Conflicting severity** — the highest defensible one wins: the higher CVSS
   score when both sides are scored, otherwise the higher band. Recorded, never
   silent.

What merging never does
-----------------------
* It never drops a source. ``sources`` is the union of every engine that
  reported the finding, deduplicated on ``(tool, rule_id)`` and sorted, so
  corroboration survives into the report and into the confidence ladder.
* It never invents a location, a CWE or a line number.
* It never discards a finding without a reason in ``merge_notes``.

Ids are re-assigned deterministically at the end (:func:`finding_model.assign_ids`)
because the surviving finding's severity and category may have changed;
``validate_findings.py`` re-assigns them again after scoring. A finding id is
therefore only stable within one stage, and the report always names the stage it
came from.

CLI
---
    python3 scripts/deduplicate_findings.py scan.json --out deduped.json
    python3 scripts/deduplicate_findings.py builtin.json semgrep.json bandit.json --out deduped.json
    python3 scripts/deduplicate_findings.py results/ --line-window 5 --no-cross-file
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

_SCRIPTS = os.path.dirname(os.path.abspath(__file__))
if _SCRIPTS not in sys.path:
    sys.path.insert(0, _SCRIPTS)

import finding_model as fm  # noqa: E402

VERSION = "1.0"
TOOL_NAME = "deduplicate_findings.py"

#: ``line_start`` tolerance for "same site" (validation-methodology.md §5).
DEFAULT_LINE_WINDOW = 3

#: A cross-file fingerprint shorter than this is too generic to merge on: two
#: unrelated findings often share a boilerplate line such as ``return result``.
DEFAULT_MIN_FINGERPRINT = 40

#: Parent/umbrella CWEs. When two engines label the same line differently, the
#: non-parent one is kept as the finding's CWE.
_PARENT_CWES = frozenset({"CWE-20", "CWE-74", "CWE-693", "CWE-707", "CWE-664",
                          "CWE-435", "CWE-436", "CWE-710"})

#: Comment syntax stripped before fingerprinting. Deliberately conservative:
#: ``#`` only when it starts a token, so ``C#`` and ``#include`` survive.
_COMMENT_RE = (
    (re.compile(r"/\*.*?\*/", re.S), " "),
    (re.compile(r"(?m)^\s*//.*$"), " "),
    (re.compile(r"\s//\s.*$"), " "),
    (re.compile(r"(?m)^\s*#\s.*$"), " "),
    (re.compile(r"\s#\s.*$"), " "),
)

_NUMBERED_EVIDENCE_RE = re.compile(r"(?m)^\s*\d+\s*\|\s?")


# --------------------------------------------------------------------------- #
# Loading
# --------------------------------------------------------------------------- #

def _iter_json_inputs(paths: Sequence[str]) -> List[str]:
    """Expand files and directories into a sorted list of ``*.json`` paths."""
    files: List[str] = []
    for raw in paths:
        if raw == "-":
            files.append("-")
            continue
        path = os.path.abspath(raw)
        if os.path.isdir(path):
            for name in sorted(os.listdir(path)):
                if name.endswith(".json"):
                    files.append(os.path.join(path, name))
            continue
        if not os.path.exists(path):
            raise SystemExit("no such input: %s" % raw)
        files.append(path)
    if not files:
        raise SystemExit("no inputs given")
    return files


def load_documents(paths: Sequence[str]) -> List[Tuple[str, Dict[str, Any]]]:
    """Load every input as a dataset.

    Accepts the three shapes every stage in this skill can emit: a full dataset
    object, a stage report with a ``findings`` array (the orchestrator and the
    built-in analyzers), or a bare array of findings.
    """
    documents: List[Tuple[str, Dict[str, Any]]] = []
    for path in _iter_json_inputs(paths):
        if path == "-":
            data = json.load(sys.stdin)
            label = "<stdin>"
        else:
            with open(path, encoding="utf-8") as handle:
                data = json.load(handle)
            label = os.path.basename(path)
        if isinstance(data, list):
            document: Dict[str, Any] = {"findings": data}
        elif isinstance(data, dict):
            document = data
        else:
            raise SystemExit("%s: expected an object or an array" % label)
        findings = document.get("findings")
        if not isinstance(findings, list):
            raise SystemExit("%s: no 'findings' array" % label)
        documents.append((label, document))
    return documents


# --------------------------------------------------------------------------- #
# Identity
# --------------------------------------------------------------------------- #

def cwe_id(finding: Dict[str, Any]) -> str:
    """The finding's CWE id, or ``""`` when it has none."""
    cwe = finding.get("cwe")
    if isinstance(cwe, dict):
        return str(cwe.get("id") or "")
    return str(cwe or "")


def normalise_evidence(evidence: Any) -> str:
    """Fingerprint evidence: drop line-number gutters, comments and whitespace."""
    if not isinstance(evidence, str) or not evidence.strip():
        return ""
    text = _NUMBERED_EVIDENCE_RE.sub("", evidence)
    for pattern, replacement in _COMMENT_RE:
        text = pattern.sub(replacement, text)
    return " ".join(text.split()).lower()


def _fix_signature(finding: Dict[str, Any]) -> str:
    return " ".join(str(finding.get("recommended_fix") or "").split()).lower()


def _severity_rank(finding: Dict[str, Any]) -> int:
    return fm.SEVERITY_RANK.get(str(finding.get("severity")), len(fm.SEVERITIES))


def _line(finding: Dict[str, Any]) -> int:
    location = finding.get("location") or {}
    try:
        return int(location.get("line_start") or 0)
    except (TypeError, ValueError):
        return 0


def _file(finding: Dict[str, Any]) -> str:
    return str((finding.get("location") or {}).get("file") or "")


def _sources(finding: Dict[str, Any]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for source in finding.get("sources") or []:
        if isinstance(source, dict) and source.get("tool"):
            out.append({"tool": str(source["tool"]),
                        "rule_id": source.get("rule_id"),
                        "raw_ref": source.get("raw_ref")})
    return out


def _source_key(source: Dict[str, Any]) -> Tuple[str, str]:
    return (str(source.get("tool")), str(source.get("rule_id")))


# --------------------------------------------------------------------------- #
# Merging
# --------------------------------------------------------------------------- #

def _merge_into(keep: Dict[str, Any], other: Dict[str, Any], reason: str) -> None:
    """Fold ``other`` into ``keep``, preserving every piece of provenance."""
    notes: List[str] = keep.setdefault("merge_notes", [])
    notes.append(reason)

    merged_sources = {_source_key(s): s for s in _sources(keep)}
    for source in _sources(other):
        merged_sources.setdefault(_source_key(source), source)
    keep["sources"] = [merged_sources[key] for key in sorted(merged_sources)]

    tools = {str(s["tool"]) for s in keep["sources"]}
    keep["corroborating_tools"] = sorted(tools)
    if len(tools) > 1:
        keep.setdefault("priority_factors", []).append(
            "corroborated by %d independent engines: %s" % (len(tools), ", ".join(sorted(tools))))

    # Additional sites: everything the folded finding pointed at, plus its own
    # aliases, minus the primary location.
    sites: List[Dict[str, Any]] = list(keep.get("locations") or [])
    candidates = [other.get("location")] + list(other.get("locations") or [])
    primary = keep.get("location") or {}
    for site in candidates:
        if not isinstance(site, dict) or not site.get("file"):
            continue
        if (site.get("file"), site.get("line_start")) == (primary.get("file"),
                                                         primary.get("line_start")):
            continue
        if site not in sites:
            sites.append({"file": site.get("file"),
                          "line_start": site.get("line_start"),
                          "line_end": site.get("line_end")})
    if sites:
        keep["locations"] = sorted(sites, key=lambda s: (str(s.get("file")), s.get("line_start") or 0))

    # Severity: the higher score wins when both are scored, else the higher band.
    keep_score, other_score = keep.get("cvss_score"), other.get("cvss_score")
    if isinstance(keep_score, (int, float)) and isinstance(other_score, (int, float)):
        if float(other_score) > float(keep_score):
            keep["cvss_score"] = other["cvss_score"]
            keep["cvss_vector"] = other.get("cvss_vector")
            keep["scoring"] = other.get("scoring", "scored")
            notes.append("severity merged: kept the higher CVSS %s" % other_score)
    elif _severity_rank(other) < _severity_rank(keep):
        # The folded finding is the more severe one: it wins.
        previous = keep.get("severity")
        keep["severity"] = other["severity"]
        notes.append("severity merged: kept %r over %r" % (keep["severity"], previous))
    elif _severity_rank(keep) < _severity_rank(other):
        notes.append("severity merged: kept the higher %r over %r"
                     % (keep.get("severity"), other.get("severity")))

    # A suppression on either side is conservative: if one engine proved the
    # finding is safe, the merged record says so rather than hiding it.
    if other.get("validation_status") == "suppressed" and keep.get("validation_status") != "suppressed":
        keep["validation_status"] = "suppressed"
        keep["suppression_reason"] = other.get("suppression_reason") or "suppressed by a contributing engine"
        notes.append("suppression carried over from %s"
                     % (other.get("sources") or [{}])[0].get("tool", "a contributing engine"))

    keep["merged_duplicates"] = int(keep.get("merged_duplicates") or 1) + 1


def _same_cwe_group(findings: Sequence[Dict[str, Any]], window: int) -> List[List[Dict[str, Any]]]:
    """Cluster findings on ``(cwe, file)`` whose lines are within ``window``."""
    buckets: Dict[Tuple[str, str], List[Dict[str, Any]]] = {}
    for finding in findings:
        buckets.setdefault((cwe_id(finding), _file(finding)), []).append(finding)
    clusters: List[List[Dict[str, Any]]] = []
    for key in sorted(buckets):
        ordered = sorted(buckets[key], key=lambda f: (_line(f), str(f.get("category"))))
        cluster: List[Dict[str, Any]] = []
        anchor = None
        for finding in ordered:
            line = _line(finding)
            if anchor is None or abs(line - anchor) <= window:
                cluster.append(finding)
                anchor = line if anchor is None else min(anchor, line)
                continue
            clusters.append(cluster)
            cluster = [finding]
            anchor = line
        if cluster:
            clusters.append(cluster)
    return clusters


def _cross_file_clusters(findings: Sequence[Dict[str, Any]],
                         min_fingerprint: int) -> List[List[Dict[str, Any]]]:
    """Cluster findings with the same CWE, fingerprint and fix across files."""
    buckets: Dict[Tuple[str, str, str], List[Dict[str, Any]]] = {}
    for finding in findings:
        fingerprint = normalise_evidence(finding.get("evidence"))
        if len(fingerprint) < min_fingerprint:
            continue
        key = (cwe_id(finding), fingerprint, _fix_signature(finding))
        buckets.setdefault(key, []).append(finding)
    return [members for _, members in sorted(buckets.items()) if len({_file(m) for m in members}) > 1]


def _specific_cwe_merges(findings: Sequence[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], int]:
    """Collapse *different* CWEs reported on the same file:line into the specific one."""
    buckets: Dict[Tuple[str, int], List[Dict[str, Any]]] = {}
    for finding in findings:
        buckets.setdefault((_file(finding), _line(finding)), []).append(finding)

    kept: List[Dict[str, Any]] = []
    removed = 0
    for key in sorted(buckets, key=lambda k: (k[0], k[1])):
        members = buckets[key]
        cwes = {cwe_id(m) for m in members}
        categories = {str(m.get("category")) for m in members}
        umbrella_only = bool(cwes & _PARENT_CWES)
        if len(members) == 1 or len(cwes) == 1 or not (umbrella_only or len(categories) == 1):
            # Two unrelated classes on one line are two bugs, not a duplicate:
            # only an umbrella CWE next to a specific one is the documented case.
            kept.extend(members)
            continue
        # The winner: non-parent CWE first, then the highest severity.
        winner = sorted(members, key=lambda m: (cwe_id(m) in _PARENT_CWES,
                                                _severity_rank(m), str(m.get("title"))))[0]
        losers = [m for m in members if m is not winner]
        for loser in losers:
            _merge_into(winner, loser,
                        "same site, less specific CWE: kept %s over %s"
                        % (cwe_id(winner), cwe_id(loser)))
            removed += 1
        kept.append(winner)
    return kept, removed


def deduplicate(dataset: Dict[str, Any], *, line_window: int = DEFAULT_LINE_WINDOW,
                cross_file: bool = True,
                min_fingerprint: int = DEFAULT_MIN_FINGERPRINT) -> Dict[str, Any]:
    """Consolidate ``dataset['findings']`` in place and return the dataset.

    Deterministic: the same inputs in the same order always produce the same
    output, including ``VULN-NNN`` ids and the ``merges`` audit trail.
    """
    findings = [f for f in (dataset.get("findings") or []) if isinstance(f, dict)]
    incoming = len(findings)
    merges: List[Dict[str, Any]] = []

    def record(keep: Dict[str, Any], members: Sequence[Dict[str, Any]], reason: str) -> None:
        merges.append({
            "kept": {"file": _file(keep), "line": _line(keep), "category": keep.get("category"),
                     "cwe": cwe_id(keep)},
            "merged": [{"file": _file(m), "line": _line(m), "category": m.get("category"),
                        "cwe": cwe_id(m),
                        "tools": sorted({str(s.get("tool")) for s in _sources(m)})}
                       for m in members],
            "reason": reason,
        })

    # Pass 1: same CWE, same file, line window.
    clusters = _same_cwe_group(findings, line_window)
    pass1: List[Dict[str, Any]] = []
    for members in clusters:
        primary = sorted(members, key=lambda m: (_line(m), _severity_rank(m),
                                                 str(m.get("title"))))[0]
        others = [m for m in members if m is not primary]
        for other in others:
            _merge_into(primary, other,
                        "same site: %s line %s within %d of line %s"
                        % (_file(primary), _line(primary), line_window, _line(other)))
        if others:
            record(primary, others, "same site (file + line window + CWE)")
        pass1.append(primary)

    # Pass 2: same root cause across files (copy-pasted helper).
    pass2: List[Dict[str, Any]] = list(pass1)
    if cross_file:
        for members in _cross_file_clusters(pass1, min_fingerprint):
            members = sorted(members, key=lambda m: (_file(m), _line(m)))
            primary = members[0]
            others = [m for m in members if m is not primary]
            for other in others:
                _merge_into(primary, other,
                            "same root cause across files: identical evidence and fix signature")
            record(primary, others, "same root cause across files")
            for other in others:
                pass2.remove(other)

    # Pass 3: different CWEs on the same line.
    pass3, removed = _specific_cwe_merges(pass2)
    if removed:
        merges.append({"kept": None,
                       "merged": [],
                       "reason": "kept the more specific CWE on %d shared site(s)" % removed})

    pass3.sort(key=lambda f: (_severity_rank(f), _file(f), _line(f),
                              str(f.get("category")), str(f.get("title"))))
    dataset["findings"] = pass3
    fm.assign_ids(dataset)

    dataset.setdefault("schema_version", fm.SCHEMA_VERSION)
    dataset["stage"] = "dedupe"
    dataset["generated_by"] = {"name": TOOL_NAME, "version": VERSION,
                               "python": "%d.%d" % sys.version_info[:2]}
    dataset["dedupe"] = {
        "incoming_findings": incoming,
        "outgoing_findings": len(pass3),
        "duplicates_removed": incoming - len(pass3),
        "line_window": line_window,
        "cross_file": bool(cross_file),
        "min_fingerprint": min_fingerprint,
        "merges": merges,
    }
    dataset["summary"] = {
        "findings": len(pass3),
        "duplicates_removed": incoming - len(pass3),
        "by_severity": _count(pass3, lambda f: str(f.get("severity"))),
        "by_category": _count(pass3, lambda f: str(f.get("category"))),
        "by_tool": _count_sources(pass3),
    }
    return dataset


def _count(findings: Iterable[Dict[str, Any]], key) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for finding in findings:
        name = key(finding)
        counts[name] = counts.get(name, 0) + 1
    return dict(sorted(counts.items()))


def _count_sources(findings: Iterable[Dict[str, Any]]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for finding in findings:
        for source in _sources(finding):
            tool = str(source.get("tool"))
            counts[tool] = counts.get(tool, 0) + 1
    return dict(sorted(counts.items()))


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Merge duplicate findings across scanners and analyzers, "
                    "preserving every source.",
        epilog="Run before validate_findings.py: validation should examine one "
               "finding per real issue, with all its provenance.",
    )
    parser.add_argument("inputs", nargs="+",
                        help="dataset files, stage reports, or directories of .json files "
                             "('-' reads stdin)")
    parser.add_argument("--out", default="deduped.json",
                        help="where to write the consolidated dataset (default: deduped.json)")
    parser.add_argument("--line-window", type=int, default=DEFAULT_LINE_WINDOW,
                        help="line tolerance for 'same site' (default: %(default)s)")
    parser.add_argument("--min-fingerprint", type=int, default=DEFAULT_MIN_FINGERPRINT,
                        help="minimum normalised evidence length for cross-file merging "
                             "(default: %(default)s)")
    parser.add_argument("--no-cross-file", action="store_true",
                        help="only merge within one file (disables copy-paste merging)")
    parser.add_argument("--summary", action="store_true",
                        help="print the summary to stdout instead of writing a file")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    documents = load_documents(args.inputs)
    merged: Dict[str, Any] = {
        "schema_version": fm.SCHEMA_VERSION,
        "findings": [],
        "coverage": {},
        "negative_findings": [],
        "sources": [],
    }
    for label, document in documents:
        merged["findings"].extend(f for f in (document.get("findings") or []) if isinstance(f, dict))
        merged["sources"].append({"input": label, "findings": len(document.get("findings") or []),
                                  "stage": document.get("stage") or "unknown"})
        if document.get("coverage") and not merged["coverage"]:
            merged["coverage"] = document["coverage"]
        for entry in document.get("negative_findings") or []:
            if entry not in merged["negative_findings"]:
                merged["negative_findings"].append(entry)
        for key in ("audit", "audit_scope"):
            if document.get(key) and key not in merged:
                merged[key] = document[key]

    result = deduplicate(merged, line_window=max(0, args.line_window),
                         cross_file=not args.no_cross_file,
                         min_fingerprint=max(1, args.min_fingerprint))
    if args.summary:
        print(json.dumps({"dedupe": result["dedupe"] | {"merges": len(result["dedupe"]["merges"])},
                          "summary": result["summary"]}, indent=2))
        return 0
    fm.save_findings(result, args.out)
    print(json.dumps({"written": args.out, "summary": result["summary"],
                      "duplicates_removed": result["dedupe"]["duplicates_removed"]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
