#!/usr/bin/env python3
"""The single report view model shared by every output format.

Why this module exists
----------------------
The three deliverables (Markdown, HTML, PDF) must not diverge. The way to make
that structural rather than hopeful is to compute *everything* once, here, and
let the three generators only differ in how they serialise it:

    findings.json ──► build_report() ──► render(report.md.j2)   -> report.md
                                   ├──► render(report.html.j2) -> report.html
                                   └──► render(report.md.j2)   -> pandoc -> report.pdf

Everything a reader can see is a field of the returned dict, so a count in the
verdict, a count in the summary table and a count in the PDF cover come from one
integer. Ordering, severity classes, anchors, display strings and the "needs
investigation" split are decided here too, once.

Two rules this module keeps
---------------------------
* **Nothing is invented.** A missing repository, commit or scanner run renders
  as ``Not recorded`` with the reason, never as a plausible-looking default.
* **The dataset is the only source of finding truth.** Counts are recomputed
  from ``findings``; a stale ``summary`` block in the input is detected and
  reported rather than trusted.

Templates are rendered by :func:`render`, a small strict subset of Jinja
syntax (``{{ expr }}``, ``{% if %}``/``{% elif %}``/``{% else %}``,
``{% for %}``, ``{# comment #}``, and a handful of filters). It is deliberate:
the skill must produce reports on a machine where nothing but Python is
installed, and an engine we own cannot silently change escaping rules.

CLI
---
    python3 scripts/report_model.py view findings.json            # the view model
    python3 scripts/report_model.py render report.md.j2 report.json
"""

from __future__ import annotations

import argparse
import datetime as _dt
import hashlib
import html
import json
import os
import re
import sys
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

import finding_model as fm  # noqa: E402

TOOL_NAME = "report_model.py"
VERSION = "1.0.0"

TEMPLATE_DIR = os.path.join(os.path.dirname(_HERE), "templates")

SEVERITIES: Tuple[str, ...] = fm.SEVERITIES
PRIORITIES: Tuple[str, ...] = fm.PRIORITIES

#: Rendering order inside a section: priority, then severity, then location.
_PRIORITY_RANK = {value: index for index, value in enumerate(fm.PRIORITIES)}
_SEVERITY_RANK = {value: index for index, value in enumerate(SEVERITIES)}


# --------------------------------------------------------------------------- #
# Template engine
# --------------------------------------------------------------------------- #

class TemplateError(Exception):
    """A template could not be rendered. Always names the offending token."""


_TOKEN_RE = re.compile(r"(\{\{.*?\}\}|\{%.*?%\}|\{#.*?#\})", re.DOTALL)
_TAG_RE = re.compile(r"^\{%\s*(.*?)\s*%\}$", re.DOTALL)


def _split_filters(expression: str) -> List[str]:
    """Split ``expr | f(a) | g`` on pipes that are not inside quotes or parens."""
    parts: List[str] = []
    depth = 0
    quote = ""
    current: List[str] = []
    for char in expression:
        if quote:
            current.append(char)
            if char == quote:
                quote = ""
            continue
        if char in "\"'":
            quote = char
            current.append(char)
        elif char in "([{":
            depth += 1
            current.append(char)
        elif char in ")]}":
            depth -= 1
            current.append(char)
        elif char == "|" and depth == 0:
            parts.append("".join(current))
            current = []
        else:
            current.append(char)
    parts.append("".join(current))
    return [part.strip() for part in parts]


def _literal_args(text: str) -> List[Any]:
    args: List[Any] = []
    quote = ""
    current: List[str] = []
    for char in text + ",":
        if quote:
            current.append(char)
            if char == quote:
                quote = ""
            continue
        if char in "\"'":
            quote = char
            current.append(char)
        elif char == ",":
            token = "".join(current).strip()
            if token:
                args.append(_eval(token, {}))
            current = []
        else:
            current.append(char)
    return args


def _eval(expression: str, context: Mapping[str, Any]) -> Any:
    """Evaluate one template expression, strictly.

    The expression grammar is Python's, evaluated against a namespace holding
    only the template context and the few builtins a template legitimately needs.
    Templates ship with the skill and are not user input; data values are never
    evaluated, only looked up.
    """
    text = expression.strip()
    normalised = re.sub(r"\btrue\b", "True", text)
    normalised = re.sub(r"\bfalse\b", "False", normalised)
    normalised = re.sub(r"\bnone\b", "None", normalised)
    safe_builtins = {"len": len, "str": str, "int": int, "float": float,
                     "sorted": sorted, "any": any, "all": all,
                     "min": min, "max": max, "round": round}
    namespace: Dict[str, Any] = {"__builtins__": safe_builtins}
    namespace.update(context)
    try:
        return eval(normalised, {"__builtins__": safe_builtins}, namespace)  # noqa: S307
    except NameError as exc:
        raise TemplateError("unknown name in %r: %s" % (text, exc)) from exc
    except Exception as exc:  # noqa: BLE001 - surfaced as a template error
        raise TemplateError("cannot evaluate %r: %s" % (text, exc)) from exc


def _apply_filters(value: Any, filters: Sequence[str], autoescape: bool) -> Any:
    escaped = False
    for item in filters:
        name, _, raw_args = item.partition("(")
        name = name.strip()
        args = _literal_args(raw_args.rsplit(")", 1)[0]) if raw_args else []
        if name in ("e", "escape"):
            value = html.escape(str(value), quote=True)
            escaped = True
        elif name == "length":
            value = len(value or [])
        elif name == "upper":
            value = str(value).upper()
        elif name == "lower":
            value = str(value).lower()
        elif name == "trim":
            value = str(value).strip()
        elif name == "join":
            value = (args[0] if args else ", ").join(str(v) for v in value or [])
        elif name == "default":
            fill = args[0] if args else ""
            value = fill if value in (None, "", [], {}) else value
        elif name == "number":
            value = "unscored" if value is None else ("%.1f" % float(value))
        elif name == "safe":
            escaped = True
        elif name == "mdcell" and value is not None:
            # A pipe inside a table cell would start a new column and a newline
            # would end the row: both are escaped here rather than at each use.
            value = re.sub(r"\r?\n", " ", str(value)).replace("|", "\\|")
        elif name == "mdline" and value is not None:
            value = " ".join(str(value).split())
        elif name == "fence":
            runs = re.findall(r"`+", str(value))
            length = max([3] + [len(run) + 1 for run in runs])
            value = "`" * length
        else:
            raise TemplateError("unknown filter %r" % name)
    if autoescape and not escaped and value is not None:
        value = html.escape(str(value), quote=True)
    return value


def _truth(path: str, context: Mapping[str, Any]) -> bool:
    return bool(_eval(path, context))


def _parse(tokens: Sequence[str], index: int, terminators: Sequence[str]) -> Tuple[List[Any], int, Optional[str]]:
    """Build a node list until a terminator tag is reached."""
    nodes: List[Any] = []
    while index < len(tokens):
        token = tokens[index]
        if token.startswith("{#"):
            index += 1
            continue
        if token.startswith("{{"):
            nodes.append(("expr", token[2:-2].strip()))
            index += 1
            continue
        match = _TAG_RE.match(token)
        if not match:
            nodes.append(("text", token))
            index += 1
            continue
        body = match.group(1).strip()
        head, _, rest = body.partition(" ")
        if head in terminators:
            return nodes, index, body
        if head == "if":
            branches: List[Tuple[Optional[str], List[Any]]] = []
            condition: Optional[str] = rest.strip()
            while True:
                body_nodes, index, terminator = _parse(tokens, index + 1, ("elif", "else", "endif"))
                branches.append((condition, body_nodes))
                if terminator is None:
                    raise TemplateError("unterminated {%% if %s %%}" % condition)
                kind, _, tail = terminator.partition(" ")
                if kind == "elif":
                    condition = tail.strip()
                    continue
                if kind == "else":
                    body_nodes, index, terminator = _parse(tokens, index + 1, ("endif",))
                    branches.append((None, body_nodes))
                    if terminator is None:
                        raise TemplateError("unterminated {% else %} in if")
                index += 1
                break
            nodes.append(("if", branches))
            continue
        if head == "for":
            target, _, iterable = rest.partition(" in ")
            if not iterable:
                raise TemplateError("{%% for %%} without 'in': %r" % body)
            body_nodes, index, terminator = _parse(tokens, index + 1, ("endfor",))
            if terminator is None:
                raise TemplateError("unterminated {%% for %s %%}" % rest)
            nodes.append(("for", target.strip(), iterable.strip(), body_nodes))
            index += 1
            continue
        raise TemplateError("unknown tag %r" % body)
    if terminators:
        raise TemplateError("expected one of %s" % (terminators,))
    return nodes, index, None


def _resolve_loop_target(target: str, item: Any) -> Dict[str, Any]:
    names = [name.strip() for name in target.split(",")]
    if len(names) == 1:
        return {names[0]: item}
    if not isinstance(item, (tuple, list)) or len(item) != len(names):
        raise TemplateError("cannot unpack %r into %s" % (item, target))
    return dict(zip(names, item))


def _run(nodes: Sequence[Any], context: Dict[str, Any], autoescape: bool, out: List[str]) -> None:
    for node in nodes:
        kind = node[0]
        if kind == "text":
            out.append(node[1])
        elif kind == "expr":
            parts = _split_filters(node[1])
            value = _eval(parts[0], context)
            out.append(str(_apply_filters(value, parts[1:], autoescape)))
        elif kind == "if":
            for condition, branch in node[1]:
                if condition is None or _truth(condition, context):
                    _run(branch, context, autoescape, out)
                    break
        elif kind == "for":
            _, target, iterable, body = node
            items = _eval(iterable, context)
            if items is None:
                raise TemplateError("{%% for %%} over a missing value: %r" % iterable)
            for index, item in enumerate(items):
                child = dict(context)
                child.update(_resolve_loop_target(target, item))
                child["loop"] = {"index": index + 1, "index0": index,
                                 "first": index == 0, "last": index == len(items) - 1,
                                 "length": len(items)}
                _run(body, child, autoescape, out)
        else:  # pragma: no cover - _parse only emits the kinds above
            raise TemplateError("unknown node %r" % (node,))


def render(template: str, context: Mapping[str, Any], *, autoescape: bool = False) -> str:
    """Render ``template`` with ``context``.

    ``autoescape`` escapes every ``{{ }}`` result unless a filter already did
    (``|e``) or the template opted out with ``|safe``. The HTML template renders
    with it on; the Markdown template renders with it off and uses ``|e`` only
    for text that must not break Markdown structure.
    """
    tokens = [part for part in _TOKEN_RE.split(template) if part]
    nodes, index, _ = _parse(tokens, 0, ())
    if index != len(tokens):  # pragma: no cover - _parse consumes everything or raises
        raise TemplateError("unconsumed template tokens at %d" % index)
    out: List[str] = []
    _run(nodes, dict(context), autoescape, out)
    return "".join(out)


def render_file(path: str, context: Mapping[str, Any], *, autoescape: bool = False) -> str:
    with open(path, encoding="utf-8") as handle:
        return render(handle.read(), context, autoescape=autoescape)


# --------------------------------------------------------------------------- #
# View model
# --------------------------------------------------------------------------- #

_PRIORITY_FACTORS_LIMIT = 4


def _utc_now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _as_list(value: Any) -> List[Any]:
    return list(value) if isinstance(value, (list, tuple)) else []


def _as_dict(value: Any) -> Dict[str, Any]:
    return dict(value) if isinstance(value, dict) else {}


def _count_by(findings: Iterable[Mapping[str, Any]], key: str,
              order: Sequence[str] = ()) -> "Dict[str, int]":
    counts: Dict[str, int] = {value: 0 for value in order}
    for finding in findings:
        value = finding.get(key)
        label = str(value) if value is not None else "unknown"
        counts[label] = counts.get(label, 0) + 1
    return counts


def _sort_key(finding: Mapping[str, Any]) -> Tuple[Any, ...]:
    priority = _PRIORITY_RANK.get(str(finding.get("priority")), len(PRIORITIES))
    severity = _SEVERITY_RANK.get(str(finding.get("severity")), len(SEVERITIES))
    location = _as_dict(finding.get("location"))
    return (priority, severity, str(location.get("file") or ""),
            int(location.get("line_start") or 0), str(finding.get("id") or ""))


def _cwes(finding: Mapping[str, Any]) -> str:
    cwe = finding.get("cwe")
    if isinstance(cwe, dict):
        identifier = cwe.get("id")
        name = cwe.get("name")
        if identifier and name:
            return "%s (%s)" % (identifier, name)
        return str(identifier or name or "not mapped")
    return str(cwe or "not mapped")


def _owasp(finding: Mapping[str, Any]) -> str:
    owasp = _as_dict(finding.get("owasp"))
    parts = ["Top 10: %s" % (owasp.get("top10_2025") or "not mapped")]
    if owasp.get("api_2023") and owasp.get("api_2023") != "not mapped":
        parts.append("API: %s" % owasp["api_2023"])
    if owasp.get("asvs") and owasp.get("asvs") != "not mapped":
        parts.append("ASVS: %s" % owasp["asvs"])
    return "; ".join(parts)


def _cvss(finding: Mapping[str, Any]) -> Dict[str, Any]:
    score = finding.get("cvss_score")
    vector = finding.get("cvss_vector")
    if score is None:
        return {"display": "unscored", "vector": vector or "",
                "note": finding.get("scoring") or "unscored"}
    return {"display": "%.1f" % float(score), "vector": vector or "", "note": "CVSS-B"}


def _evidence(finding: Mapping[str, Any]) -> Dict[str, Any]:
    text = str(finding.get("evidence") or "")
    lines = text.splitlines()
    longest_run = max([0] + [len(run) for run in re.findall(r"`+", text)])
    return {"text": text, "lines": lines, "count": len(lines),
            "empty": not text.strip(), "fence": "`" * max(3, longest_run + 1)}


def _sites(finding: Mapping[str, Any]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    primary = _as_dict(finding.get("location"))
    if primary.get("file"):
        out.append({"file": primary.get("file"),
                    "line_start": primary.get("line_start"),
                    "line_end": primary.get("line_end")})
    for site in _as_list(finding.get("locations")):
        site = _as_dict(site)
        if site.get("file"):
            entry = {"file": site.get("file"),
                     "line_start": site.get("line_start"),
                     "line_end": site.get("line_end")}
            if entry not in out:
                out.append(entry)
    return out


def _tools(finding: Mapping[str, Any]) -> List[str]:
    names = []
    for source in _as_list(finding.get("sources")):
        source = _as_dict(source)
        name = source.get("tool")
        rule = source.get("rule_id")
        if name:
            names.append("%s%s" % (name, ("/" + str(rule)) if rule else ""))
    for name in _as_list(finding.get("corroborating_tools")):
        if str(name) not in " ".join(names):
            names.append(str(name))
    return names


def _is_investigation(finding: Mapping[str, Any]) -> bool:
    """A finding the report must not present as a validated vulnerability."""
    status = str(finding.get("validation_status") or "")
    return status == "needs_review" or str(finding.get("confidence") or "") == "LOW"


def _is_suppressed(finding: Mapping[str, Any]) -> bool:
    return str(finding.get("validation_status") or "") == "suppressed"


def _display(finding: Mapping[str, Any]) -> Dict[str, Any]:
    location = _as_dict(finding.get("location"))
    line = location.get("line_start")
    line_end = location.get("line_end")
    where = str(location.get("file") or "unknown file")
    if line:
        where += ":%d" % int(line)
        if line_end and int(line_end) != int(line):
            where += "-%d" % int(line_end)
    disclosure = _as_dict(finding.get("disclosure"))
    return {
        "id": finding.get("id") or "unassigned",
        "title": finding.get("title") or "(untitled finding)",
        "category": finding.get("category") or "unclassified",
        "severity": finding.get("severity") or "Informational",
        "severity_class": str(finding.get("severity") or "Informational").lower(),
        "confidence": finding.get("confidence") or "LOW",
        "validation_status": finding.get("validation_status") or "unknown",
        "priority": finding.get("priority") or "P3",
        "cwe": _cwes(finding),
        "owasp": _owasp(finding),
        "cvss": _cvss(finding),
        "location": location,
        "where": where,
        "language": finding.get("language") or "unknown",
        "evidence": _evidence(finding),
        "description": finding.get("description") or "Not recorded.",
        "impact": finding.get("impact") or "Not recorded.",
        "attack_scenario": finding.get("attack_scenario") or "Not recorded.",
        "root_cause": finding.get("root_cause") or "",
        "preconditions": [str(x) for x in _as_list(finding.get("preconditions"))],
        "recommended_fix": finding.get("recommended_fix") or "Not recorded.",
        "references": [str(x) for x in _as_list(finding.get("references"))],
        "sources": _tools(finding),
        "priority_factors": [str(x) for x in
                             _as_list(finding.get("priority_factors"))[-_PRIORITY_FACTORS_LIMIT:]],
        "sites": _sites(finding),
        "suppression_reason": finding.get("suppression_reason") or "",
        "in_test_path": bool(finding.get("in_test_path")),
        "validation": str(finding.get("validation") or ""),
        "anchor": "vuln-%s" % str(finding.get("id") or "000").lower().replace("vuln-", ""),
        "disclosure": disclosure,
    }


def slug(text: str) -> str:
    """The anchor GitHub generates for a Markdown heading (kept in sync)."""
    value = str(text).strip().lower()
    value = re.sub(r"[^\w\s-]", "", value, flags=re.UNICODE)
    return re.sub(r"\s", "-", value)


_SEVERITY_MEANING = {
    "Critical": "Exploitation is practical and the impact is severe: full compromise, mass data "
                "exposure, or a payment path an attacker can steer.",
    "High": "Serious impact that needs one further condition, or a narrower blast radius.",
    "Medium": "Real weakness with meaningful prerequisites or limited impact.",
    "Low": "Defence-in-depth or hard-to-reach issue; worth fixing, not an emergency.",
    "Informational": "Observation with no qualifying CVSS score. Not counted as a vulnerability.",
}

_CONFIDENCE_MEANING = {
    "CONFIRMED": "The implementation, the data path and the missing control were all located in "
                 "the audited snapshot.",
    "HIGH": "Strong technical evidence; some exploitation condition remains unverified.",
    "MEDIUM": "Credible weakness; the execution path or impact needs more investigation.",
    "LOW": "Suspicious and unproven. Listed under needs investigation, never as a vulnerability.",
}

_STANDARDS = (
    "OWASP Top 10:2025, OWASP ASVS 5.0, OWASP WSTG, OWASP API Security Top 10, OWASP Cheat Sheets",
    "NIST SP 800-218 (SSDF) secure development practices",
    "MITRE CWE for weakness classification, CVE/advisories for dependency risk",
    "FIRST CVSS v4.0 for severity, with the reporting bands Critical 9.0-10.0, High 7.0-8.9, "
    "Medium 4.0-6.9, Low 0.1-3.9, Informational no score",
)


def _verdict(meta: Mapping[str, Any], counts: Mapping[str, Any],
             coverage: Mapping[str, Any]) -> List[str]:
    total = counts["total"]
    validated = counts["validated"]
    sentences: List[str] = []
    sentences.append(
        "%s was audited at %s (%s, scope %s)."
        % (meta.get("repository") or "The repository",
           meta.get("commit_short") or "an unrecorded commit",
           "dirty working tree" if meta.get("dirty") else "clean working tree",
           meta.get("scope") or "."))
    if total == 0:
        sentences.append(
            "No vulnerabilities were confirmed in the code examined. That is a statement about "
            "coverage, not about the absence of defects: read the coverage section before "
            "treating it as a clean bill of health.")
    else:
        sentences.append(
            "%d finding%s recorded: %d Critical, %d High, %d Medium, %d Low, %d Informational; "
            "%d validated, %d under investigation, %d suppressed by a compensating control."
            % (total, "" if total == 1 else "s",
               counts["by_severity"].get("Critical", 0),
               counts["by_severity"].get("High", 0),
               counts["by_severity"].get("Medium", 0),
               counts["by_severity"].get("Low", 0),
               counts["by_severity"].get("Informational", 0),
               validated, counts["needs_investigation"], counts["suppressed"]))
        worst = counts["first_priority"]
        if worst:
            sentences.append(
                "The most urgent item is %s (%s), %s at %s; fix it before the next release."
                % (worst["id"], worst["title"], worst["severity"], worst["where"]))
    missing = coverage.get("tools_unavailable") or []
    if missing:
        sentences.append(
            "The single most important limitation: %d external scanner%s could not run on this "
            "host (%s), so automated coverage is partial and the manual review carries it."
            % (len(missing), "" if len(missing) == 1 else "s", ", ".join(missing[:6])))
    elif coverage.get("limitations"):
        sentences.append("The single most important limitation: %s"
                         % coverage["limitations"][0])
    else:
        sentences.append(
            "No coverage limitation was recorded, which usually means the audit metadata was "
            "incomplete; treat the absence of findings with caution.")
    return sentences


def _coverage(dataset: Mapping[str, Any], analysis: Mapping[str, Any],
              inventory: Mapping[str, Any]) -> Dict[str, Any]:
    validation_coverage = _as_dict(dataset.get("coverage"))
    analysis_coverage = _as_dict(analysis.get("coverage"))
    inventory_coverage = _as_dict(inventory.get("coverage"))

    tools: List[Dict[str, Any]] = []
    for record in _as_list(analysis.get("scanners")):
        record = _as_dict(record)
        tools.append({
            "name": record.get("name") or "unknown",
            "kind": record.get("kind") or "unknown",
            "status": "available" if record.get("available") else "unavailable",
            "version": record.get("version") or "",
            "reason": record.get("reason") or "",
        })
    runs: List[Dict[str, Any]] = []
    for run in _as_list(analysis.get("runs")):
        run = _as_dict(run)
        runs.append({
            "tool": run.get("tool") or "unknown",
            "status": run.get("status") or "not_run",
            "exit_code": run.get("exit_code"),
            "duration_ms": run.get("duration_ms"),
            "findings": run.get("findings"),
            "error": run.get("error") or "",
        })
    unavailable = [tool["name"] for tool in tools if tool["status"] == "unavailable"]
    limitations = [str(x) for x in _as_list(analysis.get("limitations"))]
    for item in _as_list(dataset.get("limitations")):
        if str(item) not in limitations:
            limitations.append(str(item))
    for item in _as_list(validation_coverage.get("limitations")):
        if str(item) not in limitations:
            limitations.append(str(item))

    languages = sorted({str(k) for k in _as_dict(analysis_coverage.get("languages")).keys()}
                       | {str(x) for x in _as_list(analysis_coverage.get("languages"))}
                       | {str(k) for k in _as_dict(inventory.get("languages")).keys()})
    files_scanned = validation_coverage.get("files_scanned")
    if files_scanned is None:
        files_scanned = analysis_coverage.get("files_in_scope")
    if files_scanned is None:
        files_scanned = inventory_coverage.get("files_examined")

    return {
        "files_scanned": files_scanned if files_scanned is not None else "not recorded",
        "files_in_scope": analysis_coverage.get("files_in_scope",
                                                inventory_coverage.get("files_examined",
                                                                       "not recorded")),
        "languages": languages or ["not recorded"],
        "tools": tools,
        "runs": runs,
        "tools_unavailable": unavailable,
        "tools_available": [tool["name"] for tool in tools if tool["status"] == "available"],
        "tools_failed": [run["tool"] for run in runs
                         if run["status"] in ("failed", "timeout", "unparsed")],
        "tools_skipped": [run["tool"] for run in runs if run["status"] == "skipped"],
        "rules_evaluated": validation_coverage.get("rules_evaluated", "not recorded"),
        "categories_covered": [str(x) for x in _as_list(validation_coverage.get(
            "categories_covered"))],
        "never_run": [str(x) for x in _as_list(analysis_coverage.get("never_run"))],
        "excluded": [str(x) for x in _as_list(inventory.get("excluded"))][:40],
        "not_analysed": [str(x) for x in _as_list(inventory.get("not_analysed"))][:40],
        "limitations": limitations,
        "metadata_present": bool(analysis or inventory),
        "network_allowed": analysis_coverage.get("network_allowed"),
    }


def _meta(dataset: Mapping[str, Any], metadata: Mapping[str, Any],
          analysis: Mapping[str, Any], inventory: Mapping[str, Any]) -> Dict[str, Any]:
    snapshot = _as_dict(analysis.get("snapshot"))
    git = _as_dict(inventory.get("git"))
    merged: Dict[str, Any] = {}
    for source in (git, snapshot, _as_dict(metadata.get("git")), metadata):
        for key in ("repository", "commit", "commit_short", "branch", "dirty", "dirty_files",
                    "work_tree", "remote", "describe"):
            if key not in merged and source.get(key) is not None:
                merged[key] = source[key]
    commit = str(merged.get("commit") or "")
    repository = (metadata.get("repository") or merged.get("repository")
                  or (os.path.basename(str(merged.get("work_tree") or "").rstrip("/"))
                      if merged.get("work_tree") else None)
                  or (os.path.basename(str(inventory.get("root") or "").rstrip("/"))
                      if inventory.get("root") else None))
    return {
        "repository": repository or "Not recorded",
        "commit": commit or "Not recorded",
        "commit_short": str(merged.get("commit_short") or commit[:12] or "Not recorded"),
        "branch": str(merged.get("branch") or "Not recorded"),
        "dirty": bool(merged.get("dirty")) if merged.get("dirty") is not None else None,
        "dirty_display": ("dirty" if merged.get("dirty") else "clean")
        if merged.get("dirty") is not None else "not recorded",
        "dirty_files": [str(x) for x in _as_list(merged.get("dirty_files"))],
        "describe": str(merged.get("describe") or ""),
        "scope": str(metadata.get("scope") or inventory.get("root") or ".")
        .replace(str(inventory.get("root") or ""), ".") or ".",
        "audit_date": str(metadata.get("audit_date") or dataset.get("audited_at")
                          or analysis.get("generated_at")
                          or dataset.get("generated_at") or "not recorded"),
        "skill_version": str(metadata.get("skill_version") or VERSION),
        "dataset_stage": str(dataset.get("stage") or "not recorded"),
        "dataset_tool": _as_dict(dataset.get("generated_by")).get("name") or "not recorded",
        "environment": _as_dict(metadata.get("environment")),
        "prompt_injection": [str(x) for x in _as_list(dataset.get("prompt_injection"))
                             or _as_list(metadata.get("prompt_injection"))],
    }


def build_report(dataset: Mapping[str, Any], *, metadata: Optional[Mapping[str, Any]] = None,
                 analysis: Optional[Mapping[str, Any]] = None,
                 inventory: Optional[Mapping[str, Any]] = None,
                 now: Optional[str] = None) -> Dict[str, Any]:
    """Turn a validated findings dataset into the report view model."""
    metadata = _as_dict(metadata)
    analysis = _as_dict(analysis)
    inventory = _as_dict(inventory)

    findings = [f for f in _as_list(dataset.get("findings")) if isinstance(f, dict)]
    ordered = sorted(findings, key=_sort_key)
    validated = [f for f in ordered if not _is_suppressed(f) and not _is_investigation(f)]
    investigation = [f for f in ordered if "needs_review" == str(f.get("validation_status"))
                     or (not _is_suppressed(f) and _is_investigation(f))]
    suppressed = [f for f in ordered if _is_suppressed(f)]

    by_severity = _count_by(ordered, "severity", SEVERITIES)
    counts = {
        "total": len(ordered),
        "validated": len(validated),
        "needs_investigation": len(investigation),
        "suppressed": len(suppressed),
        "by_severity": by_severity,
        "by_confidence": _count_by(ordered, "confidence", fm.CONFIDENCES),
        "by_validation_status": _count_by(ordered, "validation_status", fm.VALIDATION_STATUSES),
        "by_priority": _count_by(ordered, "priority", fm.PRIORITIES),
        "by_category": dict(sorted(_count_by(ordered, "category").items())),
        "scored": sum(1 for f in ordered if f.get("cvss_score") is not None),
        "unscored": sum(1 for f in ordered if f.get("cvss_score") is None),
        "in_test_path": sum(1 for f in ordered if f.get("in_test_path")),
        "critical_high": by_severity.get("Critical", 0) + by_severity.get("High", 0),
        "first_priority": None,
    }
    if validated:
        head = _display(validated[0])
        counts["first_priority"] = {"id": head["id"], "title": head["title"],
                                    "severity": head["severity"], "where": head["where"]}

    coverage = _coverage(dataset, analysis, inventory)
    meta = _meta(dataset, metadata, analysis, inventory)

    # Never trust a stale summary: recompute and report the disagreement.
    stated = _as_dict(dataset.get("summary"))
    summary_disagreements: List[str] = []
    if stated.get("findings") not in (None, len(ordered)):
        summary_disagreements.append(
            "dataset summary claims %s findings, the array holds %d"
            % (stated.get("findings"), len(ordered)))
    for severity, value in _as_dict(stated.get("by_severity")).items():
        if by_severity.get(str(severity), 0) != value:
            summary_disagreements.append(
                "dataset summary claims %s %s, the array holds %d"
                % (value, severity, by_severity.get(str(severity), 0)))

    report = {
        "tool": {"name": TOOL_NAME, "version": VERSION},
        "generated_at": now or _utc_now(),
        "meta": meta,
        "counts": counts,
        "findings": [_display(f) for f in validated],
        "needs_investigation": [_display(f) for f in investigation],
        "suppressed": [_display(f) for f in suppressed],
        "negative_findings": [_as_dict(x) for x in _as_list(dataset.get("negative_findings"))],
        "suppressions": [_as_dict(x) for x in _as_list(dataset.get("suppressions"))],
        "coverage": coverage,
        "methodology": {
            "standards": list(_STANDARDS),
            "severity_meaning": [{"name": name, "meaning": _SEVERITY_MEANING[name]}
                                 for name in SEVERITIES],
            "confidence_meaning": [{"name": name, "meaning": _CONFIDENCE_MEANING[name]}
                                   for name in fm.CONFIDENCES],
            "bands": "Critical 9.0-10.0 | High 7.0-8.9 | Medium 4.0-6.9 | Low 0.1-3.9 | "
                     "Informational = no qualifying CVSS score",
            "approach": [
                "Repository inventory and technology detection, recorded in audit metadata.",
                "Attack-surface mapping: entry points, trust boundaries, authentication and "
                "authorization boundaries.",
                "Automated scanning with every available tool; unavailable tools are listed as "
                "coverage limitations, never as clean results.",
                "Independent source review and interprocedural data-flow tracing of "
                "source to sink, including the controls between them.",
                "Consolidation of duplicate reports into one finding per real issue, retaining "
                "every engine that reported it.",
                "Validation against the audited snapshot: evidence re-read by line number, "
                "compensating controls assessed, severity scored with CVSS v4.0 or marked "
                "unscored.",
                "Report generation from this single dataset, with cross-format checks that "
                "block delivery when the formats disagree.",
            ],
            "policy": [_as_dict(dataset.get("validation_policy"))],
        },
        "side_inputs": {"analysis": bool(analysis), "inventory": bool(inventory),
                        "metadata": bool(metadata)},
        "integrity": {"summary_disagreements": summary_disagreements},
        "pdf": {"status": "pending", "reason": ""},
    }
    report["verdict"] = _verdict(meta, counts, coverage)
    report["verdict_text"] = " ".join(report["verdict"])
    report["anchors"] = [entry["anchor"] for entry in report["findings"]]
    report["dataset_policy"] = _policy_text(_as_dict(dataset.get("validation_policy")))
    return report


def _policy_text(policy: Mapping[str, Any]) -> str:
    """One sentence describing how findings were validated and scored.

    The dataset records its own policy; repeating it verbatim would be noise, so
    it is turned into prose. Absent keys say so instead of being skipped, which
    is the difference between "no policy" and "a policy nobody wrote down".
    """
    if not policy:
        return "The dataset did not record a validation policy; scoring and evidence rules are unknown."
    parts = []
    if policy.get("scoring"):
        parts.append("Severity was scored with %s" % policy["scoring"])
    if policy.get("evidence"):
        parts.append("evidence was %s" % policy["evidence"])
    if policy.get("path_policy"):
        parts.append("findings under test paths were treated as '%s'" % policy["path_policy"])
    return ("%s." % "; ".join(parts)) if parts else "A validation policy was recorded but is empty."


# --------------------------------------------------------------------------- #
# CLI helpers shared by the generators
# --------------------------------------------------------------------------- #

OUTPUT_NAMES = {
    "markdown": "SECURITY-AUDIT-REPORT.md",
    "html": "SECURITY-AUDIT-REPORT.html",
    "pdf": "SECURITY-AUDIT-REPORT.pdf",
    "dataset": "findings.json",
    "metadata": "audit-metadata.json",
    "verification": "verification.json",
    "raw": "raw-scans",
    "evidence": "evidence",
}


def load_json_arg(path: Optional[str], label: str) -> Dict[str, Any]:
    """Load an optional side input, refusing anything that is not an object."""
    if not path:
        return {}
    try:
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
    except FileNotFoundError:
        raise SystemExit("%s: %s does not exist" % (label, path))
    except json.JSONDecodeError as exc:
        raise SystemExit("%s: %s is not valid JSON (%s)" % (label, path, exc))
    if not isinstance(data, dict):
        raise SystemExit("%s: %s must contain a JSON object" % (label, path))
    return data


def model_from_args(args: argparse.Namespace) -> Dict[str, Any]:
    """Build the view model from the parsed command line."""
    dataset = fm.load_findings(args.dataset)
    return build_report(dataset,
                        metadata=load_json_arg(getattr(args, "metadata", None), "--metadata"),
                        analysis=load_json_arg(getattr(args, "analysis", None), "--analysis"),
                        inventory=load_json_arg(getattr(args, "inventory", None), "--inventory"))


def add_common_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--dataset", required=True,
                        help="the validated findings dataset (findings.json)")
    parser.add_argument("--outdir", required=True, help="the audit output directory")
    parser.add_argument("--metadata", help="audit-metadata.json (repository, commit, date)")
    parser.add_argument("--analysis", help="the stage-3 scanner_orchestrator report")
    parser.add_argument("--inventory", help="the repository_inventory report")
    parser.add_argument("--out", help="write here instead of the standard file name in --outdir")
    parser.add_argument("--indent", type=int, default=2, help="JSON indentation for the result")


def ensure_outdir(path: str) -> str:
    os.makedirs(path, exist_ok=True)
    return path


def write_report(path: str, text: str) -> Dict[str, Any]:
    """Write ``text`` atomically and return the facts a verifier needs."""
    directory = os.path.dirname(os.path.abspath(path))
    if directory:
        os.makedirs(directory, exist_ok=True)
    temporary = path + ".tmp"
    data = text.encode("utf-8")
    with open(temporary, "wb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)
    digest = hashlib.sha256(data).hexdigest()
    return {"path": path, "bytes": len(data), "sha256": digest,
            "lines": text.count("\n") + (0 if text.endswith("\n") else 1)}


def emit(result: Mapping[str, Any], indent: int = 2) -> None:
    print(json.dumps(result, indent=indent, ensure_ascii=False, sort_keys=False))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="report_model.py",
        description="Build the shared report view model, or render a template with it.")
    sub = parser.add_subparsers(dest="command", required=True)
    view = sub.add_parser("view", help="print the view model for a findings dataset")
    view.add_argument("dataset")
    view.add_argument("--metadata")
    view.add_argument("--analysis")
    view.add_argument("--inventory")
    view.add_argument("--indent", type=int, default=1)
    render_cmd = sub.add_parser("render", help="render a template against a view model")
    render_cmd.add_argument("template")
    render_cmd.add_argument("model", help="a view model JSON, as printed by 'view'")
    render_cmd.add_argument("--autoescape", action="store_true")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "view":
        dataset = fm.load_findings(args.dataset)
        report = build_report(dataset, metadata=load_json_arg(args.metadata, "--metadata"),
                              analysis=load_json_arg(args.analysis, "--analysis"),
                              inventory=load_json_arg(args.inventory, "--inventory"))
        print(json.dumps(report, indent=args.indent, ensure_ascii=False))
        return 0
    model = load_json_arg(args.model, "model")
    sys.stdout.write(render_file(args.template, model, autoescape=args.autoescape))
    return 0


if __name__ == "__main__":
    sys.exit(main())
