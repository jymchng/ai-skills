#!/usr/bin/env python3
"""Shared finding data model for the vulnerabilities-scan skill.

One dataset, three report formats. This module owns the contract:

* :func:`load_schema` / :func:`load_findings` / :func:`save_findings` — I/O with
  deterministic serialisation, so two runs over the same snapshot produce
  byte-identical output.
* :func:`validate` — JSON Schema validation when ``jsonschema`` is importable,
  plus a stdlib fallback that checks the mandatory fields, enums and ranges, so
  the skill keeps its zero-install guarantee.
* :func:`assign_ids` — deterministic ``VULN-NNN`` assignment.
* :func:`severity_from_score` — CVSS 4.0 score to the reporting band.
* :func:`redact_value` / :func:`redact_text` / :func:`redact_finding` — secret
  redaction applied at ingestion, before anything is written.
* :func:`consistency_problems` — the cross-field rules a JSON Schema cannot
  express (severity vs score, unscored pairing, suppressed findings, id
  uniqueness).

Stdlib only. ``jsonschema`` is used when present but never required.

CLI
---
    python3 scripts/finding_model.py validate findings.json
    python3 scripts/finding_model.py ids findings.json --out findings.json
    python3 scripts/finding_model.py band 9.3
    python3 scripts/finding_model.py redact 'the-value-from-your-secret-store'
    python3 scripts/finding_model.py check-leaks findings.json --secrets secrets.txt
"""

from __future__ import annotations

import argparse
import ast
import json
import os
import re
import sys
import tempfile
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

SCHEMA_VERSION = "1.0"
SCHEMA_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir,
                           "schemas", "finding.schema.json")

#: The 20 mandatory finding fields, in report order (references/reporting-standard.md §1).
MANDATORY_FIELDS: Tuple[str, ...] = (
    "id", "title", "category", "severity", "confidence", "validation_status",
    "cwe", "owasp", "cvss_vector", "cvss_score", "location", "language",
    "evidence", "description", "impact", "attack_scenario", "recommended_fix",
    "references", "sources", "priority",
)

SEVERITIES: Tuple[str, ...] = ("Critical", "High", "Medium", "Low", "Informational")
CONFIDENCES: Tuple[str, ...] = ("CONFIRMED", "HIGH", "MEDIUM", "LOW")
VALIDATION_STATUSES: Tuple[str, ...] = ("unvalidated", "validated", "needs_review", "suppressed")
PRIORITIES: Tuple[str, ...] = ("P0", "P1", "P2", "P3")

#: Sort weight: Critical first. Used for id assignment and report ordering.
SEVERITY_RANK: Dict[str, int] = {name: i for i, name in enumerate(SEVERITIES)}

#: Lower bound of each band, highest first (references/severity-scoring.md §1).
_BANDS: Tuple[Tuple[float, str], ...] = (
    (9.0, "Critical"),
    (7.0, "High"),
    (4.0, "Medium"),
    (0.1, "Low"),
)

_ID_RE = re.compile(r"^VULN-(\d{3,4})$")
_CWE_RE = re.compile(r"^CWE-\d{1,5}$")
_VECTOR_RE = re.compile(r"^CVSS:4\.0/[A-Z]{1,3}:[A-Za-z](?:/[A-Z]{1,3}:[A-Za-z]){10,}$")
_ABS_PATH_RE = re.compile(r"^(/|[A-Za-z]:[\\/])")


# --------------------------------------------------------------------------- #
# I/O
# --------------------------------------------------------------------------- #

def load_schema(path: Optional[str] = None) -> Dict[str, Any]:
    """Load the JSON Schema that defines a findings dataset."""
    with open(path or SCHEMA_PATH, encoding="utf-8") as fh:
        return json.load(fh)


def load_findings(path: str) -> Dict[str, Any]:
    """Load a findings dataset from ``path``.

    Accepts either the dataset object or a bare list of findings (wrapped into a
    minimal dataset) so that intermediate pipeline stages can be inspected
    without ceremony.
    """
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    if isinstance(data, list):
        return {"schema_version": SCHEMA_VERSION, "findings": data}
    if not isinstance(data, dict):
        raise ValueError(f"{path}: expected a JSON object or array, got {type(data).__name__}")
    data.setdefault("schema_version", SCHEMA_VERSION)
    data.setdefault("findings", [])
    return data


def _canonical_finding(finding: Dict[str, Any]) -> Dict[str, Any]:
    """Order keys as documented, then any extras alphabetically, for stable diffs."""
    out: Dict[str, Any] = {}
    for key in MANDATORY_FIELDS:
        if key in finding:
            out[key] = finding[key]
    for key in sorted(k for k in finding if k not in out):
        out[key] = finding[key]
    return out


#: Top-level key order, so a diff between two runs is meaningful.
_DATASET_KEY_ORDER: Tuple[str, ...] = (
    "schema_version", "audit", "generated_by", "coverage", "findings",
    "negative_findings", "suppressions",
)


def dumps(dataset: Dict[str, Any]) -> str:
    """Serialise a dataset deterministically (canonical key order, 2-space indent, UTF-8).

    Ordering is fixed rather than alphabetical: mandatory finding fields come
    first so a human diff highlights real changes, and top-level keys follow
    ``_DATASET_KEY_ORDER``. Unknown keys are appended alphabetically.
    """
    payload: Dict[str, Any] = {}
    for key in _DATASET_KEY_ORDER:
        if key in dataset:
            payload[key] = dataset[key]
    for key in sorted(k for k in dataset if k not in payload):
        payload[key] = dataset[key]
    payload["findings"] = [_canonical_finding(f) for f in dataset.get("findings", [])]
    if "negative_findings" in payload:
        payload["negative_findings"] = sorted(
            payload["negative_findings"], key=lambda n: (n.get("check", ""), n.get("scope", "")))
    return json.dumps(payload, indent=2, ensure_ascii=False) + "\n"


def save_findings(dataset: Dict[str, Any], path: str) -> str:
    """Write ``dataset`` to ``path`` atomically. Returns the path written."""
    text = dumps(dataset)
    directory = os.path.dirname(os.path.abspath(path)) or "."
    os.makedirs(directory, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".findings-", suffix=".json")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise
    return path


# --------------------------------------------------------------------------- #
# Validation
# --------------------------------------------------------------------------- #

def _fallback_errors(dataset: Dict[str, Any]) -> List[str]:
    """Stdlib validation used when ``jsonschema`` is unavailable.

    Mirrors the schema's hard requirements. It deliberately does not attempt to
    interpret JSON Schema; it enforces the rules that matter for this model.
    """
    errors: List[str] = []
    if not isinstance(dataset, dict):
        return ["dataset: expected an object"]
    if "schema_version" not in dataset:
        errors.append("dataset: missing 'schema_version'")
    elif dataset["schema_version"] != SCHEMA_VERSION:
        errors.append(f"dataset.schema_version: expected {SCHEMA_VERSION!r}, "
                      f"got {dataset['schema_version']!r}")
    findings = dataset.get("findings")
    if not isinstance(findings, list):
        return errors + ["dataset.findings: expected an array"]

    for i, f in enumerate(findings):
        at = f"findings[{i}]"
        if not isinstance(f, dict):
            errors.append(f"{at}: expected an object")
            continue
        for field in MANDATORY_FIELDS:
            if field not in f:
                errors.append(f"{at}: missing mandatory field {field!r}")
        if "id" in f and not (isinstance(f["id"], str) and _ID_RE.match(f["id"])):
            errors.append(f"{at}.id: expected VULN-NNN, got {f['id']!r}")
        if f.get("severity") not in SEVERITIES:
            errors.append(f"{at}.severity: {f.get('severity')!r} not in {SEVERITIES}")
        if f.get("confidence") not in CONFIDENCES:
            errors.append(f"{at}.confidence: {f.get('confidence')!r} not in {CONFIDENCES}")
        if f.get("validation_status") not in VALIDATION_STATUSES:
            errors.append(f"{at}.validation_status: {f.get('validation_status')!r} "
                          f"not in {VALIDATION_STATUSES}")
        if f.get("priority") not in PRIORITIES:
            errors.append(f"{at}.priority: {f.get('priority')!r} not in {PRIORITIES}")
        cwe = f.get("cwe")
        if not isinstance(cwe, dict) or not _CWE_RE.match(str(cwe.get("id", ""))):
            errors.append(f"{at}.cwe.id: expected CWE-NNN")
        score = f.get("cvss_score")
        if score is not None:
            if not isinstance(score, (int, float)) or isinstance(score, bool):
                errors.append(f"{at}.cvss_score: expected number or null")
            elif not 0.0 <= float(score) <= 10.0:
                errors.append(f"{at}.cvss_score: {score} outside 0.0-10.0")
        vector = f.get("cvss_vector")
        if vector is not None and not (isinstance(vector, str) and _VECTOR_RE.match(vector)):
            errors.append(f"{at}.cvss_vector: not a CVSS 4.0 vector")
        if score is None and vector is not None:
            errors.append(f"{at}: unscored finding must have cvss_vector null")
        if vector is None and score is not None:
            errors.append(f"{at}: scored finding must have cvss_vector set")
        loc = f.get("location")
        if not isinstance(loc, dict):
            errors.append(f"{at}.location: expected an object")
        else:
            path = str(loc.get("file", ""))
            if not path:
                errors.append(f"{at}.location.file: empty")
            elif _ABS_PATH_RE.match(path):
                errors.append(f"{at}.location.file: must be relative, got {path!r}")
            start, end = loc.get("line_start"), loc.get("line_end")
            if not isinstance(start, int) or start < 1:
                errors.append(f"{at}.location.line_start: expected integer >= 1")
            if not isinstance(end, int) or end < 1:
                errors.append(f"{at}.location.line_end: expected integer >= 1")
            if isinstance(start, int) and isinstance(end, int) and end < start:
                errors.append(f"{at}.location: line_end {end} < line_start {start}")
        sources = f.get("sources")
        if not isinstance(sources, list) or not sources:
            errors.append(f"{at}.sources: expected a non-empty array")
        elif any(not isinstance(s, dict) or not s.get("tool") for s in sources):
            errors.append(f"{at}.sources: every entry needs a 'tool'")
        if f.get("validation_status") == "suppressed" and not f.get("suppression_reason"):
            errors.append(f"{at}: suppressed finding requires 'suppression_reason'")
        for field in ("title", "evidence", "description", "impact", "attack_scenario",
                      "recommended_fix", "language"):
            value = f.get(field)
            if not isinstance(value, str) or not value.strip():
                errors.append(f"{at}.{field}: expected a non-empty string")
    return errors


def validate(dataset: Dict[str, Any], schema: Optional[Dict[str, Any]] = None) -> List[str]:
    """Return a list of problems; an empty list means the dataset is valid.

    Uses ``jsonschema`` when available (full schema semantics) and the stdlib
    fallback otherwise. Cross-field rules from :func:`consistency_problems` are
    always applied on top, because JSON Schema cannot express them.
    """
    errors: List[str] = []
    try:
        import jsonschema  # type: ignore
    except ImportError:
        errors.extend(_fallback_errors(dataset))
    else:
        validator = jsonschema.Draft202012Validator(schema or load_schema())
        for err in sorted(validator.iter_errors(dataset), key=lambda e: list(e.absolute_path)):
            location = "/".join(str(p) for p in err.absolute_path) or "<root>"
            errors.append(f"{location}: {err.message}")
    errors.extend(consistency_problems(dataset))
    return errors


def consistency_problems(dataset: Dict[str, Any]) -> List[str]:
    """Rules a JSON Schema cannot express. Returns human-readable problems."""
    problems: List[str] = []
    seen: Dict[str, int] = {}
    findings = dataset.get("findings") or []
    for i, f in enumerate(findings):
        if not isinstance(f, dict):
            continue
        fid = f.get("id")
        at = f"{fid or f'findings[{i}]'}"
        if fid:
            if fid in seen:
                problems.append(f"{at}: duplicate id (also at index {seen[fid]})")
            seen[fid] = i
        score = f.get("cvss_score")
        severity = f.get("severity")
        if isinstance(score, (int, float)) and not isinstance(score, bool):
            expected = severity_from_score(float(score))
            if severity and severity != expected:
                problems.append(
                    f"{at}: severity {severity!r} contradicts CVSS {score} (band: {expected})")
        if severity == "Informational" and isinstance(score, (int, float)) and score >= 0.1:
            problems.append(f"{at}: Informational severity with a qualifying score {score}")
        loc = f.get("location") or {}
        start, end = loc.get("line_start"), loc.get("line_end")
        if isinstance(start, int) and isinstance(end, int) and end < start:
            problems.append(f"{at}: line_end {end} is before line_start {start}")
        if f.get("confidence") == "LOW" and severity == "Critical":
            problems.append(f"{at}: Critical severity with LOW confidence is not permitted")
        if f.get("validation_status") == "unvalidated":
            problems.append(f"{at}: unvalidated finding must not be in a reportable dataset")
    return problems


# --------------------------------------------------------------------------- #
# Identifiers
# --------------------------------------------------------------------------- #

def _sort_key(finding: Dict[str, Any]) -> Tuple[Any, ...]:
    loc = finding.get("location") or {}
    return (
        SEVERITY_RANK.get(str(finding.get("severity")), len(SEVERITIES)),
        str(loc.get("file", "")),
        int(loc.get("line_start") or 0),
        str(finding.get("category", "")),
        str(finding.get("title", "")),
    )


def assign_ids(dataset: Dict[str, Any], width: int = 3) -> Dict[str, Any]:
    """Assign ``VULN-NNN`` ids deterministically and return the dataset.

    Ordering is ``(severity rank, file, line_start, category, title)``: a pure
    function of the findings' content, so regenerating the same dataset yields
    the same ids. ``width`` widens the zero padding past 999 findings.
    """
    findings = list(dataset.get("findings") or [])
    width = max(3, min(4, int(width)))
    for index, finding in enumerate(sorted(findings, key=_sort_key), start=1):
        finding["id"] = f"VULN-{index:0{width}d}"
    dataset["findings"] = findings
    return dataset


def next_id(dataset: Dict[str, Any]) -> str:
    """Return the next free ``VULN-NNN`` id without mutating the dataset."""
    highest = 0
    for finding in dataset.get("findings") or []:
        match = _ID_RE.match(str(finding.get("id", "")))
        if match:
            highest = max(highest, int(match.group(1)))
    return f"VULN-{highest + 1:03d}"


# --------------------------------------------------------------------------- #
# Code-only views
# --------------------------------------------------------------------------- #
#: Line-comment markers per language. Anything unlisted is treated as C-like,
#: which is right for JS, TS, Go, Java, C#, Kotlin, Rust and Protobuf.
_COMMENT_MARKERS: Dict[str, Tuple[str, ...]] = {
    "python": ("#",), "ruby": ("#",), "graphql": ("#",), "yaml": ("#",),
    "dockerfile": ("#",), "shell": ("#",), "bash": ("#",),
    "php": ("//", "#"), "terraform": ("#", "//"),
    "javascript": ("//",), "typescript": ("//",), "go": ("//",), "java": ("//",),
    "csharp": ("//",), "kotlin": ("//",), "rust": ("//",), "swift": ("//",),
    "c": ("//",), "cpp": ("//",), "protobuf": ("//",),
    # Languages the rule table now covers, each with its own comment syntax. A
    # missing entry is not cosmetic: ``-- comment`` in SQL or ``# note`` in a
    # PowerShell script would stay visible to the rules and a commented-out
    # command would be reported as live code.
    "scala": ("//",), "groovy": ("//",),
    "powershell": ("#",), "toml": ("#",), "ini": (";", "#"), "hcl": ("#", "//"),
    "elixir": ("#",), "perl": ("#",), "r": ("#",), "lua": ("--",), "sql": ("--",),
}
#: Languages with no ``/* ... */`` form (or where it is not a comment).
_NO_BLOCK_COMMENT = frozenset({"python", "ruby", "graphql", "yaml", "dockerfile",
                               "shell", "bash", "text", "markdown", "json",
                               "powershell", "toml", "ini", "elixir", "perl", "r",
                               "sql", "lua"})
#: Languages that also use the backtick as a string delimiter.
_BACKTICK_LANGS = frozenset({"javascript", "typescript", "go", "terraform", "shell"})


def _syntax(language: str) -> Tuple[Tuple[str, ...], Optional[Tuple[str, str]], str]:
    name = (language or "").lower()
    line = _COMMENT_MARKERS.get(name, ("//",))
    block = None if name in _NO_BLOCK_COMMENT else ("/*", "*/")
    quotes = "'\"" + ("`" if name in _BACKTICK_LANGS else "")
    return line, block, quotes


def _docstring_spans(text: str) -> List[Tuple[int, int]]:
    """Character spans of Python docstrings, so prose can be told from code.

    Only the first statement of a module, class or function is a docstring; an
    assigned triple-quoted string is a literal and stays visible to the rules.
    """
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError):
        return []
    if not isinstance(tree, ast.Module):
        return []
    line_starts = [0]
    for match in re.finditer("\n", text):
        line_starts.append(match.end())

    def offset(line: int, column: int) -> int:
        if 1 <= line <= len(line_starts):
            return min(line_starts[line - 1] + column, len(text))
        return len(text)

    spans: List[Tuple[int, int]] = []
    for node in ast.walk(tree):
        body = getattr(node, "body", None)
        if not isinstance(body, list) or not body:
            continue
        first = body[0]
        if not isinstance(first, ast.Expr) or not isinstance(first.value, ast.Constant):
            continue
        if not isinstance(first.value.value, str):
            continue
        start = offset(first.value.lineno, first.value.col_offset)
        end = offset(getattr(first.value, "end_lineno", first.value.lineno),
                     getattr(first.value, "end_col_offset", 0))
        if end > start:
            spans.append((start, end))
    return spans


def mask_non_code(text: str, language: str, *, keep_strings: bool = False,
                  blank_docstrings: bool = False, keep_comments: bool = False) -> str:
    """Return ``text`` with comments (and optionally strings) blanked in place.

    Offsets and line numbers are preserved, so anything found in the masked view
    is still reported against the original file. Two precision problems die
    here: prose that *describes* a mechanism or quotes a credential is not the
    mechanism or the credential, and a rule table that stores its patterns as
    literals stops matching itself.

    ``keep_strings`` keeps string bodies (a secret *is* a string, and so is the
    SQL a rule matches); ``blank_docstrings`` additionally blanks Python
    docstrings, which are documentation even though they are literals;
    ``keep_comments`` keeps comment text, because for two rule families the
    comment *is* the evidence -- a commented-out authorization check, and a
    credential pasted into a note. Blanking it there hides real findings.
    """
    line_markers, block_pair, quotes = _syntax(language)
    if keep_comments:
        line_markers, block_pair = (), None
    out = list(text)
    length = len(text)

    def blank(start: int, end: int) -> None:
        for position in range(max(0, start), min(end, length)):
            if text[position] != "\n":
                out[position] = " "

    if blank_docstrings and (language or "").lower() == "python":
        for start, end in _docstring_spans(text):
            blank(start, end)

    index = 0
    while index < length:
        char = text[index]
        marker = next((item for item in line_markers if text.startswith(item, index)), None)
        if marker is not None:
            newline = text.find("\n", index)
            end = length if newline < 0 else newline
            blank(index, end)
            index = end
            continue
        if block_pair and text.startswith(block_pair[0], index):
            closing = text.find(block_pair[1], index + len(block_pair[0]))
            end = length if closing < 0 else closing + len(block_pair[1])
            blank(index, end)
            index = end
            continue
        if char in quotes:
            delimiter = char * 3 if text.startswith(char * 3, index) else char
            cursor = index + len(delimiter)
            while cursor < length:
                if text[cursor] == "\\":
                    cursor += 2
                    continue
                if text.startswith(delimiter, cursor):
                    cursor += len(delimiter)
                    break
                cursor += 1
            if not keep_strings:
                blank(index + len(delimiter), cursor - len(delimiter))
            index = cursor
            continue
        index += 1
    return "".join(out)


# --------------------------------------------------------------------------- #
# Severity
# --------------------------------------------------------------------------- #

def severity_from_score(score: Optional[float]) -> str:
    """Map a CVSS 4.0 base score to the reporting band.

    Bands (references/severity-scoring.md §1): Critical 9.0-10.0, High 7.0-8.9,
    Medium 4.0-6.9, Low 0.1-3.9. A ``None`` score or an exact ``0.0`` (no impact
    on any metric) is Informational, which is never presented as a vulnerability.
    """
    if score is None:
        return "Informational"
    value = float(score)
    if value <= 0.0:
        return "Informational"
    for threshold, band in _BANDS:
        if value >= threshold:
            return band
    return "Low"


def apply_severity(dataset: Dict[str, Any]) -> Dict[str, Any]:
    """Re-derive ``severity`` from ``cvss_score`` for every finding that has one."""
    for finding in dataset.get("findings") or []:
        score = finding.get("cvss_score")
        if isinstance(score, (int, float)) and not isinstance(score, bool):
            finding["severity"] = severity_from_score(float(score))
    return dataset


# --------------------------------------------------------------------------- #
# Redaction
# --------------------------------------------------------------------------- #

def redact_value(value: str, keep: Optional[int] = None) -> str:
    """Return a safe, informative stand-in for a secret.

    Shows a short prefix and the true length, which is enough to locate the
    value in the code and rotate it, and not enough to use it::

        >>> redact_value("AKIA" + "IOSFODNN7EXAMPLE")
        'AKIA…(20 chars)'
        >>> redact_value("hunter2")
        '…(7 chars)'

    Secrets shorter than 12 characters get no prefix at all: two characters of a
    seven-character password is a third of the secret.

    The result never equals the input, so no redaction marker can be mistaken
    for the secret itself.
    """
    if not isinstance(value, str):
        value = "" if value is None else str(value)
    length = len(value)
    if length == 0:
        return "…(0 chars)"
    if keep is None:
        # A 4-character prefix is only revealing when the value is long enough for
        # the remaining entropy to stay unknowable; short secrets get no prefix.
        keep = 4 if length >= 12 else 0
    keep = max(0, min(int(keep), length - 1)) if length > 1 else 0
    prefix = value[:keep]
    return f"{prefix}…({length} chars)"


def redact_text(text: str, secrets: Iterable[str]) -> Tuple[str, int]:
    """Replace every occurrence of each secret in ``text``. Returns (text, count).

    Longest secret first, so a short secret that is a prefix of a longer one
    cannot partially redact it and leave a fragment behind.
    """
    if not isinstance(text, str) or not text:
        return text, 0
    count = 0
    for secret in sorted({s for s in secrets if isinstance(s, str) and s}, key=len, reverse=True):
        if secret in text:
            occurrences = text.count(secret)
            text = text.replace(secret, redact_value(secret))
            count += occurrences
    return text, count


def shape_marker(marker: str) -> str:
    """The one spelling of a redaction marker for a credential shape.

    Every stage that sweeps text for credentials -- the analyzer's
    :func:`builtin_analyzers.redact_shapes`, the validator's
    :func:`validate_findings.redact_text` and the orchestrator's
    :func:`scanner_orchestrator.redact` -- builds its marker here, so one shape
    cannot be labelled ``[REDACTED STRIPE SECRET KEY]`` by one stage and
    ``[REDACTED STRIPE KEY]`` by the next in the same report::

        >>> shape_marker("stripe key")
        '[REDACTED STRIPE KEY]'
    """
    return "[REDACTED %s]" % str(marker or "SECRET").strip().upper()


def redact_shape_match(match: Any, marker: str) -> str:
    """Replace the credential in *match* with :func:`shape_marker` of *marker*.

    A pattern either names the value (``?P<secret>``) or matches it whole, so
    ``client_secret = "..."`` keeps its assignment and loses only the literal,
    and ``postgres://app:...@host`` keeps its scheme, user and host. Placeholders
    and existing markers are returned untouched: rewriting them would erase the
    guidance that put them there and re-spell a marker the previous stage wrote.
    """
    named = match.groupdict().get("secret")
    value = (named if named is not None else match.group(0)).strip().strip("'\"")
    if not value or is_placeholder(value) or "[REDACTED" in value or "\u2026" in value:
        return match.group(0)
    text = shape_marker(marker)
    return match.group(0).replace(named, text) if named is not None else text


#: Fields whose free text can leak a secret into a report narrative.
_REDACTABLE_FIELDS: Tuple[str, ...] = (
    "title", "evidence", "description", "impact", "attack_scenario",
    "recommended_fix", "validation",
)


#: Values that look like secrets but are not: placeholders in templates, empty
#: strings, environment references and obvious dummies. Lives here rather than in
#: the analyzers because three stages redact text and all of them must agree on
#: what "already safe" means.
SECRET_PLACEHOLDER_RE = re.compile(
    r"^(?:|x{3,}|X{3,}|\*{3,}|\.{3,}|changeme|change[_-]?me|placeholder|example|sample|dummy|"
    r"test|secret|password|passwd|your[_-]?\w*|todo|fixme|null|none|true|false|"
    r"[\$\{\}<>%\s]+|\$\{?\w+\}?|\{\{\s*\w+\s*\}\})$",
    re.IGNORECASE,
)

#: A value that is already a marker or an unfilled template hole rather than a
#: literal secret. Rewriting one of these would erase the guidance that put it
#: there, and re-redacting a report would rewrite its own markers.
ALREADY_SAFE_RE = re.compile(
    r"^(?:<[^<>]*>|\[REDACTED[^\]]*\]|\*{2,}|x{2,}|\.{2,}|-{2,}|_{2,})$", re.IGNORECASE)

PLACEHOLDER_TOKENS: Tuple[str, ...] = (
    "${", "{{", "os.environ", "process.env", "getenv", "%s", "[REDACTED",
)

#: Words that describe a credential instead of being one. A phrase built only
#: from these (``your-api-key-here``, ``insert_token_here``) is documentation: the
#: anchored regex above cannot see a hyphen-joined phrase, and redacting one would
#: delete the instruction the template is giving.
PLACEHOLDER_WORDS = frozenset({
    "a", "an", "the", "your", "my", "our", "insert", "add", "put", "here",
    "api", "key", "apikey", "secret", "token", "password", "passwd", "pwd",
    "value", "placeholder", "example", "sample", "dummy", "test", "fake",
    "change", "changeme", "me", "foo", "bar", "xxx", "xxxx",
})


def is_placeholder(value: Any) -> bool:
    """True when *value* is not a literal secret but a marker or a template hole."""
    text = str(value or "").strip().strip("'\"")
    if not text:
        return True
    if SECRET_PLACEHOLDER_RE.match(text) or ALREADY_SAFE_RE.match(text):
        return True
    if any(token in text for token in PLACEHOLDER_TOKENS):
        return True
    words = [word for word in re.split(r"[^a-z0-9]+", text.lower()) if word]
    return len(words) > 1 and all(word in PLACEHOLDER_WORDS for word in words)


def redact_finding(finding: Dict[str, Any], secrets: Iterable[str]) -> Tuple[Dict[str, Any], int]:
    """Redact secrets from a finding's free-text fields. Returns (finding, count).

    Applied at ingestion, before the finding is written: the raw value must
    never reach ``findings.json``, let alone a rendered report.
    """
    total = 0
    for field in _REDACTABLE_FIELDS:
        if field in finding and isinstance(finding[field], str):
            finding[field], n = redact_text(finding[field], secrets)
            total += n
    return finding, total


def find_leaks(dataset: Dict[str, Any], secrets: Iterable[str]) -> List[str]:
    """Report where raw secrets still appear. Used by the stage-8 verifier."""
    needles = [s for s in secrets if isinstance(s, str) and s]
    leaks: List[str] = []
    if not needles:
        return leaks
    haystacks: List[Tuple[str, str]] = []
    for key in ("audit", "coverage", "generated_by"):
        if key in dataset:
            haystacks.append((key, json.dumps(dataset[key], ensure_ascii=False)))
    for i, finding in enumerate(dataset.get("findings") or []):
        if isinstance(finding, dict):
            haystacks.append((f"findings[{i}]", json.dumps(finding, ensure_ascii=False)))
    for where, blob in haystacks:
        for needle in needles:
            if needle in blob:
                leaks.append(f"{where}: raw secret present")
                break
    return leaks


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def _cmd_validate(args: argparse.Namespace) -> int:
    dataset = load_findings(args.path)
    problems = validate(dataset)
    if problems:
        for problem in problems:
            print(f"FAIL {problem}", file=sys.stderr)
        return 1
    print(json.dumps({"valid": True, "findings": len(dataset.get("findings", [])),
                      "validator": _validator_kind()}))
    return 0


def _validator_kind() -> str:
    try:
        import jsonschema  # noqa: F401
    except ImportError:
        return "stdlib-fallback"
    return "jsonschema"


def _cmd_ids(args: argparse.Namespace) -> int:
    dataset = load_findings(args.path)
    assign_ids(dataset, width=args.width)
    if args.out:
        save_findings(dataset, args.out)
        print(json.dumps({"written": args.out, "ids": [f["id"] for f in dataset["findings"]]}))
    else:
        print(json.dumps([{"id": f["id"], "title": f["title"]} for f in dataset["findings"]]))
    return 0


def _cmd_band(args: argparse.Namespace) -> int:
    print(json.dumps({"score": args.score, "severity": severity_from_score(args.score)}))
    return 0


def _cmd_redact(args: argparse.Namespace) -> int:
    print(json.dumps({"redacted": redact_value(args.value)}))
    return 0


def _cmd_check_leaks(args: argparse.Namespace) -> int:
    dataset = load_findings(args.path)
    with open(args.secrets, encoding="utf-8") as fh:
        secrets = [line.rstrip("\n") for line in fh if line.strip()]
    leaks = find_leaks(dataset, secrets)
    print(json.dumps({"leaks": leaks, "checked": len(secrets)}))
    return 1 if leaks else 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="finding_model.py",
        description="Validate, identify, score and redact the audit findings dataset.",
        epilog="Every command prints JSON on stdout; problems go to stderr.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("validate", help="validate a findings dataset against the schema")
    p.add_argument("path", help="path to findings.json")
    p.set_defaults(func=_cmd_validate)

    p = sub.add_parser("ids", help="assign deterministic VULN-NNN ids")
    p.add_argument("path", help="path to findings.json")
    p.add_argument("--out", help="write the renumbered dataset here (default: print only)")
    p.add_argument("--width", type=int, default=3, help="id zero-padding width (3 or 4)")
    p.set_defaults(func=_cmd_ids)

    p = sub.add_parser("band", help="map a CVSS 4.0 score to a severity band")
    p.add_argument("score", type=float)
    p.set_defaults(func=_cmd_band)

    p = sub.add_parser("redact", help="show how a secret value would be redacted")
    p.add_argument("value")
    p.set_defaults(func=_cmd_redact)

    p = sub.add_parser("check-leaks", help="assert no raw secret remains in a dataset")
    p.add_argument("path", help="path to findings.json")
    p.add_argument("--secrets", required=True, help="file with one raw secret per line")
    p.set_defaults(func=_cmd_check_leaks)
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
