#!/usr/bin/env python3
"""Stage 6 verifier \u2014 prove the report set is complete, valid and self-consistent.

Four formats are produced from one dataset, which is exactly the arrangement in
which a report set silently disagrees with itself: a generator is edited, a
template is cached, a PDF is left over from yesterday's run. This script is the
gate before delivery. It checks three separate things.

**Existence and validity**
    ``SECURITY-AUDIT-REPORT.md``, ``.html``, ``.json`` and ``report-manifest.json``
    must exist and parse. The HTML must be well-formed, self-contained (no
    ``<script src>``, ``<link href>``, ``@import`` or ``url(http...)``) and carry a
    title; the JSON must match the per-finding contract and file every finding
    under a bucket that exists; the PDF must be a real PDF and
    must have produced its text.

**Agreement between formats**
    Every validated finding id, the total, and the per-severity distribution are
    read back out of each format \u2014 the Markdown summary table, the HTML severity
    cards, the JSON counts, the extracted PDF text \u2014 and compared. When
    ``--dataset`` is supplied the dataset is the authority; otherwise the formats
    are compared with each other, and a disagreement is reported either way. A
    format that cannot be checked (no ``pdftotext``, no PDF) says so instead of
    passing silently.

**No unredacted secrets**
    Every format is scanned for credential shapes (and for the exact values in
    ``--secrets-file``, when given), because a redaction bug in one template is
    precisely the kind of defect that would otherwise ship.

Exit status is 0 only when there are no problems.

Usage::

    python3 scripts/validate_reports.py --outdir audit/ --dataset findings.json \\
        --secrets-file secrets.txt
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from html.parser import HTMLParser
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

import finding_model as fm  # noqa: E402
import report_model as rm  # noqa: E402

TOOL_NAME = "validate_reports.py"
VERSION = "1.0.0"

#: Sections every Markdown report must contain, in reporting-standard order.
MD_SECTIONS: Tuple[str, ...] = (
    "## Verdict",
    "## Summary",
    "## Coverage and limitations",
    "## Findings by priority",
    "## Needs investigation",
    "## Negative findings",
    "## Suppressed findings",
    "## Methodology",
)

#: Elements that would make the HTML report depend on the network.
_EXTERNAL_REF_RE = (
    re.compile(r"<script[^>]*\ssrc\s*=", re.IGNORECASE),
    re.compile(r"<link[^>]*\shref\s*=", re.IGNORECASE),
    re.compile(r"@import\s", re.IGNORECASE),
    re.compile(r"url\(\s*['\"]?(?:https?:)?//", re.IGNORECASE),
    re.compile(r"<img[^>]*\ssrc\s*=\s*['\"]?(?:https?:)?//", re.IGNORECASE),
    re.compile(r"<iframe", re.IGNORECASE),
)

#: Credential shapes that must never reach a rendered report. This mirrors the
#: detector in ``builtin_analyzers.SECRET_PATTERNS`` on purpose: the verifier is
#: meant to catch a *redaction* failure, so it must look for the same values.
#:
#: Each pattern names the credential-bearing part ``secret`` so the scan can tell
#: a live value from a redaction marker. A redacted connection string keeps its
#: shape (``postgres://app:[REDACTED]@host/db``) and a redacted assignment keeps
#: its key, so matching the shape alone declared every correctly redacted report
#: a leak and made the delivery gate impossible to pass.
SECRET_SHAPES: Tuple[Tuple[str, re.Pattern], ...] = (
    ("aws-access-key", re.compile(r"\b(?P<secret>(?:AKIA|ASIA)[0-9A-Z]{16})\b")),
    ("private-key-block",
     re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"
                r"(?P<secret>.*?)-----END", re.DOTALL)),
    ("github-token", re.compile(r"\b(?P<secret>gh[pousr]_[A-Za-z0-9]{20,})\b")),
    ("slack-token", re.compile(r"\b(?P<secret>xox[baprs]-[A-Za-z0-9-]{10,})\b")),
    ("stripe-key", re.compile(r"\b(?P<secret>(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,})\b")),
    ("google-api-key", re.compile(r"\b(?P<secret>AIza[0-9A-Za-z_\-]{35})\b")),
    ("jwt-token",
     re.compile(r"\b(?P<secret>eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{5,})\b")),
    ("connection-string",
     re.compile(r"(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp|mssql)://"
                r"[^\s:/@]+:(?P<secret>[^\s@/]{3,})@")),
    ("credential-assignment",
     re.compile(r"(?i)\b(?:password|passwd|pwd|secret|api[_-]?key|apikey|access[_-]?token|"
                r"auth[_-]?token|client[_-]?secret|private[_-]?key)\b\s*[:=]\s*"
                r"[\"'](?P<secret>[^\"'\n]{6,120})[\"']")),
)

_VOID = frozenset({"area", "base", "br", "col", "embed", "hr", "img", "input", "link",
                   "meta", "param", "source", "track", "wbr"})
_OPTIONAL_END = frozenset({"li", "p", "dt", "dd", "tr", "td", "th", "option", "thead",
                           "tbody", "tfoot"})


class _HTMLAudit(HTMLParser):
    """Collect the facts the verifier needs, and detect unbalanced markup."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.stack: List[str] = []
        self.errors: List[str] = []
        self.titles = 0
        self.articles = 0
        self.cards: Dict[str, int] = {}
        self.doctype = False
        self._in_title = False
        self._in_card = False
        self._card_severity: Optional[str] = None
        self._card_text: List[str] = []
        self._in_article = False

    def handle_decl(self, decl: str) -> None:  # noqa: D102 - HTMLParser hook
        if decl.lower().startswith("doctype html"):
            self.doctype = True

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        attributes = dict(attrs)
        classes = (attributes.get("class") or "").split()
        if tag == "article" and "finding" in classes:
            self.articles += 1
            self._in_article = True
        if tag == "div" and "card" in classes:
            self._in_card = True
            self._card_text = []
            for name in classes:
                if name.startswith("sev-"):
                    self._card_severity = name[4:]
        if tag == "title":
            self.titles += 1
            self._in_title = True
        if tag not in _VOID:
            self.stack.append(tag)

    def handle_endtag(self, tag: str) -> None:
        if tag == "title":
            self._in_title = False
        if tag == "article":
            self._in_article = False
        if tag == "div" and self._in_card:
            self._in_card = False
            if self._card_severity:
                text = "".join(self._card_text).strip()
                match = re.search(r"-?\d+", text)
                if match:
                    self.cards[self._card_severity] = int(match.group(0))
            self._card_severity = None
        if tag in _VOID:
            return
        if tag in self.stack:
            while self.stack and self.stack[-1] != tag:
                dropped = self.stack.pop()
                if dropped not in _OPTIONAL_END:
                    self.errors.append("unclosed <%s> before </%s>" % (dropped, tag))
            if self.stack:
                self.stack.pop()
        elif tag not in _OPTIONAL_END:
            self.errors.append("stray </%s>" % tag)

    def handle_data(self, data: str) -> None:
        if self._in_card:
            self._card_text.append(data)


def _read_text(path: str) -> str:
    with open(path, encoding="utf-8", errors="replace") as handle:
        return handle.read()


def _digest(path: str) -> str:
    with open(path, "rb") as handle:
        return hashlib.sha256(handle.read()).hexdigest()


def _json_report_ids(path: str) -> List[str]:
    """Ids from the JSON report, used when neither dataset nor manifest lists any.

    Without this, a run with no ``--dataset`` and a manifest that carries no
    ``ids`` compared every format against an empty expectation and reported
    "expected 0" for a perfectly good report set. Returning ``[]`` is safe: the
    JSON section reports a parse failure itself.
    """
    if not os.path.exists(path):
        return []
    try:
        document = json.loads(_read_text(path))
    except json.JSONDecodeError:
        return []
    tickets = document.get("findings")
    if not isinstance(tickets, list):
        return []
    return [str(ticket.get("finding_id")) for ticket in tickets
            if isinstance(ticket, dict) and ticket.get("finding_id")]


def _json_report_article_ids(path: str) -> List[str]:
    """Every id the HTML renders as an article: findings plus needs-investigation.

    Used when no ``--dataset`` was given, so the article count still has an
    authority to compare against instead of silently passing.
    """
    if not os.path.exists(path):
        return []
    try:
        document = json.loads(_read_text(path))
    except json.JSONDecodeError:
        return []
    ids: List[str] = []
    for key in ("findings", "needs_investigation"):
        section = document.get(key)
        if not isinstance(section, list):
            continue
        ids.extend(str(ticket.get("finding_id")) for ticket in section
                   if isinstance(ticket, dict) and ticket.get("finding_id"))
    return ids


def _files_in_buckets(directory: str, problems: List[str],
                      warnings: List[str]) -> List[Tuple[str, str, str]]:
    """Every per-finding file on disk, as ``(bucket, name, full path)``.

    The tree is walked rather than one flat directory read, because the layout
    *is* the decision: a file whose depth does not name a known bucket is a
    filing bug and cannot be silently ignored. Buckets that should exist are
    checked as well, since an empty bucket and a stage that never ran look
    identical from the inside.
    """
    found: List[Tuple[str, str, str]] = []
    for root, _dirs, names in os.walk(directory):
        bucket = os.path.relpath(root, directory).replace(os.sep, "/")
        bucket = "" if bucket == "." else bucket
        for name in sorted(names):
            if not name.endswith(".json"):
                warnings.append("findings/ holds a file that is not a finding: %s/%s"
                                % (bucket, name))
                continue
            if bucket not in rm.FINDING_BUCKETS:
                problems.append("findings/%s/%s is not in any known bucket" % (bucket, name))
                continue
            found.append((bucket, name, os.path.join(root, name)))
    for bucket in rm.FINDING_BUCKETS:
        if not os.path.isdir(os.path.join(directory, *bucket.split("/"))):
            warnings.append("findings/%s/ was not created: an empty bucket must still exist"
                            % bucket)
    return found


def _find_by_name(directory: str, name: str) -> Optional[str]:
    """Find one file by name anywhere under the findings directory."""
    for root, _dirs, names in os.walk(directory):
        if name in names:
            return os.path.join(root, name)
    return None


def _check_finding_file(entry: Mapping[str, Any], directory: str,
                        problems: List[str], warnings: List[str]) -> None:
    """Prove one index entry really points at that finding's own JSON file.

    The register is only useful if the file it names exists, is readable, is
    about the same finding, sits in the bucket its own ``disposition`` implies
    and still has the digest the index recorded. A stale ticket from an earlier
    run would otherwise look like a delivered finding, and a finding filed under
    ``schedule/`` when it is a confirmed Critical would look like a scheduling
    choice rather than the filing bug it is.
    """
    finding_id = entry.get("id")
    promised = entry.get("json") or {}
    disposition = str(entry.get("disposition") or "")
    path = promised.get("path")
    if not path:
        problems.append("findings index entry %s has no json path" % finding_id)
        return
    resolved = str(path)
    if not os.path.exists(resolved) and disposition:
        resolved = os.path.join(directory, *disposition.split("/"),
                                os.path.basename(str(path)))
    if not os.path.exists(resolved):
        # The file may exist, in the wrong bucket. Saying so beats "missing":
        # a mis-filed finding is a layout bug, a genuinely absent one is a
        # failed run, and the two want different reactions.
        resolved = _find_by_name(directory, os.path.basename(str(path))) or resolved
    if not os.path.exists(resolved):
        problems.append("findings index entry %s points at a missing file: %s"
                        % (finding_id, path))
        return
    if disposition == "suppressed/unspecified":
        warnings.append("%s is suppressed with no suppression_kind: the dataset does "
                        "not say whether it was a false positive, unreachable or "
                        "accepted" % os.path.basename(resolved))
    if disposition:
        bucket = os.path.dirname(os.path.relpath(resolved, directory))
        bucket = bucket.replace(os.sep, "/")
        if bucket != disposition:
            problems.append("%s is filed under %r but its disposition is %r"
                            % (os.path.basename(resolved), bucket, disposition))
    try:
        document = json.loads(_read_text(resolved))
    except json.JSONDecodeError as exc:
        problems.append("%s is not valid JSON: %s" % (os.path.basename(resolved), exc))
        return
    if str(document.get("finding_id")) != str(finding_id):
        problems.append("%s describes %s but the index says %s"
                        % (os.path.basename(resolved), document.get("finding_id"), finding_id))
    if disposition and str(document.get("disposition") or "") != disposition:
        problems.append("%s repeats disposition %r, the index says %r"
                        % (os.path.basename(resolved), document.get("disposition"),
                           disposition))
    claimed = promised.get("sha256")
    if claimed and _digest(resolved) != claimed:
        problems.append("%s does not match the digest recorded in the index"
                        % os.path.basename(resolved))


def _severity_rows_markdown(text: str) -> Dict[str, int]:
    """Read the summary table rows out of the Markdown report."""
    rows: Dict[str, int] = {}
    pattern = re.compile(r"^\|\s*(Critical|High|Medium|Low|Informational)\s*\|\s*(\d+)\s*\|",
                         re.MULTILINE)
    for name, count in pattern.findall(text):
        if name in rows:
            rows[name] = -1  # duplicated row: a formatting bug, not a number
        else:
            rows[name] = int(count)
    return rows


def _total_markdown(text: str) -> Optional[int]:
    match = re.search(r"^\|\s*\*\*Total\*\*\s*\|\s*\*\*(\d+)\*\*", text, re.MULTILINE)
    return int(match.group(1)) if match else None


def _scan_secret_shapes(name: str, text: str, problems: List[str],
                        warnings: List[str]) -> None:
    """Flag a rendered credential shape unless every match is a redaction marker.

    A redacted value keeps the shape it was redacted out of, so the marker has to
    be recognised or the gate can never pass on a report that did the right
    thing. ``finding_model.is_placeholder`` is the one definition of "this is a
    marker, not a secret"; stage 5's leak guard uses the same test.
    """
    for label, pattern in SECRET_SHAPES:
        for match in pattern.finditer(text):
            value = match.groupdict().get("secret") or match.group(0)
            if fm.is_placeholder(value):
                continue
            # The value itself is never echoed: that would put the secret in the
            # verifier's own output, and from there into a CI log.
            problems.append("%s: unredacted %s near offset %d"
                            % (name, label, match.start()))
            break


def _scan_exact_values(name: str, text: str, secrets: Sequence[str],
                       problems: List[str]) -> None:
    for index, secret in enumerate(secrets):
        if secret and secret in text:
            problems.append("%s: raw secret #%d from --secrets-file is present" % (name, index + 1))


def _pdf_text(path: str) -> Tuple[Optional[str], str]:
    """Extract text with pdftotext, or say why it could not be checked."""
    if not shutil.which("pdftotext"):
        return None, "pdftotext is not installed; the PDF text was not compared"
    try:
        result = subprocess.run(["pdftotext", "-layout", path, "-"],
                                capture_output=True, text=True, timeout=120)
    except (OSError, subprocess.SubprocessError) as exc:
        return None, "pdftotext failed: %s" % exc
    if result.returncode != 0:
        return None, "pdftotext exited %d: %s" % (result.returncode,
                                                  (result.stderr or "").strip()[:200])
    return result.stdout, ""


def _page_count(path: str) -> Optional[int]:
    if not shutil.which("pdfinfo"):
        return None
    try:
        result = subprocess.run(["pdfinfo", path], capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.SubprocessError):
        return None
    match = re.search(r"^Pages:\s+(\d+)", result.stdout or "", re.MULTILINE)
    return int(match.group(1)) if match else None


def validate(outdir: str, dataset: Optional[str] = None,
             secrets: Sequence[str] = (), require_pdf: bool = False,
             manifest_path: Optional[str] = None) -> Dict[str, Any]:
    """Check a report directory. Returns a result dict; never raises on a problem."""
    problems: List[str] = []
    warnings: List[str] = []
    checked: Dict[str, Any] = {}

    expected_ids: List[str] = []
    #: Ids the HTML renders as <article class="finding">: the reportable findings
    #: *and* the "needs investigation" section, which the template renders with
    #: the same element. Counting only the first section reported every report set
    #: with a single needs-review finding as inconsistent.
    expected_article_ids: List[str] = []
    #: Every finding the run delivered, in report order: validated, then
    #: needs-investigation, then suppressed. Each must have one JSON file of its
    #: own, so this is deliberately not the same list as ``expected_ids``.
    all_finding_ids: List[str] = []
    model: Dict[str, Any] = {}
    if dataset:
        model = rm.build_report(fm.load_findings(dataset))
        expected_ids = [entry["id"] for entry in model.get("findings") or []]
        expected_article_ids = expected_ids + [entry["id"] for entry
                                              in model.get("needs_investigation") or []]
        all_finding_ids = expected_article_ids + [entry["id"] for entry
                                                 in model.get("suppressed") or []]
        checked["dataset"] = {"path": dataset, "sha256": _digest(dataset),
                              "ids": expected_ids,
                              "by_severity": (model.get("counts") or {}).get("by_severity"),
                              "total": (model.get("counts") or {}).get("total")}

    # ---- manifest ---------------------------------------------------------- #
    manifest: Dict[str, Any] = {}
    path_manifest = manifest_path or os.path.join(outdir, rm.OUTPUT_NAMES["manifest"])
    if not os.path.exists(path_manifest):
        problems.append("missing report-manifest.json: run generate_reports.py")
    else:
        try:
            manifest = json.loads(_read_text(path_manifest))
        except json.JSONDecodeError as exc:
            problems.append("report-manifest.json is not valid JSON: %s" % exc)
        else:
            checked["manifest"] = {"path": path_manifest, "ids": manifest.get("ids"),
                                   "failed": manifest.get("failed"),
                                   "unavailable": manifest.get("unavailable")}
            if manifest.get("failed"):
                problems.append("the manifest records failed formats: %s"
                                % ", ".join(manifest["failed"]))
            manifest_ids = [str(x) for x in manifest.get("ids") or []]
            if not expected_ids:
                expected_ids = manifest_ids
            if not expected_ids:
                expected_ids = _json_report_ids(
                    os.path.join(outdir, rm.OUTPUT_NAMES["json"]))
            # Only compare when the manifest actually lists ids: an older or
            # hand-built manifest may omit them, and "[] does not match [...]"
            # would fail a perfectly consistent report set.
            if manifest_ids and expected_ids and manifest_ids != expected_ids:
                problems.append("manifest ids %s do not match the dataset ids %s"
                                % (manifest_ids, expected_ids))

    # ---- Markdown ---------------------------------------------------------- #
    md_path = os.path.join(outdir, rm.OUTPUT_NAMES["markdown"])
    md_text = ""
    if not os.path.exists(md_path):
        problems.append("missing %s" % rm.OUTPUT_NAMES["markdown"])
    else:
        md_text = _read_text(md_path)
        if len(md_text.strip()) < 200:
            problems.append("the Markdown report is suspiciously short (%d bytes)"
                            % len(md_text))
        if not md_text.lstrip().startswith("# "):
            problems.append("the Markdown report does not start with an H1 title")
        for section in MD_SECTIONS:
            if section not in md_text:
                problems.append("the Markdown report lacks the %r section" % section)
        missing = [finding_id for finding_id in expected_ids
                   if finding_id not in md_text]
        if missing:
            problems.append("the Markdown report does not mention %s" % ", ".join(missing))
        rows = _severity_rows_markdown(md_text)
        total = _total_markdown(md_text)
        checked["markdown"] = {"path": md_path, "bytes": len(md_text.encode("utf-8")),
                               "sha256": _digest(md_path), "by_severity": rows,
                               "total": total}
        if any(value < 0 for value in rows.values()):
            problems.append("the Markdown summary table repeats a severity row")

    # ---- HTML -------------------------------------------------------------- #
    html_path = os.path.join(outdir, rm.OUTPUT_NAMES["html"])
    html_text = ""
    if not os.path.exists(html_path):
        problems.append("missing %s" % rm.OUTPUT_NAMES["html"])
    else:
        html_text = _read_text(html_path)
        audit = _HTMLAudit()
        try:
            audit.feed(html_text)
            audit.close()
        except Exception as exc:  # noqa: BLE001 - any parse failure is the finding
            problems.append("the HTML report did not parse: %s" % exc)
        if not audit.doctype:
            problems.append("the HTML report has no <!DOCTYPE html>")
        if audit.titles != 1:
            problems.append("the HTML report has %d <title> elements, expected 1"
                            % audit.titles)
        if audit.errors[:5]:
            problems.append("the HTML report is malformed: %s"
                            % "; ".join(audit.errors[:5]))
        for pattern in _EXTERNAL_REF_RE:
            match = pattern.search(html_text)
            if match:
                problems.append("the HTML report references an external resource (%r): it "
                                "must be self-contained" % match.group(0)[:40])
        article_ids = expected_article_ids or _json_report_article_ids(
            os.path.join(outdir, rm.OUTPUT_NAMES["json"]))
        if article_ids and audit.articles != len(article_ids):
            problems.append("the HTML report has %d finding articles, expected %d"
                            % (audit.articles, len(article_ids)))
        missing_articles = [finding_id for finding_id in article_ids
                            if finding_id not in html_text]
        if missing_articles:
            problems.append("the HTML report does not render %s"
                            % ", ".join(missing_articles))
        missing = [finding_id for finding_id in expected_ids
                   if finding_id not in html_text]
        if missing:
            problems.append("the HTML report does not mention %s" % ", ".join(missing))
        checked["html"] = {"path": html_path, "bytes": len(html_text.encode("utf-8")),
                           "sha256": _digest(html_path), "cards": audit.cards,
                           "articles": audit.articles}

    # ---- JSON -------------------------------------------------------------- #
    json_path = os.path.join(outdir, rm.OUTPUT_NAMES["json"])
    json_doc: Dict[str, Any] = {}
    json_text = ""
    if not all_finding_ids:  # no --dataset: fall back to what the manifest records
        all_finding_ids = list(manifest.get("ids") or []) + list(
            manifest.get("needs_investigation_ids") or []) + list(
            manifest.get("suppressed_ids") or [])
    if not os.path.exists(json_path):
        problems.append("missing %s" % rm.OUTPUT_NAMES["json"])
    else:
        json_text = _read_text(json_path)
        try:
            json_doc = json.loads(json_text)
        except json.JSONDecodeError as exc:
            problems.append("%s is not valid JSON: %s" % (rm.OUTPUT_NAMES["json"], exc))
        else:
            if json_doc.get("kind") != "security-audit-report":
                problems.append("the JSON report has kind %r, expected 'security-audit-report'"
                                % json_doc.get("kind"))
            tickets = json_doc.get("findings") or []
            json_ids = [str(ticket.get("finding_id")) for ticket in tickets]
            if expected_ids and json_ids != expected_ids:
                problems.append("the JSON report lists %s, the dataset has %s"
                                % (json_ids, expected_ids))
            counts = (json_doc.get("counts") or {}).get("by_severity") or {}
            checked["json"] = {"path": json_path, "ids": json_ids,
                               "by_severity": counts,
                               "total": (json_doc.get("counts") or {}).get("total")}
            for ticket in tickets:
                where = "ticket %s" % ticket.get("finding_id")
                if not ticket.get("ticketable"):
                    problems.append("%s is in the JSON findings but is not ticketable" % where)
                jira = ticket.get("jira") or {}
                for key in ("summary", "priority", "labels", "description_markdown"):
                    if not jira.get(key):
                        problems.append("%s has no jira.%s" % (where, key))
                if not str(ticket.get("fingerprint") or "").startswith("sha256:"):
                    problems.append("%s has no stable fingerprint" % where)
            directory = os.path.join(outdir, rm.OUTPUT_NAMES["findings"])
            if os.path.isdir(directory):
                found = _files_in_buckets(directory, problems, warnings)
                if all_finding_ids and len(found) != len(all_finding_ids):
                    problems.append("findings/ holds %d files, expected one per finding (%d)"
                                    % (len(found), len(all_finding_ids)))
                for bucket, name, full in found:
                    try:
                        json.loads(_read_text(full))
                    except json.JSONDecodeError as exc:
                        problems.append("findings/%s/%s is not valid JSON: %s"
                                        % (bucket, name, exc))
                # A non-empty unvalidated/ bucket means findings reached delivery
                # without a verdict: they are filed and named, never presented as
                # vulnerabilities, but the stage that should have decided them
                # did not run.
                stranded = [name for bucket, name, _ in found if bucket == "unvalidated"]
                if stranded:
                    warnings.append("%d finding(s) reached delivery unassessed in "
                                    "findings/unvalidated/: %s"
                                    % (len(stranded), ", ".join(sorted(stranded)[:5])))

                # ---- per-finding register ---------------------------------- #
                index_path = os.path.join(outdir, rm.OUTPUT_NAMES["index"])
                if not os.path.exists(index_path):
                    problems.append("missing %s: the per-finding register was not written"
                                    % rm.OUTPUT_NAMES["index"])
                else:
                    try:
                        index = json.loads(_read_text(index_path))
                    except json.JSONDecodeError as exc:
                        index = {}
                        problems.append("%s is not valid JSON: %s"
                                        % (rm.OUTPUT_NAMES["index"], exc))
                    if index:
                        if index.get("kind") != "security-audit-findings-index":
                            problems.append("%s has kind %r, expected "
                                            "'security-audit-findings-index'"
                                            % (rm.OUTPUT_NAMES["index"], index.get("kind")))
                        entries = [entry for entry in index.get("findings") or []
                                   if isinstance(entry, dict)]
                        index_ids = [str(entry.get("id")) for entry in entries]
                        if all_finding_ids and index_ids != all_finding_ids:
                            problems.append("%s lists %d finding(s), the dataset has %d"
                                            % (rm.OUTPUT_NAMES["index"], len(index_ids),
                                               len(all_finding_ids)))
                        if len(set(index_ids)) != len(index_ids):
                            problems.append("%s repeats a finding id" % rm.OUTPUT_NAMES["index"])
                        for entry in entries:
                            _check_finding_file(entry, directory, problems, warnings)
                        checked["findings_index"] = {
                            "path": index_path, "sha256": _digest(index_path),
                            "findings": len(entries),
                            "totals": index.get("totals")}
            else:
                warnings.append("no findings/ directory: per-finding JSON files were not written")

    # ---- PDF --------------------------------------------------------------- #
    pdf_path = os.path.join(outdir, rm.OUTPUT_NAMES["pdf"])
    pdf_state = "absent"
    if os.path.exists(pdf_path):
        with open(pdf_path, "rb") as handle:
            magic = handle.read(5)
        size = os.path.getsize(pdf_path)
        if magic != b"%PDF-":
            problems.append("the PDF does not start with %%PDF-")
        if size < 1024:
            problems.append("the PDF is only %d bytes: almost certainly a failed run" % size)
        pdf_state = "present"
        text, why = _pdf_text(pdf_path)
        if text is None:
            warnings.append(why)
        else:
            if len(text.strip()) < 200:
                problems.append("the PDF contains almost no extractable text")
            missing = [finding_id for finding_id in expected_ids if finding_id not in text]
            if missing:
                problems.append("the PDF text does not mention %s" % ", ".join(missing))
            for section in ("Verdict", "Coverage and limitations"):
                if section not in text:
                    warnings.append("the PDF text does not show the %r section (layout may "
                                    "have split it)" % section)
            _scan_secret_shapes("the PDF", text, problems, warnings)
            _scan_exact_values("the PDF", text, secrets, problems)
            checked["pdf"] = {"path": pdf_path, "bytes": size, "sha256": _digest(pdf_path),
                              "pages": _page_count(pdf_path), "text_chars": len(text)}
    else:
        entry = (manifest.get("formats") or {}).get("pdf")
        entry = entry if isinstance(entry, dict) else None
        status = (entry or {}).get("status")
        reason = (entry or {}).get("reason")
        if require_pdf:
            problems.append("missing %s and --require-pdf was given" % rm.OUTPUT_NAMES["pdf"])
        elif entry is None:
            # ``generate_reports.py --formats markdown,html,json`` is a supported
            # way to skip the PDF toolchain, and the manifest only lists formats
            # that were requested. Absence with no entry therefore means "not
            # asked for", not "silently missing": say so, do not fail the set.
            warnings.append("no PDF: the manifest lists no pdf format, so this run requested "
                            "only %s" % ", ".join(sorted((manifest.get("formats") or {}))))
        elif status == "failed":
            problems.append("the PDF was requested but failed: %s"
                            % (reason or "no reason recorded in the manifest"))
        elif status == "unavailable" and reason:
            warnings.append("no PDF: %s" % reason)
        else:
            problems.append("missing %s with no documented reason in the manifest"
                            % rm.OUTPUT_NAMES["pdf"])
    checked["pdf_state"] = pdf_state

    # ---- secrets ----------------------------------------------------------- #
    if md_text:
        _scan_secret_shapes("the Markdown report", md_text, problems, warnings)
        _scan_exact_values("the Markdown report", md_text, secrets, problems)
    if html_text:
        _scan_secret_shapes("the HTML report", html_text, problems, warnings)
        _scan_exact_values("the HTML report", html_text, secrets, problems)
    if json_text:
        _scan_secret_shapes("the JSON report", json_text, problems, warnings)
        _scan_exact_values("the JSON report", json_text, secrets, problems)
    if dataset and secrets:
        try:
            leaks = fm.find_leaks(fm.load_findings(dataset), secrets)
        except (OSError, ValueError) as exc:  # pragma: no cover - dataset already read
            warnings.append("could not re-read the dataset for leak checking: %s" % exc)
        else:
            problems.extend("the dataset leaks %s" % leak for leak in leaks)

    # ---- agreement between formats ----------------------------------------- #
    truth = (model.get("counts") or {}).get("by_severity") if model else None
    sources: List[Tuple[str, Optional[Mapping[str, Any]]]] = [
        ("Markdown", checked.get("markdown", {}).get("by_severity")),
        ("HTML", checked.get("html", {}).get("cards")),
        ("JSON", checked.get("json", {}).get("by_severity")),
    ]
    if truth is None:
        truth = checked.get("json", {}).get("by_severity") or checked.get("markdown", {}).get(
            "by_severity")
    if truth:
        normalised_truth = {name: int(truth.get(name, 0)) for name in fm.SEVERITIES}
        checked["expected_by_severity"] = normalised_truth
        for name, values in sources:
            if not values:
                warnings.append("the %s report did not yield a severity distribution" % name)
                continue
            normalised = {band: int(values.get(band, values.get(band.lower(), 0)))
                          for band in fm.SEVERITIES}
            if normalised != normalised_truth:
                problems.append(
                    "%s severity distribution %s does not match %s"
                    % (name, normalised, normalised_truth))
        totals = [("Markdown", checked.get("markdown", {}).get("total")),
                  ("JSON", checked.get("json", {}).get("total")),
                  ("dataset", truth and sum(int(truth.get(b, 0)) for b in fm.SEVERITIES))]
        present = [(name, value) for name, value in totals if value is not None]
        if len({value for _, value in present}) > 1:
            problems.append("the formats disagree on the total: %s" % present)

    ok = not problems
    return {"ok": ok, "tool": {"name": TOOL_NAME, "version": VERSION},
            "outdir": os.path.abspath(outdir), "problems": problems,
            "warnings": warnings, "checked": checked,
            "summary": "%d problem(s), %d warning(s)" % (len(problems), len(warnings))}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Verify that the Markdown, HTML, PDF and JSON reports exist, are "
                    "valid, agree with each other, and contain no unredacted secrets.",
        epilog="Exit status 1 means the report set must not be delivered; the problems "
               "list says exactly what disagrees.")
    parser.add_argument("--outdir", required=True, help="the audit output directory")
    parser.add_argument("--dataset", help="the findings dataset to use as the authority")
    parser.add_argument("--secrets-file",
                        help="file with one raw secret per line, to check for leaks")
    parser.add_argument("--manifest", help="override report-manifest.json path")
    parser.add_argument("--require-pdf", action="store_true",
                        help="treat a missing or unavailable PDF as a problem")
    parser.add_argument("--indent", type=int, default=2, help="JSON indentation")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    secrets: List[str] = []
    if args.secrets_file:
        with open(args.secrets_file, encoding="utf-8") as handle:
            secrets = [line.rstrip("\n") for line in handle if line.strip()]
    result = validate(args.outdir, args.dataset, secrets, args.require_pdf, args.manifest)
    rm.emit(result, args.indent)
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
