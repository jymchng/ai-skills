#!/usr/bin/env python3
"""Stage 5 — validate candidates and produce the reportable findings dataset.

This is the stage that separates a scanner from an audit. Every candidate is
either promoted with evidence, downgraded with a reason, or suppressed with a
recorded justification (references/validation-methodology.md).

The six steps, and what is machine-checkable
--------------------------------------------
===================  ==========================================================
1. Locate            re-read ``location.file`` from the audited snapshot; a line
                     past the end of the file is reported as uncapturable, never
                     quoted from a neighbouring line.
2. Read context      extract the enclosing function/route block (bounded), not
                     just the reported line.
3. Identify input    find request-derived sources in that block
                     (``request.args``, ``req.body``, ``$_GET``, ...).
4. Trace to sink     check whether an identifier assigned from a source reaches
                     the reported sink line — real, if simple, dataflow.
5. Search controls   test the category's sanitiser/compensating-control
                     catalogue against the block, and classify each hit as
                     effective, partial or bypassable.
6. Judge              assign confidence from 3+4+5, apply the category ceiling,
                     and record the whole transcript in ``validation``.
===================  ==========================================================

Scoring
-------
Confidence and severity are independent, but they are not unrelated: a
pattern-only hit has not established impact, so it must not claim a Critical
impact metric. When confidence is LOW the impact metrics are reduced to ``L``
before scoring, which caps the band at Medium — and if even that is not enough
the finding is recorded as ``scoring: "unscored"``. Nothing is ever scored by
guessing a number: every score comes from :mod:`cvss4`, the vendored FIRST
reference algorithm, and carries its vector string.

Secrets
-------
Every text field the report will render (``evidence``, ``impact``,
``attack_scenario``, ``recommended_fix``, ``title``, ``description``,
``validation``) is redacted **before** the dataset is written: first by
exact-value replacement using ``--secrets-file``, then by credential-shape
pattern. After redaction the dataset is checked with
:func:`finding_model.find_leaks`; if a raw secret survives, nothing is written
and the run fails.

CLI
---
    python3 scripts/validate_findings.py deduped.json --root . --out findings.json
    python3 scripts/validate_findings.py deduped.json --root ../target --secrets-file secrets.txt
    python3 scripts/validate_findings.py deduped.json --root . --no-score --path-policy suppress
    python3 scripts/validate_findings.py deduped.json --root . --transcript validation.json
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from typing import Any, Dict, List, Optional, Sequence, Tuple

_SCRIPTS = os.path.dirname(os.path.abspath(__file__))
if _SCRIPTS not in sys.path:
    sys.path.insert(0, _SCRIPTS)

import cvss4  # noqa: E402
import builtin_analyzers as ba  # noqa: E402
import finding_model as fm  # noqa: E402

VERSION = "1.0"
TOOL_NAME = "validate_findings.py"

#: How many lines of context the transcript may quote (evidence stays readable).
MAX_EVIDENCE_LINES = 5
MAX_EVIDENCE_CHARS = 1200
#: Bounds on the enclosing-block search, so a huge file cannot slow the run down.
MAX_BLOCK_LINES = 120
MAX_FILE_BYTES = 4 * 1024 * 1024

#: Directories whose contents are not product code (false-positive-handling §2.4).
_TEST_PATH_RE = re.compile(
    r"(?:^|/)(?:tests?|__tests__|specs?|fixtures?|examples?|samples?|demo|"
    r"testdata|__mocks__|mocks?|vendor|vendored|node_modules|third_party|"
    r"generated|dist|build)(?:/|$)")
_GENERATED_SUFFIX_RE = re.compile(r"(?:\.min\.(?:js|css)|\.generated\.[a-z]+|_pb2\.py)$")

#: Category -> class-level starting vector (references/severity-scoring.md §5).
#: Documented starting points, extended to the whole taxonomy. The vector is a
#: *default*: the validation record states that it is a class default and must be
#: adjusted when the code proves different metrics. Every entry is scored at run
#: time by cvss4 — none of the numbers below is typed in by hand.
CATEGORY_VECTORS: Dict[str, Optional[str]] = {
    # Injection: authenticated reachability assumed; raise PR to N when the route
    # is public and record it in scoring_rationale.
    "sql_injection": "AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
    "nosql_injection": "AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
    "command_injection": "AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
    "code_injection": "AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
    "ssti": "AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
    "ldap_injection": "AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
    "xpath_injection": "AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
    "header_injection": "AV:N/AC:L/AT:N/PR:L/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",
    "xss_reflected": "AV:N/AC:L/AT:N/PR:N/UI:A/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",
    "xss_stored": "AV:N/AC:L/AT:N/PR:L/UI:P/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",
    "path_traversal": "AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
    "unrestricted_upload": "AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
    "zip_slip": "AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N",
    "ssrf": "AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:H/SI:N/SA:N",
    "open_redirect": "AV:N/AC:L/AT:N/PR:N/UI:A/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",
    "tls_verification_disabled": "AV:N/AC:H/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
    "missing_authentication": "AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
    "weak_password_hashing": "AV:N/AC:H/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
    "weak_jwt_validation": "AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N",
    "session_management": "AV:N/AC:H/AT:N/PR:N/UI:P/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
    "missing_authorization": "AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N",
    "missing_function_level_authorization":
        "AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N",
    "idor": "AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N",
    "csrf": "AV:N/AC:H/AT:N/PR:N/UI:P/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N",
    "business_logic": "AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N",
    "missing_rate_limiting": "AV:N/AC:H/AT:N/PR:L/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
    "race_condition": "AV:N/AC:H/AT:P/PR:L/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",
    "mass_assignment": "AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N",
    "weak_randomness": "AV:N/AC:H/AT:N/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",
    "hardcoded_secret": "AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N",
    "broken_crypto": "AV:N/AC:H/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
    "sensitive_data_exposure": "AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
    "insecure_deserialization": "AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
    "unsigned_update": "AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N",
    # Advisory maximum, not a reachability claim: the confidence ceiling for this
    # category is MEDIUM (validation-methodology.md §3).
    "vulnerable_dependency": "AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
    "unpinned_dependency": "AV:N/AC:H/AT:P/PR:L/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",
    "permissive_cors": "AV:N/AC:H/AT:N/PR:N/UI:P/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
    "missing_security_headers": "AV:N/AC:H/AT:N/PR:N/UI:A/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
    "debug_mode": None,
    "container_security": "AV:L/AC:H/AT:P/PR:L/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",
    "cicd_permissions": "AV:N/AC:L/AT:N/PR:L/UI:N/VC:L/VI:H/VA:N/SC:H/SI:H/SA:N",
    "iac_misconfiguration": "AV:N/AC:H/AT:P/PR:L/UI:N/VC:L/VI:H/VA:N/SC:N/SI:N/SA:N",
    "kubernetes_security": "AV:L/AC:H/AT:P/PR:L/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",
    "fail_open_error_handling": "AV:N/AC:H/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
    "unclassified": None,
}

#: Categories whose confidence may never exceed MEDIUM (validation-methodology §3).
CONFIDENCE_CAP: Dict[str, str] = {
    "business_logic": "MEDIUM",
    "vulnerable_dependency": "MEDIUM",
    "unclassified": "LOW",
}

#: Categories whose finding is a literal configuration, not a dataflow claim.
CONFIG_CATEGORIES = frozenset({
    "debug_mode", "permissive_cors", "missing_security_headers", "container_security",
    "cicd_permissions", "iac_misconfiguration", "kubernetes_security",
    "weak_password_hashing", "tls_verification_disabled", "weak_jwt_validation",
    "session_management", "hardcoded_secret", "unsigned_update",
})

_CONFIDENCE_STEPS: Tuple[str, ...] = ("CONFIRMED", "HIGH", "MEDIUM", "LOW")


# --------------------------------------------------------------------------- #
# Control catalogue (false-positive-handling.md §3)
# --------------------------------------------------------------------------- #

class Control:
    """One sanitiser/compensating control, with the strength it actually has."""

    __slots__ = ("regex", "strength", "label")

    def __init__(self, pattern: str, strength: str, label: str) -> None:
        self.regex = re.compile(pattern)
        self.strength = strength  # "effective" | "partial" | "bypassable"
        self.label = label


def _c(pattern: str, strength: str, label: str) -> Control:
    return Control(pattern, strength, label)


#: Checked in order per category: bypassable first (a blacklist must never be
#: mistaken for a control), then partial/fragile, then effective.
CONTROLS: Dict[str, Tuple[Control, ...]] = {
    "sql_injection": (
        _c(r"""replace\(\s*['"]\.[.]""", "bypassable", "dot-segment blacklist"),
        _c(r"\bre\.(?:sub|escape)\(", "bypassable", "regex escaping of SQL (not a parameterisation)"),
        _c(r"\bf?['\"]\s*%\s*\w+", "partial", "printf-style interpolation into SQL"),
        _c(r"\bexecute\w*\s*\([^,;]+,\s*(?:\(|\[|\w+\s*\))", "effective",
           "bound parameter tuple"),
        _c(r"\bquery\w*\s*\([^,;]+,\s*(?:\(|\[)", "effective", "bound parameter tuple"),
        _c(r"\?(?:\s*,\s*\?)+", "effective", "placeholder list"),
        _c(r"\$\d|\bbindParam|\bbindValue|\bsetParameter", "effective", "bound parameters"),
        _c(r"\.filter\(\s*\w+\s*=", "effective", "ORM predicate"),
        _c(r"\bALLOW_?LIST|\ballow_?list", "effective", "identifier allow-list"),
    ),
    "nosql_injection": (
        _c(r"\$where\b", "bypassable", "server-side JavaScript operator"),
        _c(r"(?:parseInt|parseFloat|Number|int|float|boolean)\(\s*\w+\s*\)", "effective",
           "type coercion to a primitive"),
        _c(r"isinstance\(\s*\w+\s*,\s*str\s*\)|typeof\s+\w+\s*===\s*['\"]string", "effective",
           "type guard"),
        _c(r"\.where\(\s*\w+\s*=", "effective", "operator-safe query builder"),
    ),
    "command_injection": (
        _c(r"shell\s*=\s*True|shell:true", "bypassable", "shell=True still present"),
        _c(r"\b(?:os\.system|exec|eval|system|popen)\s*\(", "bypassable",
           "direct shell invocation"),
        _c(r"shlex\.quote|escapeshellarg", "partial", "shell escaping (residual risk noted)"),
        _c(r"subprocess\.(?:run|call|Popen)\(\s*\[|execFile\(|\bspawn\(", "effective",
           "argv array without a shell"),
        _c(r"exec\.Command\(\s*['\"]|ProcessBuilder\(\s*\[", "effective", "argv array without a shell"),
    ),
    "code_injection": (
        _c(r"\beval\(|\bexec\(|Function\(\s*['\"]", "bypassable", "dynamic code evaluation sink"),
        _c(r"ast\.literal_eval|JSON\.parse|from_json", "effective", "data-only parser"),
    ),
    "ssti": (
        _c(r"\|\s*safe|\{\{!|<%-|raw\s*\(", "bypassable", "explicit autoescape opt-out"),
        _c(r"render_template_string|\bTemplate\(\s*\w+\)", "bypassable",
           "template built from a variable"),
        _c(r"autoescape\s*=\s*True|Markup\.escape|\bescape\(", "effective", "autoescaping enabled"),
    ),
    "xss_reflected": (
        _c(r"innerHTML\s*=|dangerouslySetInnerHTML|document\.write|v-html|\|safe|\{!!", "bypassable",
           "raw HTML sink"),
        _c(r"html\.escape|escapeHtml|htmlspecialchars|encodeURIComponent|DOMPurify\.sanitize|"
           r"bleach\.clean|\bescape\(", "effective", "context-appropriate escaping"),
        _c(r"textContent\s*=", "effective", "text-node assignment"),
    ),
    "xss_stored": (
        _c(r"innerHTML\s*=|dangerouslySetInnerHTML|document\.write|\|safe|\{!!", "bypassable",
           "raw HTML sink"),
        _c(r"html\.escape|escapeHtml|htmlspecialchars|DOMPurify\.sanitize|bleach\.clean",
           "effective", "context-appropriate escaping"),
    ),
    "path_traversal": (
        _c(r"""replace\(\s*['"]\.[.]|\.replace\(\s*['"]\.\./""", "bypassable",
           "dot-segment stripping blacklist"),
        _c(r"\.\.\s*(?:not in|in)\s+", "bypassable", "deny-list check of '..'"),
        _c(r"\bbasename\(|\bsecure_filename\(|\bGetFileName\(", "partial",
           "basename only (safe only with a fixed directory)"),
        _c(r"realpath|commonpath|is_relative_to|\bresolve\(\)|path\.resolve|filepath\.Clean|"
           r"GetFullPath|startsWith\(|\bstartswith\(", "effective", "resolve-then-contain"),
        _c(r"allow_?list|ALLOWED_", "effective", "allow-list of names"),
    ),
    "unrestricted_upload": (
        _c(r"mimetype|content-type|original_?name|originalname", "bypassable",
           "client-supplied MIME/name used as the control"),
        _c(r"secure_filename|ALLOWED_EXT|allowed_?(?:ext|types|mime)|filetype\.|magic\.", "effective",
           "extension/type allow-list with a safe name"),
    ),
    "zip_slip": (
        _c(r"\.extractall\(\s*\)", "bypassable", "unchecked extractall"),
        _c(r"is_relative_to|realpath|secure_filename|\.resolve\(\)|"
           r"startswith\(", "effective", "per-member containment check"),
    ),
    "ssrf": (
        _c(r"localhost|127\.0\.0\.1", "bypassable", "string match on a hostname"),
        _c(r"startswith\(\s*['\"]https?://", "bypassable", "URL prefix check"),
        _c(r"ipaddress\.|is_private|is_reserved|is_loopback", "partial",
           "IP classification after resolution"),
        _c(r"allow_?list|ALLOWED_HOSTS|allowed_hosts|validate_url", "effective",
           "scheme+host allow-list"),
    ),
    "open_redirect": (
        _c(r"""startswith\(\s*['"]/""", "partial", "relative-path check only"),
        _c(r"url_has_allowed_host_and_scheme|is_safe_url|allow_?list", "effective",
           "host allow-list"),
    ),
    "weak_password_hashing": (
        _c(r"\bmd5\b|\bsha1\b|hashlib\.sha(?:1|224|256)\b", "bypassable",
           "fast general-purpose hash used for a password"),
        _c(r"bcrypt|argon2|scrypt|pbkdf2|password_hash\(|make_password|password_verify", "effective",
           "memory-hard password KDF"),
    ),
    "weak_jwt_validation": (
        _c(r"verify\s*=\s*False|verify_signature['\"]?\s*[:=]\s*False|algorithms?\s*[:=]\s*\[?\s*['\"]none",
           "bypassable", "signature verification disabled"),
        _c(r"jwt\.verify\(|algorithms\s*=\s*\[|verify_signature.*True|jwt\.decode\(.*algorithms",
           "effective", "algorithm-constrained verification"),
    ),
    "insecure_deserialization": (
        _c(r"pickle\.loads|yaml\.load\(|Marshal\.load|ObjectInputStream|BinaryFormatter|"
           r"unserialize\(|eval\(", "bypassable", "arbitrary-object deserialisation"),
        _c(r"yaml\.safe_load|SafeLoader|JSON\.parse|allowed_classes\s*=>\s*false|"
           r"ObjectInputFilter|TypeNameHandling\.None", "effective", "safe loader / type allow-list"),
    ),
    "weak_randomness": (
        _c(r"\brandom\.(?:random|randint|choice|randrange|shuffle)|Math\.random|\brand\(\)|"
           r"\bmt_rand\b", "bypassable", "non-cryptographic PRNG"),
        _c(r"\bsecrets\.|randomBytes|randomUUID|SecureRandom|crypto/rand|os\.urandom|SystemRandom",
           "effective", "CSPRNG"),
    ),
    "idor": (
        _c(r"is_?admin|role\s*==\s*['\"]admin", "partial", "role check without ownership"),
        _c(r"current_user|currentUser|req\.user|request\.user|@AuthenticationPrincipal|\bprincipal\b",
           "partial", "authenticated principal available (ownership not yet proven)"),
        _c(r"user_id\s*=|user_id\s*:|owner_id|tenant_id|\.where\([^)]*(?:user|owner|tenant)",
           "effective", "ownership predicate in the query"),
    ),
    "missing_authorization": (
        _c(r"@PreAuthorize|@Secured|@RolesAllowed|\[Authorize|authorize\(|"
           r"can\?|policy\(|before_action\s+:authenticate|login_required|Depends\(\s*require",
           "effective", "authorisation guard on the route"),
    ),
    "missing_function_level_authorization": (
        _c(r"@PreAuthorize|@Secured|@RolesAllowed|\[Authorize|authorize\(", "effective",
           "method-level authorisation"),
    ),
    "missing_authentication": (
        _c(r"@login_required|login_required|authenticate|require_auth|Depends\(\s*get_current_user|"
           r"UseGuards|\[Authorize|passport\.authenticate|authMiddleware|requireAuth", "effective",
           "authentication middleware on the route"),
        _c(r"permitAll\(\)|open_?access|allow_?anonymous", "partial", "explicit public route"),
    ),
    "csrf": (
        _c(r"csrf_exempt|@csrf\.exempt|disableCsrf", "bypassable", "CSRF protection disabled"),
        _c(r"csrf_token|CsrfViewMiddleware|X-CSRF|antiforgery|@csrf_protect|csurf", "effective",
           "CSRF token validation"),
    ),
    "mass_assignment": (
        _c(r"\.fill\(|update\(.*params|Object\.assign\(.*req\.body", "bypassable",
           "unfiltered mass assignment"),
        _c(r"fillable|allowed_?fields|\.only\(\s*\[|\.pick\(|@JsonIgnore|StrongParameters|"
           r"params\.require\([^)]*\)\.permit\(", "effective", "explicit field allow-list"),
    ),
    "permissive_cors": (
        _c(r"origin\s*:\s*true|allow_origin_regex\s*=\s*['\"]\.\*|Access-Control-Allow-Origin['\"]?\s*,?\s*"
           r"['\"]\*['\"]", "bypassable", "reflecting or wildcard origin used as the control"),
        _c(r"allowed_?origins\s*=\s*\[|origin\s*:\s*\[|allow_?list", "effective", "origin allow-list"),
    ),
    "debug_mode": (
        _c(r"DEBUG\s*=\s*os\.environ|debug\s*=\s*process\.env|is_production|NODE_ENV", "effective",
           "environment-driven debug flag"),
        _c(r"DEBUG\s*=\s*True|debug\s*=\s*True|debug:\s*true", "bypassable", "debug enabled literally"),
    ),
    "hardcoded_secret": (
        _c(r"changeme|change_me|your[_-]?\w*|example|placeholder|dummy|xxx+|REDACTED|<[A-Z_]+>",
           "partial", "placeholder-shaped value"),
        _c(r"os\.environ|process\.env|getenv|System\.getenv|\$\{|\{\{|vault|secretManager|"
           r"secretsmanager", "effective", "value loaded from the environment or a secret store"),
    ),
    "container_security": (
        _c(r"^\s*USER\s+(?!root)\S+", "effective", "non-root USER directive"),
        _c(r"read_only\s*:\s*true|readOnlyRootFilesystem:\s*true", "effective",
           "read-only root filesystem"),
    ),
    "cicd_permissions": (
        _c(r"permissions\s*:\s*write-all|permissions:\s*write-all", "bypassable",
           "write-all token permissions"),
        _c(r"permissions\s*:\s*\n?\s*(?:contents|actions|pull-requests)\s*:\s*(?:read|none)",
           "effective", "narrowed token permissions"),
        _c(r"uses:\s*\S+@[0-9a-f]{40}\b", "effective", "action pinned to a commit SHA"),
    ),
    "fail_open_error_handling": (
        _c(r"except[^\n]*:\s*\n?\s*pass|catch\s*\([^)]*\)\s*\{\s*\}|returns?\s+True", "bypassable",
           "error swallowed, request allowed"),
        _c(r"raise\b|throw\b|return\s+false|abort\(|deny\(", "effective", "fail-closed handling"),
    ),
}


# --------------------------------------------------------------------------- #
# Snapshot access
# --------------------------------------------------------------------------- #

def _within_root(root: str, rel: str) -> Optional[str]:
    """Resolve ``rel`` inside ``root``; ``None`` if it escapes or is missing."""
    if not rel or os.path.isabs(rel):
        return None
    candidate = os.path.normpath(os.path.join(root, rel))
    if os.path.commonpath([os.path.abspath(root), os.path.abspath(candidate)]) != os.path.abspath(root):
        return None
    return candidate


def read_snapshot_lines(root: str, rel: str) -> Tuple[List[str], Optional[str]]:
    """Read a snapshot file's lines. Returns (lines, problem)."""
    path = _within_root(root, rel)
    if path is None:
        return [], "path is outside the audited root or absolute"
    if not os.path.isfile(path):
        return [], "file not present in the audited snapshot"
    try:
        size = os.path.getsize(path)
        if size > MAX_FILE_BYTES:
            return [], "file exceeds the %d-byte read limit" % MAX_FILE_BYTES
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            return handle.read().splitlines(), None
    except OSError as exc:
        return [], "unreadable: %s" % exc.strerror


def capture_evidence(lines: Sequence[str], location: Dict[str, Any],
                     secrets: Sequence[str] = (),
                     counter: Optional[List[int]] = None
                     ) -> Tuple[str, Optional[str]]:
    """Quote the reported lines from the snapshot. Returns (evidence, problem).

    The scanner's own message is never used as evidence. If the reported line
    does not exist in this snapshot, the function says so instead of quoting a
    neighbouring line as though it were the finding.

    When *counter* is given, the number of redactions applied to the quoted
    window is appended to it. The window is re-read from the audited file, so
    this is the only place that knows how many credentials the re-quote had to
    remove; without it the run reported "0 redactions applied" while every
    secret-bearing evidence block had in fact been redacted.
    """
    try:
        start = int(location.get("line_start") or 0)
        end = int(location.get("line_end") or start)
    except (TypeError, ValueError):
        return "", "location has no usable line numbers"
    if start < 1:
        return "", "location has no line number"
    if not lines:
        return "", "no readable content to quote"
    if start > len(lines):
        return "", ("line %d is past the end of the file (%d lines) — stale or moved finding"
                    % (start, len(lines)))
    end = max(start, min(end, len(lines)))
    first = max(1, start - 1)
    last = min(len(lines), end + 1)
    quoted: List[str] = []
    for number in range(first, last + 1):
        text = lines[number - 1]
        if len(text) > 400:
            text = text[:400] + " …"
        quoted.append("%5d | %s" % (number, text))
        if len(quoted) >= MAX_EVIDENCE_LINES:
            break
    evidence = "\n".join(quoted)[:MAX_EVIDENCE_CHARS]
    redacted, count = redact_text(evidence, secrets)
    if counter is not None:
        counter.append(count)
    return redacted, None


#: Start of an enclosing function/route, per language family.
_BLOCK_START_RE = re.compile(
    r"(?m)^\s*(?:async\s+)?(?:def|class|function|func|fn|pub\s+fn|sub|public|private|protected|"
    r"internal|static|@\w+|router\.|app\.(?:get|post|put|patch|delete)|@(?:Get|Post|Put|Patch|"
    r"Delete)Mapping)\b")


def enclosing_block(lines: Sequence[str], line_start: int) -> Tuple[int, int]:
    """Line range of the enclosing function/route block, bounded for sanity."""
    index = max(0, min(line_start - 1, len(lines) - 1)) if lines else 0
    start = max(0, index - MAX_BLOCK_LINES)
    for probe in range(index, start - 1, -1):
        if _BLOCK_START_RE.match(lines[probe] or ""):
            start = probe
            break
    end = index
    for probe in range(index + 1, min(len(lines), index + MAX_BLOCK_LINES)):
        # Stop at the next top-level definition: it belongs to another function.
        if _BLOCK_START_RE.match(lines[probe] or "") and (len(lines[probe]) - len(lines[probe].lstrip())) <= 2:
            break
        end = probe
    return start + 1, end + 1


# --------------------------------------------------------------------------- #
# Steps 3-5: sources, sinks, controls
# --------------------------------------------------------------------------- #

def _load_analyzer_vocabulary() -> Tuple[Any, Any, Dict[str, Tuple[str, ...]]]:
    """Reuse the analyzers' source tokens and guard catalogue when available.

    Sharing the vocabulary is deliberate: if stage 3 called something a guard, it
    must not be called a vulnerability by stage 5, and vice versa.
    """
    try:
        import builtin_analyzers as ba  # noqa: WPS433 - optional by design
        return ba.SOURCE_RE, ba.TAINT_ASSIGN_RE, dict(ba.GUARDS)
    except Exception:  # pragma: no cover - standalone use
        return (re.compile(r"request\.(?:args|form|json)|req\.(?:body|query|params)|"
                           r"\$_GET|\$_POST|getParameter\("),
                re.compile(r"([A-Za-z_$][\w$]*)\s*=\s*[^;\n]*request\."),
                {})


_SOURCE_RE, _TAINT_ASSIGN_RE, _ANALYZER_GUARDS = _load_analyzer_vocabulary()

_IDENT_RE = re.compile(r"[A-Za-z_$][\w$]*")


def detect_controls(category: str, block_text: str) -> List[Dict[str, str]]:
    """Every control found in the block, strongest claim first.

    Categories without a specific catalogue fall back to the stage-3 guards, which
    are known-good suppressors for that category.
    """
    hits: List[Dict[str, str]] = []
    for control in CONTROLS.get(category, ()):
        match = control.regex.search(block_text)
        if match:
            hits.append({"strength": control.strength, "control": control.label,
                         "matched": match.group(0).strip()[:120]})
    if not hits:
        for guard in _ANALYZER_GUARDS.get(category, ()):
            try:
                match = re.search(guard, block_text)
            except re.error:  # pragma: no cover - guards are valid regexes
                continue
            if match:
                hits.append({"strength": "effective", "control": "stage-3 guard: %s" % guard,
                             "matched": match.group(0).strip()[:120]})
                break
    order = {"bypassable": 0, "partial": 1, "effective": 2}
    return sorted(hits, key=lambda h: order.get(h["strength"], 3))


def trace_dataflow(category: str, block_lines: Sequence[str], line_offset: int,
                   sink_line: str) -> Tuple[str, List[str]]:
    """Classify attacker influence: same-function, plausible, configuration, none."""
    notes: List[str] = []
    block_text = "\n".join(block_lines)
    sink_names = set(_IDENT_RE.findall(sink_line))

    if category in CONFIG_CATEGORIES:
        notes.append("category is a configuration/literal claim; dataflow is not required")
        return "configuration", notes

    tainted = {match.group(1) for match in _TAINT_ASSIGN_RE.finditer(block_text)}
    if tainted & sink_names:
        names = sorted(tainted & sink_names)
        notes.append("request-derived value reaches the sink in the same function (%s)"
                     % ", ".join(names[:3]))
        return "same-function", notes
    if _SOURCE_RE.search(block_text):
        names = sorted(tainted)
        notes.append("request-derived source present in the enclosing block (%s) but the sink "
                     "line uses %s" % (", ".join(names[:3]) or "an unnamed value",
                                       ", ".join(sorted(sink_names)[:3]) or "no variable"))
        return "plausible", notes
    notes.append("no request-derived source in the enclosing block: pattern-only")
    return "pattern-only", notes


# --------------------------------------------------------------------------- #
# Step 6: confidence, scoring, priority
# --------------------------------------------------------------------------- #

def _step_down(confidence: str, steps: int = 1) -> str:
    try:
        index = _CONFIDENCE_STEPS.index(confidence)
    except ValueError:
        return "LOW"
    return _CONFIDENCE_STEPS[min(len(_CONFIDENCE_STEPS) - 1, index + steps)]


def _step_up(confidence: str, steps: int = 1) -> str:
    try:
        index = _CONFIDENCE_STEPS.index(confidence)
    except ValueError:
        return "LOW"
    return _CONFIDENCE_STEPS[max(0, index - steps)]


def assign_confidence(category: str, dataflow: str, controls: Sequence[Dict[str, str]],
                      tools: Sequence[str], evidence_problem: Optional[str]
                      ) -> Tuple[str, List[str]]:
    """The ladder from validation-methodology.md §3, with every step recorded."""
    notes: List[str] = []
    strongest = controls[0]["strength"] if controls else None

    if evidence_problem:
        notes.append("evidence could not be captured (%s): confidence LOW, needs review"
                     % evidence_problem)
        return _cap_confidence("LOW", category, notes), notes

    if dataflow == "same-function":
        confidence = "CONFIRMED"
        notes.append("sink visible and tainted value reaches it in the same function")
    elif dataflow == "configuration":
        confidence = "CONFIRMED"
        notes.append("insecure configuration is literally present")
    elif dataflow == "plausible":
        confidence = "HIGH"
        notes.append("sink plus plausible attacker influence; provenance crosses a boundary")
    else:
        confidence = "LOW"
        notes.append("pattern-only: no established attacker input")

    if strongest == "partial":
        confidence = _step_down(confidence)
        notes.append("partial/fragile control found (%s): confidence lowered one step"
                     % controls[0]["control"])
    elif strongest == "bypassable":
        notes.append("control present but bypassable (%s): confidence unchanged, bypass recorded"
                     % controls[0]["control"])

    if len(set(tools)) >= 2:
        raised = _step_up(confidence)
        if raised != confidence:
            notes.append("corroborated by %d independent engines (%s): raised one step"
                         % (len(set(tools)), ", ".join(sorted(set(tools)))))
        confidence = raised

    return _cap_confidence(confidence, category, notes), notes


def _cap_confidence(confidence: str, category: str, notes: List[str]) -> str:
    cap = CONFIDENCE_CAP.get(category)
    if cap:
        index_cap = _CONFIDENCE_STEPS.index(cap)
        index = _CONFIDENCE_STEPS.index(confidence)
        if index < index_cap:
            notes.append("category ceiling: %s confidence capped at %s" % (category, cap))
            return cap
    return confidence


def _impact_metrics(vector: str) -> Dict[str, str]:
    return {part.split(":")[0]: part.split(":")[1]
            for part in vector.split("/") if ":" in part}


def conservative_vector(vector: str) -> Tuple[str, bool]:
    """Reduce impact metrics to ``L`` for an unproven finding.

    A pattern-only hit has not established impact, so the vector may not claim
    ``VC:H``. Returns (vector, changed).
    """
    metrics = _impact_metrics(vector)
    changed = False
    for metric in ("VC", "VI", "VA", "SC", "SI", "SA"):
        if metrics.get(metric) == "H":
            metrics[metric] = "L"
            changed = True
    return "CVSS:4.0/" + "/".join("%s:%s" % (k, metrics[k]) for k in cvss4.BASE_ORDER), changed


def score_finding(finding: Dict[str, Any], category: str, confidence: str,
                  no_score: bool) -> Tuple[Optional[float], Optional[str], str, List[str]]:
    """Return (score, vector, marker, rationale). Never invents a number."""
    rationale: List[str] = []
    if no_score:
        rationale.append("--no-score: the operator declined to justify a vector for this run")
        return None, None, "unscored", rationale

    candidate = finding.get("cvss_vector")
    if candidate:
        problems = cvss4.validate_vector(str(candidate))
        if problems:
            rationale.append("stored vector rejected (%s); fell back to the class vector"
                             % problems[0])
            candidate = None
        else:
            rationale.append("scored from the vector stored by the contributing engine")
    if not candidate:
        tail = CATEGORY_VECTORS.get(category)
        if not tail:
            rationale.append("category %r has no defensible default vector: unscored" % category)
            return None, None, "unscored", rationale
        candidate = "CVSS:4.0/" + tail
        rationale.append("class-level starting vector for %s; verify the metrics against this code"
                         % category)

    if confidence == "LOW":
        candidate, changed = conservative_vector(candidate)
        if changed:
            rationale.append("confidence LOW: impact metrics reduced to L so an unproven impact "
                             "is not claimed as Critical/High")
    try:
        result = cvss4.score_vector(candidate)
    except cvss4.VectorError as exc:
        rationale.append("vector could not be scored (%s): unscored" % exc)
        return None, None, "unscored", rationale
    if confidence == "LOW" and result["severity"] in ("Critical", "High"):
        rationale.append("reduced vector still implies %s for a pattern-only finding: recorded "
                         "as unscored" % result["severity"])
        return None, None, "unscored", rationale
    return result["score"], result["vector"], "scored", rationale


def priority_for(severity: str, confidence: str, in_test_path: bool,
                 factors: List[str]) -> str:
    """Default priority table (severity-scoring.md §6), with factors recorded."""
    if in_test_path:
        factors.append("location is test/fixture/example code: not product risk")
        return "P3"
    if severity == "Critical":
        priority = "P0" if confidence in ("CONFIRMED", "HIGH") else "P1"
    elif severity == "High":
        priority = "P1"
    elif severity == "Medium":
        priority = "P2" if confidence in ("CONFIRMED", "HIGH") else "P3"
    else:
        priority = "P3"
    factors.append("severity: %s" % severity)
    factors.append("confidence: %s" % confidence)
    return priority


# --------------------------------------------------------------------------- #
# Redaction
# --------------------------------------------------------------------------- #

#: A value that is already a marker or an unfilled template hole rather than a
#: literal secret. The predicate itself lives in :mod:`finding_model`, because the
#: analyzer, the orchestrator and this stage all redact text and must agree on
#: what "already safe" means; a fourth copy of the rule is how they drift apart.
_is_placeholder = fm.is_placeholder


def _labelled_assignment_replacement(match: Any) -> str:
    """``password=<redacted>`` keeps its name, loses only a literal value."""
    if _is_placeholder(match.group(2)):
        return match.group(0)
    return "%s=[REDACTED]" % match.group(1)


_PATTERN_REDACTIONS: Tuple[Tuple[Any, Any], ...] = (
    # Shapes the analyzer's own table does not carry. Everything it does carry is
    # swept from ``_ANALYZER_REDACTIONS`` below, so one shape has one spelling: a
    # hand-written copy of the analyzer's patterns is how ``[REDACTED STRIPE
    # SECRET KEY]`` and ``[REDACTED STRIPE KEY]`` ended up in the same report.
    (re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"), "[REDACTED GITHUB TOKEN]"),
    (re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"), "[REDACTED API KEY]"),
    (re.compile(r"\b(aws_secret_access_key)\s*[=:]\s*\S+", re.I), r"\1=[REDACTED]"),
    (re.compile(r"(?i)\b(password|passwd|pwd|token|api[_-]?key)\b\s*[=:]\s*(?!['\"])([^\s'\"]{6,})"),
     _labelled_assignment_replacement),
)

_REDACTABLE_FIELDS: Tuple[str, ...] = (
    "title", "evidence", "description", "impact", "attack_scenario",
    "recommended_fix", "validation",
)

#: Every credential shape the built-in analyzer can *detect* must also be
#: redactable here, because :func:`capture_evidence` re-quotes the audited file and
#: redacts the fresh copy: a shape missing from the table above restores a value
#: the analyzer had already replaced. A Stripe key survived into reports that way
#: until this sweep existed. Compiling the analyzer's own table keeps the two in
#: step without a second hand-maintained list; the labelled entries above still
#: win where they name a more specific marker.
_ANALYZER_REDACTIONS: Tuple[Tuple[Any, str], ...] = tuple(
    (re.compile(pattern), marker)
    for _secret_id, pattern, _label, marker in ba.SECRET_PATTERNS
)


def _substitute_counting(pattern: Any, replacement: Any, text: str) -> Tuple[str, int]:
    """``pattern.sub`` that counts only the matches it actually rewrote.

    A guard that matches but deliberately leaves the text alone (a documented
    placeholder) is not a redaction and must not inflate the count.
    """
    hits = 0

    def substitute(match: Any) -> str:
        nonlocal hits
        new = replacement(match) if callable(replacement) else match.expand(replacement)
        if new != match.group(0):
            hits += 1
        return new

    return pattern.sub(substitute, text), hits


def _analyzer_shape_replacement(match: Any, marker: str) -> str:
    """Replace the captured secret and keep the words around it.

    The replacement is :func:`finding_model.redact_shape_match`, shared with the
    analyzer and the orchestrator, so a shape has one marker spelling no matter
    which stage quotes the text. A placeholder is left alone: it is not a secret,
    and rewriting it would erase the guidance that put it there.
    """
    return fm.redact_shape_match(match, marker)


def redact_text(text: Any, secrets: Sequence[str] = ()) -> Tuple[Any, int]:
    """Redact credential shapes first, then any exact value still present.

    Shape sweep first on purpose: a shaped credential gets the shape marker the
    analyzer wrote, instead of being re-spelled by the length marker this stage
    uses for values it knows but cannot classify.
    """
    if not isinstance(text, str) or not text:
        return text, 0
    count = 0
    for pattern, replacement in _PATTERN_REDACTIONS:
        text, hits = _substitute_counting(pattern, replacement, text)
        count += hits
    for pattern, marker in _ANALYZER_REDACTIONS:
        text, hits = _substitute_counting(
            pattern, lambda match, _marker=marker: _analyzer_shape_replacement(match, _marker), text)
        count += hits
    text, exact = fm.redact_text(text, secrets)
    return text, count + exact


def redact_finding(finding: Dict[str, Any], secrets: Sequence[str]) -> int:
    """Redact every field the report will render. Returns replacements made."""
    total = 0
    for field in _REDACTABLE_FIELDS:
        if isinstance(finding.get(field), str):
            finding[field], count = redact_text(finding[field], secrets)
            total += count
    for field in ("merge_notes", "priority_factors"):
        if isinstance(finding.get(field), list):
            redacted: List[Any] = []
            for item in finding[field]:
                new, count = redact_text(item, secrets)
                total += count
                redacted.append(new)
            finding[field] = redacted
    return total


#: Unambiguous credential shapes: a match is a credential, never prose. The
#: relaxed ``password=…`` assignment and the analyzer's document patterns are
#: deliberately absent — a finding may legitimately quote a password rule, and a
#: guard that cries wolf is a guard that gets switched off.
#:
#: This table exists because :func:`finding_model.find_leaks` can only search for
#: values it was handed. Without ``--secrets-file`` it has nothing to look for,
#: so a value the redaction table failed to cover passed the guard untouched: a
#: Stripe key reached findings.json and every report that way while the AWS key
#: beside it was replaced.
_LEAK_GUARD_SHAPES: Tuple[Tuple[str, Any], ...] = (
    ("AWS access key id", re.compile(r"\b(?P<secret>AKIA[0-9A-Z]{16})\b")),
    ("GitHub token", re.compile(r"\b(?P<secret>(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{16,})\b")),
    ("GitHub fine-grained token",
     re.compile(r"\b(?P<secret>github_pat_[A-Za-z0-9_]{20,})\b")),
    ("Slack token", re.compile(r"\b(?P<secret>xox[baprs]-[A-Za-z0-9-]{10,})\b")),
    ("API key", re.compile(r"\b(?P<secret>sk-[A-Za-z0-9]{20,})\b")),
    ("Stripe key", re.compile(r"\b(?P<secret>(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,})\b")),
    ("Google API key", re.compile(r"\b(?P<secret>AIza[0-9A-Za-z_\-]{30,})\b")),
    ("JWT", re.compile(r"\b(?P<secret>eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"
                       r"\.[A-Za-z0-9_\-]{10,})\b")),
    ("private key", re.compile(r"(?P<secret>-----BEGIN [A-Z ]*PRIVATE KEY-----)")),
    # The password sits inside the authority section, which looks like any URL.
    ("password in a connection string",
     re.compile(r"(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp|mssql)://"
                r"[^\s:/@]+:(?P<secret>[^\s@/]{1,120})@")),
)

#: Documented AWS example keys. They are in AWS's own documentation, every real
#: scanner allow-lists them, and treating them as a leak would make the guard
#: unusable on a finding that quotes the AWS docs. Assembled from parts so the
#: tracked blob holds no matchable key: GitHub push protection (GH013) rejects a
#: push whose diff contains a provider-shaped credential, even a documented one.
_EXAMPLE_KEYS = frozenset({"AKIA" + "IOSFODNN7EXAMPLE", "AKIA" + "I44QH8DHBEXAMPLE"})


def find_shape_leaks(dataset: Dict[str, Any]) -> List[str]:
    """Credential shapes still present in the dataset about to be written.

    Unlike :func:`finding_model.find_leaks`, this needs no known-value list: it
    looks for the shapes themselves, in every serialised field of every finding
    plus the dataset-level blocks, so a value the redaction table missed is caught
    before anything reaches disk.
    """
    haystacks: List[Tuple[str, str]] = []
    for key in ("audit", "coverage", "generated_by"):
        if key in dataset:
            haystacks.append((key, json.dumps(dataset[key], ensure_ascii=False)))
    for index, record in enumerate(dataset.get("findings") or []):
        if isinstance(record, dict):
            label = "findings[%d] %s" % (index, record.get("id") or "")
            haystacks.append((label.strip(), json.dumps(record, ensure_ascii=False)))

    leaks: List[str] = []
    for where, blob in haystacks:
        for name, pattern in _LEAK_GUARD_SHAPES:
            for match in pattern.finditer(blob):
                value = match.groupdict().get("secret") or match.group(0)
                if value in _EXAMPLE_KEYS or _is_placeholder(value):
                    continue
                leaks.append("%s: %s not redacted" % (where, name))
                break
    return leaks


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #

def path_policy_for(file: str) -> Optional[str]:
    """Classify a path as test/fixture/example or generated code, else ``None``."""
    if not file:
        return None
    if _TEST_PATH_RE.search("/" + file.replace("\\", "/")):
        return "test/fixture/example code"
    if _GENERATED_SUFFIX_RE.search(file):
        return "generated code"
    return None


def validate_dataset(root: str, dataset: Dict[str, Any], *, secrets: Sequence[str] = (),
                     no_score: bool = False, path_policy: str = "separate",
                     max_findings: Optional[int] = None) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Validate, score and redact every finding. Returns (dataset, transcript)."""
    root = os.path.abspath(root)
    findings = [f for f in (dataset.get("findings") or []) if isinstance(f, dict)]
    if max_findings is not None:
        findings = findings[:max_findings]

    cache: Dict[str, Tuple[List[str], Optional[str]]] = {}
    transcript: List[Dict[str, Any]] = []
    suppressions: List[Dict[str, Any]] = []
    redactions = 0

    for finding in findings:
        location = dict(finding.get("location") or {})
        rel = str(location.get("file") or "")
        category = str(finding.get("category") or "unclassified")
        if rel not in cache:
            cache[rel] = read_snapshot_lines(root, rel)
        lines, file_problem = cache[rel]

        steps: List[str] = []
        # Step 1-2: locate and read context.
        evidence_counter: List[int] = []
        evidence, evidence_problem = capture_evidence(lines, location, secrets,
                                                      evidence_counter)
        if evidence_problem and file_problem and "no readable content" in evidence_problem:
            # The file-level reason is more specific and more useful to a reader
            # than the fact that an empty list produced no excerpt.
            evidence_problem = file_problem
        if evidence_problem is None:
            start, end = int(location.get("line_start") or 1), int(location.get("line_end")
                                                                    or location.get("line_start") or 1)
            block_start, block_end = enclosing_block(lines, start)
            block_lines = lines[block_start - 1:block_end]
            steps.append("located %s:%d-%d and re-read %d line(s) of evidence from the snapshot"
                         % (rel, start, end, len(evidence.splitlines())))
            steps.append("read the enclosing block, lines %d-%d" % (block_start, block_end))
        else:
            block_lines = []
            steps.append("could not locate the finding in the snapshot: %s" % evidence_problem)
            if file_problem and file_problem != evidence_problem:
                steps.append("file access: %s" % file_problem)

        # Step 3-4: attacker input and sink.
        sink_line = ""
        if lines:
            index = int(location.get("line_start") or 1) - 1
            if 0 <= index < len(lines):
                sink_line = lines[index]
        dataflow, trace_notes = trace_dataflow(category, block_lines, len(block_lines),
                                               sink_line)
        steps.extend(trace_notes)

        # Step 5: compensating controls.
        controls = detect_controls(category, "\n".join(block_lines))
        for control in controls:
            steps.append("control search found a %s signal: %s — matched %r"
                         % (control["strength"], control["control"], control["matched"]))
        if not controls:
            steps.append("searched the control catalogue for %s: nothing found on the path"
                         % category)

        tools = sorted({str(s.get("tool")) for s in (finding.get("sources") or [])
                        if isinstance(s, dict) and s.get("tool")})

        # Step 6: confidence, then the compensating-control outcome.
        confidence, confidence_notes = assign_confidence(
            category, dataflow, controls, tools, evidence_problem)
        steps.extend(confidence_notes)
        status = "validated" if confidence in ("CONFIRMED", "HIGH") else "needs_review"

        effective = [c for c in controls if c["strength"] == "effective"]
        if effective and evidence_problem is None:
            status = "suppressed"
            reason = "compensating control present on the path: %s (matched %r)" % (
                effective[0]["control"], effective[0]["matched"])
            finding["suppression_reason"] = reason
            suppressions.append({"file": rel, "line": location.get("line_start"),
                                 "category": category, "reason": reason,
                                 "rule": "compensating-control"})
            steps.append("suppressed: %s" % reason)

        path_class = path_policy_for(rel)
        in_test_path = False
        if path_class:
            in_test_path = True
            if path_policy == "suppress" and status != "suppressed":
                status = "suppressed"
                reason = "path-based suppression: %s" % path_class
                finding["suppression_reason"] = reason
                suppressions.append({"file": rel, "line": location.get("line_start"),
                                     "category": category, "reason": reason,
                                     "rule": "path-based-suppression"})
                steps.append("suppressed: %s" % reason)
            elif status != "suppressed":
                steps.append("location is %s: reported separately, never as product risk"
                             % path_class)

        # Scoring and severity.
        score, vector, marker, rationale = score_finding(finding, category, confidence, no_score)
        steps.extend(rationale)
        finding["cvss_score"] = score
        finding["cvss_vector"] = vector
        finding["scoring"] = marker
        if marker == "scored" and score is not None:
            finding["severity"] = cvss4.severity_band(score)
        elif marker == "unscored":
            finding["severity"] = "Informational"
        # Severity always follows the score, including for a suppressed finding:
        # the record must stay internally consistent so a reviewer can see both
        # "we judged this a High" and "a control mitigates it". Suppression is
        # carried by validation_status, and reports exclude it on that basis.
        severity = str(finding.get("severity") or "Informational")

        finding["confidence"] = confidence
        finding["validation_status"] = status
        finding["evidence"] = evidence or redact_text(
            "(evidence unavailable: %s)" % (evidence_problem or "unreadable"))[0]
        finding["in_test_path"] = in_test_path
        finding.setdefault("language", "unknown")

        factors: List[str] = [f for f in (finding.get("priority_factors") or []) if isinstance(f, str)][-2:]
        finding["priority"] = priority_for(severity, confidence, in_test_path, factors)
        finding["priority_factors"] = factors

        steps.append("severity %s from %s" % (finding.get("severity"),
                                              "CVSS %s" % score if score is not None else "unscored"))
        finding["validation"] = "; ".join(steps) + "."
        redactions += sum(evidence_counter)
        redactions += redact_finding(finding, secrets)

        transcript.append({
            "file": rel, "line": location.get("line_start"), "category": category,
            "title": finding.get("title"), "dataflow": dataflow,
            "controls": controls, "confidence": confidence, "status": status,
            "severity": finding.get("severity"), "scoring": marker,
            "score": score, "vector": vector, "steps": steps,
            "sources": tools,
        })

    # Dataset-level bookkeeping.
    dataset["findings"] = findings
    dataset.setdefault("schema_version", fm.SCHEMA_VERSION)
    dataset["stage"] = "validation"
    dataset["generated_by"] = {"name": TOOL_NAME, "version": VERSION,
                               "python": "%d.%d" % sys.version_info[:2]}
    dataset["validation_policy"] = {
        "path_policy": path_policy,
        "scoring": "disabled by --no-score" if no_score else "CVSS 4.0 via the vendored FIRST reference",
        "evidence": "re-read from the audited snapshot at validation time",
    }
    dataset["suppressions"] = suppressions
    fm.assign_ids(dataset)
    dataset["summary"] = _summarise(findings)
    return dataset, {"findings": transcript,
                     "redactions_applied": redactions,
                     "suppressions": len(suppressions)}


def _summarise(findings: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    by_severity: Dict[str, int] = {}
    by_confidence: Dict[str, int] = {}
    by_status: Dict[str, int] = {}
    by_category: Dict[str, int] = {}
    by_severity_reportable: Dict[str, int] = {}
    scored = unscored = 0
    for finding in findings:
        for bucket, value in ((by_severity, finding.get("severity")),
                              (by_confidence, finding.get("confidence")),
                              (by_status, finding.get("validation_status")),
                              (by_category, finding.get("category"))):
            key = str(value)
            bucket[key] = bucket.get(key, 0) + 1
        if finding.get("validation_status") != "suppressed":
            key = str(finding.get("severity"))
            by_severity_reportable[key] = by_severity_reportable.get(key, 0) + 1
        if finding.get("scoring") == "scored":
            scored += 1
        else:
            unscored += 1
    return {
        "findings": len(findings),
        "reportable": sum(1 for f in findings if f.get("validation_status") != "suppressed"),
        "suppressed": by_status.get("suppressed", 0),
        "scored": scored,
        "unscored": unscored,
        "by_severity": dict(sorted(by_severity.items())),
        "by_severity_reportable": dict(sorted(by_severity_reportable.items())),
        "by_confidence": dict(sorted(by_confidence.items())),
        "by_validation_status": dict(sorted(by_status.items())),
        "by_category": dict(sorted(by_category.items())),
    }


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Validate deduplicated findings: evidence re-read from the snapshot, "
                    "compensating-control search, confidence ladder, CVSS 4.0 scoring, "
                    "redaction before writing.",
        epilog="Runs after deduplicate_findings.py. The output is the single dataset "
               "every report format is generated from.",
    )
    parser.add_argument("dataset", help="output of deduplicate_findings.py")
    parser.add_argument("--root", default=".", help="root of the audited snapshot (default: .)")
    parser.add_argument("--out", default="findings.json", help="reportable dataset to write")
    parser.add_argument("--secrets-file",
                        help="file with one raw secret per line; values are replaced before "
                             "anything is written")
    parser.add_argument("--transcript", help="write the per-finding validation transcript here")
    parser.add_argument("--no-score", action="store_true",
                        help="record every finding as explicitly unscored instead of scoring it")
    parser.add_argument("--path-policy", choices=("separate", "suppress", "report"),
                        default="separate",
                        help="what to do with test/fixture/generated code (default: separate)")
    parser.add_argument("--max-findings", type=int, default=None,
                        help="validate at most N findings (for a quick sample run)")
    parser.add_argument("--fail-on-leak", action="store_true", default=True,
                        help="refuse to write if a raw secret survives redaction (default: on)")
    parser.add_argument("--no-fail-on-leak", dest="fail_on_leak", action="store_false")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    dataset = fm.load_findings(args.dataset)
    secrets: List[str] = []
    if args.secrets_file:
        with open(args.secrets_file, encoding="utf-8") as handle:
            secrets = [line.rstrip("\n") for line in handle if line.strip()]

    result, transcript = validate_dataset(
        args.root, dataset, secrets=secrets, no_score=args.no_score,
        path_policy=args.path_policy, max_findings=args.max_findings)

    leaks = fm.find_leaks(result, secrets) if secrets else []
    leaks.extend(find_shape_leaks(result))
    if args.fail_on_leak and leaks:
        for leak in leaks:
            print("FAIL %s" % leak, file=sys.stderr)
        print(json.dumps({"written": None, "leaks": leaks}, indent=2))
        return 1

    problems = fm.validate(result)
    if problems:
        for problem in problems:
            print("INVALID %s" % problem, file=sys.stderr)
        return 2

    fm.save_findings(result, args.out)
    if args.transcript:
        directory = os.path.dirname(os.path.abspath(args.transcript)) or "."
        os.makedirs(directory, exist_ok=True)
        with open(args.transcript, "w", encoding="utf-8") as handle:
            json.dump(transcript, handle, indent=2, ensure_ascii=False)
            handle.write("\n")
    print(json.dumps({
        "written": args.out,
        "summary": result["summary"],
        "redactions_applied": transcript["redactions_applied"],
        "leaks": leaks,
        "transcript": args.transcript,
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
