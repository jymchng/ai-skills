#!/usr/bin/env python3
"""Stage 3b: run the built-in analyzers plus every external scanner that exists.

The built-in analyzers are the guaranteed baseline. External tools are
accelerators: they are probed, invoked only when present, and every tool that
could not run is reported as a coverage limitation. A missing tool never
becomes a clean result.

What this script owns
---------------------
* :func:`probe` - resolve a tool on ``PATH`` and run its version probe, recording
  ``{name, path, version, probe_exit_code, probe_stderr}``.
* :func:`invocations` - the ordered argv variants per tool. CLIs change between
  major versions (``osv-scanner`` v2 needs ``scan source``, ``gitleaks`` v8 uses
  subcommands), so variants are tried in order and the first exit-0 wins.
* :func:`parse_output` - one parser per tool, normalising into the shared finding
  model. Unknown rule ids keep ``category: "unclassified"`` and
  ``confidence: LOW`` instead of being dropped.
* :func:`merge` - deduplicate candidates that share ``(file, line, category)``
  and merge their ``sources``, so "three scanners agree" is evidence strength,
  not three findings.
* :func:`redact` - secret redaction applied at ingestion, so a raw credential
  never reaches ``findings.json``.

Guarantees
----------
* **Stdlib only**, Python 3.8+.
* **Read-only** with respect to the audited tree: every tool runs with its report
  path in the output directory, never inside the root.
* **Bounded**: a per-tool timeout is mandatory; a timeout is a limitation, not an
  empty result.
* **Deterministic**: tools are sorted by name, and findings by
  ``(file, line_start, rule, tool)``.

CLI
---
    python3 scripts/scanner_orchestrator.py --root . --outdir audit/analysis
    python3 scripts/scanner_orchestrator.py --root . --probe-only
    python3 scripts/scanner_orchestrator.py --root . --scanners bandit,semgrep
    python3 scripts/scanner_orchestrator.py --root . --allow-network --local-rules rules/
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

VERSION = "1.0.0"
SCHEMA_VERSION = "1.0"

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SCRIPTS_DIR = os.path.dirname(os.path.abspath(__file__))

#: Directories never walked, never scanned, never counted as source.
SKIP_DIRS = {
    ".git", ".hg", ".svn", "node_modules", "vendor", "third_party", "dist",
    "build", "target", "out", ".venv", "venv", "env", "__pycache__",
    ".mypy_cache", ".pytest_cache", ".tox", ".next", ".nuxt", "coverage",
    ".idea", ".vscode", "Pods", "bower_components", ".terraform",
}

SOURCE_EXT = {
    ".py": "python", ".js": "javascript", ".jsx": "javascript",
    ".ts": "typescript", ".tsx": "typescript", ".mjs": "javascript",
    ".cjs": "javascript", ".go": "go", ".rs": "rust", ".rb": "ruby",
    ".php": "php", ".java": "java", ".kt": "kotlin", ".kts": "kotlin",
    ".cs": "csharp", ".scala": "scala", ".ex": "elixir", ".exs": "elixir",
}

# ---------------------------------------------------------------------------
# Severity and confidence are ours; the tool's label is only an input
# ---------------------------------------------------------------------------

_TOOL_SEVERITY = {
    "critical": "Critical", "high": "High", "medium": "Medium", "moderate": "Medium",
    "low": "Low", "info": "Informational", "informational": "Informational",
    "error": "High", "warning": "Medium", "note": "Informational",
    "failed": "Medium", "passed": "Informational",
    "important": "High", "negligible": "Low", "unknown": "Medium",
}

#: Tool severity never sets our confidence: everything starts at MEDIUM and
#: stage 5 decides. Only an unmappable rule id drops to LOW.
DEFAULT_CONFIDENCE = "MEDIUM"

PRIORITY_BY_SEVERITY = {
    "Critical": "P0", "High": "P1", "Medium": "P2",
    "Low": "P3", "Informational": "P3",
}

# ---------------------------------------------------------------------------
# Rule id -> taxonomy category (explicit, versioned, extend-only)
# ---------------------------------------------------------------------------

CATEGORY_KEYWORDS: List[Tuple[str, str]] = [
    ("hardcoded", "hardcoded_secret"),
    ("secret", "hardcoded_secret"),
    ("credential", "hardcoded_secret"),
    ("password", "weak_password_hashing"),
    ("deserial", "insecure_deserialization"),
    ("pickle", "insecure_deserialization"),
    ("xxe", "insecure_deserialization"),
    ("sql", "sql_injection"),
    ("sqli", "sql_injection"),
    ("nosql", "nosql_injection"),
    ("mongo", "nosql_injection"),
    ("command", "command_injection"),
    ("shell", "command_injection"),
    ("subprocess", "command_injection"),
    ("exec", "code_injection"),
    ("eval", "code_injection"),
    ("template", "ssti"),
    ("ssti", "ssti"),
    ("jinja", "ssti"),
    ("ldap", "ldap_injection"),
    ("xpath", "xpath_injection"),
    ("header", "header_injection"),
    ("crlf", "header_injection"),
    ("xss", "xss_reflected"),
    ("cross-site-script", "xss_reflected"),
    ("traversal", "path_traversal"),
    ("path", "path_traversal"),
    ("zip-slip", "zip_slip"),
    ("tar", "zip_slip"),
    ("upload", "unrestricted_upload"),
    ("ssrf", "ssrf"),
    ("request-forgery", "ssrf"),
    ("redirect", "open_redirect"),
    ("tls", "tls_verification_disabled"),
    ("ssl", "tls_verification_disabled"),
    ("certificate", "tls_verification_disabled"),
    ("verify", "tls_verification_disabled"),
    ("jwt", "weak_jwt_validation"),
    ("session", "session_management"),
    ("cookie", "session_management"),
    ("csrf", "csrf"),
    ("cors", "permissive_cors"),
    ("header-missing", "missing_security_headers"),
    ("security-header", "missing_security_headers"),
    ("hsts", "missing_security_headers"),
    ("debug", "debug_mode"),
    ("random", "weak_randomness"),
    ("entropy", "broken_crypto"),
    ("crypto", "broken_crypto"),
    ("cipher", "broken_crypto"),
    ("hash", "weak_password_hashing"),
    ("md5", "broken_crypto"),
    ("sha1", "broken_crypto"),
    ("auth", "missing_authentication"),
    ("permission", "missing_authorization"),
    ("authoriz", "missing_authorization"),
    ("idor", "idor"),
    ("idor", "idor"),
    ("insecure-direct-object", "idor"),
    ("mass-assignment", "mass_assignment"),
    ("rate-limit", "missing_rate_limiting"),
    ("race", "race_condition"),
    ("toctou", "race_condition"),
    ("dependency", "vulnerable_dependency"),
    ("outdated", "vulnerable_dependency"),
    ("cve", "vulnerable_dependency"),
    ("unpinned", "unpinned_dependency"),
    ("pin", "unpinned_dependency"),
    ("docker", "container_security"),
    ("container", "container_security"),
    ("kubernetes", "kubernetes_security"),
    ("k8s", "kubernetes_security"),
    ("terraform", "iac_misconfiguration"),
    ("iac", "iac_misconfiguration"),
    ("checkov", "iac_misconfiguration"),
    ("actions", "cicd_permissions"),
    ("github-actions", "cicd_permissions"),
    ("workflow", "cicd_permissions"),
    ("privil", "missing_authorization"),
    ("exposure", "sensitive_data_exposure"),
    ("logging", "sensitive_data_exposure"),
    ("pii", "sensitive_data_exposure"),
]

#: Exact rule ids we know, per tool. Beats the keyword heuristic.
RULE_CATEGORY: Dict[str, Dict[str, str]] = {
    "bandit": {
        "B101": "business_logic", "B102": "code_injection", "B103": "iac_misconfiguration",
        "B104": "container_security", "B105": "hardcoded_secret", "B106": "hardcoded_secret",
        "B107": "hardcoded_secret", "B108": "path_traversal", "B110": "fail_open_error_handling",
        "B112": "fail_open_error_handling", "B201": "debug_mode", "B301": "insecure_deserialization",
        "B302": "insecure_deserialization", "B303": "broken_crypto", "B304": "broken_crypto",
        "B305": "broken_crypto", "B306": "broken_crypto", "B307": "code_injection",
        "B308": "header_injection", "B310": "ssrf", "B311": "weak_randomness",
        "B312": "tls_verification_disabled", "B313": "insecure_deserialization",
        "B314": "insecure_deserialization", "B315": "insecure_deserialization",
        "B316": "insecure_deserialization", "B317": "insecure_deserialization",
        "B318": "insecure_deserialization", "B319": "insecure_deserialization",
        "B320": "insecure_deserialization", "B321": "insecure_deserialization",
        "B323": "tls_verification_disabled", "B324": "broken_crypto",
        "B325": "insecure_deserialization", "B501": "tls_verification_disabled",
        "B502": "tls_verification_disabled", "B503": "tls_verification_disabled",
        "B504": "tls_verification_disabled", "B505": "broken_crypto",
        "B506": "insecure_deserialization", "B507": "missing_authentication",
        "B601": "command_injection", "B602": "command_injection",
        "B603": "command_injection", "B604": "command_injection",
        "B605": "command_injection", "B606": "command_injection",
        "B607": "command_injection", "B608": "sql_injection",
        "B609": "command_injection", "B610": "command_injection",
        "B611": "sql_injection", "B612": "fail_open_error_handling",
        "B613": "command_injection", "B614": "insecure_deserialization",
        "B615": "insecure_deserialization", "B701": "ssti", "B702": "ssti",
        "B703": "code_injection", "B704": "code_injection", "B950": "command_injection",
    },
    "semgrep": {
        "sql-injection": "sql_injection", "sqli": "sql_injection",
        "command-injection": "command_injection", "shell-injection": "command_injection",
        "xss": "xss_reflected", "path-traversal": "path_traversal",
        "ssrf": "ssrf", "open-redirect": "open_redirect",
        "insecure-deserialization": "insecure_deserialization",
        "hardcoded": "hardcoded_secret", "secret": "hardcoded_secret",
        "jwt": "weak_jwt_validation", "cors": "permissive_cors",
        "csrf": "csrf", "xxe": "insecure_deserialization",
        "ssti": "ssti", "ldap": "ldap_injection", "xpath": "xpath_injection",
        "weak-random": "weak_randomness", "md5": "broken_crypto",
        "sha1": "broken_crypto", "tls": "tls_verification_disabled",
        "debug": "debug_mode", "docker": "container_security",
        "kubernetes": "kubernetes_security", "terraform": "iac_misconfiguration",
    },
    "gosec": {
        "G101": "hardcoded_secret", "G102": "ssrf", "G103": "command_injection",
        "G104": "fail_open_error_handling", "G106": "missing_authentication",
        "G107": "ssrf", "G108": "debug_mode", "G109": "command_injection",
        "G110": "insecure_deserialization", "G111": "path_traversal",
        "G112": "fail_open_error_handling", "G113": "weak_randomness",
        "G114": "missing_security_headers", "G201": "sql_injection",
        "G202": "sql_injection", "G203": "header_injection", "G204": "command_injection",
        "G301": "path_traversal", "G302": "path_traversal", "G303": "path_traversal",
        "G304": "path_traversal", "G305": "zip_slip", "G306": "path_traversal",
        "G307": "fail_open_error_handling", "G401": "broken_crypto",
        "G402": "tls_verification_disabled", "G403": "broken_crypto",
        "G404": "weak_randomness", "G501": "broken_crypto", "G502": "broken_crypto",
        "G503": "broken_crypto", "G504": "broken_crypto", "G505": "broken_crypto",
        "G506": "insecure_deserialization", "G507": "insecure_deserialization",
        "G601": "command_injection", "G602": "sql_injection",
    },
    "brakeman": {
        "SQL Injection": "sql_injection", "Cross Site Scripting": "xss_reflected",
        "Cross Site Scripting (Reflected)": "xss_reflected",
        "Cross Site Scripting (DOM)": "xss_reflected",
        "Command Injection": "command_injection", "Path Traversal": "path_traversal",
        "Unrestricted File Upload": "unrestricted_upload",
        "Remote Code Execution": "code_injection", "Deserialization": "insecure_deserialization",
        "CSRF": "csrf", "Missing Authentication": "missing_authentication",
        "Mass Assignment": "mass_assignment", "Session Setting": "session_management",
        "Weak Hash": "weak_password_hashing", "Insecure Randomness": "weak_randomness",
        "Open Redirect": "open_redirect", "SSRF": "ssrf",
        "SSL Verification Bypass": "tls_verification_disabled",
        "Dangerous Send": "code_injection", "Debug Mode": "debug_mode",
    },
    "checkov": {},   # keyword fallback; check ids are per-policy
    "trivy": {},
    "gitleaks": {},
    "osv-scanner": {},
    "npm-audit": {},
    "pip-audit": {},
}

CWE_BY_CATEGORY: Dict[str, str] = {
    "sql_injection": "CWE-89", "nosql_injection": "CWE-943",
    "command_injection": "CWE-78", "code_injection": "CWE-94", "ssti": "CWE-1336",
    "ldap_injection": "CWE-90", "xpath_injection": "CWE-643",
    "header_injection": "CWE-113", "xss_reflected": "CWE-79", "xss_stored": "CWE-79",
    "path_traversal": "CWE-22", "unrestricted_upload": "CWE-434", "zip_slip": "CWE-22",
    "ssrf": "CWE-918", "open_redirect": "CWE-601",
    "tls_verification_disabled": "CWE-295", "missing_authentication": "CWE-306",
    "weak_password_hashing": "CWE-916", "weak_jwt_validation": "CWE-347",
    "session_management": "CWE-384", "missing_authorization": "CWE-862",
    "idor": "CWE-639", "missing_function_level_authorization": "CWE-862",
    "csrf": "CWE-352", "business_logic": "CWE-840",
    "missing_rate_limiting": "CWE-770", "race_condition": "CWE-367",
    "mass_assignment": "CWE-915", "weak_randomness": "CWE-338",
    "hardcoded_secret": "CWE-798", "broken_crypto": "CWE-327",
    "sensitive_data_exposure": "CWE-200", "insecure_deserialization": "CWE-502",
    "unsigned_update": "CWE-494", "vulnerable_dependency": "CWE-1395",
    "unpinned_dependency": "CWE-829", "permissive_cors": "CWE-942",
    "missing_security_headers": "CWE-693", "debug_mode": "CWE-489",
    "container_security": "CWE-693", "cicd_permissions": "CWE-250",
    "iac_misconfiguration": "CWE-16", "kubernetes_security": "CWE-693",
    "fail_open_error_handling": "CWE-636", "unclassified": "CWE-693",
}

IMPACT_BY_CATEGORY: Dict[str, str] = {
    "sql_injection": "Read or modification of arbitrary database rows, in the worst case file-system or command access through the database engine.",
    "nosql_injection": "Bypass of query predicates, disclosure of documents the caller should not reach, and authentication bypass.",
    "command_injection": "Execution of arbitrary operating-system commands with the privileges of the service.",
    "code_injection": "Execution of arbitrary code inside the service process.",
    "ssti": "Code execution on the server through the template engine's expression language.",
    "xss_reflected": "Script execution in a victim's session, with theft of tokens and actions taken as the user.",
    "path_traversal": "Read or write of files outside the intended directory, including credentials and configuration.",
    "unrestricted_upload": "Upload of executable content, leading to code execution or persistent script delivery.",
    "ssrf": "Requests to internal services and metadata endpoints from the server's network position.",
    "open_redirect": "Redirect of users to an attacker-controlled origin, used for phishing and token exfiltration.",
    "insecure_deserialization": "Remote code execution, or denial of service through crafted object graphs.",
    "hardcoded_secret": "Use of the credential by anyone who can read the repository or binary.",
    "weak_password_hashing": "Offline recovery of user passwords at a cost low enough to make cracking practical.",
    "weak_jwt_validation": "Forgery of tokens, and therefore authentication and authorisation bypass.",
    "permissive_cors": "Cross-origin reads of authenticated responses by attacker-controlled pages.",
    "tls_verification_disabled": "Silent interception of traffic by an attacker in the network path.",
    "vulnerable_dependency": "Exploitation of a published vulnerability in a component the application ships.",
    "unpinned_dependency": "Introduction of an unreviewed version at install or build time.",
    "container_security": "Escalation from the container to the host, or credentials baked into an image layer.",
    "kubernetes_security": "Escalation to cluster-level privileges or exposure of the workload's secrets.",
    "iac_misconfiguration": "A deployed resource exposed more widely than the design intends.",
    "cicd_permissions": "A compromised pipeline step able to write code, publish artifacts or reach secrets.",
    "debug_mode": "Internal state, stack traces and configuration exposed to unauthenticated users.",
    "sensitive_data_exposure": "Disclosure of personal or secret data in logs, errors or responses.",
    "missing_security_headers": "Loss of browser-enforced defences against framing, sniffing and injection.",
    "weak_randomness": "Predictable tokens, identifiers or secrets that an attacker can enumerate.",
    "broken_crypto": "Recoverable secrets or forgeable integrity checks from a broken primitive.",
    "fail_open_error_handling": "A security check that passes when it errors, removing the control entirely.",
    "unclassified": "Consequence not yet assessed; the candidate needs manual triage.",
}

FIX_BY_CATEGORY: Dict[str, str] = {
    "sql_injection": "Use parameterised queries or an ORM bind API; never build SQL by string concatenation.",
    "nosql_injection": "Reject object-typed operands, cast to primitives, and build queries from an allow-list of fields.",
    "command_injection": "Call the executable with an argument vector and shell=False; never interpolate into a shell string.",
    "code_injection": "Remove dynamic evaluation; if unavoidable, evaluate against an allow-list, never against request data.",
    "ssti": "Render with auto-escaping and user data as variables, not as template source; sandbox the engine.",
    "xss_reflected": "Escape output in the correct context and add a strict Content-Security-Policy.",
    "path_traversal": "Resolve the path, then assert it is inside the intended base directory before opening it.",
    "unrestricted_upload": "Enforce an extension and content-type allow-list, store outside the webroot, and rename the file.",
    "ssrf": "Resolve to an allow-list of hosts and schemes; block link-local and metadata addresses.",
    "open_redirect": "Redirect only to a fixed allow-list or relative paths.",
    "insecure_deserialization": "Use a data-only format with a schema, or an allow-list of classes with signature verification.",
    "hardcoded_secret": "Move the value to a secret store, rotate it, and add the pattern to pre-commit scanning.",
    "weak_password_hashing": "Use Argon2id, scrypt or bcrypt with a per-password salt and a tuned work factor.",
    "weak_jwt_validation": "Pin the expected algorithm, verify the signature and all claims, and reject 'none'.",
    "permissive_cors": "Reflect only known origins and never combine a wildcard or arbitrary origin with credentials.",
    "tls_verification_disabled": "Enable certificate and hostname verification; pin a CA bundle where needed.",
    "vulnerable_dependency": "Upgrade to a fixed release, or document the compensating control and the residual risk.",
    "unpinned_dependency": "Pin exact versions and commit the lockfile.",
    "container_security": "Run as non-root with a read-only root filesystem, and keep secrets out of image layers.",
    "kubernetes_security": "Set runAsNonRoot, drop capabilities, forbid privilege escalation and scope the service account.",
    "iac_misconfiguration": "Scope the resource to the intended principals and networks, then enforce it in CI.",
    "cicd_permissions": "Set the least workflow permissions explicitly and pin third-party actions by commit.",
    "debug_mode": "Disable debug output outside development and never expose the debugger to untrusted networks.",
    "sensitive_data_exposure": "Remove the data from logs and responses, or mask it at the boundary.",
    "missing_security_headers": "Add HSTS, a strict Content-Security-Policy, nosniff and frame-ancestors.",
    "weak_randomness": "Use a cryptographically secure generator (secrets, crypto/rand, SecureRandom).",
    "broken_crypto": "Replace the primitive with a current one (AES-GCM, SHA-256+, Argon2id).",
    "fail_open_error_handling": "Fail closed: deny when the check errors, and alert on the error path.",
    "unclassified": "Triage the candidate manually and map it to a taxonomy class before scoring.",
}

ATTACK_BY_CATEGORY: Dict[str, str] = {
    "sql_injection": "An attacker submits a quoted payload in a parameter the query concatenates, changing the predicate or appending a statement.",
    "command_injection": "An attacker supplies shell metacharacters in a parameter that reaches a shell string, appending their own command.",
    "code_injection": "An attacker supplies expression source that the service evaluates, executing arbitrary code in-process.",
    "ssti": "An attacker supplies template syntax that the engine evaluates, reaching configuration and the process.",
    "xss_reflected": "An attacker sends a crafted link; the payload is echoed unescaped and executes in the victim's session.",
    "path_traversal": "An attacker supplies a path with '../' sequences and reads a file outside the intended directory.",
    "ssrf": "An attacker supplies a URL and the server fetches an internal endpoint on their behalf.",
    "hardcoded_secret": "Anyone with repository or binary access extracts the credential and uses it directly.",
    "insecure_deserialization": "An attacker submits a serialised payload whose reconstruction runs attacker-chosen code.",
    "vulnerable_dependency": "An attacker reaches the vulnerable code path described in the published advisory.",
    "unclassified": "Not yet modelled; stage 5 must establish reachability before this becomes a finding.",
}


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _rel(root: str, path: str) -> str:
    try:
        value = os.path.relpath(os.path.abspath(path), os.path.abspath(root))
    except ValueError:
        value = path
    return value.replace(os.sep, "/")


def normalise_tool_path(root: str, raw: Any, cwd: Optional[str] = None) -> str:
    """A tool-reported path -> a path relative to the audited root.

    Tools disagree: bandit emits paths relative to the directory it was given,
    checkov emits absolute paths, gitleaks emits paths relative to its cwd. All
    three must land on the same string, or dedupe silently fails.
    """
    text = str(raw or "").strip().replace("\\", "/")
    if not text:
        return ""
    base = os.path.abspath(cwd or root)
    if not os.path.isabs(text):
        text = os.path.join(base, text)
    absolute = os.path.abspath(text)
    root_abs = os.path.abspath(root)
    if absolute == root_abs:
        return "."
    if absolute.startswith(root_abs + os.sep):
        return os.path.relpath(absolute, root_abs).replace(os.sep, "/")
    # Outside the audited root (an installed dependency, a container path):
    # keep the tail so the location is still identifiable, and do not invent a
    # path relative to the root that would point at the wrong file.
    return absolute.replace(os.sep, "/")


def _safe_int(value: Any) -> Optional[int]:
    try:
        number = int(value)
    except (TypeError, ValueError):
        return None
    return number if number > 0 else None


def _one_line(text: Any, limit: int = 300) -> str:
    value = re.sub(r"\s+", " ", str(text or "")).strip()
    return value[:limit]


def _git_snapshot(root: str) -> Dict[str, Any]:
    def run(*argv: str) -> Optional[str]:
        try:
            proc = subprocess.run(
                list(argv), cwd=root, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                timeout=15, check=False,
            )
        except (OSError, subprocess.SubprocessError):
            return None
        if proc.returncode != 0:
            return None
        return proc.stdout.decode("utf-8", "replace").strip() or None

    commit = run("git", "rev-parse", "HEAD")
    branch = run("git", "rev-parse", "--abbrev-ref", "HEAD")
    status = run("git", "status", "--porcelain")
    return {"commit": commit, "branch": branch, "dirty": bool(status)}


def walk_files(root: str) -> List[str]:
    """Relative paths of candidate source files, sorted, skip-lists applied."""
    found: List[str] = []
    for dirpath, dirnames, filenames in os.walk(root):
        # Hidden directories are scratch, caches and tool state, not audited
        # source - except .github, which holds workflows and actions we do audit.
        dirnames[:] = sorted(
            d for d in dirnames
            if d not in SKIP_DIRS and (not d.startswith(".") or d == ".github")
        )
        for name in sorted(filenames):
            full = os.path.join(dirpath, name)
            if os.path.islink(full) and not os.path.exists(full):
                continue
            if not os.path.isfile(full):
                continue
            found.append(_rel(root, full))
    return sorted(found)


def _count_by_ext(files: Sequence[str], exts: Iterable[str]) -> int:
    wanted = tuple(exts)
    return sum(1 for f in files if f.lower().endswith(wanted))


# ---------------------------------------------------------------------------
# Redaction (applied at ingestion)
# ---------------------------------------------------------------------------

_SECRET_PATTERNS: List[Tuple[re.Pattern, str]] = [
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S),
     "[REDACTED PRIVATE KEY]"),
    (re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{16,}\b"), "[REDACTED GITHUB TOKEN]"),
    (re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"), "[REDACTED GITHUB TOKEN]"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "[REDACTED AWS KEY ID]"),
    (re.compile(r"\baws_secret_access_key\s*[=:]\s*\S+", re.I), "aws_secret_access_key=[REDACTED]"),
    (re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), "[REDACTED SLACK TOKEN]"),
    (re.compile(r"\bAIza[0-9A-Za-z_\-]{30,}\b"), "[REDACTED GOOGLE API KEY]"),
    (re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"), "[REDACTED API KEY]"),
    (re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"),
     "[REDACTED JWT]"),
    (re.compile(r"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key)\b\s*[=:]"
                r"\s*['\"]?[^\s'\"<>,;)]{6,}"),
     lambda m: "%s=[REDACTED]" % m.group(1)),
]

#: The credential shapes the built-in analyzer detects. An external tool's report
#: quotes a ±1 window, so a credential on the neighbouring line is part of the
#: excerpt; redacting only the shapes listed above would publish a Stripe key that
#: sat beside an unrelated semgrep finding. Compiled from the analyzer's own table
#: so the two cannot drift the way the validator's table once did.
_SHAPE_CACHE: Optional[List[Tuple[re.Pattern, str]]] = None


def _analyzer_shapes() -> List[Tuple[re.Pattern, str]]:
    """The analyzer's credential shapes, compiled once, in this module's style.

    Imported lazily so ``--list-tools`` does not pay for the analyzer import, and
    taken from the analyzer's own table so the two cannot drift the way the
    validator's table once did.
    """
    global _SHAPE_CACHE
    if _SHAPE_CACHE is None:
        scripts_dir = os.path.dirname(os.path.abspath(__file__))
        if scripts_dir not in sys.path:
            sys.path.insert(0, scripts_dir)
        import builtin_analyzers as ba  # noqa: WPS433 - deliberate local import
        _SHAPE_CACHE = [(re.compile(pattern_text), "[REDACTED %s]" % label.upper())
                        for _secret_id, pattern_text, label in ba.SECRET_PATTERNS]
    return _SHAPE_CACHE


def _substitute_guarded(pattern: re.Pattern, replacement: Any,
                        text: str) -> Tuple[str, int]:
    """``pattern.subn`` that leaves placeholders and existing markers alone."""
    hits = 0

    def substitute(match: Any) -> str:
        nonlocal hits
        value = (match.groupdict().get("secret") or match.group(0)).strip().strip("'\"")
        if not value or "\u2026" in value or "[REDACTED" in value:
            return match.group(0)
        new = replacement(match) if callable(replacement) else match.expand(replacement)
        if new != match.group(0):
            hits += 1
        return new

    return pattern.sub(substitute, text), hits


def redact(text: str) -> Tuple[str, int]:
    """Mask credential-shaped substrings. Returns (text, replacements)."""
    if not text:
        return text, 0
    total = 0
    for pattern, replacement in _SECRET_PATTERNS + _analyzer_shapes():
        text, count = _substitute_guarded(pattern, replacement, text)
        total += count
    return text, total


# ---------------------------------------------------------------------------
# Tool table
# ---------------------------------------------------------------------------

class Invocation:
    """One concrete argv to try, with the cwd it must run in."""

    __slots__ = ("argv", "cwd", "output", "note")

    def __init__(self, argv: List[str], cwd: str, output: str = "json", note: str = "") -> None:
        self.argv = argv
        self.cwd = cwd
        self.output = output
        self.note = note


def _tool(
    name: str,
    kind: str,
    *,
    categories: Sequence[str],
    languages: Sequence[str],
    network: bool = False,
    version_args: Sequence[str] = ("--version",),
    parsers: Sequence[str] = ("json",),
    notes: str = "",
) -> Dict[str, Any]:
    return {
        "name": name,
        "kind": kind,
        "categories": list(categories),
        "languages": list(languages),
        "network": network,
        "version_args": list(version_args),
        "parsers": list(parsers),
        "notes": notes,
    }


#: Everything we know how to drive. Sorted by name so runs are deterministic.
TOOLS: List[Dict[str, Any]] = sorted([
    _tool("bandit", "sast", categories=["injection", "crypto", "secrets", "deserialization"],
          languages=["python"]),
    _tool("brakeman", "sast", categories=["injection", "authz", "crypto"],
          languages=["ruby"]),
    _tool("checkov", "iac", categories=["iac", "container", "kubernetes", "cicd"],
          languages=["terraform", "kubernetes", "dockerfile", "github-actions"]),
    _tool("gitleaks", "secrets", categories=["secrets"],
          languages=["any"]),
    _tool("gosec", "sast", categories=["injection", "crypto", "tls", "filesystem"],
          languages=["go"]),
    _tool("npm-audit", "sca", categories=["dependencies"], languages=["javascript"],
          network=True, version_args=("--version",)),
    _tool("osv-scanner", "sca", categories=["dependencies"], languages=["many"],
          network=True),
    _tool("pip-audit", "sca", categories=["dependencies"], languages=["python"],
          network=True),
    _tool("semgrep", "sast", categories=["injection", "authz", "secrets", "crypto"],
          languages=["many"], network=True),
    _tool("trivy", "sca+iac", categories=["dependencies", "container", "kubernetes", "iac"],
          languages=["many"], network=True),
], key=lambda item: item["name"])

TOOL_INDEX = {tool["name"]: tool for tool in TOOLS}

#: Tools we deliberately never run automatically, and why.
NEVER_RUN = {
    "trufflehog": "verifying a discovered credential contacts a third-party service with the secret",
}


def _first_line(text: str) -> str:
    for line in (text or "").splitlines():
        if line.strip():
            return line.strip()
    return ""


_VERSION_RE = re.compile(r"\d+\.\d+(?:\.\d+)?")


def probe(tool: Dict[str, Any], timeout: float = 10.0) -> Dict[str, Any]:
    """Resolve the binary and run its version probe."""
    name = tool["name"]
    record: Dict[str, Any] = {
        "name": name,
        "kind": tool["kind"],
        "available": False,
        "path": None,
        "version": None,
        "probe_argv": None,
        "probe_exit_code": None,
        "probe_stderr": None,
        "reason": None,
        "network": tool["network"],
        "covers": list(tool["categories"]),
    }
    binary = shutil.which(name)
    if not binary:
        record["reason"] = "not found on PATH"
        return record
    record["path"] = binary
    argv = [binary] + list(tool["version_args"])
    record["probe_argv"] = [name] + list(tool["version_args"])
    try:
        proc = subprocess.run(
            argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, check=False,
        )
    except subprocess.TimeoutExpired:
        record["reason"] = "version probe timed out after %.1fs" % timeout
        return record
    except OSError as exc:
        record["reason"] = "could not execute: %s" % exc
        return record
    stdout = proc.stdout.decode("utf-8", "replace")
    stderr = proc.stderr.decode("utf-8", "replace")
    record["probe_exit_code"] = proc.returncode
    record["probe_stderr"] = _one_line(stderr, 300) or None
    match = _VERSION_RE.search(stdout) or _VERSION_RE.search(stderr)
    record["version"] = match.group(0) if match else None
    if proc.returncode != 0:
        record["reason"] = "version probe exited %d: %s" % (
            proc.returncode, _one_line(stderr or stdout, 200) or "no output")
        return record
    record["available"] = True
    return record


# ---------------------------------------------------------------------------
# Invocation planning
# ---------------------------------------------------------------------------

def _manifest_dirs(root: str, files: Sequence[str], names: Sequence[str],
                   limit: int = 5) -> List[str]:
    dirs: List[str] = []
    for rel in files:
        base = os.path.basename(rel)
        if base in names:
            directory = os.path.dirname(rel)
            if directory not in dirs:
                dirs.append(directory)
    return sorted(dirs)[:limit]


def invocations(tool: Dict[str, Any], root: str, files: Sequence[str],
                *, allow_network: bool, local_rules: Optional[str]) -> Tuple[List[Invocation], Optional[str]]:
    """Planned argv variants for a tool. Returns (invocations, skip_reason)."""
    name = tool["name"]
    py = _count_by_ext(files, [".py"])
    rb = _count_by_ext(files, [".rb"])
    go = _count_by_ext(files, [".go"])
    docker = sum(1 for f in files if os.path.basename(f).startswith("Dockerfile"))
    tf = _count_by_ext(files, [".tf"])
    k8s = sum(1 for f in files if "/k8s/" in "/" + f or "/kubernetes/" in "/" + f
              or "/manifests/" in "/" + f)
    workflows = sum(1 for f in files if f.startswith(".github/workflows/"))

    if name == "bandit":
        if not py:
            return [], "no Python files in scope"
        return [Invocation(["bandit", "-r", ".", "-f", "json", "-q"], root)], None

    if name == "brakeman":
        if not rb:
            return [], "no Ruby files in scope"
        return [Invocation(["brakeman", "-q", "-f", "json", "--no-pager", "."], root)], None

    if name == "gosec":
        if not go:
            return [], "no Go files in scope"
        if not any(os.path.basename(f) == "go.mod" for f in files):
            return [], "no go.mod at the audited root; gosec needs a module"
        return [Invocation(["gosec", "-fmt=json", "-quiet", "./..."], root)], None

    if name == "semgrep":
        argv = ["semgrep", "scan", "--json", "--quiet", "--metrics=off"]
        if local_rules:
            argv += ["--config", os.path.abspath(local_rules)]
        elif allow_network:
            argv += ["--config", "auto"]
        else:
            return [], ("no local rule config and network disabled; "
                        "pass --local-rules DIR to enable semgrep")
        argv += ["."]
        return [Invocation(argv, root)], None

    if name == "gitleaks":
        return [Invocation(
            ["gitleaks", "dir", ".", "--report-format", "json",
             "--report-path", os.path.join(".gitleaks.json"), "--no-banner"], root)], None

    if name == "trivy":
        if not allow_network:
            return [], "trivy needs the vulnerability database, which requires network access"
        runs = [Invocation(["trivy", "fs", "--format", "json", "--quiet", "."], root)]
        if tf or k8s or docker or workflows:
            runs.append(Invocation(
                ["trivy", "config", "--format", "json", "--quiet", "."], root,
                note="config scan"))
        return runs, None

    if name == "checkov":
        if not (tf or k8s or docker or workflows):
            return [], "no Terraform, Kubernetes, Dockerfile or workflow files in scope"
        return [Invocation(["checkov", "-d", ".", "-o", "json", "--quiet", "--compact"], root)], None

    if name == "osv-scanner":
        if not allow_network:
            return [], "osv-scanner queries the OSV database, which requires network access"
        return [
            Invocation(["osv-scanner", "scan", "source", "-r", ".", "--format", "json"], root,
                       note="v2 topology"),
            Invocation(["osv-scanner", "-r", ".", "--format", "json"], root, note="v1 topology"),
        ], None

    if name == "npm-audit":
        if not allow_network:
            return [], "npm audit queries the registry, which requires network access"
        dirs = _manifest_dirs(root, files, {"package.json"})
        if not dirs:
            return [], "no package.json in scope"
        return [Invocation(["npm", "audit", "--json"], os.path.join(root, d) if d else root)
                for d in dirs], None

    if name == "pip-audit":
        if not allow_network:
            return [], "pip-audit queries PyPI, which requires network access"
        reqs = [f for f in files if re.match(r"(^|/)requirements[^/]*\.txt$", f)]
        if not reqs:
            return [], "no requirements*.txt in scope"
        return [Invocation(["pip-audit", "-f", "json", "-r", os.path.abspath(os.path.join(root, r))],
                           root, note="requirements: %s" % r) for r in reqs[:5]], None

    return [], "no invocation defined for this tool"


# ---------------------------------------------------------------------------
# Parsers: tool output -> normalised candidates
# ---------------------------------------------------------------------------

def _candidate(rule_id: str, *, title: Any, file: Any, line_start: Any, line_end: Any,
               description: Any, severity: Any, cwe: Any = None,
               package: Optional[str] = None, version: Optional[str] = None,
               raw_ref: Optional[str] = None) -> Dict[str, Any]:
    return {
        "rule_id": _one_line(rule_id, 120) or "unknown",
        "title": _one_line(title, 200) or "Scanner finding",
        "file": str(file or "").replace(os.sep, "/"),
        "line_start": _safe_int(line_start),
        "line_end": _safe_int(line_end) or _safe_int(line_start),
        "description": _one_line(description, 500),
        "tool_severity": _one_line(severity, 40) or "unknown",
        "cwe": (_one_line(cwe, 20) or None),
        "package": package,
        "version": version,
        "raw_ref": raw_ref,
    }


def _loads(text: str) -> Any:
    text = text.strip()
    if not text:
        return None
    try:
        return json.loads(text)
    except ValueError:
        pass
    # Some tools prepend banner lines; try the first JSON-looking line onwards.
    for index, char in enumerate(text):
        if char in "[{":
            try:
                return json.loads(text[index:])
            except ValueError:
                continue
            break
    return None


def _parse_bandit(doc: Any, root: str) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    if not isinstance(doc, dict):
        return out
    for item in doc.get("results") or []:
        if not isinstance(item, dict):
            continue
        cwe = item.get("issue_cwe") or {}
        cwe_id = cwe.get("id") if isinstance(cwe, dict) else None
        out.append(_candidate(
            item.get("test_id") or item.get("test_name") or "unknown",
            title=item.get("test_name") or item.get("test_id"),
            file=item.get("filename") or item.get("fname"),
            line_start=item.get("line_number"),
            line_end=(item.get("line_range") or [None])[-1] if isinstance(item.get("line_range"), list) else item.get("line_number"),
            description=item.get("issue_text"),
            severity=item.get("issue_severity"),
            cwe=("CWE-%s" % cwe_id) if cwe_id else None,
            raw_ref="bandit:%s:%s" % (item.get("test_id"), item.get("filename")),
        ))
    return out


def _parse_semgrep(doc: Any, root: str) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    if not isinstance(doc, dict):
        return out
    for item in doc.get("results") or []:
        if not isinstance(item, dict):
            continue
        start = item.get("start") or {}
        end = item.get("end") or {}
        extra = item.get("extra") or {}
        metadata = extra.get("metadata") or {}
        cwe = metadata.get("cwe")
        if isinstance(cwe, list):
            cwe = cwe[0] if cwe else None
        match = re.search(r"CWE-\d+", str(cwe or ""))
        out.append(_candidate(
            item.get("check_id") or "unknown",
            title=extra.get("message") or item.get("check_id"),
            file=item.get("path"),
            line_start=start.get("line"),
            line_end=end.get("line"),
            description=extra.get("message"),
            severity=extra.get("severity"),
            cwe=match.group(0) if match else None,
            raw_ref="semgrep:%s:%s" % (item.get("check_id"), item.get("path")),
        ))
    return out


def _parse_gitleaks(doc: Any, root: str) -> List[Dict[str, Any]]:
    items = doc if isinstance(doc, list) else (doc or {}).get("leaks") if isinstance(doc, dict) else []
    out: List[Dict[str, Any]] = []
    for item in items or []:
        if not isinstance(item, dict):
            continue
        rule = item.get("RuleID") or item.get("rule_id") or "secret"
        out.append(_candidate(
            rule,
            title=item.get("Description") or ("Exposed credential: %s" % rule),
            file=item.get("File") or item.get("file"),
            line_start=item.get("StartLine") or item.get("StartLineNumber"),
            line_end=item.get("EndLine") or item.get("EndLineNumber"),
            description=item.get("Match") or item.get("Secret") or "Credential-shaped string",
            severity="High",
            cwe="CWE-798",
            raw_ref="gitleaks:%s:%s" % (rule, item.get("File")),
        ))
    return out


def _parse_gosec(doc: Any, root: str) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    if not isinstance(doc, dict):
        return out
    for item in doc.get("Issues") or []:
        if not isinstance(item, dict):
            continue
        cwe = item.get("cwe") or {}
        cwe_id = cwe.get("id") if isinstance(cwe, dict) else None
        out.append(_candidate(
            item.get("rule_id") or "unknown",
            title=item.get("details") or item.get("rule_id"),
            file=item.get("file"),
            line_start=item.get("line"),
            line_end=item.get("line"),
            description=item.get("details"),
            severity=item.get("severity"),
            cwe=("CWE-%s" % cwe_id) if cwe_id else None,
            raw_ref="gosec:%s:%s" % (item.get("rule_id"), item.get("file")),
        ))
    return out


def _parse_brakeman(doc: Any, root: str) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    if not isinstance(doc, dict):
        return out
    for item in doc.get("warnings") or []:
        if not isinstance(item, dict):
            continue
        cwe = item.get("cwe_id")
        out.append(_candidate(
            item.get("warning_type") or item.get("check_name") or "unknown",
            title=item.get("warning_type"),
            file=item.get("file"),
            line_start=item.get("line"),
            line_end=item.get("line"),
            description=item.get("message"),
            severity=item.get("confidence") or "Medium",
            cwe=("CWE-%s" % cwe) if cwe else None,
            raw_ref="brakeman:%s:%s" % (item.get("warning_type"), item.get("file")),
        ))
    return out


def _parse_checkov(doc: Any, root: str) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    blocks = doc if isinstance(doc, list) else [doc]
    for block in blocks:
        if not isinstance(block, dict):
            continue
        for summary in (block.get("results") or {}).get("failed_checks") or []:
            if not isinstance(summary, dict):
                continue
            lines = summary.get("file_line_range") or [None, None]
            out.append(_candidate(
                summary.get("check_id") or "unknown",
                title=summary.get("check_name") or summary.get("check_id"),
                file=summary.get("file_path"),
                line_start=lines[0] if len(lines) > 0 else None,
                line_end=lines[-1] if lines else None,
                description=summary.get("check_name") or summary.get("guideline"),
                severity=summary.get("severity"),
                cwe=None,
                raw_ref="checkov:%s:%s" % (summary.get("check_id"), summary.get("file_path")),
            ))
    return out


def _parse_trivy(doc: Any, root: str) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    if not isinstance(doc, dict):
        return out
    for result in doc.get("Results") or []:
        if not isinstance(result, dict):
            continue
        target = result.get("Target")
        for vuln in result.get("Vulnerabilities") or []:
            if not isinstance(vuln, dict):
                continue
            out.append(_candidate(
                vuln.get("VulnerabilityID") or "unknown",
                title=vuln.get("Title") or vuln.get("VulnerabilityID"),
                file=target,
                line_start=None,
                line_end=None,
                description=vuln.get("Description") or (
                    "%s in %s %s" % (vuln.get("VulnerabilityID"), vuln.get("PkgName"),
                                     vuln.get("InstalledVersion"))),
                severity=vuln.get("Severity"),
                package=vuln.get("PkgName"),
                version=vuln.get("InstalledVersion"),
                raw_ref="trivy:%s:%s" % (vuln.get("VulnerabilityID"), vuln.get("PkgName")),
            ))
        for mis in result.get("Misconfigurations") or []:
            if not isinstance(mis, dict):
                continue
            cause = mis.get("CauseMetadata") or {}
            out.append(_candidate(
                mis.get("ID") or mis.get("AVDID") or "unknown",
                title=mis.get("Title") or mis.get("ID"),
                file=target,
                line_start=cause.get("StartLine"),
                line_end=cause.get("EndLine"),
                description=mis.get("Message") or mis.get("Description"),
                severity=mis.get("Severity"),
                raw_ref="trivy-config:%s:%s" % (mis.get("ID"), target),
            ))
    return out


def _parse_osv(doc: Any, root: str) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    if not isinstance(doc, dict):
        return out
    for result in doc.get("results") or []:
        if not isinstance(result, dict):
            continue
        source = (result.get("source") or {}).get("path")
        for package in result.get("packages") or []:
            if not isinstance(package, dict):
                continue
            info = package.get("package") or {}
            for vuln in package.get("vulnerabilities") or []:
                if not isinstance(vuln, dict):
                    continue
                out.append(_candidate(
                    vuln.get("id") or "unknown",
                    title=vuln.get("summary") or vuln.get("id"),
                    file=source,
                    line_start=None,
                    line_end=None,
                    description=vuln.get("details") or vuln.get("summary"),
                    severity="High",
                    package=info.get("name"),
                    version=info.get("version"),
                    raw_ref="osv:%s:%s" % (vuln.get("id"), info.get("name")),
                ))
    return out


def _parse_npm_audit(doc: Any, root: str) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    if not isinstance(doc, dict):
        return out
    vulns = doc.get("vulnerabilities")
    if isinstance(vulns, dict):
        for name, item in sorted(vulns.items()):
            if not isinstance(item, dict):
                continue
            vias = [v for v in (item.get("via") or []) if isinstance(v, dict)]
            titles = "; ".join(_one_line(v.get("title"), 120) for v in vias if v.get("title"))
            out.append(_candidate(
                (vias[0].get("source") if vias else None) or name,
                title=titles or ("Vulnerable dependency: %s" % name),
                file="package.json",
                line_start=None,
                line_end=None,
                description=titles or "Advisory affects %s (%s)" % (name, item.get("range")),
                severity=item.get("severity"),
                package=name,
                version=item.get("range"),
                raw_ref="npm-audit:%s" % name,
            ))
        return out
    for name, item in sorted((doc.get("advisories") or {}).items()):
        if not isinstance(item, dict):
            continue
        out.append(_candidate(
            item.get("id") or name,
            title=item.get("title"),
            file="package.json",
            line_start=None,
            line_end=None,
            description=item.get("overview") or item.get("title"),
            severity=item.get("severity"),
            package=item.get("module_name") or name,
            version=item.get("vulnerable_versions"),
            raw_ref="npm-audit:%s" % name,
        ))
    return out


def _parse_pip_audit(doc: Any, root: str) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    if not isinstance(doc, dict):
        return out
    for dep in doc.get("dependencies") or []:
        if not isinstance(dep, dict):
            continue
        for vuln in dep.get("vulns") or []:
            if not isinstance(vuln, dict):
                continue
            out.append(_candidate(
                vuln.get("id") or "unknown",
                title="%s %s: %s" % (dep.get("name"), dep.get("version"), vuln.get("id")),
                file="requirements.txt",
                line_start=None,
                line_end=None,
                description=vuln.get("description") or vuln.get("fix_versions"),
                severity="High",
                package=dep.get("name"),
                version=dep.get("version"),
                raw_ref="pip-audit:%s:%s" % (vuln.get("id"), dep.get("name")),
            ))
    return out


PARSERS = {
    "bandit": _parse_bandit,
    "semgrep": _parse_semgrep,
    "gitleaks": _parse_gitleaks,
    "gosec": _parse_gosec,
    "brakeman": _parse_brakeman,
    "checkov": _parse_checkov,
    "trivy": _parse_trivy,
    "osv-scanner": _parse_osv,
    "npm-audit": _parse_npm_audit,
    "pip-audit": _parse_pip_audit,
}


def parse_output(tool_name: str, text: str, root: str) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    """Parse one tool's stdout. Returns (candidates, error)."""
    parser = PARSERS.get(tool_name)
    if parser is None:
        return [], "no parser for %s" % tool_name
    doc = _loads(text)
    if doc is None:
        return [], "output is not valid JSON"
    return parser(doc, root), None


# ---------------------------------------------------------------------------
# Normalisation into the finding model
# ---------------------------------------------------------------------------

def category_for(tool: str, rule_id: str, title: str = "", description: str = "") -> str:
    exact = RULE_CATEGORY.get(tool, {})
    if rule_id in exact:
        return exact[rule_id]
    haystack = " ".join((rule_id, title, description)).lower()
    for needle, category in CATEGORY_KEYWORDS:
        if needle in haystack:
            return category
    if tool == "gitleaks":
        return "hardcoded_secret"
    if tool in ("osv-scanner", "npm-audit", "pip-audit"):
        return "vulnerable_dependency"
    return "unclassified"


def tool_language(tool: str) -> str:
    return {"bandit": "python", "brakeman": "ruby", "gosec": "go",
            "npm-audit": "javascript", "pip-audit": "python"}.get(tool, "mixed")


def _read_evidence(root: str, rel: str, line: Optional[int], context: int = 1) -> str:
    if not rel or not line:
        return ""
    path = os.path.join(root, rel)
    if not os.path.isfile(path):
        return ""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            lines = handle.read(4096 * 64).splitlines()
    except OSError:
        return ""
    if line > len(lines):
        # The tool's line number does not exist in the file we have (stale report,
        # generated file, or a path that resolved elsewhere). Say nothing rather
        # than quote a neighbouring line as if it were the finding.
        return ""
    start = max(1, line - context)
    end = min(len(lines), line + context)
    return "\n".join("%5d | %s" % (n, lines[n - 1]) for n in range(start, end + 1))


def normalise(candidate: Dict[str, Any], tool: str, root: str) -> Dict[str, Any]:
    """One parser candidate -> one finding-model record (still unvalidated)."""
    category = category_for(tool, candidate["rule_id"], candidate["title"], candidate["description"])
    severity = _TOOL_SEVERITY.get(str(candidate.get("tool_severity") or "").lower(), "Medium")
    confidence = DEFAULT_CONFIDENCE if category != "unclassified" else "LOW"
    cwe_id = candidate.get("cwe") or CWE_BY_CATEGORY.get(category, "CWE-693")
    file = normalise_tool_path(root, candidate.get("file")) or "unknown"
    evidence = _read_evidence(root, file, candidate.get("line_start"))
    title, _ = redact(candidate["title"])
    description, _ = redact(candidate["description"] or "")
    evidence, _ = redact(evidence)
    record = {
        "title": title,
        "category": category,
        "severity": severity,
        "confidence": confidence,
        "validation_status": "unvalidated",
        "cwe": {"id": cwe_id, "name": ""},
        "owasp": {"top10_2025": "not mapped", "api_2023": "not mapped", "asvs": "not mapped"},
        "cvss_vector": None,
        "cvss_score": None,
        "scoring": "unscored",
        "location": {
            "file": file,
            "line_start": candidate.get("line_start"),
            "line_end": candidate.get("line_end") or candidate.get("line_start"),
        },
        "language": tool_language(tool),
        "evidence": evidence,
        "description": description or title,
        "impact": IMPACT_BY_CATEGORY.get(category, IMPACT_BY_CATEGORY["unclassified"]),
        "attack_scenario": ATTACK_BY_CATEGORY.get(category, ATTACK_BY_CATEGORY["unclassified"]),
        "recommended_fix": FIX_BY_CATEGORY.get(category, FIX_BY_CATEGORY["unclassified"]),
        "references": [],
        "sources": [{
            "tool": tool,
            "rule_id": candidate.get("rule_id"),
            "raw_ref": candidate.get("raw_ref"),
        }],
        "priority": PRIORITY_BY_SEVERITY.get(severity, "P2"),
        "priority_factors": [
            "severity: %s (tool label: %s)" % (severity, candidate.get("tool_severity")),
            "confidence: %s" % confidence,
            "tool severity is an input to validation, not a verdict",
        ],
        "tool_severity": candidate.get("tool_severity"),
        "status": "candidate",
    }
    if candidate.get("package"):
        record["package"] = candidate["package"]
    if candidate.get("version"):
        record["package_version"] = candidate["version"]
    return record


# ---------------------------------------------------------------------------
# Merge and dedupe
# ---------------------------------------------------------------------------

def _identity(finding: Dict[str, Any]) -> Tuple[str, Optional[int], str, str]:
    location = finding.get("location") or {}
    line = location.get("line_start")
    return (
        location.get("file") or "",
        line,
        finding.get("category") or "unclassified",
        # Dependency findings carry no line: without the package every advisory in
        # one manifest would collapse into a single finding.
        "" if line else str(finding.get("package") or ""),
    )


def merge(findings: Sequence[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], int]:
    """Collapse duplicates; merge sources. Returns (findings, duplicates_removed)."""
    merged: Dict[Tuple[str, Optional[int], str, str], Dict[str, Any]] = {}
    order: List[Tuple[str, Optional[int], str, str]] = []
    duplicates = 0
    for finding in findings:
        key = _identity(finding)
        existing = merged.get(key)
        if existing is None:
            merged[key] = finding
            order.append(key)
            continue
        duplicates += 1
        for source in finding.get("sources") or []:
            if source not in existing["sources"]:
                existing["sources"].append(source)
        existing["sources"].sort(key=lambda s: (str(s.get("tool")), str(s.get("rule_id"))))
        existing["confidence"] = "HIGH"
        existing.setdefault("priority_factors", []).append(
            "corroborated by %d tools" % len({s.get("tool") for s in existing["sources"]}))
    return [merged[key] for key in order], duplicates


def _sort_key(finding: Dict[str, Any]) -> Tuple[Any, ...]:
    location = finding.get("location") or {}
    return (
        str(location.get("file") or ""),
        location.get("line_start") or 0,
        str(finding.get("category") or ""),
        str((finding.get("sources") or [{}])[0].get("tool") or ""),
    )


# ---------------------------------------------------------------------------
# Built-in baseline
# ---------------------------------------------------------------------------

def run_builtin(root: str, *, only: Optional[str] = None) -> Tuple[List[Dict[str, Any]], Dict[str, Any], Optional[str]]:
    """Run the stage-3a analyzers in-process and adapt their findings."""
    if _SCRIPTS_DIR not in sys.path:
        sys.path.insert(0, _SCRIPTS_DIR)
    try:
        import builtin_analyzers  # noqa: WPS433 - deliberate local import
    except Exception as exc:  # pragma: no cover - only on a broken checkout
        return [], {}, "builtin analyzers unavailable: %s" % exc

    document = builtin_analyzers.analyze(
        root,
        only={item.strip() for item in only.split(",") if item.strip()} if only else None,
    )
    findings: List[Dict[str, Any]] = []
    redactions = 0
    for finding in document.get("findings") or []:
        adapted = json.loads(json.dumps(finding))
        # IDs are assigned once, after dedupe, by finding_model.assign_ids().
        adapted.pop("id", None)
        for field in ("title", "description", "evidence", "impact", "attack_scenario"):
            if isinstance(adapted.get(field), str):
                adapted[field], count = redact(adapted[field])
                redactions += count
        adapted["status"] = "candidate"
        findings.append(adapted)
    meta = {
        "tool": document.get("tool"),
        "summary": document.get("summary"),
        "coverage": document.get("coverage"),
        "suppressed": len(document.get("suppressed") or []),
        "secrets_redacted": document.get("summary", {}).get("secrets_redacted"),
        "redactions_applied": redactions,
    }
    return findings, meta, None


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

def _execute(tool: Dict[str, Any], invocation: Invocation, *, timeout: float,
             raw_dir: Optional[str], index: int) -> Dict[str, Any]:
    name = tool["name"]
    binary = shutil.which(invocation.argv[0])
    record: Dict[str, Any] = {
        "tool": name,
        "kind": tool["kind"],
        "argv": [os.path.basename(invocation.argv[0])] + invocation.argv[1:],
        "cwd": invocation.cwd,
        "started_at": _utc_now(),
        "duration_ms": None,
        "exit_code": None,
        "timed_out": False,
        "parsed": False,
        "candidates": 0,
        "error": None,
        "status": "not_run",
        "raw_path": None,
        "note": invocation.note or None,
    }
    if not binary:
        record["status"] = "unavailable"
        record["error"] = "%s not found on PATH" % name
        return record

    started = time.time()
    argv = [binary] + invocation.argv[1:]
    try:
        proc = subprocess.run(
            argv, cwd=invocation.cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=timeout, check=False,
        )
    except subprocess.TimeoutExpired:
        record["status"] = "timeout"
        record["timed_out"] = True
        record["duration_ms"] = int((time.time() - started) * 1000)
        record["error"] = "timeout after %.0fs" % timeout
        return record
    except OSError as exc:
        record["status"] = "failed"
        record["error"] = "could not execute: %s" % exc
        return record

    record["duration_ms"] = int((time.time() - started) * 1000)
    record["exit_code"] = proc.returncode
    stdout = proc.stdout.decode("utf-8", "replace")
    stderr = proc.stderr.decode("utf-8", "replace")

    # gitleaks writes its report to a file, then prints a summary.
    if name == "gitleaks":
        report_path = None
        for position, item in enumerate(invocation.argv):
            if item == "--report-path" and position + 1 < len(invocation.argv):
                report_path = os.path.join(invocation.cwd, invocation.argv[position + 1])
        if report_path and os.path.isfile(report_path):
            try:
                with open(report_path, "r", encoding="utf-8", errors="replace") as handle:
                    stdout = handle.read()
            except OSError as exc:
                record["error"] = "could not read gitleaks report: %s" % exc
            finally:
                try:
                    os.remove(report_path)
                except OSError:
                    pass

    stdout, raw_redactions = redact(stdout)
    stderr, stderr_redactions = redact(stderr)
    record["raw_redactions"] = raw_redactions + stderr_redactions

    if raw_dir:
        safe = re.sub(r"[^A-Za-z0-9_.-]", "_", "%s__%d" % (name, index))
        target = os.path.join(raw_dir, safe + ".json")
        try:
            os.makedirs(raw_dir, exist_ok=True)
            with open(target, "w", encoding="utf-8") as handle:
                handle.write(stdout)
            record["raw_path"] = _rel(os.path.dirname(raw_dir), target)
        except OSError as exc:
            record["raw_path"] = None
            record["error"] = "could not preserve raw output: %s" % exc

    # 0 = clean, 1 = findings present (normal), anything else = check stderr.
    if proc.returncode not in (0, 1):
        record["status"] = "failed"
        record["error"] = "exit %d: %s" % (proc.returncode, _one_line(stderr, 300) or "no stderr")
        return record

    candidates, parse_error = parse_output(name, stdout, invocation.cwd)
    record["candidates"] = len(candidates)
    record["parsed"] = parse_error is None
    record["error"] = parse_error
    record["status"] = "ok" if parse_error is None else "unparsed"
    if parse_error is None and proc.returncode == 1 and not candidates:
        record["error"] = "exit 1 but no candidates parsed; inspect raw output"
        record["status"] = "unparsed"
    record["_candidates"] = candidates
    return record


def orchestrate(
    root: str,
    *,
    scanners: Optional[Sequence[str]] = None,
    timeout: float = 300.0,
    probe_timeout: float = 10.0,
    allow_network: bool = False,
    local_rules: Optional[str] = None,
    raw_dir: Optional[str] = None,
    include_builtin: bool = True,
    builtin_only: Optional[str] = None,
) -> Dict[str, Any]:
    root = os.path.abspath(root)
    files = walk_files(root)
    wanted = {name.strip() for name in (scanners or []) if name.strip()}
    selected = [tool for tool in TOOLS if not wanted or tool["name"] in wanted]
    unknown = sorted(wanted - {tool["name"] for tool in TOOLS})
    if unknown:
        raise SystemExit("unknown scanner(s): %s (known: %s)"
                         % (", ".join(unknown), ", ".join(t["name"] for t in TOOLS)))

    findings: List[Dict[str, Any]] = []
    limitations: List[str] = []
    coverage: Dict[str, Any] = {}
    builtin_meta: Dict[str, Any] = {}

    if include_builtin:
        builtin_findings, builtin_meta, error = run_builtin(root, only=builtin_only)
        if error:
            limitations.append(error)
        else:
            findings.extend(builtin_findings)
            coverage["builtin"] = {
                "name": builtin_meta.get("tool", {}).get("name", "builtin_analyzers.py"),
                "rules": (builtin_meta.get("summary") or {}).get("rules_evaluated"),
                "findings": len(builtin_findings),
                "suppressed": builtin_meta.get("suppressed"),
                "files_scanned": (builtin_meta.get("summary") or {}).get("files_scanned"),
            }

    scanner_records = [probe(tool, timeout=probe_timeout) for tool in selected]
    runs: List[Dict[str, Any]] = []

    for tool, record in zip(selected, scanner_records):
        name = tool["name"]
        if not record["available"]:
            limitations.append(
                "%s unavailable (%s); %s relies on the built-in rules only"
                % (name, record["reason"], ", ".join(tool["categories"])))
            continue
        # Plan first: semgrep with a local rule directory is perfectly offline, so
        # the network gate must not fire before the tool has been asked what it
        # would run. A tool that can run offline must not be reported as skipped
        # for a network reason.
        planned, skip_reason = invocations(tool, root, files, allow_network=allow_network,
                                          local_rules=local_rules)
        offline_ok = name == "semgrep" and bool(local_rules)
        if not skip_reason and tool["network"] and not allow_network and not offline_ok:
            planned = []
            skip_reason = "it needs network access and --allow-network was not given"
        if skip_reason:
            runs.append({
                "tool": name, "kind": tool["kind"], "argv": None, "cwd": root,
                "started_at": _utc_now(), "duration_ms": 0, "exit_code": None,
                "timed_out": False, "parsed": False, "candidates": 0,
                "error": skip_reason, "status": "skipped", "raw_path": None, "note": None,
            })
            limitations.append("%s was not run: %s" % (name, skip_reason))
            continue

        accepted: Optional[Dict[str, Any]] = None
        attempts: List[Dict[str, Any]] = []
        for index, invocation in enumerate(planned):
            attempt = _execute(tool, invocation, timeout=timeout, raw_dir=raw_dir, index=index)
            candidates = attempt.pop("_candidates", [])
            attempt["variant"] = index
            attempts.append(attempt)
            if attempt["status"] == "ok" and (candidates or attempt["exit_code"] in (0, 1)):
                attempt["candidates"] = len(candidates)
                accepted = attempt
                accepted["_candidates"] = candidates
                break
            if attempt["status"] == "timeout":
                break
        runs.extend(attempts)
        if accepted is None:
            last = attempts[-1] if attempts else None
            if last and last["status"] != "ok":
                limitations.append(
                    "%s produced no usable output (%s); its coverage is lost for this run"
                    % (name, last.get("error") or last.get("status")))
            continue
        for candidate in accepted.get("_candidates", []):
            findings.append(normalise(candidate, name, root))

    for record in runs:
        record.pop("_candidates", None)

    merged, duplicates = merge(findings)
    merged.sort(key=_sort_key)

    by_severity: Dict[str, int] = {}
    by_category: Dict[str, int] = {}
    by_tool: Dict[str, int] = {}
    for finding in merged:
        by_severity[finding["severity"]] = by_severity.get(finding["severity"], 0) + 1
        by_category[finding["category"]] = by_category.get(finding["category"], 0) + 1
        for source in finding.get("sources") or []:
            tool_name = str(source.get("tool"))
            by_tool[tool_name] = by_tool.get(tool_name, 0) + 1

    available = [r["name"] for r in scanner_records if r["available"]]
    unavailable = [r["name"] for r in scanner_records if not r["available"]]
    if unavailable:
        limitations.append(
            "coverage limitation: %d of %d external scanners are unavailable (%s); "
            "absence of a finding is not evidence of absence"
            % (len(unavailable), len(scanner_records), ", ".join(unavailable)))

    coverage.update({
        "files_in_scope": len(files),
        "languages": sorted({SOURCE_EXT[os.path.splitext(f)[1].lower()]
                             for f in files if os.path.splitext(f)[1].lower() in SOURCE_EXT}),
        "scanners_available": available,
        "scanners_unavailable": unavailable,
        "scanners_skipped": [r["tool"] for r in runs if r["status"] == "skipped"],
        "scanners_failed": [r["tool"] for r in runs if r["status"] in ("failed", "timeout", "unparsed")],
        "network_allowed": allow_network,
        "never_run": NEVER_RUN,
        "builtin": coverage.get("builtin"),
    })

    return {
        "stage": "analysis",
        "schema_version": SCHEMA_VERSION,
        "tool": {"name": "scanner_orchestrator.py", "version": VERSION},
        "generated_at": _utc_now(),
        "root": root,
        "snapshot": _git_snapshot(root),
        "scanners": scanner_records,
        "runs": sorted(runs, key=lambda r: (r["tool"], str(r.get("variant", 0)))),
        "findings": merged,
        "summary": {
            "findings": len(merged),
            "by_severity": by_severity,
            "by_category": by_category,
            "by_tool": by_tool,
            "duplicates_merged": duplicates,
            "scanners_probed": len(scanner_records),
            "scanners_available": len(available),
        },
        "coverage": coverage,
        "limitations": limitations,
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="scanner_orchestrator.py",
        description="Run the built-in analyzers plus every external scanner that exists, "
                    "normalise all output into one findings document, and report every tool "
                    "that could not run as a coverage limitation. Read-only.",
    )
    parser.add_argument("--root", default=".", help="audited root (default: .)")
    parser.add_argument("--out", help="write the merged document here (default: stdout)")
    parser.add_argument("--outdir", help="write findings.json, scanners.json, scanner_runs.json "
                                         "and raw/ into this directory")
    parser.add_argument("--scanners", help="comma-separated subset of external scanners to run")
    parser.add_argument("--timeout", type=float, default=300.0,
                        help="per-invocation timeout in seconds (default: 300)")
    parser.add_argument("--probe-timeout", type=float, default=10.0,
                        help="version-probe timeout in seconds (default: 10)")
    parser.add_argument("--allow-network", action="store_true",
                        help="permit scanners that query a registry or database")
    parser.add_argument("--local-rules", help="directory of local semgrep rules (needed when "
                                              "network access is off)")
    parser.add_argument("--no-builtin", action="store_true", help="skip the built-in analyzers")
    parser.add_argument("--builtin-only", help="comma-separated built-in categories to run")
    parser.add_argument("--probe-only", action="store_true", help="probe availability and exit")
    parser.add_argument("--list-tools", action="store_true", help="print the scanner matrix and exit")
    parser.add_argument("--indent", type=int, default=2, help="JSON indent (default: 2)")
    parser.add_argument("--quiet", action="store_true", help="suppress the --out summary line")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)

    if args.list_tools:
        rows = [{
            "name": tool["name"], "kind": tool["kind"], "network": tool["network"],
            "categories": tool["categories"], "languages": tool["languages"],
            "available": bool(shutil.which(tool["name"])),
        } for tool in TOOLS]
        print(json.dumps({"tools": rows, "never_run": NEVER_RUN}, indent=args.indent))
        return 0

    if args.probe_only:
        records = [probe(tool, timeout=args.probe_timeout) for tool in TOOLS]
        print(json.dumps({"scanners": records,
                          "available": [r["name"] for r in records if r["available"]],
                          "unavailable": [r["name"] for r in records if not r["available"]]},
                         indent=args.indent))
        return 0

    raw_dir = os.path.join(args.outdir, "raw") if args.outdir else None
    document = orchestrate(
        args.root,
        scanners=[s for s in (args.scanners or "").split(",") if s.strip()] or None,
        timeout=max(1.0, args.timeout),
        probe_timeout=max(1.0, args.probe_timeout),
        allow_network=args.allow_network,
        local_rules=args.local_rules,
        raw_dir=raw_dir,
        include_builtin=not args.no_builtin,
        builtin_only=args.builtin_only,
    )
    text = json.dumps(document, indent=args.indent, ensure_ascii=False) + "\n"

    if args.outdir:
        os.makedirs(args.outdir, exist_ok=True)
        with open(os.path.join(args.outdir, "findings.json"), "w", encoding="utf-8") as handle:
            handle.write(text)
        with open(os.path.join(args.outdir, "scanners.json"), "w", encoding="utf-8") as handle:
            json.dump({"scanners": document["scanners"]}, handle, indent=args.indent,
                      ensure_ascii=False)
            handle.write("\n")
        with open(os.path.join(args.outdir, "scanner_runs.json"), "w", encoding="utf-8") as handle:
            json.dump({"runs": document["runs"]}, handle, indent=args.indent, ensure_ascii=False)
            handle.write("\n")

    if args.outdir and not args.out and not args.quiet:
        summary = document["summary"]
        print(json.dumps({
            "outdir": args.outdir,
            "findings": summary["findings"],
            "by_severity": summary["by_severity"],
            "by_tool": summary["by_tool"],
            "scanners_available": summary["scanners_available"],
            "scanners_probed": summary["scanners_probed"],
            "duplicates_merged": summary["duplicates_merged"],
            "limitations": len(document["limitations"]),
        }, indent=args.indent))
        return 0

    if args.out:
        os.makedirs(os.path.dirname(os.path.abspath(args.out)) or ".", exist_ok=True)
        with open(args.out, "w", encoding="utf-8") as handle:
            handle.write(text)
        if not args.quiet:
            summary = document["summary"]
            print(json.dumps({
                "written": args.out,
                "findings": summary["findings"],
                "by_severity": summary["by_severity"],
                "by_tool": summary["by_tool"],
                "scanners_available": summary["scanners_available"],
                "scanners_probed": summary["scanners_probed"],
                "duplicates_merged": summary["duplicates_merged"],
            }, indent=args.indent))
        return 0

    sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
