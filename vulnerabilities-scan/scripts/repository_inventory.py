#!/usr/bin/env python3
"""Deterministic, read-only repository inventory (audit stage 1).

Everything downstream depends on this file being honest, so the accounting is
the point rather than a side effect:

* Every discovered path lands in exactly one bucket, and
  ``len(files) == sum(buckets.values())``. A path is never counted twice.
* Paths that are *not* analysed are listed with a reason from the closed set in
  ``schemas/finding.schema.json`` (``binary``, ``too_large``, ``unreadable``,
  ``generated``, ``excluded``, ``submodule``), so stage 8 can turn them into
  coverage limitations instead of silent omissions.
* Directory traversal is sorted and no timestamp enters the file list, so two
  runs over the same snapshot produce byte-identical JSON. Timestamps are
  recorded once at the top level.

Read-only: this script opens target files for reading only and never writes
inside the audited tree. The one optional write is ``--out``.

Git metadata is collected with ``git --no-optional-locks`` so that even
``git status`` cannot refresh the index of the repository being audited.

Usage
-----
    python3 scripts/repository_inventory.py                       # JSON to stdout
    python3 scripts/repository_inventory.py --out inventory.json
    python3 scripts/repository_inventory.py --exclude 'vendor/**' --max-bytes 524288
    python3 scripts/repository_inventory.py --root . --hash        # add sha256 per file
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence, Tuple

SCHEMA_VERSION = "1.0"
TOOL_VERSION = "1.0.0"

DEFAULT_MAX_BYTES = 1024 * 1024          # 1 MiB, per references/security-methodology.md §2
SNIFF_BYTES = 8192
DECODE_PROBE_BYTES = 65536

# --------------------------------------------------------------------------- #
# Classification tables
# --------------------------------------------------------------------------- #

#: Extension to language name. Values match the ``language`` vocabulary used by
#: ``schemas/finding.schema.json`` and ``references/language-security-guides.md``.
LANGUAGE_BY_EXT: Dict[str, str] = {
    ".py": "python", ".pyi": "python", ".pyx": "python",
    ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript", ".jsx": "javascript",
    ".ts": "typescript", ".tsx": "typescript", ".mts": "typescript", ".cts": "typescript",
    ".go": "go",
    ".rb": "ruby", ".rake": "ruby", ".gemspec": "ruby",
    ".php": "php", ".phtml": "php",
    ".java": "java",
    ".cs": "csharp", ".csx": "csharp",
    ".kt": "kotlin", ".kts": "kotlin",
    ".scala": "scala",
    ".swift": "swift",
    ".rs": "rust",
    ".c": "c", ".h": "c",
    ".cc": "cpp", ".cpp": "cpp", ".cxx": "cpp", ".hpp": "cpp", ".hh": "cpp",
    ".m": "objectivec", ".mm": "objectivec",
    ".ex": "elixir", ".exs": "elixir",
    ".erl": "erlang",
    ".clj": "clojure", ".cljs": "clojure",
    ".hs": "haskell",
    ".lua": "lua",
    ".pl": "perl", ".pm": "perl",
    ".r": "r",
    ".sh": "shell", ".bash": "shell", ".zsh": "shell", ".ksh": "shell",
    ".ps1": "powershell", ".psm1": "powershell",
    ".sql": "sql",
    ".vue": "vue", ".svelte": "svelte",
    ".proto": "protobuf",
    ".tf": "terraform", ".tfvars": "terraform",
    ".hcl": "hcl",
    ".yml": "yaml", ".yaml": "yaml",
    ".json": "json", ".json5": "json", ".jsonc": "json",
    ".toml": "toml", ".ini": "ini", ".cfg": "ini", ".conf": "config",
    ".env": "dotenv",
    ".md": "markdown", ".markdown": "markdown", ".rst": "rst", ".adoc": "asciidoc",
    ".html": "html", ".htm": "html",
    ".css": "css", ".scss": "scss", ".sass": "scss", ".less": "less",
    ".xml": "xml", ".xsd": "xml", ".xsl": "xml",
    ".gradle": "groovy", ".groovy": "groovy",
    ".csproj": "xml", ".fsproj": "xml", ".vbproj": "xml", ".sln": "sln",
    ".pom": "xml",
    ".dockerfile": "dockerfile",
    ".j2": "jinja", ".jinja": "jinja", ".jinja2": "jinja", ".hbs": "handlebars",
    ".erb": "erb", ".ejs": "ejs", ".pug": "pug", ".twig": "twig",
    ".lock": "lockfile",
    ".txt": "text", ".csv": "csv", ".log": "text",
    ".map": "sourcemap",
    ".graphql": "graphql", ".gql": "graphql",
    ".ipynb": "notebook",
}

BINARY_EXTS: frozenset = frozenset({
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".webp", ".tif", ".tiff", ".psd",
    ".svgz", ".pdf", ".zip", ".gz", ".bz2", ".xz", ".zst", ".7z", ".rar", ".tar", ".tgz",
    ".jar", ".war", ".ear", ".class", ".so", ".dylib", ".dll", ".a", ".lib", ".o", ".obj",
    ".exe", ".bin", ".dat", ".db", ".sqlite", ".sqlite3", ".mdb",
    ".woff", ".woff2", ".ttf", ".otf", ".eot",
    ".mp3", ".mp4", ".mov", ".avi", ".mkv", ".wav", ".flac", ".webm", ".ogg",
    ".wasm", ".pyc", ".pyo", ".pyd", ".node", ".pak", ".iso", ".dmg", ".deb", ".rpm",
    ".keystore", ".jks", ".p12", ".pfx", ".der",
})

FILENAME_LANGUAGE: Dict[str, str] = {
    "dockerfile": "dockerfile",
    "containerfile": "dockerfile",
    "makefile": "makefile",
    "gnumakefile": "makefile",
    "gemfile": "ruby",
    "rakefile": "ruby",
    "procfile": "text",
    "jenkinsfile": "groovy",
    "vagrantfile": "ruby",
    "cmakelists.txt": "cmake",
    "go.mod": "gomod",
    "go.sum": "lockfile",
    "pipfile": "toml",
    "pipfile.lock": "json",
    "requirements.txt": "text",
    "package.json": "json",
    "package-lock.json": "json",
    "yarn.lock": "lockfile",
    "pnpm-lock.yaml": "yaml",
    "poetry.lock": "toml",
    "uv.lock": "toml",
    "cargo.toml": "toml",
    "cargo.lock": "lockfile",
    "composer.json": "json",
    "composer.lock": "json",
    "pom.xml": "xml",
    "build.gradle": "groovy",
    "build.gradle.kts": "kotlin",
    "settings.gradle": "groovy",
    "settings.gradle.kts": "kotlin",
    "tsconfig.json": "json",
    ".gitignore": "text",
    ".gitattributes": "text",
    ".dockerignore": "text",
    ".editorconfig": "ini",
    ".nvmrc": "text",
    ".python-version": "text",
    ".ruby-version": "text",
    ".tool-versions": "text",
    ".env": "dotenv",
}

#: Ordered (regex, kind, ecosystem) for dependency manifests. First match wins.
MANIFEST_RULES: Tuple[Tuple[str, str, str], ...] = (
    (r"^package\.json$", "manifest", "npm"),
    (r"^package-lock\.json$", "lockfile", "npm"),
    (r"^npm-shrinkwrap\.json$", "lockfile", "npm"),
    (r"^yarn\.lock$", "lockfile", "npm"),
    (r"^pnpm-lock\.yaml$", "lockfile", "npm"),
    (r"^\.yarnrc(\.yml)?$", "config", "npm"),
    (r"^requirements[^/]*\.(txt|in)$", "manifest", "pypi"),
    (r"^constraints[^/]*\.txt$", "manifest", "pypi"),
    (r"^Pipfile$", "manifest", "pypi"),
    (r"^Pipfile\.lock$", "lockfile", "pypi"),
    (r"^poetry\.lock$", "lockfile", "pypi"),
    (r"^uv\.lock$", "lockfile", "pypi"),
    (r"^pyproject\.toml$", "manifest", "pypi"),
    (r"^setup\.(py|cfg)$", "manifest", "pypi"),
    (r"^environment\.ya?ml$", "manifest", "conda"),
    (r"^go\.mod$", "manifest", "go"),
    (r"^go\.sum$", "lockfile", "go"),
    (r"^go\.work$", "manifest", "go"),
    (r"^Gemfile$", "manifest", "rubygems"),
    (r"^Gemfile\.lock$", "lockfile", "rubygems"),
    (r"\.gemspec$", "manifest", "rubygems"),
    (r"^composer\.json$", "manifest", "packagist"),
    (r"^composer\.lock$", "lockfile", "packagist"),
    (r"^pom\.xml$", "manifest", "maven"),
    (r"^build\.gradle(\.kts)?$", "manifest", "gradle"),
    (r"^settings\.gradle(\.kts)?$", "manifest", "gradle"),
    (r"^gradle\.properties$", "config", "gradle"),
    (r"\.csproj$", "manifest", "nuget"),
    (r"\.fsproj$", "manifest", "nuget"),
    (r"\.vbproj$", "manifest", "nuget"),
    (r"^packages\.config$", "manifest", "nuget"),
    (r"^Directory\.(Build|Packages)\.props$", "config", "nuget"),
    (r"^packages\.lock\.json$", "lockfile", "nuget"),
    (r"^Cargo\.toml$", "manifest", "cargo"),
    (r"^Cargo\.lock$", "lockfile", "cargo"),
    (r"^mix\.exs$", "manifest", "hex"),
    (r"^mix\.lock$", "lockfile", "hex"),
    (r"^pubspec\.yaml$", "manifest", "pub"),
    (r"^pubspec\.lock$", "lockfile", "pub"),
    (r"^Package\.swift$", "manifest", "swiftpm"),
    (r"^Podfile$", "manifest", "cocoapods"),
    (r"^composer\.lock$", "lockfile", "packagist"),
    (r"^bower\.json$", "manifest", "bower"),
)
_MANIFEST_RES = tuple((re.compile(p, re.IGNORECASE), kind, eco) for p, kind, eco in MANIFEST_RULES)

#: Path shapes treated as generated build output: excluded by default, recorded.
GENERATED_DIRS: frozenset = frozenset({
    "node_modules", "bower_components", "dist", "build", "out", "target", "bin", "obj",
    "vendor", "third_party", "site-packages", ".venv", "venv", "env", "virtualenv",
    ".tox", ".nox", ".mypy_cache", ".pytest_cache", ".ruff_cache", "__pycache__",
    ".next", ".nuxt", ".svelte-kit", ".parcel-cache", ".turbo", ".gradle", ".idea",
    ".terraform", "coverage", "htmlcov", ".nyc_output", "Pods", "DerivedData",
})
GENERATED_FILE_RE = re.compile(
    r"(\.min\.(js|css)$|\.bundle\.js$|_pb2(_grpc)?\.py$|\.pb\.go$|\.generated\.\w+$"
    r"|\.designer\.cs$|\.g\.cs$|\.d\.ts$|\.map$|\.lock\.py$)", re.IGNORECASE)

#: Documentation and licence files: inventoried, never analysed for code bugs.
DOC_FILE_RE = re.compile(
    r"(^readme|^changelog|^changes|^history|^contributing|^code_of_conduct|^security"
    r"|^licen[cs]e|^copying|^notice|^authors|^maintainers|^governance)", re.IGNORECASE)
DOC_EXT = frozenset({".md", ".markdown", ".rst", ".adoc", ".asciidoc", ".txt", ".textile"})

CONFIG_EXTS = frozenset({
    ".yaml", ".yml", ".json", ".json5", ".toml", ".ini", ".cfg", ".conf", ".properties",
    ".env", ".xml", ".plist", ".cnf", ".config", ".settings", ".editorconfig",
})
CONFIG_FILE_RE = re.compile(r"(^\.env|^\.?env\.|\.env$|^\.?envrc$|\.conf$|\.cfg$|\.ini$"
                            r"|config\.\w+$|secrets?\.\w+$|credentials?$)", re.IGNORECASE)

IAC_FILE_RE = re.compile(r"(^Dockerfile|\.dockerfile$|^Containerfile|\.tf$|\.tfvars$"
                         r"|^Chart\.yaml$|^values.*\.ya?ml$|^kustomization\.ya?ml$"
                         r"|^docker-compose.*\.ya?ml$|^compose\.ya?ml$|\.hcl$"
                         r"|^serverless\.ya?ml$|^template\.ya?ml$|^ansible\.cfg$)", re.IGNORECASE)
IAC_DIR_RE = re.compile(r"(^|/)(k8s|kubernetes|kube|helm|charts|terraform|deploy|deployment"
                        r"|manifests|infrastructure|infra|ansible|playbooks)(/|$)", re.IGNORECASE)
#: Directories that hold CloudFormation templates. Checked before ``IAC_DIR_RE`` so
#: a template is labelled ``cloudformation`` instead of inheriting the generic
#: ``kubernetes`` label that directory merely implies.
CFN_DIR_RE = re.compile(r"(^|/)(cloudformation|cfn|cfn-templates|cloudformation-templates"
                        r"|stacks)(/|$)", re.IGNORECASE)
WORKFLOW_RE = re.compile(r"^\.github/workflows/[^/]+\.ya?ml$", re.IGNORECASE)
CI_FILE_RE = re.compile(r"(^\.gitlab-ci\.yml$|^\.travis\.yml$|^Jenkinsfile$|^azure-pipelines\.yml$"
                        r"|^\.circleci/config\.yml$|^bitbucket-pipelines\.yml$|^\.drone\.yml$)",
                        re.IGNORECASE)


# --------------------------------------------------------------------------- #
# .gitignore-style matching
# --------------------------------------------------------------------------- #

def _glob_to_regex(pattern: str) -> str:
    """Translate a gitignore glob to a regex fragment (``*`` never crosses ``/``)."""
    out: List[str] = []
    i, n = 0, len(pattern)
    while i < n:
        char = pattern[i]
        if char == "*":
            if pattern.startswith("**/", i):
                out.append("(?:[^/]+/)*")     # zero or more directories
                i += 3
            elif pattern.startswith("**", i):
                out.append(".*")
                i += 2
            else:
                out.append("[^/]*")
                i += 1
        elif char == "?":
            out.append("[^/]")
            i += 1
        elif char == "[":
            close = pattern.find("]", i + 1)
            if close == -1:
                out.append(re.escape("["))
                i += 1
            else:
                body = pattern[i + 1:close]
                if body.startswith("!"):
                    body = "^" + body[1:]
                out.append("[" + body.replace("\\", "\\\\") + "]")
                i = close + 1
        elif char == "\\" and i + 1 < n:
            out.append(re.escape(pattern[i + 1]))
            i += 2
        else:
            out.append(re.escape(char))
            i += 1
    return "".join(out)


class IgnoreRule:
    """One compiled .gitignore line.

    ``base`` is the directory (relative to the audit root, ``""`` at the top)
    whose .gitignore declared the rule; patterns are interpreted relative to it
    so that nested .gitignore files behave the way git makes them behave.
    """

    __slots__ = ("base", "regex", "negated", "dir_only", "source", "raw")

    def __init__(self, raw: str, base: str, source: str) -> None:
        self.raw = raw
        self.base = base
        self.source = source
        self.negated = raw.startswith("!")
        body = raw[1:] if self.negated else raw
        # Trailing spaces are insignificant unless escaped; keep it simple and
        # strip them, which is what every real-world .gitignore means.
        body = body.rstrip()
        self.dir_only = body.endswith("/")
        if self.dir_only:
            body = body[:-1]
        anchored = body.startswith("/") or "/" in body
        if body.startswith("/"):
            body = body[1:]
        translated = _glob_to_regex(body)
        prefix = "^" if anchored else r"^(?:[^/]+/)*"
        suffix = "$" if self.dir_only or anchored else r"(?:/.*)?$"
        # Unanchored patterns also match at any depth, so the suffix permits the
        # rest of the path: "build" ignores "build/" and everything under it.
        self.regex = re.compile(prefix + translated + suffix)

    def matches(self, relpath: str, is_dir: bool) -> bool:
        if self.dir_only and not is_dir:
            # A directory rule still ignores a file beneath that directory,
            # which the walk handles by pruning; match ancestors for safety.
            parts = relpath.split("/")[:-1]
            for depth in range(1, len(parts) + 1):
                if self.regex.match("/".join(parts[:depth])):
                    return True
            return False
        return bool(self.regex.match(relpath))


class IgnoreStack:
    """Nested .gitignore files, outermost first; deeper rules win."""

    def __init__(self, pairs: Sequence[Tuple[str, str]]) -> None:
        self.levels: List[Tuple[str, List[IgnoreRule]]] = []
        for base, text in pairs:
            self.push(base, text)

    def push(self, base: str, text: str) -> None:
        rules = []
        for raw in text.splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            rules.append(IgnoreRule(line, base, source=".gitignore"))
        self.levels.append((base, rules))

    def pop(self) -> None:
        if self.levels:
            self.levels.pop()

    def ignored(self, relpath: str, is_dir: bool) -> bool:
        decision = False
        for base, rules in self.levels:
            sub = relpath if not base else relpath[len(base) + 1:]
            if base and not relpath.startswith(base + "/"):
                continue
            for rule in rules:
                if rule.matches(sub, is_dir):
                    decision = not rule.negated
        return decision


# --------------------------------------------------------------------------- #
# File classification
# --------------------------------------------------------------------------- #

def _ext(filename: str) -> str:
    lower = filename.lower()
    _, dot_ext = os.path.splitext(lower)
    if dot_ext:
        return dot_ext
    if lower.startswith(".") and lower.count(".") == 1:
        return lower            # .env, .gitignore
    return ""


def classify(relpath: str, filename: str) -> Tuple[str, Optional[str]]:
    """Return ``(bucket, language)`` for one path.

    Buckets come from references/security-methodology.md §2. Order matters:
    infrastructure and manifests are checked before the generic source/config
    rules, because ``Dockerfile``, ``package.json`` and ``compose.yaml`` would
    otherwise be classified as prose or config.
    """
    lower = filename.lower()
    language = FILENAME_LANGUAGE.get(lower) or LANGUAGE_BY_EXT.get(_ext(filename))

    if lower in ("dockerfile", "containerfile") or lower.startswith("dockerfile."):
        return "iac", "dockerfile"
    if relpath.startswith(".github/workflows/") and _ext(filename) in (".yml", ".yaml"):
        return "iac", "github-actions"
    if _ext(filename) in (".tf", ".tfvars", ".hcl"):
        return "iac", "terraform"
    if filename in ("Chart.yaml", "Chart.lock", "kustomization.yaml", "kustomization.yml"):
        return "iac", "kubernetes"
    if CFN_DIR_RE.search(relpath) and _ext(filename) in (".yml", ".yaml", ".json"):
        return "iac", "cloudformation"
    if IAC_FILE_RE.search(filename):
        return "iac", language or "yaml"
    if IAC_DIR_RE.search(relpath) and _ext(filename) in (".yml", ".yaml", ".json"):
        return "iac", "kubernetes"
    # Matched on the *file name*, not the path: ``CI_FILE_RE`` is anchored with
    # ``^...$``, so testing it against ``ci/.gitlab-ci.yml`` never matched and the
    # file fell through to ``config`` -- where the CI rules, keyed on the iac
    # bucket, could not see it. A pipeline file in a subdirectory is still a
    # pipeline file.
    if CI_FILE_RE.search(filename):
        return "iac", language or "yaml"

    for regex, kind, _eco in _MANIFEST_RES:
        if regex.search(filename):
            return "manifest", language or "manifest"

    if lower.startswith(".") and lower in (".gitignore", ".gitattributes", ".dockerignore",
                                           ".editorconfig", ".nvmrc", ".python-version",
                                           ".ruby-version", ".tool-versions", ".envrc"):
        return "config", language

    if _ext(filename) in BINARY_EXTS:
        return "binary", language or "binary"

    if _ext(filename) in (".py", ".pyi", ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx",
                          ".mts", ".cts", ".go", ".rb", ".rake", ".php", ".phtml", ".java",
                          ".cs", ".csx", ".kt", ".kts", ".scala", ".swift", ".rs", ".c",
                          ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh", ".m", ".mm", ".ex",
                          ".exs", ".erl", ".clj", ".cljs", ".hs", ".lua", ".pl", ".pm",
                          ".sh", ".bash", ".zsh", ".ksh", ".ps1", ".psm1", ".sql", ".vue",
                          ".svelte", ".proto", ".graphql", ".gql") or \
            lower in ("gemfile", "rakefile", "vagrantfile"):
        return "source", language

    if _ext(filename) in DOC_EXT or DOC_FILE_RE.search(filename):
        return "docs", language

    if CONFIG_FILE_RE.search(filename) or _ext(filename) in CONFIG_EXTS:
        return "config", language

    return "docs" if language in ("markdown", "rst") else "config", language


def is_generated(relpath: str, filename: str) -> bool:
    """True when a path is build output we exclude by default but must record."""
    parts = relpath.split("/")[:-1]
    for part in parts:
        if part in GENERATED_DIRS:
            return True
    if filename in GENERATED_DIRS:
        return True
    return bool(GENERATED_FILE_RE.search(filename))


def sniff(relpath: str, path: str, size: int) -> Tuple[str, Optional[str]]:
    """Decide binary/text. Returns ``(kind, reason)`` where kind is text|binary|unreadable."""
    try:
        with open(path, "rb") as handle:
            chunk = handle.read(SNIFF_BYTES)
    except OSError:
        return "unreadable", "unreadable"
    if not chunk and size > 0:
        return "unreadable", "unreadable"
    if b"\x00" in chunk:
        return "binary", "binary"
    probe = b""
    if size > 0:
        try:
            with open(path, "rb") as handle:
                probe = handle.read(DECODE_PROBE_BYTES)
        except OSError:
            return "unreadable", "unreadable"
    try:
        probe.decode("utf-8")
    except UnicodeDecodeError:
        # Latin-1 always decodes, so a strict UTF-8 failure on the first 64 KiB
        # is the practical signal for "not text we can trust line numbers on".
        return "unreadable", "undecodable"
    return "text", None


def count_lines(path: str) -> Optional[int]:
    try:
        lines = 0
        with open(path, "rb") as handle:
            while True:
                chunk = handle.read(1024 * 256)
                if not chunk:
                    break
                lines += chunk.count(b"\n")
        return lines + 1
    except OSError:
        return None


def file_hash(path: str) -> Optional[str]:
    digest = hashlib.sha256()
    try:
        with open(path, "rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 256), b""):
                digest.update(chunk)
    except OSError:
        return None
    return digest.hexdigest()


# --------------------------------------------------------------------------- #
# Submodules
# --------------------------------------------------------------------------- #

def read_submodules(root: str) -> List[Dict[str, Any]]:
    """Parse .gitmodules. Their content is not in this snapshot, so it is a gap."""
    result: List[Dict[str, Any]] = []
    path = os.path.join(root, ".gitmodules")
    if not os.path.isfile(path):
        return result
    try:
        with open(path, encoding="utf-8", errors="replace") as handle:
            text = handle.read()
    except OSError:
        return result
    current: Dict[str, Any] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("[submodule"):
            if current.get("path"):
                result.append(current)
            # `[submodule "vendor/lib"]` -> vendor/lib. Quoted names are the
            # norm; the bare form is accepted so hand-written files still parse.
            match = re.match(r'\[submodule\s+"([^"]*)"\]', line)
            if match is None:
                match = re.match(r"\[submodule\s+'([^']*)'\]", line)
            current = {"name": match.group(1) if match else line.strip("[]").strip()}
        elif "=" in line:
            key, _, value = line.partition("=")
            key, value = key.strip().lower(), value.strip()
            if key == "path":
                current["path"] = value.replace("\\", "/")
            elif key == "url":
                current["url"] = value
    if current.get("path"):
        result.append(current)
    result.sort(key=lambda item: item.get("path", ""))
    return result


def _contains_submodule(relpath: str, submodule_paths: set) -> bool:
    """True when ``relpath`` is a submodule checkout or an ancestor of one."""
    for path in submodule_paths:
        if path == relpath or path.startswith(relpath + "/"):
            return True
    return False


# --------------------------------------------------------------------------- #
# Git metadata
# --------------------------------------------------------------------------- #

def _git(root: str, *args: str, timeout: int = 15) -> Optional[str]:
    """Run one read-only git command. ``--no-optional-locks`` forbids index writes."""
    try:
        proc = subprocess.run(
            ["git", "--no-optional-locks", "-C", root, *args],
            capture_output=True, text=True, timeout=timeout, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0:
        return None
    return proc.stdout.strip()


def git_state(root: str) -> Dict[str, Any]:
    """Capture the snapshot identity. Missing git is a limitation, not an error."""
    state: Dict[str, Any] = {
        "is_repository": False, "branch": None, "commit": None, "commit_short": None,
        "dirty": None, "dirty_files": [], "remote": None, "describe": None,
        "unborn": False, "error": None,
    }
    toplevel = _git(root, "rev-parse", "--show-toplevel")
    if toplevel is None:
        state["error"] = "not a git repository, or git is unavailable"
        return state
    state["is_repository"] = True
    state["work_tree"] = toplevel.replace("\\", "/")
    state["branch"] = _git(root, "rev-parse", "--abbrev-ref", "HEAD")
    commit = _git(root, "rev-parse", "HEAD")
    if commit is None:
        state["unborn"] = True
    else:
        state["commit"] = commit
        state["commit_short"] = commit[:12]
        state["describe"] = _git(root, "describe", "--tags", "--always", "--dirty")
    status = _git(root, "status", "--porcelain", "--untracked-files=no")
    if status is not None:
        lines = [line for line in status.splitlines() if line.strip()]
        state["dirty"] = bool(lines)
        state["dirty_files"] = lines[:200]
        state["dirty_truncated"] = len(lines) > 200
    state["remote"] = _git(root, "config", "--get", "remote.origin.url")
    return state


# --------------------------------------------------------------------------- #
# Walk
# --------------------------------------------------------------------------- #

def _read_text(path: str) -> str:
    try:
        with open(path, encoding="utf-8", errors="replace") as handle:
            return handle.read()
    except OSError:
        return ""


def inventory(
    root: str,
    extra_excludes: Sequence[str] = (),
    max_bytes: int = DEFAULT_MAX_BYTES,
    with_hashes: bool = False,
    include_generated: bool = False,
) -> Dict[str, Any]:
    """Walk ``root`` once and produce the inventory document."""
    root = os.path.abspath(root)
    if not os.path.isdir(root):
        raise SystemExit(f"error: not a directory: {root}")

    root_pairs: List[Tuple[str, str]] = []
    gitignore = os.path.join(root, ".gitignore")
    if os.path.isfile(gitignore):
        root_pairs.append(("", _read_text(gitignore)))
    info_exclude = os.path.join(root, ".git", "info", "exclude")
    if os.path.isfile(info_exclude):
        root_pairs.append(("", _read_text(info_exclude)))
    if extra_excludes:
        root_pairs.append(("", "\n".join(extra_excludes)))
    ignore = IgnoreStack(root_pairs)

    submodule_paths = {item["path"] for item in read_submodules(root)}

    files: List[Dict[str, Any]] = []
    not_analysed: List[Dict[str, Any]] = []
    excluded: List[Dict[str, Any]] = []
    limitations: List[str] = []
    total_bytes = 0

    def record(relpath: str, abspath: str, filename: str, size: int) -> None:
        nonlocal total_bytes
        bucket, language = classify(relpath, filename)
        kind, reason = sniff(relpath, abspath, size)
        entry: Dict[str, Any] = {
            "path": relpath,
            "bucket": bucket,
            "language": language,
            "size": size,
            "binary": kind == "binary",
        }
        if kind == "text":
            entry["lines"] = count_lines(abspath)
            if with_hashes:
                entry["sha256"] = file_hash(abspath)
        else:
            entry["lines"] = None
            if kind == "unreadable":
                bucket = "unreadable"
                entry["bucket"] = "unreadable"
            elif bucket not in ("binary",):
                bucket = "binary"
                entry["bucket"] = "binary"
        if size > max_bytes:
            not_analysed.append({"path": relpath, "reason": "too_large", "size": size})
            entry["too_large"] = True
        elif kind in ("binary", "unreadable"):
            not_analysed.append({"path": relpath, "reason": reason or kind})
        files.append(entry)
        total_bytes += size

    def walk(dir_abs: str, dir_rel: str) -> None:
        try:
            entries = sorted(os.scandir(dir_abs), key=lambda e: e.name)
        except OSError:
            limitations.append(f"cannot list directory: {dir_rel or '.'}")
            return
        for entry in entries:
            name = entry.name
            if name == ".git":
                continue
            relpath = f"{dir_rel}/{name}" if dir_rel else name
            try:
                is_dir = entry.is_dir(follow_symlinks=False)
                is_symlink = entry.is_symlink()
            except OSError:
                not_analysed.append({"path": relpath, "reason": "unreadable"})
                files.append({"path": relpath, "bucket": "unreadable", "language": None,
                              "size": 0, "binary": False, "lines": None})
                continue

            if is_symlink and not is_dir:
                try:
                    target_ok = os.path.exists(entry.path)
                except OSError:
                    target_ok = False
                if not target_ok:
                    not_analysed.append({"path": relpath, "reason": "unreadable"})
                    files.append({"path": relpath, "bucket": "unreadable", "language": None,
                                  "size": 0, "binary": False, "lines": None})
                    limitations.append(f"broken symlink: {relpath}")
                    continue

            if relpath in submodule_paths:
                continue            # accounted for in `submodules`

            if is_dir:
                if _contains_submodule(relpath, submodule_paths):
                    # The directory holds submodule checkouts: their content is
                    # not part of this snapshot, so label it accurately instead
                    # of letting it look like a generated-output exclude.
                    excluded.append({"path": relpath, "reason": "submodule", "kind": "directory"})
                    continue
                if ignore.ignored(relpath, True):
                    excluded.append({"path": relpath, "reason": "excluded", "kind": "directory"})
                    continue
                if not include_generated and name in GENERATED_DIRS:
                    excluded.append({"path": relpath, "reason": "generated", "kind": "directory"})
                    continue
                nested = os.path.join(dir_abs, name, ".gitignore")
                pushed = False
                if os.path.isfile(nested):
                    ignore.push(relpath, _read_text(nested))
                    pushed = True
                walk(entry.path, relpath)
                if pushed:
                    ignore.pop()
                continue

            if not entry.is_file(follow_symlinks=True):
                continue
            if ignore.ignored(relpath, False):
                excluded.append({"path": relpath, "reason": "excluded", "kind": "file"})
                continue
            if not include_generated and is_generated(relpath, name):
                excluded.append({"path": relpath, "reason": "generated", "kind": "file"})
                continue
            try:
                size = entry.stat(follow_symlinks=True).st_size
            except OSError:
                size = 0
            record(relpath, entry.path, name, size)

    walk(root, "")

    files.sort(key=lambda item: item["path"])
    not_analysed.sort(key=lambda item: (item["path"], item["reason"]))
    excluded.sort(key=lambda item: item["path"])

    buckets: Dict[str, int] = {}
    languages: Dict[str, Dict[str, Any]] = {}
    for item in files:
        buckets[item["bucket"]] = buckets.get(item["bucket"], 0) + 1
        if item["bucket"] in ("binary", "unreadable"):
            continue
        lang = item.get("language") or "unknown"
        slot = languages.setdefault(lang, {"language": lang, "files": 0, "bytes": 0, "lines": 0})
        slot["files"] += 1
        slot["bytes"] += item["size"]
        slot["lines"] += item.get("lines") or 0

    language_rows = sorted(languages.values(), key=lambda row: (-row["bytes"], row["language"]))
    for row in language_rows:
        row["share"] = round(row["bytes"] / total_bytes, 4) if total_bytes else 0.0

    # Source-only census: the report's "what is this written in" claim should not
    # be diluted by YAML, JSON and Markdown counts.
    source_languages: Dict[str, int] = {}
    source_bytes: Dict[str, int] = {}
    for item in files:
        if item["bucket"] != "source":
            continue
        lang = item.get("language") or "unknown"
        source_languages[lang] = source_languages.get(lang, 0) + 1
        source_bytes[lang] = source_bytes.get(lang, 0) + item["size"]
    source_rows = [
        {"language": lang, "files": count, "bytes": source_bytes[lang]}
        for lang, count in source_languages.items()
    ]
    source_rows.sort(key=lambda row: (-row["files"], row["language"]))

    manifests = []
    for item in files:
        if item["bucket"] != "manifest":
            continue
        name = os.path.basename(item["path"])
        for regex, kind, ecosystem in _MANIFEST_RES:
            if regex.search(name):
                manifests.append({"path": item["path"], "kind": kind, "ecosystem": ecosystem,
                                  "size": item["size"]})
                break

    submodules = []
    for item in read_submodules(root):
        path = item.get("path", "")
        present = os.path.isdir(os.path.join(root, path))
        linked = os.path.isfile(os.path.join(root, path, ".git")) or \
            os.path.isdir(os.path.join(root, path, ".git"))
        submodules.append({
            "path": path, "name": item.get("name"), "url": item.get("url"),
            "checked_out": bool(present and linked),
        })
        not_analysed.append({"path": path, "reason": "submodule"})

    if submodules:
        limitations.append(f"{len(submodules)} submodule(s) not analysed: their content is not "
                           f"part of this snapshot")
    if not_analysed:
        counts: Dict[str, int] = {}
        for item in not_analysed:
            counts[item["reason"]] = counts.get(item["reason"], 0) + 1
        limitations.append("files not analysed: " + ", ".join(
            f"{reason}={count}" for reason, count in sorted(counts.items())))
    if buckets.get("binary"):
        limitations.append(f"{buckets['binary']} binary file(s) were inventoried but not analysed")
    if buckets.get("unreadable"):
        limitations.append(f"{buckets['unreadable']} unreadable file(s) were inventoried but not "
                           f"analysed")
    if excluded:
        limitations.append(f"{len(excluded)} path(s) excluded by .gitignore or generated-output "
                           f"rules; see `excluded`")

    git = git_state(root)
    if not git["is_repository"]:
        limitations.append("audit target is not a git repository: commit identity and dirty state "
                           "are unavailable, so findings cannot be tied to a snapshot")

    invariant_ok = len(files) == sum(buckets.values())
    if not invariant_ok:                    # defensive: would mean a classification bug
        limitations.append("inventory bookkeeping error: bucket counts do not reconcile")

    # Submodule paths appear in `not_analysed` but are not file entries, so
    # `files_examined` counts by membership rather than by subtraction.
    skipped_paths = {item["path"] for item in not_analysed}
    files_examined = sum(1 for item in files if item["path"] not in skipped_paths)

    return {
        "stage": "inventory",
        "schema_version": SCHEMA_VERSION,
        "tool": {"name": "repository_inventory.py", "version": TOOL_VERSION},
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "root": root,
        "limits": {"max_bytes": max_bytes, "include_generated": include_generated,
                   "excludes": list(extra_excludes)},
        "git": git,
        "totals": {
            "files": len(files),
            "bytes": total_bytes,
            "languages": len(language_rows),
            "manifests": len(manifests),
            "excluded": len(excluded),
            "not_analysed": len(not_analysed),
            "submodules": len(submodules),
            "buckets_reconcile": invariant_ok,
        },
        "buckets": dict(sorted(buckets.items())),
        "languages": language_rows,
        "source_languages": source_rows,
        "manifests": manifests,
        "submodules": submodules,
        "excluded": excluded,
        "not_analysed": not_analysed,
        # Ready to paste into a findings dataset's `coverage` object.
        "coverage": {
            "files_examined": files_examined,
            "files_skipped": not_analysed,
            "limitations": limitations,
        },
        "limitations": limitations,
        "files": files,
    }


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="repository_inventory.py",
        description="Read-only, deterministic file inventory for a security audit (stage 1).",
        epilog="Prints JSON on stdout. Never modifies the audited tree.",
    )
    parser.add_argument("--root", default=".", help="repository root to inventory (default: .)")
    parser.add_argument("--out", help="write JSON here instead of stdout")
    parser.add_argument("--exclude", action="append", default=[], metavar="PATTERN",
                        help="extra .gitignore-style exclusion (repeatable)")
    parser.add_argument("--max-bytes", type=int, default=DEFAULT_MAX_BYTES,
                        help=f"files larger than this are inventoried but not analysed "
                             f"(default {DEFAULT_MAX_BYTES})")
    parser.add_argument("--hash", action="store_true", help="record sha256 per analysed file")
    parser.add_argument("--include-generated", action="store_true",
                        help="walk node_modules/dist/vendor instead of recording them as excluded")
    parser.add_argument("--indent", type=int, default=2, help="JSON indent (default 2)")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    document = inventory(
        root=args.root,
        extra_excludes=args.exclude,
        max_bytes=max(0, args.max_bytes),
        with_hashes=args.hash,
        include_generated=args.include_generated,
    )
    text = json.dumps(document, indent=args.indent, ensure_ascii=False) + "\n"
    if args.out:
        out_dir = os.path.dirname(os.path.abspath(args.out))
        os.makedirs(out_dir, exist_ok=True)
        with open(args.out, "w", encoding="utf-8") as handle:
            handle.write(text)
        print(json.dumps({"written": args.out, "files": document["totals"]["files"],
                          "buckets": document["buckets"]}))
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
