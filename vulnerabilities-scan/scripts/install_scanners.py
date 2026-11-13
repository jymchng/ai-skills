#!/usr/bin/env python3
"""Install the optional external scanners this skill can drive, on this platform.

The audit never installs anything. This script is operator tooling: an audit run
that quietly pip-installed a scanner would break rule 1 of the skill (read-only
with respect to the machine as well as the repository) and would make the
coverage report depend on what the agent decided to fetch that afternoon. So the
installer is a separate, explicit act with a printed plan.

What this script owns
---------------------
* :func:`detect_platform` - OS, distribution, architecture and release, from
  ``platform`` and ``/etc/os-release``, never from a guess about the user agent.
* :func:`detect_managers` - which package managers and language runtimes exist
  on ``PATH`` right now (``apt-get``, ``dnf``, ``pacman``, ``apk``, ``zypper``,
  ``brew``, ``winget``, ``choco``, ``scoop``, ``pipx``, ``pip``, ``go``, ``gem``,
  ``npm``).
* :func:`plan_tool` - the ordered steps to install one scanner here, each step
  naming its manager, its argv, and whether it needs root.
* :func:`apply_steps` - run a plan, stopping at the first failure so a half
  installed toolchain is not reported as complete.
* :func:`verify` - re-probe every requested tool through
  ``scanner_orchestrator.probe``, which is the same code an audit uses. A tool
  this script believes it installed but the orchestrator cannot find is a
  failure, not a success with a caveat.

Why the matrix lives in ``scanner_orchestrator.TOOLS``
------------------------------------------------------
The tool list, the binary names and the version probes already exist there, and
they are what an audit actually needs. A second copy in the installer would drift
on the first rename, so this module imports that table and refuses to run without
it. ``npm-audit`` is the reason the distinction between a tool's *name* and its
*binary* is modelled explicitly: the tool is ``npm-audit``, the binary is ``npm``.

Policy, stated because these are the decisions a reviewer will ask about
-----------------------------------------------------------------------
* **No silent elevation.** A step that needs root is printed with ``sudo`` and
  left for the operator to run, unless ``--allow-sudo`` is passed. Then it is run
  as ``sudo -n`` so a missing password fails instead of hanging a pipeline.
* **No ``curl | sh``.** Downloads are resolved through the release API, extracted
  with path traversal rejected, and installed under ``--prefix`` (default
  ``~/.local/bin``), never over a system directory.
* **Checksums when published, and a flag when not.** A download whose release
  publishes a checksum file is verified; one that does not is refused unless
  ``--allow-unverified`` is passed. Verification is recorded either way.
* **No implicit toolchains.** Go and Ruby are used when present; they are never
  installed as a side effect of installing a scanner. The plan says which tool
  needs them instead.

CLI
---
    python3 scripts/install_scanners.py --list
    python3 scripts/install_scanners.py --check
    python3 scripts/install_scanners.py --dry-run
    python3 scripts/install_scanners.py --only semgrep,bandit
    python3 scripts/install_scanners.py --yes --allow-sudo
    python3 scripts/install_scanners.py --yes --allow-download --prefix ~/bin
    python3 scripts/install_scanners.py --check --json

Exit codes
----------
    0  every requested tool is available, or the plan printed cleanly
    1  at least one requested tool is still unavailable after the run
    2  the request cannot be satisfied here: unsupported platform or a missing
       companion module (``scanner_orchestrator.py``)
"""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import os
import platform as platform_module
import shutil
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from typing import Any, Dict, Iterable, List, Optional, Sequence

VERSION = "1.0.0"

_SCRIPTS_DIR = os.path.dirname(os.path.abspath(__file__))
if _SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, _SCRIPTS_DIR)

try:  # the tool matrix is the audit's, not ours
    import scanner_orchestrator as so  # noqa: E402
except Exception as exc:  # pragma: no cover - import failure is reported, not raised
    so = None  # type: ignore[assignment]
    _IMPORT_ERROR = str(exc)
else:
    _IMPORT_ERROR = ""

MISSING_COMPANION = (
    "scanner_orchestrator.py must sit next to this script: it owns the scanner "
    "matrix (names, binaries, version probes) and this installer only drives it."
)

ALL = ("linux", "macos", "windows")
UNIX = ("linux", "macos")
LINUX = ("linux",)
MACOS = ("macos",)
WINDOWS = ("windows",)

PEP668 = ("on Debian/Ubuntu this may be refused by PEP 668; install pipx from "
          "the distribution instead of pip-installing it")

# --------------------------------------------------------------------------- #
# Platform and manager detection
# --------------------------------------------------------------------------- #

_DISTRO_FAMILIES = {
    "debian": "debian", "ubuntu": "debian", "linuxmint": "debian", "pop": "debian",
    "kali": "debian", "raspbian": "debian", "devuan": "debian", "elementary": "debian",
    "fedora": "fedora", "rhel": "fedora", "centos": "fedora", "rocky": "fedora",
    "almalinux": "fedora", "ol": "fedora", "amzn": "fedora",
    "arch": "arch", "manjaro": "arch", "endeavouros": "arch", "artix": "arch",
    "alpine": "alpine",
    "opensuse": "suse", "opensuse-leap": "suse", "opensuse-tumbleweed": "suse",
    "sles": "suse", "sled": "suse",
}


def _read_os_release(path: str = "/etc/os-release") -> Dict[str, str]:
    """Parse ``/etc/os-release`` without a shell and without a library."""
    values: Dict[str, str] = {}
    try:
        with open(path, encoding="utf-8", errors="replace") as handle:
            for line in handle:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, raw = line.partition("=")
                values[key.strip()] = raw.strip().strip('"').strip("'")
    except OSError:
        return {}
    return values


def detect_platform(sys_platform: Optional[str] = None,
                    machine: Optional[str] = None,
                    os_release: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """Return ``{os, distro, family, arch, release, description}``.

    ``sys_platform``/``machine``/``os_release`` are injectable so the plan can be
    tested for Windows and macOS on a Linux host, and so a container that
    misreports ``uname`` can be corrected by an operator reading the output.
    """
    raw = (sys_platform or sys.platform).lower()
    if raw.startswith("win") or raw == "cygwin":
        os_name = "windows"
    elif raw == "darwin":
        os_name = "macos"
    elif raw.startswith("linux"):
        os_name = "linux"
    else:
        os_name = "unknown"

    release = os_release if os_release is not None else (
        _read_os_release() if os_name == "linux" else {})
    distro = (release.get("ID") or "").lower()
    family = _DISTRO_FAMILIES.get(distro, distro or (os_name if os_name != "unknown" else ""))

    arch_raw = (machine or platform_module.machine() or "").lower()
    if arch_raw in ("x86_64", "amd64", "x64"):
        arch = "x86_64"
    elif arch_raw in ("aarch64", "arm64"):
        arch = "arm64"
    elif arch_raw in ("armv7l", "armv6l", "armhf"):
        arch = "armv7"
    else:
        arch = arch_raw or "unknown"

    return {
        "os": os_name,
        "distro": distro,
        "family": family,
        "arch": arch,
        "release": release.get("VERSION_ID") or "",
        "description": release.get("PRETTY_NAME") or raw,
    }


#: manager id -> the executable that proves it is usable
MANAGER_BINARIES: Dict[str, str] = {
    "apt": "apt-get",
    "dnf": "dnf",
    "pacman": "pacman",
    "apk": "apk",
    "zypper": "zypper",
    "brew": "brew",
    "winget": "winget",
    "choco": "choco",
    "scoop": "scoop",
    "pipx": "pipx",
    "pip": "pip3",
    "go": "go",
    "gem": "gem",
    "npm": "npm",
    "node": "node",
    "download": "python3",
}


def detect_managers(which: Any = None) -> Dict[str, bool]:
    """Which managers exist on ``PATH`` right now.

    ``which`` is injectable so tests can describe a Debian host, a macOS laptop
    and a Windows runner without owning any of them.
    """
    lookup = which or shutil.which
    managers: Dict[str, bool] = {}
    for manager, binary in MANAGER_BINARIES.items():
        if manager == "download":
            managers[manager] = True  # urllib; nothing to install first
        elif manager == "pip":
            managers[manager] = bool(lookup(binary) or lookup("pip"))
        else:
            managers[manager] = bool(lookup(binary))
    return managers


# --------------------------------------------------------------------------- #
# Recipes: one entry per scanner, ordered by preference
# --------------------------------------------------------------------------- #

def _step(manager: str, platforms: Sequence[str], argv: Sequence[Sequence[str]],
          *, needs_root: bool = False, note: str = "") -> Dict[str, Any]:
    return {
        "manager": manager,
        "platforms": tuple(platforms),
        "argv": [list(item) for item in argv],
        "needs_root": bool(needs_root),
        "note": note,
    }


#: How each tool is installed, best method first. A method is usable when its
#: platform matches and its manager is present; the first usable one wins, which
#: is why brew precedes go on macOS and pipx precedes pip everywhere.
RECIPES: Dict[str, List[Dict[str, Any]]] = {
    "bandit": [
        _step("pipx", ALL, [["pipx", "install", "bandit"]]),
        _step("brew", MACOS, [["brew", "install", "bandit"]]),
        _step("apt", LINUX, [["apt-get", "install", "-y", "bandit"]],
              needs_root=True, note="distribution package; may lag upstream"),
        _step("dnf", LINUX, [["dnf", "install", "-y", "python3-bandit"]],
              needs_root=True, note="distribution package; may lag upstream"),
        _step("pacman", LINUX, [["pacman", "-S", "--noconfirm", "bandit"]], needs_root=True),
        _step("apk", LINUX, [["apk", "add", "--no-cache", "py3-bandit"]], needs_root=True),
        _step("pip", UNIX, [["{python}", "-m", "pip", "install", "--user", "bandit"]],
              note=PEP668),
    ],
    "brakeman": [
        _step("gem", ALL, [["gem", "install", "brakeman", "--no-document"]]),
        _step("brew", MACOS, [["brew", "install", "brakeman"]]),
        _step("apt", LINUX, [["apt-get", "install", "-y", "ruby-brakeman"]],
              needs_root=True, note="distribution package"),
    ],
    "checkov": [
        _step("pipx", ALL, [["pipx", "install", "checkov"]]),
        _step("brew", MACOS, [["brew", "install", "checkov"]]),
        _step("pip", UNIX, [["{python}", "-m", "pip", "install", "--user", "checkov"]],
              note=PEP668),
    ],
    "gitleaks": [
        _step("brew", MACOS, [["brew", "install", "gitleaks"]]),
        _step("winget", WINDOWS, [["winget", "install", "--id", "Gitleaks.Gitleaks",
                                   "-e", "--source", "winget"]]),
        _step("choco", WINDOWS, [["choco", "install", "gitleaks", "-y"]]),
        _step("scoop", WINDOWS, [["scoop", "install", "gitleaks"]]),
        _step("pacman", LINUX, [["pacman", "-S", "--noconfirm", "gitleaks"]], needs_root=True),
        _step("go", ALL, [["go", "install", "github.com/gitleaks/gitleaks/v8@latest"]],
              note="installs into $(go env GOPATH)/bin, which must be on PATH"),
        _step("download", ALL, [], note="GitHub release, installed under --prefix"),
    ],
    "gosec": [
        _step("brew", MACOS, [["brew", "install", "gosec"]]),
        _step("go", ALL, [["go", "install", "github.com/securego/gosec/v2/cmd/gosec@latest"]],
              note="installs into $(go env GOPATH)/bin, which must be on PATH"),
        _step("download", ALL, [], note="GitHub release, installed under --prefix"),
    ],
    "npm-audit": [
        _step("node", ALL, [], note="npm audit ships with Node.js; nothing else to install"),
        _step("npm", ALL, [], note="npm audit ships with Node.js; nothing else to install"),
    ],
    "osv-scanner": [
        _step("brew", MACOS, [["brew", "install", "osv-scanner"]]),
        _step("winget", WINDOWS, [["winget", "install", "--id", "Google.OSVScanner",
                                   "-e", "--source", "winget"]]),
        _step("pacman", LINUX, [["pacman", "-S", "--noconfirm", "osv-scanner"]],
              needs_root=True),
        _step("go", ALL, [["go", "install", "github.com/google/osv-scanner/v2/cmd/osv-scanner@latest"]],
              note="installs into $(go env GOPATH)/bin, which must be on PATH"),
        _step("download", ALL, [], note="GitHub release, installed under --prefix"),
    ],
    "pip-audit": [
        _step("pipx", ALL, [["pipx", "install", "pip-audit"]]),
        _step("brew", MACOS, [["brew", "install", "pip-audit"]]),
        _step("apt", LINUX, [["apt-get", "install", "-y", "pip-audit"]], needs_root=True),
        _step("pip", UNIX, [["{python}", "-m", "pip", "install", "--user", "pip-audit"]],
              note=PEP668),
    ],
    "semgrep": [
        _step("pipx", ALL, [["pipx", "install", "semgrep"]]),
        _step("brew", MACOS, [["brew", "install", "semgrep"]]),
        _step("pip", UNIX, [["{python}", "-m", "pip", "install", "--user", "semgrep"]],
              note=PEP668),
    ],
    "trivy": [
        _step("brew", MACOS, [["brew", "install", "aquasecurity/trivy/trivy"]]),
        _step("winget", WINDOWS, [["winget", "install", "--id", "AquaSecurity.Trivy",
                                   "-e", "--source", "winget"]]),
        _step("choco", WINDOWS, [["choco", "install", "trivy", "-y"]]),
        _step("scoop", WINDOWS, [["scoop", "install", "trivy"]]),
        _step("pacman", LINUX, [["pacman", "-S", "--noconfirm", "trivy"]], needs_root=True),
        # Debian and Fedora do not ship trivy: apt-get/dnf only work after the
        # Aqua repository is configured, which is documented rather than done
        # silently here, so the release binary is the better default.
        _step("download", ALL, [], note="GitHub release, installed under --prefix"),
        _step("apt", LINUX, [["apt-get", "install", "-y", "trivy"]], needs_root=True,
              note="only after the aquasecurity apt repository is configured: "
                   "see references/scanner-reference.md"),
        _step("dnf", LINUX, [["dnf", "install", "-y", "trivy"]], needs_root=True,
              note="only after the aquasecurity yum repository is configured: "
                   "see references/scanner-reference.md"),
    ],
}

#: Tools that need a runtime which is deliberately *not* installed for them:
#: adding a Go toolchain as a side effect of wanting gosec is a bigger decision
#: than an installer should take on the operator's behalf.
TOOLCHAIN_NOTES = {
    "go": "the Go toolchain (https://go.dev/dl/) provides gosec, gitleaks and osv-scanner",
    "gem": "Ruby (https://www.ruby-lang.org/) provides brakeman",
    "node": "Node.js (https://nodejs.org/) provides npm audit",
}

#: How to get pipx itself, when it is the missing link. Ordered like RECIPES.
PIPX_INSTALLERS: List[Dict[str, Any]] = [
    _step("apt", LINUX, [["apt-get", "install", "-y", "pipx"], ["pipx", "ensurepath"]],
          needs_root=True),
    _step("dnf", LINUX, [["dnf", "install", "-y", "pipx"], ["pipx", "ensurepath"]],
          needs_root=True),
    _step("pacman", LINUX, [["pacman", "-S", "--noconfirm", "python-pipx"],
                             ["pipx", "ensurepath"]], needs_root=True),
    _step("apk", LINUX, [["apk", "add", "--no-cache", "py3-pip"],
                          ["{python}", "-m", "pip", "install", "--user", "pipx"],
                          ["{python}", "-m", "pipx", "ensurepath"]], needs_root=True),
    _step("zypper", LINUX, [["zypper", "--non-interactive", "install", "python3-pipx"]],
          needs_root=True),
    _step("brew", MACOS, [["brew", "install", "pipx"], ["pipx", "ensurepath"]]),
    _step("pip", ALL, [["{python}", "-m", "pip", "install", "--user", "pipx"],
                       ["{python}", "-m", "pipx", "ensurepath"]], note=PEP668),
]

#: How to get a Node.js that carries npm, for npm-audit.
NODE_INSTALLERS: List[Dict[str, Any]] = [
    _step("apt", LINUX, [["apt-get", "install", "-y", "nodejs", "npm"]], needs_root=True),
    _step("dnf", LINUX, [["dnf", "install", "-y", "nodejs", "npm"]], needs_root=True),
    _step("pacman", LINUX, [["pacman", "-S", "--noconfirm", "nodejs", "npm"]], needs_root=True),
    _step("apk", LINUX, [["apk", "add", "--no-cache", "nodejs", "npm"]], needs_root=True),
    _step("zypper", LINUX, [["zypper", "--non-interactive", "install", "nodejs", "npm"]],
          needs_root=True),
    _step("brew", MACOS, [["brew", "install", "node"]]),
    _step("winget", WINDOWS, [["winget", "install", "--id", "OpenJS.NodeJS.LTS",
                               "-e", "--source", "winget"]]),
    _step("choco", WINDOWS, [["choco", "install", "nodejs-lts", "-y"]]),
    _step("scoop", WINDOWS, [["scoop", "install", "nodejs-lts"]]),
]


# --------------------------------------------------------------------------- #
# Planning
# --------------------------------------------------------------------------- #

def _platform_applies(step: Dict[str, Any], plat: Dict[str, Any]) -> bool:
    return plat["os"] in step["platforms"]


def _manager_present(step: Dict[str, Any], managers: Dict[str, bool],
                     plat: Dict[str, Any], *, bootstrap: bool = True) -> bool:
    """Can this step's manager be made to exist here?

    ``pipx`` and ``node`` are the two managers this installer can create for
    itself, so a host with only apt still has a viable way to install semgrep.
    The recursive ``_pick`` is depth-limited by ``bootstrap``: the bootstrappers
    below never depend on pipx or node, so one level is all that is needed.
    """
    manager = step["manager"]
    if manager == "download":
        return True
    if manager == "pipx":
        if managers.get("pipx"):
            return True
        return bool(bootstrap and _pick(PIPX_INSTALLERS, plat, managers,
                                        bootstrap=False))
    if manager == "node":
        if managers.get("node") or managers.get("npm"):
            return True
        return bool(bootstrap and _pick(NODE_INSTALLERS, plat, managers,
                                        bootstrap=False))
    return bool(managers.get(manager))


def _pick(steps: Sequence[Dict[str, Any]], plat: Dict[str, Any],
          managers: Dict[str, bool], *, bootstrap: bool = True) -> Optional[Dict[str, Any]]:
    for step in steps:
        if _platform_applies(step, plat) and _manager_present(step, managers, plat,
                                                              bootstrap=bootstrap):
            return step
    return None


def _manual_hint(tool: str, plat: Dict[str, Any]) -> str:
    """A precise sentence for the case where no manager can do it here."""
    needs = ""
    for step in RECIPES.get(tool, []):
        if step["manager"] in TOOLCHAIN_NOTES and _platform_applies(step, plat):
            needs = " Needs %s." % TOOLCHAIN_NOTES[step["manager"]]
            break
    return ("No supported package manager on this host can install %s.%s "
            "Install the runtime above, or pass --allow-download."
            % (tool, needs))


def plan_tool(tool_name: str, plat: Dict[str, Any], managers: Dict[str, bool],
              *, prefix: str = "~/.local/bin", allow_download: bool = False,
              allow_unverified: bool = False) -> Dict[str, Any]:
    """Return the ordered steps to install one tool on this host.

    The result always carries ``tool``, ``binary``, ``method``, ``steps`` and
    ``status``. ``status`` is one of ``planned`` (steps exist), ``present`` (the
    binary is already on PATH), ``manual`` (nothing can do it here, with a
    reason) or ``refused`` (a download was required but not permitted).
    """
    target = so.TOOL_INDEX.get(tool_name) if so else None
    if target is None:
        return {"tool": tool_name, "binary": tool_name, "method": None, "steps": [],
                "status": "manual", "reason": "not in scanner_orchestrator.TOOLS"}

    binary = target.get("binary") or tool_name
    record: Dict[str, Any] = {
        "tool": tool_name,
        "binary": binary,
        "kind": target.get("kind"),
        "network": bool(target.get("network")),
        "method": None,
        "steps": [],
        "status": "planned",
        "reason": None,
    }
    if shutil.which(binary):
        record.update(status="present", method="already-installed")
        return record

    chosen = _pick(RECIPES.get(tool_name, []), plat, managers)
    if chosen is None:
        record.update(status="manual", reason=_manual_hint(tool_name, plat))
        return record

    if chosen["manager"] == "download":
        if not allow_download:
            record.update(status="refused",
                          method="download",
                          reason="needs --allow-download (a GitHub release, not a package)")
            return record
        plan = [{"manager": "download", "argv": ["<download>", tool_name],
                 "needs_root": False,
                 "note": "verified when the release publishes a checksum; "
                         "otherwise --allow-unverified is required"}]
        if allow_unverified:
            plan[0]["note"] += " (unverified downloads permitted)"
        record.update(method="download", steps=plan)
        return record

    # A toolchain that is present but whose binary lives outside PATH is the
    # most common Linux failure; say so instead of a bare "installed".
    steps: List[Dict[str, Any]] = []
    if chosen["manager"] == "pipx" and not managers.get("pipx"):
        bootstrap = _pick(PIPX_INSTALLERS, plat, managers)
        if bootstrap is None:
            record.update(status="manual", method="pipx",
                          reason="pipx is missing and no manager here can install it")
            return record
        steps.extend({"manager": bootstrap["manager"], "argv": list(argv),
                      "needs_root": bootstrap["needs_root"],
                      "note": "prerequisite: " + (bootstrap["note"] or "install pipx")}
                     for argv in bootstrap["argv"])

    if chosen["manager"] == "node" and not (managers.get("node") or managers.get("npm")):
        bootstrap = _pick(NODE_INSTALLERS, plat, managers)
        if bootstrap is None:
            record.update(status="manual", method="node",
                          reason="Node.js is missing and no manager here can install it")
            return record
        steps.extend({"manager": bootstrap["manager"], "argv": list(argv),
                      "needs_root": bootstrap["needs_root"],
                      "note": "prerequisite: " + (bootstrap["note"] or "install Node.js")}
                     for argv in bootstrap["argv"])

    for argv in chosen["argv"]:
        steps.append({"manager": chosen["manager"], "argv": list(argv),
                      "needs_root": chosen["needs_root"],
                      "note": chosen["note"]})
    if not steps:  # npm/node: the binary is the runtime, nothing to run
        steps.append({"manager": chosen["manager"], "argv": [],
                      "needs_root": False, "note": chosen["note"]})
    record.update(method=chosen["manager"], steps=steps)
    return record


def render_argv(argv: Sequence[str], *, python: str) -> List[str]:
    """Substitute the placeholders a recipe may use in its argv."""
    rendered: List[str] = []
    for item in argv:
        rendered.append(str(item).format(python=python))
    return rendered


def shell_line(argv: Sequence[str], needs_root: bool, *, allow_sudo: bool = False) -> str:
    """The copy-pasteable command for a step, elevation included when needed.

    Privilege is decided by :func:`_is_root` in exactly one place, so what is
    printed and what is executed can never disagree about whether sudo is
    required.
    """
    words = list(argv)
    if needs_root and not _is_root():
        words = ["sudo"] + words
    return " ".join(words)


def build_plan(tools: Sequence[str], plat: Dict[str, Any], managers: Dict[str, bool],
               *, prefix: str = "~/.local/bin", allow_download: bool = False,
               allow_unverified: bool = False) -> Dict[str, Any]:
    """The whole plan, in the argument order given (sorted for determinism)."""
    records = [plan_tool(name, plat, managers, prefix=prefix,
                         allow_download=allow_download,
                         allow_unverified=allow_unverified)
               for name in sorted(dict.fromkeys(tools))]
    counts: Dict[str, int] = {}
    for record in records:
        counts[record["status"]] = counts.get(record["status"], 0) + 1
    return {
        "platform": plat,
        "managers": {k: v for k, v in sorted(managers.items()) if v},
        "tools": records,
        "summary": {
            "requested": len(records),
            "present": counts.get("present", 0),
            "planned": counts.get("planned", 0),
            "refused": counts.get("refused", 0),
            "manual": counts.get("manual", 0),
        },
    }


# --------------------------------------------------------------------------- #
# Release downloads
# --------------------------------------------------------------------------- #

#: Repository and asset naming per tool. Asset names are not uniform across
#: projects (case, separators and arch words differ), so each tool declares its
#: own pattern rather than hoping for a convention that does not exist.
RELEASES: Dict[str, Dict[str, Any]] = {
    "gitleaks": {
        "repo": "gitleaks/gitleaks",
        "patterns": {"linux": "gitleaks_{ver}_linux_{arch}.tar.gz",
                     "macos": "gitleaks_{ver}_darwin_{arch}.tar.gz",
                     "windows": "gitleaks_{ver}_windows_{arch}.zip"},
        "arch": {"x86_64": "x64", "arm64": "arm64", "armv7": "armv7"},
        "binary": "gitleaks",
        "checksums": ("*checksums*",),
    },
    "gosec": {
        "repo": "securego/gosec",
        "patterns": {"linux": "gosec_{ver}_linux_{arch}.tar.gz",
                     "macos": "gosec_{ver}_darwin_{arch}.tar.gz",
                     "windows": "gosec_{ver}_windows_{arch}.zip"},
        "arch": {"x86_64": "amd64", "arm64": "arm64", "armv7": "armv6"},
        "binary": "gosec",
        "checksums": ("*checksums*",),
    },
    "osv-scanner": {
        "repo": "google/osv-scanner",
        "patterns": {"linux": "osv-scanner_{os}_{arch}",
                     "macos": "osv-scanner_{os}_{arch}",
                     "windows": "osv-scanner_{os}_{arch}.exe"},
        "os": {"linux": "linux", "macos": "darwin", "windows": "windows"},
        "arch": {"x86_64": "amd64", "arm64": "arm64"},
        "binary": "osv-scanner",
        "checksums": ("*checksums*", "*.sha256*"),
    },
    "trivy": {
        "repo": "aquasecurity/trivy",
        "patterns": {"linux": "trivy_{ver}_Linux-{arch}.tar.gz",
                     "macos": "trivy_{ver}_macOS-{arch}.tar.gz",
                     "windows": "trivy_{ver}_windows-{arch}.zip"},
        "arch": {"x86_64": "64bit", "arm64": "ARM64"},
        "binary": "trivy",
        "checksums": ("*checksums*",),
    },
}


def select_asset(tool: str, plat: Dict[str, Any], version: str,
                 asset_names: Iterable[str]) -> Optional[str]:
    """Pick the release asset for this platform, or None.

    Kept pure so the per-project naming can be tested against a canned release
    payload; nothing here touches the network.
    """
    spec = RELEASES.get(tool)
    if not spec:
        return None
    pattern = spec["patterns"].get(plat["os"])
    arch = spec.get("arch", {}).get(plat["arch"])
    if not pattern or not arch:
        return None
    wanted = pattern.format(ver=version, arch=arch,
                            os=spec.get("os", {}).get(plat["os"], plat["os"])).lower()
    for name in asset_names:
        if name.lower() == wanted:
            return name
    for name in asset_names:  # tolerate a version prefix inside the asset name
        if wanted in name.lower():
            return name
    return None


def select_checksum_asset(tool: str, asset_names: Iterable[str]) -> Optional[str]:
    """The checksum file for a release, when the project publishes one."""
    spec = RELEASES.get(tool) or {}
    patterns = spec.get("checksums") or ()
    for name in sorted(asset_names):
        for pattern in patterns:
            if fnmatch.fnmatch(name.lower(), pattern):
                return name
    return None


def _safe_members(names: Iterable[str]) -> List[str]:
    """Reject absolute paths, parent traversal and drive separators."""
    safe: List[str] = []
    for name in names:
        normalised = name.replace("\\", "/")
        if normalised.startswith("/") or ".." in normalised.split("/"):
            raise ValueError("unsafe archive member: %s" % name)
        if len(normalised) > 1 and normalised[1] == ":":
            raise ValueError("unsafe archive member: %s" % name)
        safe.append(name)
    return safe


def extract_binary(archive: str, binary: str, dest_dir: str) -> str:
    """Extract ``binary`` from a release archive into ``dest_dir`` safely.

    Supports ``.tar.gz``/``.tgz``, ``.zip`` and a bare executable. The archive
    member list is validated before anything is written, so a crafted release
    cannot escape ``dest_dir``.
    """
    os.makedirs(dest_dir, exist_ok=True)
    target = os.path.join(dest_dir, binary)
    lower = archive.lower()
    if lower.endswith((".tar.gz", ".tgz")):
        with tarfile.open(archive, "r:gz") as handle:
            members = handle.getmembers()
            _safe_members(member.name for member in members)
            wanted = [m for m in members
                      if m.isfile() and os.path.basename(m.name) == binary]
            if not wanted:
                raise ValueError("archive does not contain %s" % binary)
            source = handle.extractfile(wanted[0])
            if source is None:
                raise ValueError("archive member %s is not readable" % binary)
            with open(target, "wb") as out:
                out.write(source.read())
    elif lower.endswith(".zip"):
        with zipfile.ZipFile(archive) as handle:
            names = handle.namelist()
            _safe_members(names)
            wanted = [n for n in names
                      if os.path.basename(n.replace("\\", "/")) in (binary, binary + ".exe")]
            if not wanted:
                raise ValueError("archive does not contain %s" % binary)
            with handle.open(wanted[0]) as source, open(target, "wb") as out:
                out.write(source.read())
    else:
        shutil.copyfile(archive, target)
    os.chmod(target, 0o755)
    return target


def _http_get(url: str, *, timeout: float = 30.0, limit: int = 64 * 1024 * 1024) -> bytes:
    """Fetch a URL with a size limit, using only the standard library."""
    import urllib.request  # imported here so ``--list`` never needs it

    request = urllib.request.Request(url, headers={"User-Agent": "vulnerabilities-scan-installer"})
    with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
        data = response.read(limit + 1)
    if len(data) > limit:
        raise ValueError("response exceeded %d bytes" % limit)
    return data


def _release_payload(tool: str, *, timeout: float = 30.0) -> Dict[str, Any]:
    spec = RELEASES[tool]
    url = "https://api.github.com/repos/%s/releases/latest" % spec["repo"]
    payload = json.loads(_http_get(url, timeout=timeout).decode("utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("unexpected release payload for %s" % tool)
    return payload


def download_tool(tool: str, plat: Dict[str, Any], prefix: str, *,
                  allow_unverified: bool = False, timeout: float = 30.0) -> Dict[str, Any]:
    """Download, verify and install one tool's release binary under ``prefix``.

    Returns ``{status, path, version, verified, reason}``. ``status`` is
    ``installed``, ``manual`` (nothing to download for this platform) or
    ``refused`` (no checksum was published and ``--allow-unverified`` was not
    given).
    """
    spec = RELEASES.get(tool)
    if not spec:
        return {"status": "manual", "path": None, "version": None,
                "verified": False, "reason": "no release recipe for %s" % tool}
    payload = _release_payload(tool, timeout=timeout)
    version = str(payload.get("tag_name") or "").lstrip("v")
    assets = [asset for asset in payload.get("assets") or [] if isinstance(asset, dict)]
    names = [str(asset.get("name")) for asset in assets]
    chosen = select_asset(tool, plat, version, names)
    if not chosen:
        return {"status": "manual", "path": None, "version": version or None,
                "verified": False,
                "reason": "release %s publishes no asset for %s/%s"
                          % (version or "?", plat["os"], plat["arch"])}

    chosen_url = next((asset.get("browser_download_url") for asset in assets
                       if str(asset.get("name")) == chosen), None)
    if not chosen_url:
        return {"status": "manual", "path": None, "version": version or None,
                "verified": False, "reason": "release asset has no download URL"}

    digest_asset = select_checksum_asset(tool, names)
    digest_url = next((asset.get("browser_download_url") for asset in assets
                       if str(asset.get("name")) == digest_asset), None) if digest_asset else None
    if not digest_url and not allow_unverified:
        return {"status": "refused", "path": None, "version": version,
                "verified": False,
                "reason": "release %s publishes no checksum file; pass --allow-unverified "
                          "to accept an unverified download" % version}

    payload_bytes = _http_get(chosen_url, timeout=timeout)
    verified = False
    if digest_url:
        manifest = _http_get(digest_url, timeout=timeout).decode("utf-8", "replace")
        expected = None
        for line in manifest.splitlines():
            parts = line.split()
            if len(parts) >= 2 and os.path.basename(parts[-1].lstrip("*")) == chosen:
                expected = parts[0].lower()
                break
        actual = hashlib.sha256(payload_bytes).hexdigest()
        if expected and expected != actual:
            return {"status": "refused", "path": None, "version": version,
                    "verified": False,
                    "reason": "checksum mismatch for %s: expected %s, got %s"
                              % (chosen, expected, actual)}
        verified = bool(expected)

    target_dir = os.path.abspath(os.path.expanduser(prefix))
    with tempfile.TemporaryDirectory() as staging:
        local = os.path.join(staging, chosen)
        with open(local, "wb") as handle:
            handle.write(payload_bytes)
        installed = extract_binary(local, spec["binary"], target_dir)
    return {"status": "installed", "path": installed, "version": version or None,
            "verified": verified, "reason": None}


# --------------------------------------------------------------------------- #
# Applying a plan
# --------------------------------------------------------------------------- #

def _run(argv: Sequence[str], *, timeout: float) -> Dict[str, Any]:
    """Run one argv, escalating only to ``sudo -n`` and only when permitted."""
    words = list(argv)
    if not words:
        return {"argv": words, "returncode": 0, "stdout": "", "stderr": "",
                "status": "skipped", "reason": "nothing to run"}
    try:
        proc = subprocess.run(words, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              timeout=timeout, check=False)
    except FileNotFoundError as exc:
        return {"argv": words, "returncode": None, "stdout": "", "stderr": str(exc),
                "status": "failed", "reason": "command not found: %s" % words[0]}
    except subprocess.TimeoutExpired:
        return {"argv": words, "returncode": None, "stdout": "", "stderr": "",
                "status": "failed", "reason": "timed out after %.0fs" % timeout}
    stdout = proc.stdout.decode("utf-8", "replace")
    stderr = proc.stderr.decode("utf-8", "replace")
    return {"argv": words, "returncode": proc.returncode,
            "stdout": stdout[-2000:], "stderr": stderr[-2000:],
            "status": "ok" if proc.returncode == 0 else "failed",
            "reason": None if proc.returncode == 0 else _first_line(stderr or stdout)}


def _first_line(text: str) -> str:
    for line in (text or "").splitlines():
        if line.strip():
            return line.strip()[:300]
    return ""


def apply_steps(record: Dict[str, Any], *, allow_sudo: bool, timeout: float,
                python: Optional[str] = None, prefix: str = "~/.local/bin",
                allow_unverified: bool = False) -> Dict[str, Any]:
    """Execute a planned tool's steps, stopping at the first failure.

    A step that needs root and is not permitted to elevate is not executed and
    not counted as done: it becomes ``manual`` with the exact command to run,
    which keeps the summary honest about what this process achieved.
    """
    applied: List[Dict[str, Any]] = []
    interpreter = python or sys.executable or "python3"
    if record["status"] != "planned":
        return dict(record, applied=applied)

    if record.get("method") == "download":
        result = download_tool(record["tool"], _planning_platform(), prefix,
                               allow_unverified=allow_unverified)
        applied.append(result)
        ok = result.get("status") == "installed"
        return dict(record, status="applied" if ok else result.get("status", "manual"),
                    applied=applied, reason=result.get("reason"))

    for step in record["steps"]:
        argv = render_argv(step["argv"], python=interpreter)
        if step["needs_root"] and not allow_sudo and not _is_root():
            # Stop here rather than attempt the next step: it depends on this
            # one, so running it would only add a confusing failure on top of
            # the instruction the operator actually needs.
            applied.append({"argv": argv, "returncode": None, "stdout": "", "stderr": "",
                            "status": "manual",
                            "reason": "needs root: " + shell_line(argv, True)})
            return dict(record, status="manual", applied=applied,
                        reason=applied[-1]["reason"])
        if not argv:
            applied.append({"argv": [], "returncode": 0, "stdout": "", "stderr": "",
                            "status": "skipped",
                            "reason": step.get("note") or "nothing to run"})
            continue
        effective = (["sudo", "-n"] + argv) if step["needs_root"] and not _is_root() else argv
        outcome = _run(effective, timeout=timeout)
        outcome["note"] = step.get("note") or ""
        applied.append(outcome)
        if outcome["status"] == "failed":
            return dict(record, status="failed", applied=applied,
                        reason=outcome.get("reason"))

    blocked = [item for item in applied if item["status"] == "manual"]
    return dict(record, status="manual" if blocked else "applied", applied=applied)


def _is_root() -> bool:
    return bool(hasattr(os, "geteuid") and os.geteuid() == 0)


_PLANNING_PLATFORM: Dict[str, Any] = {}


def _planning_platform() -> Dict[str, Any]:
    return _PLANNING_PLATFORM or detect_platform()


# --------------------------------------------------------------------------- #
# Verification: the same probe an audit uses
# --------------------------------------------------------------------------- #

def verify(tools: Sequence[str], *, timeout: float = 10.0) -> List[Dict[str, Any]]:
    """Probe every tool through the orchestrator's own ``probe``."""
    records: List[Dict[str, Any]] = []
    for name in sorted(dict.fromkeys(tools)):
        target = so.TOOL_INDEX.get(name) if so else None
        if target is None:
            records.append({"name": name, "binary": name, "available": False,
                            "version": None, "reason": "not in scanner_orchestrator.TOOLS"})
            continue
        record = so.probe(target, timeout=timeout)
        records.append({"name": name, "binary": target.get("binary") or name,
                        "available": bool(record.get("available")),
                        "version": record.get("version"), "path": record.get("path"),
                        "reason": record.get("reason")})
    return records


# --------------------------------------------------------------------------- #
# Reporting
# --------------------------------------------------------------------------- #

def render_text(plan: Dict[str, Any], *, allow_sudo: bool, mode: str) -> str:
    """Human-readable plan. The JSON document remains the machine interface."""
    plat = plan["platform"]
    lines: List[str] = []
    lines.append("platform: %s %s (%s, %s)" % (
        plat["os"], plat["release"] or "", plat["distro"] or plat["family"] or "?",
        plat["arch"]))
    if plan.get("managers"):
        lines.append("managers: %s" % ", ".join(plan["managers"]))
    lines.append("mode: %s" % mode)
    lines.append("")
    for record in plan["tools"]:
        head = "%-12s %-16s %s" % (record["tool"], record.get("method") or "-",
                                   record["status"])
        if record["status"] == "present":
            lines.append(head)
            continue
        lines.append(head)
        if record.get("reason"):
            lines.append("    %s" % record["reason"])
        for step in record.get("steps") or []:
            argv = render_argv(step["argv"], python=sys.executable or "python3")
            if not argv:
                lines.append("    # %s" % (step.get("note") or "nothing to run"))
                continue
            lines.append("    $ %s" % shell_line(argv, step["needs_root"],
                                                 allow_sudo=allow_sudo))
            if step.get("note"):
                lines.append("      # %s" % step["note"])
    summary = plan["summary"]
    lines.append("")
    lines.append("%d requested: %d present, %d planned, %d refused, %d manual" % (
        summary["requested"], summary["present"], summary["planned"],
        summary["refused"], summary["manual"]))
    return "\n".join(lines)


def render_check(records: Sequence[Dict[str, Any]]) -> str:
    lines = []
    for record in records:
        lines.append("%-12s %-9s %-10s %s" % (
            record["name"], "available" if record["available"] else "MISSING",
            record.get("version") or "-", record.get("path") or record.get("reason") or ""))
    missing = [record["name"] for record in records if not record["available"]]
    lines.append("")
    lines.append("%d of %d available%s" % (
        len(records) - len(missing), len(records),
        "" if not missing else "; missing: " + ", ".join(missing)))
    return "\n".join(lines)


def matrix() -> List[Dict[str, Any]]:
    """The install matrix as data: one row per tool, one column per platform."""
    rows: List[Dict[str, Any]] = []
    for tool in so.TOOLS if so else []:
        name = tool["name"]
        row: Dict[str, Any] = {
            "tool": name,
            "binary": tool.get("binary") or name,
            "kind": tool.get("kind"),
            "languages": tool.get("languages"),
            "network": bool(tool.get("network")),
            "methods": {},
        }
        for os_name in ALL:
            plat = detect_platform(sys_platform={"linux": "linux", "macos": "darwin",
                                                 "windows": "win32"}[os_name],
                                   machine="x86_64" if os_name != "windows" else "AMD64",
                                   os_release={"ID": "debian"} if os_name == "linux" else {})
            applicable = [step["manager"] for step in RECIPES.get(name, [])
                          if _platform_applies(step, plat)]
            row["methods"][os_name] = applicable
        rows.append(row)
    return rows


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="install_scanners.py",
        description="Install the optional external scanners this skill can drive. "
                    "Prints a plan by default; nothing is executed without --yes.",
        epilog="The audit itself never installs anything. Run this once, as an "
               "operator, then re-run scanner_orchestrator.py --probe-only to "
               "confirm what the audit can now see.",
    )
    parser.add_argument("--list", action="store_true",
                        help="print the install matrix (tool, binary, method per OS) and exit")
    parser.add_argument("--check", action="store_true",
                        help="probe the tools and exit 1 if any requested tool is missing")
    parser.add_argument("--dry-run", action="store_true",
                        help="print the plan and the exact commands; the default")
    parser.add_argument("--yes", action="store_true",
                        help="execute the plan instead of printing it")
    parser.add_argument("--only", "--tools", dest="only",
                        help="comma-separated subset (default: every tool the audit can drive)")
    parser.add_argument("--skip", help="comma-separated tools to leave alone")
    parser.add_argument("--prefix", default="~/.local/bin",
                        help="install directory for downloaded release binaries "
                             "(default: ~/.local/bin)")
    parser.add_argument("--allow-sudo", action="store_true",
                        help="run root steps with 'sudo -n' instead of printing them")
    parser.add_argument("--allow-download", action="store_true",
                        help="permit GitHub release downloads when no package manager covers a tool")
    parser.add_argument("--allow-unverified", action="store_true",
                        help="accept a download whose release publishes no checksum file")
    parser.add_argument("--timeout", type=float, default=900.0,
                        help="per-command timeout in seconds (default: 900)")
    parser.add_argument("--json", action="store_true", help="emit JSON instead of a text plan")
    parser.add_argument("--quiet", action="store_true", help="print only the JSON summary")
    return parser


def _selected(args: argparse.Namespace) -> List[str]:
    everything = [tool["name"] for tool in (so.TOOLS if so else [])]
    if args.only:
        wanted = [name.strip() for name in args.only.split(",") if name.strip()]
    else:
        wanted = everything
    skipped = {name.strip() for name in (args.skip or "").split(",") if name.strip()}
    return [name for name in wanted if name not in skipped and name in everything]


def main(argv: Optional[Sequence[str]] = None) -> int:
    global _PLANNING_PLATFORM
    args = build_parser().parse_args(argv)

    if so is None:
        print("error: %s (%s)" % (MISSING_COMPANION, _IMPORT_ERROR), file=sys.stderr)
        return 2

    plat = detect_platform()
    _PLANNING_PLATFORM = plat

    if plat["os"] == "unknown":
        print("error: unsupported platform %r; this installer covers Linux, macOS and "
              "Windows" % sys.platform, file=sys.stderr)
        return 2

    if args.list:
        payload = {"platform": plat, "tools": matrix()}
        print(json.dumps(payload, indent=2, ensure_ascii=False))
        return 0

    tools = _selected(args)
    if not tools:
        print("error: no known tool selected", file=sys.stderr)
        return 2

    if args.check:
        records = verify(tools)
        if args.json:
            print(json.dumps({"platform": plat, "tools": records,
                              "available": [r["name"] for r in records if r["available"]],
                              "missing": [r["name"] for r in records if not r["available"]]},
                             indent=2, ensure_ascii=False))
        else:
            print(render_check(records))
        return 0 if all(record["available"] for record in records) else 1

    managers = detect_managers()
    plan = build_plan(tools, plat, managers, prefix=args.prefix,
                      allow_download=args.allow_download,
                      allow_unverified=args.allow_unverified)

    # The default is a plan, and a plan is always safe to print: nothing runs,
    # nothing is downloaded, and a CI job that forgets --yes gets a readable
    # answer instead of a prompt it cannot see.
    if args.dry_run or not args.yes:
        if args.json:
            print(json.dumps(plan, indent=2, ensure_ascii=False))
        elif not args.quiet:
            print(render_text(plan, allow_sudo=args.allow_sudo, mode="plan"))
            print("\nRe-run with --yes to execute these steps.", file=sys.stderr)
        return 0

    applied: List[Dict[str, Any]] = []
    for record in plan["tools"]:
        if record["status"] != "planned":
            applied.append(dict(record, applied=[]))
            continue
        outcome = apply_steps(record, allow_sudo=args.allow_sudo, timeout=args.timeout,
                              prefix=args.prefix,
                              allow_unverified=args.allow_unverified)
        applied.append(outcome)
        if not args.quiet and not args.json:
            print("%-12s %s" % (record["tool"], outcome["status"]), file=sys.stderr)

    after = verify(tools)
    available = {record["name"]: record["available"] for record in after}
    summary = {
        "requested": len(applied),
        "available": sum(1 for name in available if available[name]),
        "still_missing": [name for name in tools if not available.get(name)],
    }
    payload = {
        "platform": plat,
        "mode": "apply",
        "allow_sudo": args.allow_sudo,
        "allow_download": args.allow_download,
        "prefix": os.path.abspath(os.path.expanduser(args.prefix)),
        "tools": applied,
        "verified": after,
        "summary": summary,
    }
    if args.json:
        print(json.dumps(payload, indent=2, ensure_ascii=False))
    elif not args.quiet:
        print(render_text(build_plan(tools, plat, detect_managers(), prefix=args.prefix,
                                     allow_download=args.allow_download,
                                     allow_unverified=args.allow_unverified),
                          allow_sudo=args.allow_sudo, mode="after"))
        print("")
        print(render_check(after))
        if summary["still_missing"]:
            print("\nstill missing: %s" % ", ".join(summary["still_missing"]),
                  file=sys.stderr)

    if summary["still_missing"]:
        return 1
    _warn_prefix(args.prefix)
    return 0


def _warn_prefix(prefix: str) -> None:
    """One-line reminder when a downloaded binary will not be found by the audit."""
    target = os.path.abspath(os.path.expanduser(prefix))
    path_entries = [os.path.abspath(os.path.expanduser(entry))
                    for entry in (os.environ.get("PATH") or "").split(os.pathsep) if entry]
    if target not in path_entries:
        print("note: %s is not on PATH; add it before running an audit "
              "(export PATH=\"%s:$PATH\")" % (target, target), file=sys.stderr)


if __name__ == "__main__":
    sys.exit(main())
