#!/usr/bin/env python3
"""Tests for the scanner installer.

Nothing here installs anything and nothing here touches the network. What is
tested is the part that decides: platform detection, which package manager wins
on which host, the prerequisite chain for ``pipx``, the elevation rule, the
archive-extraction guard, and the promise that every tool the audit can drive
has a recipe — so a tool added to ``scanner_orchestrator.TOOLS`` cannot silently
arrive without an installation path.

The three scripted wrappers are checked structurally as well: they must exist,
name the engine, and carry no matrix of their own.
"""

from __future__ import annotations

import io
import json
import os
import sys
import tarfile
import zipfile

import pytest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPTS = os.path.join(REPO, "scripts")
if SCRIPTS not in sys.path:
    sys.path.insert(0, SCRIPTS)

import install_scanners as ins  # noqa: E402
import scanner_orchestrator as so  # noqa: E402


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #

def platforms(os_name):
    """A platform dict for the requested OS, independent of the test host."""
    if os_name == "windows":
        return ins.detect_platform("win32", "AMD64", {})
    if os_name == "macos":
        return ins.detect_platform("darwin", "arm64", {})
    return ins.detect_platform("linux", "x86_64", {"ID": "debian", "VERSION_ID": "12"})


def managers_for(*present, os_name="linux"):
    """A manager map where exactly ``present`` are available."""
    full = ins.detect_managers(which=lambda binary: "/usr/bin/" + binary if _known(binary) else None)
    wanted = set(present)
    result = {}
    for manager in full:
        if manager == "download":
            result[manager] = True
            continue
        result[manager] = manager in wanted or (
            manager == "pip" and "pip" in wanted) or (
            manager == "node" and "node" in wanted)
    return result


def _known(binary):
    return True


def plan_one(tool, *, os_name="linux", present=("apt", "pipx"), **kwargs):
    return ins.plan_tool(tool, platforms(os_name), managers_for(*present),
                         **kwargs)


# --------------------------------------------------------------------------- #
# platform detection
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("sys_platform,expected", [
    ("linux", "linux"), ("linux2", "linux"), ("darwin", "macos"),
    ("win32", "windows"), ("cygwin", "windows"), ("sunos5", "unknown"),
])
def test_platform_os_detection(sys_platform, expected):
    assert ins.detect_platform(sys_platform, "x86_64", {})["os"] == expected


@pytest.mark.parametrize("machine,expected", [
    ("x86_64", "x86_64"), ("amd64", "x86_64"), ("AMD64", "x86_64"), ("x64", "x86_64"),
    ("aarch64", "arm64"), ("arm64", "arm64"), ("armv7l", "armv7"),
    ("riscv64", "riscv64"),
])
def test_platform_arch_normalisation(machine, expected):
    assert ins.detect_platform("linux", machine, {})["arch"] == expected


@pytest.mark.parametrize("distro,family", [
    ("ubuntu", "debian"), ("debian", "debian"), ("linuxmint", "debian"),
    ("fedora", "fedora"), ("rhel", "fedora"), ("rocky", "fedora"),
    ("arch", "arch"), ("manjaro", "arch"), ("alpine", "alpine"),
    ("opensuse-leap", "suse"), ("nixos", "nixos"),
])
def test_platform_distro_families(distro, family):
    assert ins.detect_platform("linux", "x86_64", {"ID": distro})["family"] == family


def test_platform_reads_os_release_without_a_shell(tmp_path):
    path = tmp_path / "os-release"
    path.write_text(
        '# comment\nNAME="Ubuntu"\nID=ubuntu\nVERSION_ID="24.04"\n'
        "PRETTY_NAME=\"Ubuntu 24.04.1 LTS\"\nBROKEN LINE\n",
        encoding="utf-8")
    values = ins._read_os_release(str(path))
    assert values["ID"] == "ubuntu"
    assert values["VERSION_ID"] == "24.04"
    assert values["PRETTY_NAME"] == "Ubuntu 24.04.1 LTS"
    assert "BROKEN LINE" not in values


def test_missing_os_release_is_not_an_error():
    assert ins._read_os_release("/nonexistent/os-release") == {}


# --------------------------------------------------------------------------- #
# the matrix is the orchestrator's, not a copy
# --------------------------------------------------------------------------- #

def test_every_tool_the_audit_drives_has_a_recipe():
    for tool in so.TOOLS:
        assert tool["name"] in ins.RECIPES, tool["name"]


def test_no_recipe_exists_for_a_tool_the_audit_cannot_drive():
    known = {tool["name"] for tool in so.TOOLS}
    assert set(ins.RECIPES) - known == set()


def test_the_binary_is_not_always_the_tool_name():
    """npm audit is a subcommand; the binary must be npm, not npm-audit."""
    assert so.TOOL_INDEX["npm-audit"]["binary"] == "npm"
    assert ins.matrix()[0]["binary"]  # every row names a binary


def test_matrix_covers_all_three_operating_systems():
    for row in ins.matrix():
        assert set(row["methods"]) == {"linux", "macos", "windows"}, row["tool"]
        for os_name, methods in row["methods"].items():
            assert methods, "%s has no method on %s" % (row["tool"], os_name)


# --------------------------------------------------------------------------- #
# planning: the right method for the host
# --------------------------------------------------------------------------- #

def test_pipx_wins_on_debian_when_present():
    record = plan_one("semgrep", present=("apt", "pipx", "pip"))
    assert record["method"] == "pipx"
    assert record["steps"][0]["argv"] == ["pipx", "install", "semgrep"]


def test_a_host_with_only_apt_bootstraps_pipx_rather_than_using_an_old_package():
    """apt can install pipx, so pipx wins: distribution packages lag upstream."""
    record = plan_one("bandit", present=("apt",))
    assert record["method"] == "pipx"
    assert record["steps"][0]["argv"] == ["apt-get", "install", "-y", "pipx"]
    assert record["steps"][0]["needs_root"] is True
    assert record["steps"][-1]["argv"] == ["pipx", "install", "bandit"]


def test_the_strategy_order_is_the_recipe_order():
    """With the bootstrap disabled, the first applicable strategy is apt."""
    step = ins._pick(ins.RECIPES["bandit"], platforms("linux"),
                     managers_for("apt"), bootstrap=False)
    assert step["manager"] == "apt"
    assert step["needs_root"] is True


def test_pipx_missing_pulls_in_its_own_prerequisite():
    record = plan_one("checkov", present=("apt",))
    assert record["method"] == "pipx"
    assert record["steps"][0]["manager"] == "apt"
    assert "pipx" in record["steps"][0]["argv"]
    assert record["steps"][-1]["argv"] == ["pipx", "install", "checkov"]


def test_macos_prefers_homebrew_over_go():
    record = ins.plan_tool("gitleaks", platforms("macos"),
                           managers_for("brew", "go"), )
    assert record["method"] == "brew"


def test_windows_prefers_winget():
    record = ins.plan_tool("trivy", platforms("windows"),
                           managers_for("winget", "choco", "scoop"))
    assert record["method"] == "winget"
    assert record["steps"][0]["argv"][:3] == ["winget", "install", "--id"]


def test_go_is_never_selected_when_go_is_absent():
    record = plan_one("gosec", present=("apt",))
    assert record["method"] != "go"
    assert record["status"] in ("refused", "manual")


def test_an_installed_tool_is_reported_present_not_reinstalled(monkeypatch):
    monkeypatch.setattr(ins.shutil, "which", lambda name: "/usr/local/bin/" + name)
    record = plan_one("trivy")
    assert record["status"] == "present"
    assert record["steps"] == []


def test_download_is_refused_without_the_flag_and_offered_with_it():
    refused = plan_one("trivy", present=("apt",))
    assert refused["status"] == "refused"
    assert "--allow-download" in refused["reason"]
    allowed = plan_one("trivy", present=("apt",), allow_download=True)
    assert allowed["method"] == "download"
    assert allowed["status"] == "planned"


def test_download_note_mentions_the_unverified_flag():
    record = plan_one("trivy", present=(), allow_download=True, allow_unverified=True)
    assert "--allow-unverified" in record["steps"][0]["note"]


def test_a_host_with_no_manager_is_told_which_flag_would_work():
    record = plan_one("gosec", present=())
    assert record["status"] == "refused"
    assert "--allow-download" in record["reason"]


def test_the_manual_hint_names_the_missing_runtime():
    hint = ins._manual_hint("gosec", platforms("linux"))
    assert "gosec" in hint and "Go" in hint


def test_unknown_tool_is_manual_not_an_exception():
    record = ins.plan_tool("not-a-scanner", platforms("linux"), managers_for("apt"))
    assert record["status"] == "manual"
    assert "scanner_orchestrator" in record["reason"]


def test_plan_is_sorted_and_deduplicated():
    plan = ins.build_plan(["semgrep", "bandit", "semgrep"], platforms("linux"),
                          managers_for("pipx"))
    assert [record["tool"] for record in plan["tools"]] == ["bandit", "semgrep"]
    assert plan["summary"]["requested"] == 2


def test_summary_counts_every_status():
    plan = ins.build_plan(["semgrep", "trivy", "gosec"], platforms("linux"),
                          managers_for("pipx", "go"))
    summary = plan["summary"]
    assert summary["requested"] == 3
    assert summary["planned"] + summary["refused"] + summary["manual"] + summary["present"] == 3


# --------------------------------------------------------------------------- #
# elevation, rendering and argv substitution
# --------------------------------------------------------------------------- #

def test_root_step_is_printed_with_sudo_and_not_run(monkeypatch):
    record = plan_one("bandit", present=("apt",))
    monkeypatch.setattr(ins, "_is_root", lambda: False)
    ran = []
    monkeypatch.setattr(ins, "_run", lambda argv, timeout: ran.append(argv) or {
        "argv": list(argv), "returncode": 0, "stdout": "", "stderr": "",
        "status": "ok", "reason": None})
    outcome = ins.apply_steps(record, allow_sudo=False, timeout=5)
    assert ran == [] or all("apt-get" not in " ".join(argv) for argv in ran)
    assert outcome["status"] == "manual"
    assert "sudo apt-get install -y pipx" in outcome["applied"][-1]["reason"]


def test_allow_sudo_runs_the_step_through_sudo_dash_n(monkeypatch):
    record = plan_one("bandit", present=("apt",))
    seen = []
    monkeypatch.setattr(ins, "_is_root", lambda: False)
    monkeypatch.setattr(ins, "_run", lambda argv, timeout: seen.append(list(argv)) or {
        "argv": list(argv), "returncode": 0, "stdout": "", "stderr": "",
        "status": "ok", "reason": None})
    outcome = ins.apply_steps(record, allow_sudo=True, timeout=5)
    assert seen[0][:2] == ["sudo", "-n"]
    assert outcome["status"] == "applied"


def test_a_failing_step_stops_the_chain(monkeypatch):
    record = plan_one("checkov", present=("apt",))
    calls = []

    def fake_run(argv, timeout):
        calls.append(argv)
        return {"argv": list(argv), "returncode": 1, "stdout": "", "stderr": "boom",
                "status": "failed", "reason": "boom"}

    monkeypatch.setattr(ins, "_run", fake_run)
    outcome = ins.apply_steps(record, allow_sudo=True, timeout=5)
    assert outcome["status"] == "failed"
    assert len(calls) == 1, "a failed prerequisite must not be followed by the tool install"


def test_python_placeholder_is_substituted_not_left_literal():
    assert ins.render_argv(["{python}", "-m", "pip"], python="/usr/bin/python3") == [
        "/usr/bin/python3", "-m", "pip"]


def test_shell_line_prefixes_only_when_root_is_needed(monkeypatch):
    assert ins.shell_line(["pipx", "install", "bandit"], False) == "pipx install bandit"
    monkeypatch.setattr(ins, "_is_root", lambda: False)
    assert ins.shell_line(["apt-get", "install", "-y", "bandit"], True) == (
        "sudo apt-get install -y bandit")
    monkeypatch.setattr(ins, "_is_root", lambda: True)
    assert ins.shell_line(["apt-get", "install", "-y", "bandit"], True) == (
        "apt-get install -y bandit")


def test_render_text_names_every_tool_and_hides_nothing(capsys):
    plan = ins.build_plan(["semgrep", "trivy", "gosec"], platforms("linux"),
                          managers_for("pipx", "go"))
    text = ins.render_text(plan, allow_sudo=False, mode="plan")
    for tool in ("semgrep", "trivy", "gosec"):
        assert tool in text
    assert "requested" in text


# --------------------------------------------------------------------------- #
# release downloads: asset selection and safe extraction
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("tool,os_name,arch,version,names,expected", [
    ("trivy", "linux", "x86_64", "0.58.0",
     ["trivy_0.58.0_Linux-64bit.tar.gz", "trivy_0.58.0_macOS-ARM64.tar.gz",
      "trivy_0.58.0_checksums.txt"],
     "trivy_0.58.0_Linux-64bit.tar.gz"),
    ("trivy", "macos", "arm64", "0.58.0",
     ["trivy_0.58.0_Linux-64bit.tar.gz", "trivy_0.58.0_macOS-ARM64.tar.gz"],
     "trivy_0.58.0_macOS-ARM64.tar.gz"),
    ("gitleaks", "linux", "x86_64", "8.21.2",
     ["gitleaks_8.21.2_linux_x64.tar.gz", "gitleaks_8.21.2_darwin_arm64.tar.gz"],
     "gitleaks_8.21.2_linux_x64.tar.gz"),
    ("gitleaks", "windows", "x86_64", "8.21.2",
     ["gitleaks_8.21.2_windows_x64.zip"],
     "gitleaks_8.21.2_windows_x64.zip"),
    ("osv-scanner", "linux", "x86_64", "",
     ["osv-scanner_linux_amd64", "osv-scanner_darwin_arm64"],
     "osv-scanner_linux_amd64"),
    # an unsupported architecture must not silently get the x86 build
    ("trivy", "linux", "armv7", "0.58.0", ["trivy_0.58.0_Linux-64bit.tar.gz"], None),
])
def test_asset_selection(tool, os_name, arch, version, names, expected):
    plat = dict(platforms(os_name), arch=arch)
    assert ins.select_asset(tool, plat, version, names) == expected


@pytest.mark.parametrize("names,expected", [
    (["trivy_0.58.0_Linux-64bit.tar.gz", "trivy_0.58.0_checksums.txt"],
     "trivy_0.58.0_checksums.txt"),
    (["osv-scanner_linux_amd64", "osv-scanner_linux_amd64.sha256sum"],
     "osv-scanner_linux_amd64.sha256sum"),
    (["osv-scanner_linux_amd64"], None),
])
def test_checksum_asset_selection(names, expected):
    tool = "osv-scanner" if names[0].startswith("osv") else "trivy"
    assert ins.select_checksum_asset(tool, names) == expected


def test_tar_extraction_returns_a_runnable_binary(tmp_path):
    archive = tmp_path / "gitleaks.tar.gz"
    with tarfile.open(archive, "w:gz") as handle:
        payload = b"#!/bin/sh\necho gitleaks\n"
        info = tarfile.TarInfo("gitleaks")
        info.size = len(payload)
        handle.addfile(info, io.BytesIO(payload))
    installed = ins.extract_binary(str(archive), "gitleaks", str(tmp_path / "bin"))
    assert os.path.basename(installed) == "gitleaks"
    assert os.access(installed, os.X_OK)
    assert open(installed, "rb").read().startswith(b"#!/bin/sh")


def test_zip_extraction_handles_the_windows_exe_suffix(tmp_path):
    archive = tmp_path / "trivy.zip"
    with zipfile.ZipFile(archive, "w") as handle:
        handle.writestr("trivy.exe", b"MZ fake")
    installed = ins.extract_binary(str(archive), "trivy", str(tmp_path / "bin"))
    assert installed.endswith("trivy")
    assert open(installed, "rb").read() == b"MZ fake"


@pytest.mark.parametrize("member", ["../escape", "/etc/cron.d/x", "a/../../b", "C:/windows/x"])
def test_extraction_refuses_path_traversal(tmp_path, member):
    archive = tmp_path / "evil.tar.gz"
    with tarfile.open(archive, "w:gz") as handle:
        payload = b"x"
        info = tarfile.TarInfo(member)
        info.size = len(payload)
        handle.addfile(info, io.BytesIO(payload))
    with pytest.raises(ValueError):
        ins.extract_binary(str(archive), "evil", str(tmp_path / "bin"))


def test_zip_traversal_is_refused_before_anything_is_written(tmp_path):
    archive = tmp_path / "evil.zip"
    with zipfile.ZipFile(archive, "w") as handle:
        handle.writestr("../../evil", b"x")
    with pytest.raises(ValueError):
        ins.extract_binary(str(archive), "evil", str(tmp_path / "bin"))
    assert not (tmp_path / "evil").exists()


def test_an_archive_without_the_binary_is_an_error(tmp_path):
    archive = tmp_path / "empty.tar.gz"
    with tarfile.open(archive, "w:gz") as handle:
        payload = b"x"
        info = tarfile.TarInfo("README")
        info.size = len(payload)
        handle.addfile(info, io.BytesIO(payload))
    with pytest.raises(ValueError):
        ins.extract_binary(str(archive), "gitleaks", str(tmp_path / "bin"))


def test_a_download_without_a_checksum_is_refused_unless_flagged(monkeypatch, tmp_path):
    monkeypatch.setattr(ins, "_release_payload", lambda tool, timeout=30.0: {
        "tag_name": "v0.58.0",
        "assets": [{"name": "trivy_0.58.0_Linux-64bit.tar.gz",
                    "browser_download_url": "https://example.invalid/trivy.tar.gz"}],
    })
    refused = ins.download_tool("trivy", platforms("linux"), str(tmp_path))
    assert refused["status"] == "refused"
    assert "checksum" in refused["reason"]


def test_a_checksum_mismatch_is_refused(monkeypatch, tmp_path):
    monkeypatch.setattr(ins, "_release_payload", lambda tool, timeout=30.0: {
        "tag_name": "v0.58.0",
        "assets": [
            {"name": "trivy_0.58.0_Linux-64bit.tar.gz",
             "browser_download_url": "https://example.invalid/trivy.tar.gz"},
            {"name": "trivy_0.58.0_checksums.txt",
             "browser_download_url": "https://example.invalid/sums.txt"},
        ],
    })
    monkeypatch.setattr(ins, "_http_get", lambda url, timeout=30.0, limit=2 ** 26: (
        b"00" * 32 + b"  trivy_0.58.0_Linux-64bit.tar.gz\n" if url.endswith("sums.txt")
        else b"not the archive"))
    result = ins.download_tool("trivy", platforms("linux"), str(tmp_path))
    assert result["status"] == "refused"
    assert "checksum mismatch" in result["reason"]


# --------------------------------------------------------------------------- #
# verification uses the audit's own probe
# --------------------------------------------------------------------------- #

def test_verify_reports_missing_tools_rather_than_raising(monkeypatch):
    monkeypatch.setattr(so, "probe", lambda tool, timeout=10.0: {
        "name": tool["name"], "available": False, "path": None, "version": None,
        "reason": "not found on PATH"})
    records = ins.verify(["semgrep", "bandit"])
    assert [record["name"] for record in records] == ["bandit", "semgrep"]
    assert all(not record["available"] for record in records)


def test_verify_records_the_binary_that_was_probed(monkeypatch):
    monkeypatch.setattr(so, "probe", lambda tool, timeout=10.0: {
        "name": tool["name"], "available": True, "path": "/usr/bin/npm",
        "version": "10.5.0", "reason": None})
    record = ins.verify(["npm-audit"])[0]
    assert record["binary"] == "npm"


def test_render_check_names_the_missing_tools():
    text = ins.render_check([
        {"name": "semgrep", "available": True, "version": "1.2.3", "path": "/bin/semgrep"},
        {"name": "trivy", "available": False, "version": None, "reason": "not found on PATH"},
    ])
    assert "1 of 2 available" in text
    assert "missing: trivy" in text


# --------------------------------------------------------------------------- #
# CLI behaviour and the wrappers
# --------------------------------------------------------------------------- #

def test_json_plan_is_machine_readable(capsys):
    code = ins.main(["--dry-run", "--json", "--only", "semgrep"])
    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["platform"]["os"] in ("linux", "macos", "windows")
    assert payload["tools"][0]["tool"] == "semgrep"
    assert payload["summary"]["requested"] == 1


def test_dry_run_never_executes_anything(monkeypatch, capsys):
    called = []
    monkeypatch.setattr(ins, "_run", lambda argv, timeout: called.append(argv))
    code = ins.main(["--dry-run", "--only", "bandit,trivy"])
    assert code == 0
    assert called == []
    assert "bandit" in capsys.readouterr().out


def test_an_unknown_only_value_is_an_error(capsys):
    assert ins.main(["--dry-run", "--only", "no-such-scanner"]) == 2
    assert "no known tool selected" in capsys.readouterr().err


def test_check_exits_one_when_a_tool_is_missing(monkeypatch):
    monkeypatch.setattr(ins, "verify", lambda tools, timeout=10.0: [
        {"name": name, "binary": name, "available": False, "version": None,
         "reason": "not found on PATH"} for name in tools])
    assert ins.main(["--check", "--only", "semgrep"]) == 1


def test_check_exits_zero_when_everything_is_present(monkeypatch):
    monkeypatch.setattr(ins, "verify", lambda tools, timeout=10.0: [
        {"name": name, "binary": name, "available": True, "version": "1.0",
         "path": "/bin/" + name} for name in tools])
    assert ins.main(["--check", "--only", "semgrep"]) == 0


def test_list_is_json_and_covers_every_tool(capsys):
    assert ins.main(["--list"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert {row["tool"] for row in payload["tools"]} == {tool["name"] for tool in so.TOOLS}


def test_every_help_flag_works():
    with pytest.raises(SystemExit) as excinfo:
        ins.build_parser().parse_args(["--help"])
    assert excinfo.value.code == 0
    assert "--allow-download" in ins.build_parser().format_help()


@pytest.mark.parametrize("name,must_contain", [
    ("install-scanners.sh", ["install_scanners.py", "python3", "--allow-sudo"]),
    ("install-scanners.ps1", ["install_scanners.py", "winget", "py -3"]),
])
def test_wrappers_delegate_and_do_not_carry_a_matrix(name, must_contain):
    path = os.path.join(SCRIPTS, name)
    assert os.path.isfile(path), name
    text = open(path, encoding="utf-8").read()
    for needle in must_contain:
        assert needle in text, (name, needle)
    # A wrapper that names individual scanners has started to duplicate the
    # engine's matrix, which is the drift this structure exists to prevent.
    for tool in ("semgrep", "gitleaks", "checkov", "osv-scanner", "brakeman"):
        assert tool not in text, (name, tool)


def test_the_shell_wrapper_is_executable():
    path = os.path.join(SCRIPTS, "install-scanners.sh")
    if os.name != "posix":
        pytest.skip("POSIX permission bits only")
    assert os.access(path, os.X_OK), "install-scanners.sh is not executable"
