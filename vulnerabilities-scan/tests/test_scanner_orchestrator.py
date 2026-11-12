#!/usr/bin/env python3
"""Tests for the stage-3b scanner orchestrator.

Every external scanner is simulated with a fake executable placed on ``PATH``,
because this host has none installed: the probe, timeout, parse, normalise,
dedupe and "unavailable is not clean" paths are exactly what must be proved.

Scratch directories live under the repository (``.scratch/tests``) rather than
``/tmp``, which is a full shared tmpfs here.
"""

from __future__ import annotations

import json
import os
import shutil
import stat
import sys

import hashlib

import pytest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPTS = os.path.join(REPO, "scripts")
if SCRIPTS not in sys.path:
    sys.path.insert(0, SCRIPTS)

import scanner_orchestrator as so  # noqa: E402

SCRATCH_ROOT = os.path.join(REPO, ".scratch", "tests")

#: A live-shaped token the redaction tests need, assembled from parts so no
#: tracked blob contains a matchable credential: GitHub push protection (GH013)
#: rejects a push whose diff carries one, which is what happened to this
#: repository before the suite was written this way.
GITHUB_TOKEN = "ghp_" + "abcdefghijklmnopqrstuvwx12"


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

@pytest.fixture()
def workdir(request):
    # Keep the directory name short: parametrised ids carry payloads that would
    # otherwise exceed the 255-byte limit on a single path component.
    digest = hashlib.sha1(request.node.name.encode("utf-8")).hexdigest()[:12]
    path = os.path.join(SCRATCH_ROOT, digest)
    shutil.rmtree(path, ignore_errors=True)
    os.makedirs(path)
    yield path
    shutil.rmtree(path, ignore_errors=True)


def write(root, rel, content):
    path = os.path.join(root, rel)
    os.makedirs(os.path.dirname(path) or root, exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(content)
    return path


def fake_tool(bindir, name, body, version="1.0.0"):
    """Create an executable named *name* that runs *body* as Python."""
    path = os.path.join(bindir, name)
    header = "#!/usr/bin/env python3\nimport sys, json\n"
    body = ("if '--version' in sys.argv:\n    print('%s %s')\n    sys.exit(0)\n"
            % (name, version)) + body
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(header + body)
    os.chmod(path, os.stat(path).st_mode | stat.S_IEXEC)
    return path


def run(monkeypatch, root, bindir=None, **kwargs):
    """Call orchestrate() with PATH limited to *bindir* plus the real python."""
    path = (bindir or "") + os.pathsep + "/usr/bin:/bin"
    monkeypatch.setenv("PATH", path)
    return so.orchestrate(root, **kwargs)


# ---------------------------------------------------------------------------
# probing
# ---------------------------------------------------------------------------

def test_probe_missing_tool_records_reason():
    record = so.probe({"name": "definitely-not-installed-xyz", "kind": "sast",
                       "version_args": ["--version"], "network": False,
                       "categories": ["x"]})
    assert record["available"] is False
    assert record["path"] is None
    assert record["reason"] == "not found on PATH"


def test_probe_reads_version(workdir, monkeypatch):
    bindir = os.path.join(workdir, "bin")
    os.makedirs(bindir)
    fake_tool(bindir, "bandit", "sys.exit(0)\n", version="1.7.5")
    monkeypatch.setenv("PATH", bindir + os.pathsep + "/usr/bin:/bin")
    record = so.probe(so.TOOL_INDEX["bandit"])
    assert record["available"] is True
    assert record["version"] == "1.7.5"
    assert record["probe_exit_code"] == 0


def test_probe_failing_version_is_unavailable(workdir, monkeypatch):
    bindir = os.path.join(workdir, "bin")
    os.makedirs(bindir)
    path = os.path.join(bindir, "gosec")
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(_BROKEN_PROBE)
    os.chmod(path, os.stat(path).st_mode | stat.S_IEXEC)
    monkeypatch.setenv("PATH", bindir + os.pathsep + "/usr/bin:/bin")
    record = so.probe(so.TOOL_INDEX["gosec"])
    assert record["available"] is False
    assert "exited 3" in record["reason"]


# ---------------------------------------------------------------------------
# parsing and normalisation
# ---------------------------------------------------------------------------

_BROKEN_PROBE = (
    "#!/usr/bin/env python3\n"
    "import sys\n"
    "sys.stderr.write('gosec: unknown flag --version\\n')\n"
    "sys.exit(3)\n"
)

BANDIT_OUTPUT = json.dumps({
    "results": [{
        "test_id": "B608", "test_name": "hardcoded_sql_expressions",
        "filename": "app/db.py", "line_number": 4, "line_range": [4, 5],
        "issue_text": "Possible SQL injection vector through string-based query construction.",
        "issue_severity": "MEDIUM", "issue_cwe": {"id": 89},
    }],
    "metrics": {},
})


def _scanner_main(name, payload, exit_code=1):
    return ("sys.stdout.write(%r)\n"
            "sys.exit(%d)\n" % (payload, exit_code))


def test_bandit_output_is_normalised(workdir, monkeypatch):
    root = os.path.join(workdir, "repo")
    write(root, "app/db.py",
          "import sqlite3\n"
          "\n"
          "def q(cur, name):\n"
          "    cur.execute(\"select * from t where n = '%s'\" % name)\n"
          "    return cur\n")
    bindir = os.path.join(workdir, "bin")
    os.makedirs(bindir)
    fake_tool(bindir, "bandit", _scanner_main("bandit", BANDIT_OUTPUT))

    document = run(monkeypatch, root, bindir, include_builtin=False,
                   scanners=["bandit"])
    assert document["summary"]["findings"] == 1
    finding = document["findings"][0]
    assert finding["category"] == "sql_injection"
    assert finding["location"] == {"file": "app/db.py", "line_start": 4, "line_end": 5}
    assert finding["cwe"]["id"] == "CWE-89"
    assert finding["sources"][0]["tool"] == "bandit"
    # evidence is re-read from source, not echoed from the tool
    assert "cur.execute" in finding["evidence"]
    # the tool's severity is an input, never the verdict
    assert finding["severity"] == "Medium"
    assert finding["confidence"] == "MEDIUM"
    assert finding["scoring"] == "unscored"
    assert "tool label: MEDIUM" in " ".join(finding["priority_factors"])


def test_unknown_rule_id_is_kept_as_unclassified(workdir, monkeypatch):
    payload = json.dumps({"results": [{
        "test_id": "X999", "test_name": "mystery_check",
        "filename": "app/db.py", "line_number": 1,
        "issue_text": "something unusual", "issue_severity": "HIGH"}]})
    root = os.path.join(workdir, "repo")
    write(root, "app/db.py", "x = 1\n")
    bindir = os.path.join(workdir, "bin")
    os.makedirs(bindir)
    fake_tool(bindir, "bandit", _scanner_main("bandit", payload))
    document = run(monkeypatch, root, bindir, include_builtin=False, scanners=["bandit"])
    finding = document["findings"][0]
    assert finding["category"] == "unclassified"
    assert finding["confidence"] == "LOW"


@pytest.mark.parametrize("tool,payload,expected", [
    ("gosec", json.dumps({"Issues": [{"rule_id": "G404", "details": "weak random",
                                      "file": "main.go", "line": "7", "severity": "HIGH",
                                      "cwe": {"id": 338}}]}), "weak_randomness"),
    ("brakeman", json.dumps({"warnings": [{"warning_type": "SQL Injection",
                                           "message": "possible sql injection",
                                           "file": "app/controllers/users_controller.rb",
                                           "line": 3, "cwe_id": 89,
                                           "confidence": "High"}]}), "sql_injection"),
    ("semgrep", json.dumps({"results": [{
        "check_id": "python.lang.security.audit.subprocess-shell-true",
        "path": "app/run.py", "start": {"line": 2}, "end": {"line": 2},
        "extra": {"message": "subprocess with shell=True", "severity": "ERROR",
                  "metadata": {"cwe": ["CWE-78: OS Command Injection"]}}}]}), "command_injection"),
    ("checkov", json.dumps({"results": {"failed_checks": [{
        "check_id": "CKV_DOCKER_3", "check_name": "Ensure container runs as non-root",
        "file_path": "/Dockerfile", "file_line_range": [1, 4],
        "severity": "HIGH"}]}}), "container_security"),
])
def test_tool_parsers_map_categories(workdir, monkeypatch, tool, payload, expected):
    root = os.path.join(workdir, "repo")
    write(root, "app/x.py", "x = 1\n")
    write(root, "app/run.py", "import subprocess\nsubprocess.run(cmd, shell=True)\n")
    write(root, "main.go", "package main\n")
    write(root, "go.mod", "module example.com/app\n")
    write(root, "app/controllers/users_controller.rb", "class UsersController\nend\n")
    write(root, "Dockerfile", "FROM python:3.11\nUSER root\n")
    # checkov reports absolute paths; the parser must normalise them to the root
    payload = payload.replace('"file_path": "/Dockerfile"',
                              '"file_path": "%s"' % os.path.join(root, "Dockerfile"))
    bindir = os.path.join(workdir, "bin")
    os.makedirs(bindir)
    # semgrep needs a local rule config to be planned without network access
    fake_tool(bindir, tool, _scanner_main(tool, payload))
    rules = os.path.join(workdir, "rules")
    os.makedirs(rules)
    document = run(monkeypatch, root, bindir, include_builtin=False, scanners=[tool],
                   local_rules=rules)
    assert document["findings"], document["runs"]
    assert document["findings"][0]["category"] == expected


# ---------------------------------------------------------------------------
# absent and skipped tools
# ---------------------------------------------------------------------------

def test_missing_scanners_become_limitations_not_clean_results(workdir, monkeypatch):
    root = os.path.join(workdir, "repo")
    write(root, "app/db.py", "x = 1\n")
    document = run(monkeypatch, root, os.path.join(workdir, "empty-bin"),
                   include_builtin=False)
    assert document["findings"] == []
    joined = " ".join(document["limitations"])
    assert "not evidence of absence" in joined
    assert document["coverage"]["scanners_unavailable"], "coverage must list them"
    for record in document["scanners"]:
        assert record["available"] is False
        assert record["reason"]


def test_network_tool_is_skipped_without_permission(workdir, monkeypatch):
    root = os.path.join(workdir, "repo")
    write(root, "requirements.txt", "flask==2.0.0\n")
    bindir = os.path.join(workdir, "bin")
    os.makedirs(bindir)
    fake_tool(bindir, "pip-audit", _scanner_main("pip-audit", "{}", 0))
    document = run(monkeypatch, root, bindir, include_builtin=False, scanners=["pip-audit"])
    run_record = document["runs"][0]
    assert run_record["status"] == "skipped"
    assert "requires network access" in " ".join(document["limitations"])
    assert document["coverage"]["network_allowed"] is False


def test_semgrep_without_rules_or_network_is_skipped(workdir, monkeypatch):
    root = os.path.join(workdir, "repo")
    write(root, "app/x.py", "x = 1\n")
    bindir = os.path.join(workdir, "bin")
    os.makedirs(bindir)
    fake_tool(bindir, "semgrep", _scanner_main("semgrep", "{}", 0))
    document = run(monkeypatch, root, bindir, include_builtin=False, scanners=["semgrep"])
    assert document["runs"][0]["status"] == "skipped"
    assert "--local-rules" in " ".join(document["limitations"])


def test_timeout_is_a_limitation_not_an_empty_result(workdir, monkeypatch):
    root = os.path.join(workdir, "repo")
    write(root, "app/x.py", "x = 1\n")
    bindir = os.path.join(workdir, "bin")
    os.makedirs(bindir)
    fake_tool(bindir, "bandit", "import time\ntime.sleep(5)\nprint('{}')\n")
    document = run(monkeypatch, root, bindir, include_builtin=False,
                   scanners=["bandit"], timeout=1)
    record = document["runs"][0]
    assert record["status"] == "timeout"
    assert record["timed_out"] is True
    assert any("no usable output" in line for line in document["limitations"])


def test_unparseable_output_is_reported(workdir, monkeypatch):
    root = os.path.join(workdir, "repo")
    write(root, "app/x.py", "x = 1\n")
    bindir = os.path.join(workdir, "bin")
    os.makedirs(bindir)
    fake_tool(bindir, "bandit", "print('this is not json')\nsys.exit(0)\n")
    document = run(monkeypatch, root, bindir, include_builtin=False, scanners=["bandit"])
    assert document["runs"][0]["status"] == "unparsed"
    assert document["runs"][0]["error"]
    assert any("bandit" in line for line in document["limitations"])


def test_missing_binary_at_execution_is_recorded(workdir, monkeypatch):
    root = os.path.join(workdir, "repo")
    write(root, "app/x.py", "x = 1\n")
    bindir = os.path.join(workdir, "bin")
    os.makedirs(bindir)
    fake = fake_tool(bindir, "bandit", _scanner_main("bandit", "{}", 0))
    planned, reason = so.invocations(so.TOOL_INDEX["bandit"], root, so.walk_files(root),
                                     allow_network=False, local_rules=None)
    assert reason is None and planned
    os.remove(fake)
    record = so._execute(so.TOOL_INDEX["bandit"], planned[0], timeout=5,
                         raw_dir=None, index=0)
    assert record["status"] == "unavailable"
    assert "not found on PATH" in record["error"]


# ---------------------------------------------------------------------------
# dedupe, redaction, determinism, read-only
# ---------------------------------------------------------------------------

def test_two_tools_on_the_same_line_merge_into_one_finding(workdir, monkeypatch):
    root = os.path.join(workdir, "repo")
    os.makedirs(root)
    write(root, "Dockerfile", "FROM python:3.11\nUSER root\nCMD python app.py\n")
    bindir = os.path.join(workdir, "bin")
    os.makedirs(bindir)
    checkov = json.dumps({"results": {"failed_checks": [{
        "check_id": "CKV_DOCKER_1", "check_name": "runs as root",
        "file_path": os.path.join(root, "Dockerfile"),
        "file_line_range": [2, 2], "severity": "HIGH"}]}})
    trivy = json.dumps({"Results": [{"Target": "Dockerfile", "Misconfigurations": [{
        "ID": "DS002", "Title": "Image user should not be root", "Severity": "HIGH",
        "Message": "container runs as root", "CauseMetadata": {"StartLine": 2, "EndLine": 2}}]}]})
    fake_tool(bindir, "checkov", _scanner_main("checkov", checkov))
    fake_tool(bindir, "trivy", _scanner_main("trivy", trivy))
    document = run(monkeypatch, root, bindir, include_builtin=False,
                   scanners=["checkov", "trivy"], allow_network=True)
    assert document["summary"]["findings"] == 1, document["findings"]
    assert document["summary"]["duplicates_merged"] == 1
    finding = document["findings"][0]
    assert finding["confidence"] == "HIGH"
    assert {source["tool"] for source in finding["sources"]} == {"checkov", "trivy"}


def test_secret_is_redacted_before_it_reaches_the_dataset(workdir, monkeypatch):
    root = os.path.join(workdir, "repo")
    write(root, "app/config.py", "TOKEN = %r\n" % GITHUB_TOKEN)
    bindir = os.path.join(workdir, "bin")
    os.makedirs(bindir)
    payload = json.dumps([{
        "RuleID": "github-pat", "Description": "GitHub token",
        "File": "app/config.py", "StartLine": 1, "EndLine": 1,
        "Secret": GITHUB_TOKEN,
        "Match": "TOKEN = %r" % GITHUB_TOKEN}])
    fake_tool(bindir, "gitleaks", _scanner_main("gitleaks", payload))
    document = run(monkeypatch, root, bindir, include_builtin=False,
                   scanners=["gitleaks"], raw_dir=os.path.join(workdir, "raw"))
    text = json.dumps(document)
    assert GITHUB_TOKEN not in text
    assert "REDACTED" in text
    assert document["findings"][0]["category"] == "hardcoded_secret"
    for name in os.listdir(os.path.join(workdir, "raw")):
        with open(os.path.join(workdir, "raw", name), encoding="utf-8") as handle:
            assert GITHUB_TOKEN not in handle.read()


def test_two_runs_differ_only_in_timestamps(workdir, monkeypatch):
    root = os.path.join(workdir, "repo")
    write(root, "app/db.py", "def q():\n    return 1\n")
    bindir = os.path.join(workdir, "bin")
    os.makedirs(bindir)
    fake_tool(bindir, "bandit", _scanner_main("bandit", BANDIT_OUTPUT))
    first = run(monkeypatch, root, bindir, include_builtin=False, scanners=["bandit"])
    second = run(monkeypatch, root, bindir, include_builtin=False, scanners=["bandit"])
    first.pop("generated_at")
    second.pop("generated_at")
    for record in first["runs"] + second["runs"]:
        record.pop("duration_ms", None)
        record.pop("started_at", None)
    assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)


def test_run_is_read_only(workdir, monkeypatch):
    root = os.path.join(workdir, "repo")
    write(root, "app/db.py", "def q():\n    return 1\n")
    write(root, "Dockerfile", "FROM python:3.11\nUSER root\n")
    before = {}
    for dirpath, _, filenames in os.walk(root):
        for name in filenames:
            full = os.path.join(dirpath, name)
            before[full] = (os.stat(full).st_mtime_ns, os.stat(full).st_size)
    bindir = os.path.join(workdir, "bin")
    os.makedirs(bindir)
    fake_tool(bindir, "bandit", _scanner_main("bandit", BANDIT_OUTPUT))
    run(monkeypatch, root, bindir, include_builtin=True, allow_network=True,
        raw_dir=os.path.join(workdir, "raw"))
    after = {}
    for dirpath, _, filenames in os.walk(root):
        for name in filenames:
            full = os.path.join(dirpath, name)
            after[full] = (os.stat(full).st_mtime_ns, os.stat(full).st_size)
    assert before == after


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def test_list_tools_and_probe_only_are_valid_json(monkeypatch, capsys):
    assert so.main(["--list-tools"]) == 0
    listed = json.loads(capsys.readouterr().out)
    assert {tool["name"] for tool in listed["tools"]} >= {"bandit", "semgrep", "gitleaks"}
    assert listed["never_run"]["trufflehog"]

    monkeypatch.setenv("PATH", "/usr/bin:/bin")
    assert so.main(["--probe-only"]) == 0
    probed = json.loads(capsys.readouterr().out)
    assert set(probed["available"]).isdisjoint({"semgrep", "bandit", "gitleaks"})


def test_cli_writes_sidecar_files(workdir, monkeypatch, capsys):
    root = os.path.join(workdir, "repo")
    write(root, "app/x.py", "x = 1\n")
    bindir = os.path.join(workdir, "bin")
    os.makedirs(bindir)
    fake_tool(bindir, "bandit", _scanner_main("bandit", BANDIT_OUTPUT))
    monkeypatch.setenv("PATH", bindir + os.pathsep + "/usr/bin:/bin")
    outdir = os.path.join(workdir, "analysis")
    assert so.main(["--root", root, "--outdir", outdir, "--scanners", "bandit"]) == 0
    for name in ("findings.json", "scanners.json", "scanner_runs.json"):
        assert os.path.isfile(os.path.join(outdir, name)), name
    document = json.load(open(os.path.join(outdir, "findings.json"), encoding="utf-8"))
    coverage = document["coverage"]
    assert coverage["scanners_unavailable"] == []
    assert coverage["network_allowed"] is False
    assert coverage["never_run"]["trufflehog"]
    assert document["limitations"] == []
    assert document["tool"]["name"] == "scanner_orchestrator.py"
    summary = json.loads(capsys.readouterr().out)
    assert summary["findings"] == len(document["findings"])


def test_unknown_scanner_name_is_rejected(workdir):
    with pytest.raises(SystemExit):
        so.orchestrate(os.path.join(workdir, "repo"), scanners=["nope-scanner"])
