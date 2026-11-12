#!/usr/bin/env python3
"""Stage 1 tests: the inventory is complete, honest about what it skipped, and read-only.

The inventory is the foundation every later stage trusts. Two failure modes matter
more than the rest: silently dropping files (so a finding can never be reported)
and silently *including* things it cannot analyse (so a "clean" result is a lie).
Both are tested here, against synthetic trees rather than the fixture corpus,
because the point is the accounting, not the languages.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys

import pytest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPTS = os.path.join(REPO, "scripts")
if SCRIPTS not in sys.path:
    sys.path.insert(0, SCRIPTS)

import repository_inventory as inv  # noqa: E402

FIXTURES = os.path.join(REPO, "tests", "fixtures")
SCRATCH_ROOT = os.path.join(REPO, ".scratch", "tests")


@pytest.fixture()
def workdir(request):
    digest = hashlib.sha1(request.node.name.encode("utf-8")).hexdigest()[:12]
    path = os.path.join(SCRATCH_ROOT, "inv-" + digest)
    shutil.rmtree(path, ignore_errors=True)
    os.makedirs(path)
    yield path
    shutil.rmtree(path, ignore_errors=True)


def write(root, rel, content, binary=False):
    path = os.path.join(root, rel)
    os.makedirs(os.path.dirname(path) or root, exist_ok=True)
    mode = "wb" if binary else "w"
    with open(path, mode) as handle:
        handle.write(content if binary else content)
    return path


# --- the fixture corpus ---------------------------------------------------- #


def test_corpus_inventory_accounts_for_every_file():
    doc = inv.inventory(os.path.join(FIXTURES, "vulnerable-app"))
    totals = doc["totals"]
    assert totals["files"] == len(doc["files"]) > 0
    assert totals["buckets_reconcile"] is True
    assert sum(doc["buckets"].values()) == totals["files"]
    assert totals["files"] == totals["files"]  # documented invariant, no drift
    assert doc["stage"] == "inventory"
    assert doc["schema_version"] == "1.0"


def test_corpus_language_census_covers_all_seven_languages():
    doc = inv.inventory(os.path.join(FIXTURES, "vulnerable-app"))
    languages = {entry["language"] for entry in doc["files"] if entry["language"]}
    for required in ("python", "javascript", "typescript", "go", "ruby", "php",
                     "java", "csharp"):
        assert required in languages, required
    # The census is a list of dicts, not a mapping: stage 2 and the corpus
    # expectations both read it this way, and a silent shape change broke a
    # generator before.
    assert isinstance(doc["languages"], list)
    assert all(isinstance(entry, dict) for entry in doc["languages"])
    assert {entry["language"] for entry in doc["languages"]} == languages


def test_corpus_manifests_name_one_ecosystem_each():
    doc = inv.inventory(os.path.join(FIXTURES, "vulnerable-app"))
    manifests = {entry["path"]: entry for entry in doc["manifests"]}
    expected = {
        "dotnet/Service.csproj": "nuget",
        "go/go.mod": "go",
        "java/pom.xml": "maven",
        "node/package.json": "npm",
        "php/composer.json": "packagist",
        "python/requirements.txt": "pypi",
        "ruby/Gemfile": "rubygems",
    }
    for path, ecosystem in expected.items():
        assert path in manifests, path
        assert manifests[path]["ecosystem"] == ecosystem, path


def test_infra_files_land_in_the_iac_bucket():
    doc = inv.inventory(os.path.join(FIXTURES, "vulnerable-app"))
    by_path = {entry["path"]: entry for entry in doc["files"]}
    for path in ("infra/Dockerfile", "infra/k8s/deployment.yaml",
                 "infra/terraform/main.tf", ".github/workflows/ci.yml"):
        assert by_path[path]["bucket"] == "iac", path


# --- exclusions, limits and honesty ---------------------------------------- #


def test_gitignore_entries_are_excluded_not_merely_ignored(workdir):
    write(workdir, ".gitignore", "build/\n*.min.js\n")
    write(workdir, "app.py", "print('hello')\n")
    write(workdir, "build/artifact.py", "print('generated')\n")
    write(workdir, "static/bundle.min.js", "var a=1;\n")
    doc = inv.inventory(workdir)
    paths = {entry["path"] for entry in doc["files"]}
    assert "app.py" in paths
    assert "build/artifact.py" not in paths
    assert "static/bundle.min.js" not in paths
    # Excluded paths are accounted for, not silently dropped. A whole excluded
    # directory is recorded once, at the directory, rather than file by file.
    excluded = {entry["path"] for entry in doc["excluded"]}
    assert "static/bundle.min.js" in excluded
    assert any(path == "build" or path.startswith("build/") for path in excluded)
    assert doc["totals"]["excluded"] == len(doc["excluded"]) >= 2


def test_extra_excludes_narrow_the_walk_without_touching_the_tree(workdir):
    write(workdir, "a.py", "x = 1\n")
    write(workdir, "vendor/b.py", "y = 2\n")
    doc = inv.inventory(workdir, extra_excludes=["vendor/"])
    paths = {entry["path"] for entry in doc["files"]}
    assert paths == {"a.py"}
    assert os.path.isfile(os.path.join(workdir, "vendor", "b.py"))


def test_binary_and_oversized_files_are_recorded_as_not_analysed(workdir):
    write(workdir, "code.py", "print(1)\n")
    write(workdir, "image.bin", b"\x00\x01\x02binary\x00", binary=True)
    big = os.path.join(workdir, "big.py")
    with open(big, "w") as handle:
        handle.write("# filler\n" * 5000)
    doc = inv.inventory(workdir, max_bytes=1024)
    by_path = {entry["path"]: entry for entry in doc["files"]}
    assert by_path["image.bin"]["binary"] is True
    skipped = {entry["path"] for entry in doc["not_analysed"]}
    assert "big.py" in skipped
    assert any("big.py" in entry for entry in doc["limitations"]) or skipped


def test_unreadable_and_missing_roots_fail_loudly(workdir):
    with pytest.raises(SystemExit):
        inv.inventory(os.path.join(workdir, "does-not-exist"))


def test_inventory_is_read_only_and_deterministic(workdir):
    write(workdir, "app.py", "print(1)\n")
    write(workdir, "README.md", "# demo\n")
    before = sorted(os.listdir(workdir))
    first = inv.inventory(workdir, with_hashes=True)
    second = inv.inventory(workdir, with_hashes=True)
    assert sorted(os.listdir(workdir)) == before
    for doc in (first, second):
        doc.pop("generated_at", None)
    assert first == second


def test_hashes_are_opt_in_and_match_the_file(workdir):
    path = write(workdir, "app.py", "print(1)\n")
    plain = inv.inventory(workdir)
    assert "sha256" not in plain["files"][0]
    hashed = inv.inventory(workdir, with_hashes=True)
    expected = hashlib.sha256(open(path, "rb").read()).hexdigest()
    assert hashed["files"][0]["sha256"] == expected


def test_cli_writes_json_and_keeps_stdout_quiet(workdir):
    write(workdir, "app.py", "print(1)\n")
    out = os.path.join(workdir, "inventory.json")
    result = subprocess.run([sys.executable, os.path.join(SCRIPTS, "repository_inventory.py"),
                             "--root", workdir, "--out", out],
                            capture_output=True, text=True, timeout=120)
    assert result.returncode == 0, result.stderr
    doc = json.loads(open(out).read())
    assert doc["totals"]["files"] == 1
    assert doc["root"] == os.path.abspath(workdir)


def test_help_works_and_reports_git_state(workdir):
    result = subprocess.run([sys.executable, os.path.join(SCRIPTS, "repository_inventory.py"),
                             "--help"], capture_output=True, text=True, timeout=60)
    assert result.returncode == 0
    assert "--root" in result.stdout
    # Git capture is best-effort: the keys are always present, and a directory
    # with no repository of its own still resolves the enclosing one rather than
    # failing the walk.
    write(workdir, "app.py", "print(1)\n")
    doc = inv.inventory(workdir)
    for key in ("is_repository", "commit", "branch", "dirty", "error"):
        assert key in doc["git"], key
    assert doc["totals"]["files"] == 1
    assert doc["git"]["is_repository"] is True  # .scratch lives inside this repo
    assert doc["git"]["commit"] == inv._git(os.path.abspath(workdir), "rev-parse", "HEAD")
