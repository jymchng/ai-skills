#!/usr/bin/env python3
"""Stage 2a tests: technology detection names the stack the corpus actually uses.

Stage 2a decides which rules are worth running and which vocabulary stages 3-5
use (``process_exec``, ``serialisation``, ``auth``). A false positive here is not
cosmetic: it changes which rules fire, so the assertions are about *named*
frameworks and dependency categories, not just non-empty lists.
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

import detect_technologies as dt  # noqa: E402
import repository_inventory as inv  # noqa: E402

FIXTURES = os.path.join(REPO, "tests", "fixtures")
SCRATCH_ROOT = os.path.join(REPO, ".scratch", "tests")


@pytest.fixture(scope="module")
def vulnerable():
    return dt.detect(os.path.join(FIXTURES, "vulnerable-app"))


@pytest.fixture(scope="module")
def secure():
    return dt.detect(os.path.join(FIXTURES, "secure-app"))


def names(entries):
    return {entry["name"] for entry in entries}


def test_every_language_in_the_corpus_is_recognised(vulnerable):
    frameworks = names(vulnerable["frameworks"])
    for expected in ("Flask", "Express", "Django", "Ruby on Rails", "Symfony",
                     "Java Servlet", "net/http"):
        assert expected in frameworks, (expected, sorted(frameworks))
    # The C# fixture is a convention-routed MVC controller: it declares no route
    # attribute, so no framework name is derivable from its dependencies either
    # (no spring / ASP.NET Core package reference). That gap is recorded in
    # docs/VALIDATION-RESULTS.md rather than papered over here.
    assert "Spring" not in frameworks


def test_dependency_categories_are_populated(vulnerable):
    categories = vulnerable["categories"]
    assert "pickle" in categories["serialisation"]
    assert "PyYAML" in categories["serialisation"]
    for name in ("child_process", "os/exec"):
        assert name in categories["process_exec"]
    assert {"PyJWT", "jsonwebtoken"} <= set(categories["auth"])
    assert {"requests", "Guzzle"} <= set(categories["http_client"])


def test_package_managers_are_derived_from_the_manifests(vulnerable):
    found = {(entry["name"], entry["kind"]) for entry in vulnerable["package_managers"]}
    for expected in (("pip", "requirements"), ("bundler", "manifest"),
                     ("composer", "manifest"), ("go modules", "manifest"),
                     ("maven", "manifest"), ("nuget", "manifest")):
        assert expected in found, (expected, sorted(found))


def test_runtime_versions_come_from_the_manifest_text(vulnerable):
    versions = {entry["name"]: entry["version"] for entry in vulnerable["runtimes"]}
    assert versions["go"] == "1.21"
    assert versions["dotnet"] == "net8.0"
    # A runtime with no declared version is still named, with version None: the
    # report must not invent a version.
    assert "python" in versions and versions["python"] is None


def test_ci_and_infrastructure_are_classified_by_kind(vulnerable):
    assert names(vulnerable["ci"]) == {"GitHub Actions"}
    kinds = {entry["kind"] for entry in vulnerable["infrastructure"]}
    assert {"ci_workflow", "container_image", "kubernetes_manifest", "terraform"} <= kinds


def test_monorepo_components_follow_the_manifests(vulnerable):
    monorepo = vulnerable["monorepo"]
    assert monorepo["is_monorepo"] is True
    components = {entry["path"] for entry in monorepo["components"]}
    assert {"python", "node", "go", "ruby", "php", "java", "dotnet"} <= components


def test_secure_corpus_is_detected_as_the_same_stack(secure):
    """The look-alikes must be recognised: otherwise a clean result proves nothing."""
    frameworks = names(secure["frameworks"])
    assert {"Flask", "Express", "Django", "Ruby on Rails", "Symfony"} <= frameworks
    assert "Helmet" in secure["categories"].get("security_middleware", [])


def test_limitations_are_reported_rather_than_hidden():
    """A framework with no route rule must be named as a coverage gap, not skipped."""
    import attack_surface as asf
    root = os.path.join(FIXTURES, "vulnerable-app")
    document = inv.inventory(root)
    surface = asf.analyse(root, document, dt.detect(root, document))
    joined = " ".join(surface["limitations"])
    assert "java servlet" in joined
    assert "net/http" in joined


def test_detect_is_read_only_and_deterministic():
    root = os.path.join(FIXTURES, "secure-app")
    before = sorted(os.listdir(root))
    first = dt.detect(root)
    second = dt.detect(root)
    assert sorted(os.listdir(root)) == before
    for doc in (first, second):
        doc.pop("generated_at", None)
    assert first == second


def test_cli_writes_a_json_document(tmp_path):
    root = os.path.join(FIXTURES, "secure-app")
    inventory_path = str(tmp_path / "inventory.json")
    out = str(tmp_path / "technologies.json")
    inventory = inv.inventory(root)
    with open(inventory_path, "w") as handle:
        json.dump(inventory, handle)
    result = subprocess.run([sys.executable, os.path.join(SCRIPTS, "detect_technologies.py"),
                             "--root", root, "--inventory", inventory_path, "--out", out],
                            capture_output=True, text=True, timeout=180)
    assert result.returncode == 0, result.stderr
    document = json.loads(open(out).read())
    assert document["stage"] == "technologies"
    assert document["schema_version"] == "1.0"
    assert document["snapshot"]["files"] == len(inventory["files"])
