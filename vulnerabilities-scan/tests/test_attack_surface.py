#!/usr/bin/env python3
"""Stage 2b tests: the attack surface is enumerated per framework, with honest limits.

Entry points decide which "missing authentication" and "IDOR" findings are even
possible, and the auth mechanisms found here are the compensating control stage 5
uses to suppress a false positive. Both directions are tested: routes that exist
must be found, and a route with no visible mechanism must be reported as *not
visible* rather than as missing authentication.
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

import attack_surface as asf  # noqa: E402
import detect_technologies as dt  # noqa: E402
import repository_inventory as inv  # noqa: E402

FIXTURES = os.path.join(REPO, "tests", "fixtures")
SCRATCH_ROOT = os.path.join(REPO, ".scratch", "tests")


@pytest.fixture(scope="module")
def surface():
    root = os.path.join(FIXTURES, "vulnerable-app")
    inventory = inv.inventory(root)
    return asf.analyse(root, inventory, dt.detect(root, inventory))


@pytest.fixture(scope="module")
def secure_surface():
    return asf.analyse(os.path.join(FIXTURES, "secure-app"))


def paths(document, framework=None):
    return {entry["path"] for entry in document["entry_points"]
            if framework is None or entry["framework"] == framework}


def test_routes_are_found_in_every_supported_language(surface):
    # Python (Flask/FastAPI) and Node (Express) are the frameworks the corpus
    # declares with an enumerable route table. Go/Ruby/PHP/Java routes in the same
    # corpus are *not* enumerated today; that gap is measured and recorded in
    # docs/VALIDATION-RESULTS.md rather than asserted away here.
    for expected in ("/orders", "/orders/<order_id>", "/session", "/users",
                     "/orders/report", "/fetch"):
        assert expected in paths(surface), (expected, sorted(paths(surface)))
    frameworks = {entry["framework"] for entry in surface["entry_points"]}
    assert {"fastapi", "express"} <= frameworks


def test_each_entry_point_is_addressable_and_well_formed(surface):
    ids = [entry["id"] for entry in surface["entry_points"]]
    assert ids == ["EP-%03d" % (index + 1) for index in range(len(ids))]
    for entry in surface["entry_points"]:
        assert entry["kind"] == "http_route"
        assert entry["method"] in {"GET", "POST", "PUT", "PATCH", "DELETE", "ANY"}
        assert entry["path"].startswith("/"), entry
        assert entry["file"] and entry["line"] > 0
        assert entry["framework"]


def test_summary_agrees_with_the_entry_point_list(surface):
    summary = surface["summary"]
    assert summary["entry_points"] == len(surface["entry_points"])
    assert summary["http_routes"] == len(surface["entry_points"])
    assert sum(summary["by_framework"].values()) == summary["entry_points"]
    assert sum(summary["by_method"].values()) == summary["entry_points"]
    assert summary["without_visible_auth"] == sum(
        1 for entry in surface["entry_points"]
        if (entry.get("auth") or {}).get("assessment") == "no_mechanism_detected")


def test_absence_of_auth_is_reported_as_absence_of_evidence(surface):
    """The wording matters: an unauthenticated-looking route is a lead, not a finding."""
    limitation = " ".join(surface["limitations"])
    assert "no visible authentication" in limitation
    assert "not proof of missing authentication" in limitation
    for entry in surface["entry_points"]:
        auth = entry.get("auth") or {}
        if auth.get("assessment") == "no_mechanism_detected":
            assert auth["mechanisms"] == []


def test_auth_mechanisms_are_attributed_to_their_file(surface, secure_surface):
    mechanisms = {(entry["mechanism"], entry["file"]) for entry in surface["auth_mechanisms"]}
    assert ("flask-login", "python/orders/identity.py") in mechanisms
    assert ("rails-before-action", "ruby/app/controllers/orders_controller.rb") in mechanisms
    # The secured look-alike uses more mechanisms, including framework idioms the
    # vulnerable copy never shows: that difference is what stage 5 relies on.
    secure_mechanisms = {entry["mechanism"] for entry in secure_surface["auth_mechanisms"]}
    assert {"aspnet-identity", "devise", "java-principal", "session-check"} <= secure_mechanisms
    for entry in secure_surface["auth_mechanisms"]:
        assert entry["file"] and entry["line"] > 0


def test_trust_boundaries_count_untrusted_sources(surface):
    trust = surface["trust_boundaries"]
    assert trust["input_occurrences"] > 0
    assert trust["untrusted_sources"]["request query"] > 0
    assert trust["untrusted_sources"]["uploaded file"] > 0
    assert trust["note"]


def test_non_http_surfaces_are_classified(surface):
    assert surface["non_http"], "the corpus has an /admin route worth a non-HTTP surface"
    for entry in surface["non_http"]:
        assert entry["kind"] in {"admin-interface", "queue-consumer", "websocket",
                                 "rpc-handler", "graphql", "cli-entry"}
        assert entry["file"] and entry["line"] > 0


def test_undecomposable_frameworks_are_named_as_a_limitation(surface):
    """Silence would read as 'no endpoints'; the gap must be stated."""
    joined = " ".join(surface["limitations"])
    assert "no route-discovery rule" in joined
    assert "java servlet" in joined


def test_analyse_is_read_only_and_deterministic():
    root = os.path.join(FIXTURES, "vulnerable-app")
    before = sorted(os.listdir(root))
    first = asf.analyse(root)
    second = asf.analyse(root)
    assert sorted(os.listdir(root)) == before
    for document in (first, second):
        document.pop("generated_at", None)
        document.get("snapshot", {}).pop("generated_at", None)
    assert first == second


def test_cli_writes_a_json_document(tmp_path):
    root = os.path.join(FIXTURES, "vulnerable-app")
    inventory = inv.inventory(root)
    technologies = dt.detect(root, inventory)
    inventory_path = str(tmp_path / "inventory.json")
    tech_path = str(tmp_path / "technologies.json")
    out = str(tmp_path / "attack-surface.json")
    with open(inventory_path, "w") as handle:
        json.dump(inventory, handle)
    with open(tech_path, "w") as handle:
        json.dump(technologies, handle)
    result = subprocess.run([sys.executable, os.path.join(SCRIPTS, "attack_surface.py"),
                             "--root", root, "--inventory", inventory_path,
                             "--technologies", tech_path, "--out", out],
                            capture_output=True, text=True, timeout=180)
    assert result.returncode == 0, result.stderr
    document = json.loads(open(out).read())
    assert document["stage"] == "attack_surface"
    assert document["summary"]["entry_points"] == len(document["entry_points"]) > 0
