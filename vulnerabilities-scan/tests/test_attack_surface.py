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
import re
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


#: One genuine snippet per non-HTTP kind. The previous version of this test used
#: the fixture corpus, which only ever "matched" because ``/admin`` appeared in a
#: route string and in a CORS origin -- the exact phantom this stage now rejects.
NON_HTTP_SAMPLES = {
    "graphql": ("python", "type Query {\n  orders: [Order]\n}\n"),
    "graphql-server": ("python", "schema = graphene.Schema(query=Query)\n"),
    "graphql-resolver": ("python", "@Mutation()\ndef create_order(root, info):\n    ...\n"),
    "websocket": ("javascript", "const server = new WebSocketServer({ port: 8080 });\n"),
    "grpc-service": ("python", "def add_OrderServicer_to_server(servicer, server):\n"),
    "rpc-handler": ("python", "@rpc.method()\ndef list_orders():\n    ...\n"),
    "queue-consumer": ("python", "@celery_app.task\ndef send_receipt(order_id):\n"),
    "scheduled-job": ("java", '@Scheduled(cron = "0 0 * * * *")\n'),
    "cli-entry": ("python", 'if __name__ == "__main__":\n    main()\n'),
    "file-watcher": ("javascript", "chokidar.watch('/etc');\n"),
    "admin-interface": ("python", "admin.site.register(Order)\n"),
}


def test_non_http_surfaces_are_classified():
    """Every kind is recognised from a mechanism, and reported with a location."""
    for kind, (language, source) in NON_HTTP_SAMPLES.items():
        found = asf.discover_non_http(source, language)
        assert [hit["kind"] for hit in found] == [kind], (kind, found)
        assert found[0]["line"] == 1, (kind, found)
        assert found[0]["evidence"], kind


def test_masked_view_preserves_offsets_and_line_numbers():
    """Masking must be invisible to line arithmetic: evidence quotes the raw file."""
    source = 'x = """doc"""\n# comment\nif __name__ == "__main__":\n    pass\n'
    masked = asf.mask_non_code(source, "python")
    assert len(masked) == len(source)
    assert masked.count("\n") == source.count("\n")
    assert "doc" not in masked and "comment" not in masked
    assert "__name__" in masked
    found = asf.discover_non_http(source, "python")
    assert found[0]["line"] == 3
    assert found[0]["evidence"].startswith("if __name__ ==")


def test_docstrings_and_comments_do_not_create_surfaces():
    """A file that *describes* a WebSocket server does not expose one."""
    python = """
""" + '"""' + """This module documents a WebSocketServer, an /admin panel and jsonrpc.""" + '"""' + """
# new WebSocketServer({port: 80}); @celery_app.task admin.site.register(X)
def unrelated():
    return "new WebSocket() and @celery_app.task"
"""
    assert asf.discover_non_http(python, "python") == []

    javascript = """
// const server = new WebSocketServer({ port: 80 });
/* chokidar.watch('/etc'); jsonrpc */
const note = "new WebSocket() and @celery_app.task";
"""
    assert asf.discover_non_http(javascript, "javascript") == []


def test_a_commented_out_guard_is_not_a_mechanism():
    """The vulnerable fixture comments its decorator out -- that *is* the finding."""
    commented = "def orders():\n    # @login_required\n    return list_orders()\n"
    active = "def orders():\n    @login_required\n    return list_orders()\n"
    assert asf.discover_auth(commented, "python") == []
    assert [item["mechanism"] for item in asf.discover_auth(active, "python")] == ["login_required"]


def test_string_bearing_mechanisms_are_still_found():
    """Two rules read a literal on purpose; the code-only view must not blind them."""
    php = ("<?php\n"
           "Route::get('/orders', 'OrderController@index')->middleware('auth');\n"
           "$user = $_SESSION['user'];\n")
    mechanisms = {item["mechanism"] for item in asf.discover_auth(php, "php")}
    assert {"laravel-middleware", "php-session-auth"} <= mechanisms


def test_fixture_corpora_report_no_phantom_non_http_surfaces(surface, secure_surface):
    """``/admin/promote`` is a route, not a non-HTTP surface; a CORS origin is not one either."""
    for document in (surface, secure_surface):
        assert document["non_http"] == []


def test_one_surface_per_kind_per_file(tmp_path):
    """A rule that fires on every call describes one mechanism, not N entry points."""
    (tmp_path / "worker.py").write_text(
        "@celery_app.task\ndef a():\n    ...\n\n"
        "@celery_app.task\ndef b():\n    ...\n\n"
        'if __name__ == "__main__":\n    a()\n\n'
        'if __name__ == "__main__":\n    a()\n', encoding="utf-8")
    document = asf.analyse(str(tmp_path))
    assert document["summary"]["non_http_by_kind"] == {"cli-entry": 1, "queue-consumer": 1}
    assert sorted(item["kind"] for item in document["non_http"]) == ["cli-entry", "queue-consumer"]


def test_self_scan_invents_no_surfaces():
    """The regression that started this: a pure-Python CLI repo has no web surface."""
    document = asf.analyse(SCRIPTS)
    kinds = {item["kind"] for item in document["non_http"]}
    assert kinds <= {"cli-entry"}, sorted(kinds)
    assert document["auth_mechanisms"] == []

    # ... and the CLI entries it does report are the real ``__main__`` guards,
    # exactly one per file, pinned to that guard's line.
    guards = {}
    for name in sorted(os.listdir(SCRIPTS)):
        if not name.endswith(".py"):
            continue
        with open(os.path.join(SCRIPTS, name), encoding="utf-8") as handle:
            for number, line in enumerate(handle, start=1):
                if re.match(r"if\s+__name__\s*==", line):
                    guards[name] = number
    reported = {item["file"]: item["line"] for item in document["non_http"]}
    assert reported == guards, (reported, guards)


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
