#!/usr/bin/env python3
"""Coverage and precision tests for the built-in analyzers.

The full end-to-end suite arrives with the fixture corpus; this file guards the
contracts that are cheapest to break: every required class has at least one
detector, and the authentication / authorization / IDOR rules fire on vulnerable
code while staying silent on the secured look-alike.

Scratch directories live under the repository (``.scratch/tests``), not ``/tmp``.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import sys

import pytest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPTS = os.path.join(REPO, "scripts")
if SCRIPTS not in sys.path:
    sys.path.insert(0, SCRIPTS)

import builtin_analyzers as ba  # noqa: E402

SCRATCH_ROOT = os.path.join(REPO, ".scratch", "tests")

#: Classes produced by a dedicated pass rather than by an entry in RULES.
GENERATED = {
    "hardcoded_secret",        # secret scan, rule ids ``secret-*``
    "vulnerable_dependency",   # dependency pass, rule ids ``dependency-<CVE>``
    "unpinned_dependency",     # dependency pass, rule id ``dependency-unpinned``
    "missing_rate_limiting",   # attack-surface pass, rule id ``surface-no-rate-limit``
}

#: Classes this skill promises to detect, from the taxonomy reference.
REQUIRED_CLASSES = (
    "sql_injection", "nosql_injection", "command_injection", "code_injection", "ssti",
    "ldap_injection", "xpath_injection", "header_injection", "xss_reflected", "xss_stored",
    "path_traversal", "unrestricted_upload", "zip_slip", "ssrf", "open_redirect",
    "tls_verification_disabled", "missing_authentication", "weak_password_hashing",
    "weak_jwt_validation", "session_management", "missing_authorization", "idor",
    "missing_function_level_authorization", "csrf", "business_logic",
    "missing_rate_limiting", "race_condition", "mass_assignment", "weak_randomness",
    "hardcoded_secret", "broken_crypto", "sensitive_data_exposure",
    "insecure_deserialization", "unsigned_update", "vulnerable_dependency",
    "unpinned_dependency", "permissive_cors", "missing_security_headers", "debug_mode",
    "container_security", "cicd_permissions", "iac_misconfiguration",
    "kubernetes_security", "fail_open_error_handling",
)


@pytest.fixture()
def workdir(request):
    digest = hashlib.sha1(request.node.name.encode("utf-8")).hexdigest()[:12]
    path = os.path.join(SCRATCH_ROOT, digest)
    shutil.rmtree(path, ignore_errors=True)
    os.makedirs(path)
    yield path
    shutil.rmtree(path, ignore_errors=True)


def write(root, rel, text):
    path = os.path.join(root, rel)
    os.makedirs(os.path.dirname(path) or root, exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(text)


def categories(found):
    return {finding["category"] for finding in found}


# ---------------------------------------------------------------------------
# rule inventory
# ---------------------------------------------------------------------------

def test_every_rule_declares_a_known_category_and_reference():
    unknown = {rule["category"] for rule in ba.RULES} - set(ba.CATEGORY_META)
    assert not unknown, unknown
    for rule in ba.RULES:
        meta = ba.CATEGORY_META[rule["category"]]
        assert meta["cwe"].startswith("CWE-"), rule["id"]
        assert meta["references"], rule["id"]
        assert rule["patterns"], rule["id"]
        assert rule["severity"] in ("Critical", "High", "Medium", "Low", "Informational")


def test_required_classes_have_a_detector(workdir):
    """Static rules cover most classes; secrets, dependencies, rate limits and the
    route-level checks come from dedicated passes, so all four are proved by
    behaviour rather than by the rule table alone."""
    implemented = {rule["category"] for rule in ba.RULES}
    missing = [name for name in REQUIRED_CLASSES
               if name not in implemented and name not in GENERATED]
    assert not missing, missing

    root = os.path.join(workdir, "repo")
    write(root, "app/config.py", "AWS = 'AKIAABCDEFGHIJKLMNOP'\n")
    write(root, "requirements.txt", "requests\n")
    write(root, "package.json", '{"dependencies": {"lodash": "4.17.15"}}')
    write(root, "app/login.py", "def login(request):\n    return check(request.form['password'])\n")

    document = ba.analyze(root, attack_surface={"entry_points": [{
        "file": "app/login.py", "line": 1, "method": "POST",
        "path": "/login", "language": "python",
        "auth": {"assessment": "no_mechanism_detected"},
    }]})
    seen = categories(document["findings"])
    for name in ("hardcoded_secret", "unpinned_dependency", "vulnerable_dependency",
                 "missing_rate_limiting", "missing_authentication"):
        assert name in seen, (name, sorted(seen))
    serialised = json.dumps(document)
    assert "AKIAABCDEFGHIJKLMNOP" not in serialised, "the secret must be redacted"


def test_rule_ids_are_unique():
    ids = [rule["id"] for rule in ba.RULES]
    assert len(ids) == len(set(ids))


# ---------------------------------------------------------------------------
# authn / authz / IDOR precision
# ---------------------------------------------------------------------------

VULNERABLE = {
    "py/auth_flag.py": "SKIP_AUTH = True\n\ndef profile(request):\n    return db.profile(request.args['id'])\n",
    "js/identity.js": ("app.get('/me', (req, res) => {\n"
                       "  const uid = req.headers['x-user-id'];\n"
                       "  res.json(db.user(uid));\n});\n"),
    "py/role.py": ("def update(request, user_id):\n"
                   "    is_admin = request.json.get('is_admin')\n"
                   "    return db.delete_all() if is_admin else None\n"),
    "py/commented.py": ("def delete_account():\n"
                        "    # @login_required\n"
                        "    return db.Account.delete(request.args['id'])\n"),
    "py/invoice.py": ("def invoice():\n"
                      "    return Invoice.query.get(request.args['invoice_id'])\n"),
    "js/invoice.js": ("app.get('/invoices/:id', async (req, res) => {\n"
                      "  const inv = await Invoice.findById(req.params.id);\n"
                      "  res.json(inv);\n});\n"),
    "rb/invoice.rb": ("class InvoicesController < ApplicationController\n"
                      "  def show\n    @invoice = Invoice.find(params[:id])\n  end\nend\n"),
    "go/invoice.go": ("package main\n\nfunc show(c *gin.Context) {\n"
                      "    db.First(&invoice, c.Param(\"id\"))\n}\n"),
}

SECURE = {
    "py/auth_flag.py": ("SKIP_AUTH = False\n\n@login_required\n"
                        "def profile(request):\n"
                        "    return db.profile(request.args['id'], owner=current_user)\n"),
    "js/identity.js": ("app.get('/me', authenticate, (req, res) => {\n"
                       "  const uid = req.user.id;\n"
                       "  res.json(db.user(uid));\n});\n"),
    "py/role.py": ("def update(request, user_id):\n"
                   "    is_admin = current_user.is_admin\n"
                   "    return db.admin_panel() if is_admin else None\n"),
    "py/commented.py": ("@login_required\n"
                        "def delete_account():\n"
                        "    return db.Account.delete(request.args['id'])\n"),
    "py/invoice.py": ("def invoice():\n"
                      "    return Invoice.query.filter_by(\n"
                      "        id=request.args['invoice_id'], owner_id=current_user.id\n"
                      "    ).first()\n"),
    "js/invoice.js": ("app.get('/invoices/:id', authenticate, async (req, res) => {\n"
                      "  const inv = await Invoice.findOne({ _id: req.params.id, owner: req.user.id });\n"
                      "  res.json(inv);\n});\n"),
    "rb/invoice.rb": ("class InvoicesController < ApplicationController\n"
                      "  def show\n    @invoice = current_user.invoices.find(params[:id])\n  end\nend\n"),
    "go/invoice.go": ("package main\n\nfunc show(c *gin.Context) {\n"
                      "    db.Where(\"user_id = ?\", currentUser.ID).First(&invoice, c.Param(\"id\"))\n}\n"),
}


def _scan(root):
    return ba.analyze(root)["findings"]


def test_authn_authz_idor_fire_on_vulnerable_code(workdir):
    root = os.path.join(workdir, "vulnerable")
    for rel, text in VULNERABLE.items():
        write(root, rel, text)
    found = _scan(root)
    seen = categories(found)
    assert "missing_authentication" in seen, seen
    assert "missing_authorization" in seen, seen
    assert "idor" in seen, seen

    files = {(f["category"], f["location"]["file"]) for f in found}
    assert ("missing_authentication", "py/auth_flag.py") in files
    assert ("missing_authentication", "js/identity.js") in files
    assert ("missing_authorization", "py/role.py") in files
    assert ("missing_authorization", "py/commented.py") in files
    assert ("idor", "py/invoice.py") in files
    assert ("idor", "go/invoice.go") in files


def test_secured_lookalikes_are_silent(workdir):
    root = os.path.join(workdir, "secure")
    for rel, text in SECURE.items():
        write(root, rel, text)
    found = _scan(root)
    assert found == [], [(f["category"], f["location"], f["sources"][0]["rule_id"])
                         for f in found]


def test_each_finding_carries_the_mandatory_narrative(workdir):
    root = os.path.join(workdir, "vulnerable")
    write(root, "py/invoice.py", VULNERABLE["py/invoice.py"])
    (finding,) = _scan(root)
    for field in ("title", "category", "severity", "confidence", "cwe", "owasp",
                  "location", "language", "evidence", "description", "impact",
                  "attack_scenario", "recommended_fix", "references", "sources", "priority"):
        assert finding.get(field) not in (None, "", [], {}), field
    assert finding["cwe"]["id"] == "CWE-639"
    assert finding["evidence"].strip(), "evidence must quote the source line"
