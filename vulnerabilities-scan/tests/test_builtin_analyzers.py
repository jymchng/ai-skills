#!/usr/bin/env python3
"""Coverage and precision tests for the built-in analyzers.

The full end-to-end suite arrives with the fixture corpus; this file guards the
contracts that are cheapest to break: every required class has at least one
detector, and the authentication / authorization / IDOR rules fire on vulnerable
code while staying silent on the secured look-alike.

Scratch directories live under the repository (``.scratch/tests``), not ``/tmp``.
"""

from __future__ import annotations

import collections
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

#: A shape-valid AWS key id, assembled from parts so the tracked blob holds no
#: matchable credential: GitHub push protection (GH013) rejects such a push.
AWS_KEY_ID = "AKIA" + "ABCDEFGHIJKLMNOP"

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
    write(root, "app/config.py", "AWS = '%s'\n" % AWS_KEY_ID)
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
    assert AWS_KEY_ID not in serialised, "the secret must be redacted"


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


# ---------------------------------------------------------------------------
# documents and text buckets
#
# A credential committed to a README is as usable as one in a module, and the
# file is usually published. Documents are read by the secret pass only, so a
# tutorial's SQL snippet never becomes a finding.
# ---------------------------------------------------------------------------

def _github_token():
    """A GitHub-shaped token, assembled so no literal in this file is a live key."""
    return "ghp_" + "Ab1" * 12


def test_token_in_readme_is_detected_scored_and_redacted(workdir):
    token = _github_token()
    root = os.path.join(workdir, "repo")
    write(root, "README.md", f"# Deploy\n\nUse the key `{token}` when calling the API.\n")
    write(root, "app/main.py", "def main():\n    return 1\n")

    document = ba.analyze(root)
    (finding,) = document["findings"]

    assert finding["category"] == "hardcoded_secret"
    assert finding["location"] == {"file": "README.md", "line_start": 3, "line_end": 3}
    # tagged with the document language, not the code language
    assert finding["language"] == "markdown"
    # scored: a severity band and a priority, with the reason stated
    assert finding["severity"] == "High"
    assert finding["confidence"] == "HIGH"
    assert finding["priority"] == "P1"
    assert finding["priority_factors"][:2] == ["severity: High", "confidence: HIGH"]
    # a doc-specific note, so the reader knows where it is and why it matters more
    assert "documentation" in finding["title"]
    assert "documentation" in finding["description"]
    assert "published" in finding["description"]
    assert finding["sources"] == [{"tool": "builtin_analyzers.py",
                                   "rule_id": "secret-github-token", "raw_ref": None}]
    # redacted: the marker quotes a prefix and the true length, never the value
    assert token not in json.dumps(document)
    assert token not in finding["evidence"]
    assert "ghp_\u2026(40 chars)" in finding["evidence"]
    assert document["summary"]["secrets_redacted"] == 1
    assert document["summary"]["documents_scanned"] >= 1
    assert "docs" in document["coverage"]["buckets_scanned"]


def test_credentials_are_found_in_every_document_and_text_bucket(workdir):
    token = _github_token()
    root = os.path.join(workdir, "repo")
    documents = {
        "README.md": ("markdown", f"# App\n\nToken: {token}\n"),
        "docs/guide.rst": ("rst", f"Guide\n=====\n\nKey: {token}\n"),
        "CHANGELOG.md": ("markdown", f"## 1.1\n\n- rotate {token}\n"),
        "notes.txt": ("text", f"reminder: {token}\n"),
        "nb.ipynb": ("notebook", json.dumps({"cells": [{"source": [f"KEY = '{token}'"]}]})),
        ".env.example": (None, f"API_KEY={token}\n"),
    }
    for rel, (_language, text) in documents.items():
        write(root, rel, text)

    document = ba.analyze(root)
    found = {(f["location"]["file"], f["language"]) for f in document["findings"]}
    for rel, (language, _text) in documents.items():
        assert any(name == rel for name, _lang in found), (rel, sorted(found))
        if language:
            assert (rel, language) in found, (rel, sorted(found))
    assert token not in json.dumps(document)


def test_prose_never_produces_code_findings(workdir):
    token = _github_token()
    root = os.path.join(workdir, "repo")
    write(root, "docs/tutorial.md",
          "# Tutorial\n\n"
          "```python\n"
          "db.execute(f\"SELECT * FROM users WHERE id={request.args['id']}\")\n"
          "```\n\n"
          "The page then writes <script>alert(document.cookie)</script> unescaped.\n\n"
          f"And here is the key it used: {token}\n")

    document = ba.analyze(root)
    seen = categories(document["findings"])
    assert "sql_injection" not in seen, seen
    assert "xss_reflected" not in seen, seen
    assert seen == {"hardcoded_secret"}, seen
    (finding,) = document["findings"]
    assert finding["location"]["file"] == "docs/tutorial.md"
    quoted = open(os.path.join(root, "docs/tutorial.md"), encoding="utf-8").read()
    assert token in quoted.splitlines()[finding["location"]["line_start"] - 1]
    assert token not in json.dumps(document)


def test_illustrative_doc_lines_are_not_reported(workdir):
    root = os.path.join(workdir, "repo")
    write(root, "README.md",
          "# Configuration\n\n"
          "```\n"
          "api_key = \"your-api-key-here\"\n"
          "password = \"changeme\"\n"
          "token = \"example\"\n"
          "url = \"postgresql://user:...@localhost/db\"\n"
          "```\n")
    write(root, "docs/setup.rst", "Setup\n=====\n\nSet ``client_secret = \"sample\"`` first.\n")

    assert _scan(root) == []


def test_a_real_token_beside_an_illustration_is_still_reported(workdir):
    token = _github_token()
    root = os.path.join(workdir, "repo")
    write(root, "README.md",
          "# Configuration\n\n"
          "api_key = \"your-api-key-here\"   # placeholder, safe\n"
          f"Deploy with `{token}` now\n")

    (finding,) = _scan(root)
    assert finding["location"]["line_start"] == 4
    assert token not in json.dumps(finding)
    assert "ghp_\u2026(40 chars)" in finding["evidence"]


def test_doc_line_numbers_point_at_the_audited_file(workdir):
    token = _github_token()
    root = os.path.join(workdir, "repo")
    body = "".join(f"line {number}\n" for number in range(1, 20))
    write(root, "docs/deploy.md", body + f"\nexport GITHUB_TOKEN={token}\n")
    (finding,) = _scan(root)
    with open(os.path.join(root, "docs/deploy.md"), encoding="utf-8") as handle:
        quoted = handle.read().splitlines()[finding["location"]["line_start"] - 1]
    assert token in quoted, (finding["location"], quoted)


def test_document_findings_conform_to_the_schema(workdir):
    """A document finding is a finding like any other: same mandatory fields.

    The analysis document is checked against the JSON Schema only. The stage-5
    cross-field rule that refuses ``unvalidated`` findings in a *reportable*
    dataset does not apply yet: this is stage 3, and the status is deliberately
    ``unvalidated``, exactly as it is for code findings.
    """
    import jsonschema

    import finding_model as fm

    token = _github_token()
    root = os.path.join(workdir, "repo")
    write(root, "README.md", f"# App\n\nKey: {token}\n")
    document = ba.analyze(root)

    problems = ["%s: %s" % ("/".join(str(part) for part in error.absolute_path), error.message)
                for error in jsonschema.Draft202012Validator(fm.load_schema()).iter_errors(document)]
    assert problems == []
    assert document["findings"][0]["validation_status"] == "unvalidated"
    assert "docs" in document["coverage"]["buckets_scanned"]


# ---------------------------------------------------------------------------
# a secret beside an unrelated finding
#
# Evidence quotes a ±1 window, so the neighbouring line is published with the
# finding. Redacting only the value a rule matched left a credential sitting on
# that neighbour in the excerpt, and it travelled into analysis.json, the
# deduplicated dataset and every report.
# ---------------------------------------------------------------------------

def test_a_secret_beside_an_unrelated_finding_is_redacted_from_its_evidence(workdir):
    stripe = "sk_live_" + "Z" * 24
    root = os.path.join(workdir, "repo")
    write(root, "app/orders.py",
          "from flask import request\n"
          "def handler(request):\n"
          "    # billing key: " + stripe + "\n"
          "    return db.execute(\"SELECT * FROM orders WHERE id=\" + request.args['id'])\n")

    document = ba.analyze(root)
    sql = [f for f in document["findings"] if f["category"] == "sql_injection"]
    assert len(sql) == 1, [f["category"] for f in document["findings"]]
    evidence = sql[0]["evidence"]

    assert stripe not in json.dumps(document), "the raw key reached the analysis document"
    assert stripe not in evidence
    # the marker, not a blank: a reader still sees that something was redacted
    assert "sk_l\u2026(32 chars)" in evidence, evidence
    # and the finding itself is still readable
    assert "SELECT * FROM orders WHERE id=" in evidence

    # the secret finding quotes its own window, centred one line earlier
    secret_finding = [f for f in document["findings"] if f["category"] == "hardcoded_secret"][0]
    assert stripe not in secret_finding["evidence"]
    assert "sk_l\u2026(32 chars)" in secret_finding["evidence"]


def test_build_finding_redacts_whatever_evidence_it_is_handed():
    """Defence in depth: a caller that quotes its own excerpt cannot leak one."""
    stripe = "sk_live_" + "Z" * 24
    rule = {"category": "sql_injection", "title": "t", "severity": "High",
            "confidence": "MEDIUM", "guards": [], "extra_references": [], "id": "r1"}
    record = ba.build_finding(rule, file="app/q.py", line_start=2, line_end=2,
                              evidence="    2 | key = " + stripe, language="python")
    assert stripe not in record["evidence"]
    assert "sk_l\u2026(32 chars)" in record["evidence"]


def test_redact_shapes_leaves_placeholders_and_markers_alone():
    assert ba.redact_shapes('api_key = "your-api-key-here"') == 'api_key = "your-api-key-here"'
    marker = "    3 | billing: sk_l\u2026(32 chars)"
    assert ba.redact_shapes(marker) == marker
    assert ba.redact_shapes("password = \"${DB_PASS}\"") == "password = \"${DB_PASS}\""
    # and a real value in the same shape is still redacted
    stripe = "sk_live_" + "Z" * 24
    assert stripe not in ba.redact_shapes("key: " + stripe)


# ---------------------------------------------------------------------------
# Precision: what the rules read, and what they leave alone
# ---------------------------------------------------------------------------


def _scan_categories(workdir, files):
    root = os.path.join(workdir, "repo")
    for rel, text in files.items():
        write(root, rel, text)
    return categories(ba.analyze(root)["findings"])


def test_error_handling_that_guards_nothing_is_not_a_fail_open(workdir):
    """`except: pass` is only a security fail-open when what it guards decides
    something. Swallowing a regex or JSON error is error tolerance, and flagging
    it made every repository that parses input look vulnerable."""
    benign = {
        "app/patterns.py": ("import re\n\n\n"
                            "def compile_all(patterns):\n"
                            "    compiled = []\n"
                            "    for pattern in patterns:\n"
                            "        try:\n"
                            "            compiled.append(re.compile(pattern))\n"
                            "        except re.error:\n"
                            "            continue\n"
                            "    return compiled\n"),
        "app/load.py": ("import json\n\n\n"
                        "def load(text):\n"
                        "    try:\n"
                        "        return json.loads(text)\n"
                        "    except ValueError:\n"
                        "        pass\n"),
    }
    assert "fail_open_error_handling" not in _scan_categories(workdir, benign)

    # The same shape around a security decision is still reported.
    guarded = {
        "app/verify.py": ("def handler(request):\n"
                          "    try:\n"
                          "        verify_signature(request.body, request.headers['x-signature'])\n"
                          "    except ValueError:\n"
                          "        pass\n"
                          "    return process(request)\n"),
    }
    root = os.path.join(workdir, "guarded")
    for rel, text in guarded.items():
        write(root, rel, text)
    found = ba.analyze(root)["findings"]
    assert any(f["category"] == "fail_open_error_handling"
               and f["location"]["file"] == "app/verify.py" for f in found), \
        [f["category"] for f in found]


def test_a_commented_out_guard_is_evidence_not_noise(workdir):
    """Comments are read on purpose: a commented-out check is the finding, and a
    credential pasted into a note is a credential."""
    comment = "def delete_account(request):\n    # @login_required\n    return db.Account.delete(request.args['id'])\n"
    seen = _scan_categories(workdir, {"app/del.py": comment})
    assert "missing_authorization" in seen, seen

    stripe = "sk_live_" + "Y" * 24
    root = os.path.join(workdir, "secret")
    write(root, "app/notes.py", "def f():\n    # billing key: " + stripe + "\n    return 1\n")
    document = ba.analyze(root)
    assert stripe not in json.dumps(document)
    assert any(f["category"] == "hardcoded_secret" for f in document["findings"]), \
        [f["category"] for f in document["findings"]]


def test_a_detection_signature_file_is_skipped_and_says_so(workdir):
    """The analyzer's own rule table stores patterns as literals. Running those
    patterns over the table reports the table as a vulnerability -- a self-match
    by construction, and the reason a self-scan was unreadable."""
    root = os.path.join(workdir, "repo")
    # A miniature of the real file: a rule table with the shapes it detects.
    write(root, "scripts/builtin_analyzers.py",
          'RULES = [\n'
          '    ("sql-injection", r"execute\\\\s*\\\\(\\\\s*f[\\"\']"),\n'
          '    ("fail-open", r"except[^\\\\n]*:\\\\s*\\\\n\\\\s*pass"),\n'
          ']\n'
          'KEY = "sk_live_' + "X" * 24 + '"\n')
    write(root, "scripts/real_code.py",
          'import re\n\n\ndef f(request):\n'
          '    return db.execute("SELECT * FROM t WHERE id=" + request.args["id"])\n')

    document = ba.analyze(root)
    files = {finding["location"]["file"] for finding in document["findings"]}
    assert "scripts/builtin_analyzers.py" not in files, files
    assert any(finding["category"] == "sql_injection"
               and finding["location"]["file"] == "scripts/real_code.py"
               for finding in document["findings"]), \
        [finding["category"] for finding in document["findings"]]
    assert any("detection-signature file" in note for note in document["limitations"]), \
        document["limitations"]


def test_a_whitespace_anchored_match_reports_the_line_it_matched(workdir):
    """`(?m)^\\s*from_port` must name the line the port is declared on, not the
    blank line the indentation started from."""
    root = os.path.join(workdir, "repo")
    write(root, "infra/main.tf",
          'resource "aws_security_group" "app" {\n'
          '  ingress {\n'
          '    # reachable from the private range only\n'
          '    from_port = 22\n'
          '    cidr_blocks = ["10.0.0.0/8"]\n'
          '  }\n'
          '}\n')
    found = [f for f in ba.analyze(root)["findings"]
             if f["location"]["file"] == "infra/main.tf"]
    assert found, "the open management port should still be reported"
    assert {f["location"]["line_start"] for f in found} == {4}, \
        [(f["category"], f["location"]["line_start"]) for f in found]


#: The only self-findings a scan of this tool's own ``scripts/`` tree may report,
#: keyed by ``(category, file)`` with an expected count and the reason it
#: survives. Everything else was a false positive by construction: the rule table
#: matching its own pattern literals, a docstring naming a mechanism, or an
#: example credential quoted beside the shape that detects it. Adding a rule that
#: fires on this repository must either fix the rule or justify an entry here.
SELF_SCAN_ALLOW_LIST = {
    ("hardcoded_secret", "validate_reports.py"): (
        1, "a connection-string *shape* quoted in a comment documenting the redaction marker"),
    ("sensitive_data_exposure", "finding_model.py"): (
        1, "a print of a variable literally named ``secrets``, which is what the rule looks for"),
    ("xss_stored", "finding_model.py"): (
        1, "an f-string comparison that contains ``<`` and a brace, the shape the rule matches"),
}


def test_a_self_scan_of_the_scripts_tree_reports_only_the_allow_list():
    """The measurement behind this goal, asserted rather than described.

    Before the precision work, scanning this repository's own ``scripts/``
    directory produced 27 findings -- 16 ``hardcoded_secret`` (the rule table and
    its docstrings quoting the example tokens they detect) and 8
    ``fail_open_error_handling`` (``except re.error: continue`` around
    ``re.compile``) among them. The rule-definition files are now excluded, and
    the fail-open rule requires the swallowed exception to guard a security
    decision, so only the documented three remain.
    """
    document = ba.analyze(SCRIPTS)
    reported = collections.Counter(
        (finding["category"], os.path.basename(finding["location"]["file"]))
        for finding in document["findings"])
    allowed = collections.Counter({key: count
                                   for key, (count, _reason) in SELF_SCAN_ALLOW_LIST.items()})

    assert reported == allowed, {
        "unexpected_self_findings": dict(reported - allowed),
        "documented_but_absent": dict(allowed - reported),
        "documented_allow_list": {key: reason
                                  for key, (_count, reason) in SELF_SCAN_ALLOW_LIST.items()},
    }

    # The two artefacts this goal names are gone, not merely fewer.
    assert not [f for f in document["findings"]
                if f["category"] == "fail_open_error_handling"], \
        [f["location"] for f in document["findings"]
         if f["category"] == "fail_open_error_handling"]
    for name in ba.SIGNATURE_FILES:
        assert not [f for f in document["findings"]
                    if os.path.basename(f["location"]["file"]) == name], name


def test_the_self_scan_is_quiet_because_it_says_what_it_skipped():
    """A silent skip would be indistinguishable from a clean scan. Every excluded
    rule-definition file must appear in the coverage limitations."""
    document = ba.analyze(SCRIPTS)
    limitations = " \n".join(document["limitations"])
    for name in ba.SIGNATURE_FILES:
        assert name in limitations, (name, document["limitations"])
    assert "detection-signature file" in limitations
