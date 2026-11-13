#!/usr/bin/env python3
"""Every scan family added beyond the original seven languages, in both directions.

The vulnerable corpus grew one directory per new family and the secure corpus grew
its mirror image, so each rule here is pinned twice: it must fire on the code that
is actually wrong, and it must stay silent on the code that does the same job
safely. A rule that only has a positive is a rule nobody has measured.

Two classification defects are pinned here as well, because they decided whether
the new rules were reachable at all: a pipeline file in a subdirectory was
classified ``config`` (the anchored pattern was matched against the whole path,
never the file name), and a CloudFormation template inherited ``kubernetes`` from
whatever directory held it.
"""

from __future__ import annotations

import os
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPTS = os.path.join(REPO, "scripts")
if SCRIPTS not in sys.path:
    sys.path.insert(0, SCRIPTS)

import builtin_analyzers as ba
import repository_inventory as inv

FIXTURES = os.path.join(REPO, "tests", "fixtures")

#: ``(rule id, fixture directory, expected language of that directory's main file)``
FAMILIES = (
    ("rust-sql-format", "rust", "rust"),
    ("rust-command-shell", "rust", "rust"),
    ("rust-path-traversal", "rust", "rust"),
    ("c-command-exec", "c", "c"),
    ("c-weak-random-token", "c", "c"),
    ("sh-eval-variable", "shell", "shell"),
    ("sh-curl-pipe-shell", "shell", "shell"),
    ("sh-predictable-temp", "shell", "shell"),
    ("ps-invoke-expression", "powershell", "powershell"),
    ("ps-download-execute", "powershell", "powershell"),
    ("sql-xp-cmdshell", "sql", "sql"),
    ("cfn-public-access", "cloudformation", "cloudformation"),
    ("cfn-open-ingress", "cloudformation", "cloudformation"),
    ("cfn-wildcard-iam", "cloudformation", "cloudformation"),
    ("cfn-no-encryption", "cloudformation", "cloudformation"),
    ("ansible-no-cert-check", "ansible", "kubernetes"),
    ("ansible-templated-command", "ansible", "kubernetes"),
    ("ansible-world-writable", "ansible", "kubernetes"),
    ("gitlab-ci-shell-pipe", "ci", "yaml"),
    ("jenkins-shell-pipe", "ci", "groovy"),
    ("iac-floating-image", "ci", "yaml"),
    ("compose-docker-socket", "compose", "yaml"),
    ("compose-host-network", "compose", "yaml"),
    # Swift and Kotlin: new coverage that reuses an existing rule where the pattern
    # is a JDK/Foundation API call rather than language syntax.
    ("swift-command-shell", "swift", "swift"),
    ("swift-sql-interpolation", "swift", "swift"),
    ("java-sql-concat", "kotlin", "kotlin"),
    ("cmd-java-runtime", "kotlin", "kotlin"),
    ("unsafe-deserialization", "kotlin", "kotlin"),
    ("weak-password-hash", "kotlin", "kotlin"),
    ("path-traversal", "kotlin", "kotlin"),
)


def _analyse(corpus: str, family: str):
    root = os.path.join(FIXTURES, corpus, family)
    inventory = inv.inventory(root)
    return inventory, ba.analyze(root, inventory)


def _rule_ids(document):
    return {source.get("rule_id")
            for finding in document["findings"]
            for source in finding.get("sources") or []}


def test_every_new_rule_fires_on_the_code_that_is_wrong():
    for rule_id, family, _language in FAMILIES:
        _inventory, document = _analyse("vulnerable-app", family)
        assert rule_id in _rule_ids(document), (rule_id, family, sorted(_rule_ids(document)))


def test_no_new_rule_fires_on_the_safe_look_alike():
    """The other half of the measurement: the mirror image must produce nothing."""
    for rule_id, family, _language in FAMILIES:
        _inventory, document = _analyse("secure-app", family)
        assert document["findings"] == [], (rule_id, family, [
            (f["location"]["file"], [s.get("rule_id") for s in f.get("sources") or []])
            for f in document["findings"]])


def test_each_family_directory_is_classified_and_scanned():
    """A rule is only reachable if its files land in a scanned bucket.

    Classification is path-based: a ``cloudformation/`` directory only identifies a
    template when the path still contains it, so this exercises the corpus-relative
    path the audit actually walks, not a subtree scanned in isolation.
    """
    for _rule_id, family, language in FAMILIES:
        root = os.path.join(FIXTURES, "vulnerable-app", family)
        inventory = inv.inventory(os.path.join(FIXTURES, "vulnerable-app"))
        entries = [entry for entry in inventory["files"]
                   if entry["path"].startswith(family + "/")]
        assert entries, family
        for entry in entries:
            assert entry["bucket"] in ("source", "iac", "config", "manifest"), (
                family, entry["path"], entry["bucket"])
        assert language in {entry["language"] for entry in entries}, (family, entries)
        assert inv.inventory(root)["files"], family


def test_a_pipeline_file_in_a_subdirectory_is_infrastructure():
    """The anchored CI pattern was matched against the path, so nothing matched."""
    for path in ("ci/.gitlab-ci.yml", "ci/Jenkinsfile"):
        bucket, language = inv.classify(path, os.path.basename(path))
        assert bucket == "iac", (path, bucket, language)


def test_a_cloudformation_template_is_not_called_kubernetes():
    bucket, language = inv.classify("cloudformation/stack.yaml", "stack.yaml")
    assert (bucket, language) == ("iac", "cloudformation"), (bucket, language)


def test_comments_are_masked_before_the_new_rules_read_them():
    """``keep_comments`` is on for the two families that need comment evidence, so a
    rule must not match its own subject inside a note. SQL's ``--`` and
    PowerShell's ``#`` were both missing from the syntax table."""
    import finding_model as fm

    sql = "-- EXEC master..xp_cmdshell 'whoami'\nSELECT 1;\n"
    assert "xp_cmdshell" not in fm.mask_non_code(sql, "sql")
    assert "xp_cmdshell" in sql

    powershell = "# Invoke-Expression $payload\nWrite-Host ready\n"
    assert "Invoke-Expression" not in fm.mask_non_code(powershell, "powershell")

    lua = "-- os.execute(cmd)\nlocal x = 1\n"
    assert "os.execute" not in fm.mask_non_code(lua, "lua")


def test_a_literal_command_is_not_an_injection():
    """``system("date")`` is not a shell injection; a variable argument is."""
    import tempfile

    literal = os.path.join(tempfile.mkdtemp(prefix="scan-families-"), "literal.c")
    with open(literal, "w", encoding="utf-8") as handle:
        handle.write('#include <stdlib.h>\nint main(void) { system("date"); return 0; }\n')
    document = ba.analyze(os.path.dirname(literal), inv.inventory(os.path.dirname(literal)))
    assert document["findings"] == [], [
        (f["location"], [s.get("rule_id") for s in f.get("sources") or []])
        for f in document["findings"]]


def test_querying_the_configuration_is_not_invoking_it():
    """Reading the ``xp_cmdshell`` setting is not running a command through it."""
    import tempfile

    root = tempfile.mkdtemp(prefix="scan-families-")
    with open(os.path.join(root, "check.sql"), "w", encoding="utf-8") as handle:
        handle.write("SELECT name, value_in_use FROM sys.configurations\n"
                     "WHERE name = 'xp_cmdshell';\n")
    document = ba.analyze(root, inv.inventory(root))
    assert document["findings"] == []


def test_dropping_every_capability_is_not_adding_them():
    """``cap_drop: - ALL`` is the mitigation, not the finding."""
    import tempfile

    root = tempfile.mkdtemp(prefix="scan-families-")
    os.makedirs(os.path.join(root, "compose"))
    target = os.path.join(root, "compose", "docker-compose.yml")
    with open(target, "w", encoding="utf-8") as handle:
        handle.write("services:\n  api:\n    image: example/api:1.4.2\n"
                     "    cap_drop:\n      - ALL\n")
    document = ba.analyze(root, inv.inventory(root))
    assert document["findings"] == []
