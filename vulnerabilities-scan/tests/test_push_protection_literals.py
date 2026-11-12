"""Guard: no live-key-shaped literal may be committed to the tracked tree.

GitHub rejects a push with ``GH013`` when secret scanning's push protection
recognises a credential in the objects being uploaded. The scan is purely
textual, so a *fabricated* key with the right shape blocks the push exactly like
a real one: the fix is always to assemble the value at run time
(``"sk_live_" + "Z" * 24``) and keep the literal out of the object.

Nothing below knows whether a value is real; that is the point. There is no
per-file exemption and no suppression comment -- the only escape hatch is
:data:`DOCUMENTED_EXAMPLES`, a value the provider itself publishes as fake and
push protection lets through for that reason.
"""

from __future__ import annotations

import os
import re
import subprocess

# --------------------------------------------------------------------------- #
# The shapes push protection reacts to. Each pattern matches a *complete*
# credential, so the analyzer's own pattern text (``\bAKIA[0-9A-Z]{16}\b`` in
# ``builtin_analyzers``) stays clean: the characters after the prefix there are
# regex syntax, not a key body.
# --------------------------------------------------------------------------- #

PROVIDER_SHAPES = {
    "stripe live key": re.compile(r"\bsk_live_[0-9A-Za-z]{16,}"),
    "github token": re.compile(r"\bghp_[0-9A-Za-z]{20,}"),
    "aws access key id": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "slack bot token": re.compile(r"\bxoxb-[0-9A-Za-z-]{10,}"),
    # A header alone (``-----BEGIN RSA PRIVATE KEY-----``) is a delimiter, not a
    # key; a base64 body is what makes it a rejection, so the header only counts
    # when a key-material line follows it.
    "private key block": re.compile(
        r"-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----(?:\\n|[\r\n])"
        r"(?:[A-Za-z0-9+/]{40,}={0,2}(?:\\n|[\r\n])?)+"),
}

#: Values a provider publishes as examples, so push protection allows them.
#: Assembled here because this file -- which is itself tracked -- is scanned too.
DOCUMENTED_EXAMPLES = frozenset({
    "AKIA" + "IOSFODNN7EXAMPLE",   # AWS's documentation key id
})


def _preview(shape: str, value: str) -> str:
    """Describe a match without reproducing it in a failure message."""
    return "%s (%d chars)" % (shape, len(value))


def scan_text(text: str) -> list[tuple[int, str, str]]:
    """Return ``(line number, shape, preview)`` for every credential-shaped run."""
    found = []
    for shape, pattern in PROVIDER_SHAPES.items():
        for match in pattern.finditer(text):
            if match.group(0) in DOCUMENTED_EXAMPLES:
                continue
            lineno = text.count("\n", 0, match.start()) + 1
            found.append((lineno, shape, _preview(shape, match.group(0))))
    return sorted(found)


def scan_file(path: str, relative_to: str = "") -> list[str]:
    """Return ``path:line: shape (...)`` messages for one file."""
    with open(path, encoding="utf-8", errors="replace") as handle:
        text = handle.read()
    label = os.path.relpath(path, relative_to) if relative_to else path
    return ["%s:%d: %s -- assemble the value at run time instead"
            % (label, lineno, preview)
            for lineno, _shape, preview in scan_text(text)]


def _repository_root() -> str:
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def tracked_files() -> list[str]:
    """Paths git would upload, so ignored build output cannot hide a literal."""
    root = _repository_root()
    output = subprocess.run(["git", "ls-files", "-z"], cwd=root,
                            check=True, capture_output=True).stdout
    return [os.path.join(root, name) for name in output.decode().split("\0") if name]


def find_violations(paths: list[str] | None = None) -> list[str]:
    """Scan every given path, or the whole tracked tree when none is given."""
    root = _repository_root()
    paths = tracked_files() if paths is None else paths
    violations = []
    for path in paths:
        if os.path.isfile(path):
            violations.extend(scan_file(path, relative_to=root))
    return violations


# --------------------------------------------------------------------------- #
# The guard
# --------------------------------------------------------------------------- #

def test_no_tracked_file_contains_a_live_key_shaped_literal():
    """A hit here is a push rejection waiting to happen."""
    violations = find_violations()
    assert not violations, (
        "credential-shaped literals in the tracked tree would be rejected by "
        "GitHub push protection (GH013):\n  " + "\n  ".join(violations))


def test_the_guard_reports_the_path_and_line_of_a_planted_literal(tmp_path):
    """A guard that cannot say *where* is a guard nobody acts on."""
    planted = tmp_path / "planted.py"
    # The value is assembled here so this test file stays clean itself.
    planted.write_text("clean = 1\n"
                       "done = 2\n"
                       "token = " + repr("ghp_" + "Ab1" * 12) + "\n")
    violations = find_violations([str(planted)])
    assert len(violations) == 1, violations
    assert "planted.py:3: github token" in violations[0], violations[0]
    # The message locates the value without reproducing it.
    assert "Ab1" not in violations[0], violations[0]


def test_the_guard_catches_every_shape_it_claims_to(tmp_path):
    """Every pattern gets one positive, so a typo in a pattern cannot hide."""
    samples = {
        "stripe live key": "sk_live_" + "Z" * 24,
        "github token": "ghp_" + "Ab1" * 12,
        "aws access key id": "AKIA" + "Q" * 16,
        "slack bot token": "xoxb-" + "1234567890-abcdefghijkl",
        "private key block": ("-----BEGIN RSA " + "PRIVATE KEY-----\n"
                              + "MIIEowIBAAKCAQEA" * 4 + "\n"),
    }
    for shape, value in samples.items():
        planted = tmp_path / ("planted_%s.txt" % shape.replace(" ", "_"))
        planted.write_text("prefix " + value + " suffix\n")
        violations = find_violations([str(planted)])
        assert violations, shape
        assert shape in violations[0], (shape, violations[0])


def test_the_guard_accepts_delimiters_markers_and_documented_examples():
    """The guard must not fire on the analyzer's own pattern text or on markers."""
    clean = "\n".join([
        r'(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b", "[REDACTED AWS KEY ID]")',
        r'(r"-----BEGIN [A-Z ]*PRIVATE KEY-----", "[REDACTED PRIVATE KEY]")',
        r'"sk_live_" + "Z" * 24',
        "severity: informational -- no credential here",
        "AKIA\u2026(20 chars)",
        "ghp_\u2026(40 chars)",
        "xoxb-\u2026(24 chars)",
        "-----BEGIN RSA " + "PRIVATE KEY-----",
        "AKIA" + "IOSFODNN7EXAMPLE",
    ])
    assert scan_text(clean) == []


def test_the_guard_would_not_accept_a_real_looking_key_block():
    """The delimiter above must not be allowed to hide a block with a body."""
    block = ("-----BEGIN RSA " + "PRIVATE KEY-----\n"
             + "MIIEowIBAAKCAQEA" * 4 + "\n"
             + "-----END RSA " + "PRIVATE KEY-----\n")
    found = scan_text(block)
    assert [shape for _line, shape, _preview in found] == ["private key block"]
