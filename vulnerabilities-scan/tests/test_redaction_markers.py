"""One credential shape, one marker spelling, in every stage that redacts text.

Three stages sweep text for credentials: the analyzer at ingestion, the validator
when it re-quotes the audited file, and the orchestrator when it ingests an
external tool's output. They used to keep three hand-written pattern tables, so
the same Stripe key read ``[REDACTED STRIPE SECRET KEY]`` from one stage and
``[REDACTED STRIPE KEY]`` from the next -- in the same report, in the same
evidence block. Neither marker leaks, but a reader who sees two labels cannot
tell whether two different things were redacted.

The fix is structural, and these tests pin it: :data:`builtin_analyzers.
SECRET_PATTERNS` is the only table, its ``marker`` column is the only spelling,
and :func:`finding_model.shape_marker` is the only function that builds one.
"""

from __future__ import annotations

import os
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPTS = os.path.join(REPO, "scripts")
if SCRIPTS not in sys.path:
    sys.path.insert(0, SCRIPTS)

import builtin_analyzers as ba
import finding_model as fm
import scanner_orchestrator as so
import validate_findings as vf

#: One sample per ``SECRET_PATTERNS`` entry, assembled at run time so the tracked
#: tree holds no matchable credential (see tests/test_push_protection_literals.py).
SAMPLES = {
    "aws-access-key": "AKIA" + "Q" * 16,
    "private-key-block": ("-----BEGIN RSA " + "PRIVATE KEY-----\n"
                          + "MIIEowIBAAKCAQEA" * 4 + "\n"
                          + "-----END RSA " + "PRIVATE KEY-----"),
    "github-token": "ghp_" + "Ab1" * 12,
    "slack-token": "xoxb-" + "1234567890-abcdefghijkl",
    "stripe-key": "sk_live_" + "Z" * 24,
    "google-api-key": "AIza" + "A" * 35,
    "jwt-token": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0." + "x" * 43,
    "generic-assignment": 'client_secret = "abc123def456"',
    "connection-string": "postgres://app:S3cretPassw0rd@db.internal:5432/app",
}


def _stage_outputs(text):
    """The same input through all three stages, in the shape each one returns."""
    validator, validator_hits = vf.redact_text(text)
    orchestrator, orchestrator_hits = so.redact(text)
    return {
        "analyzer": ba.redact_shapes(text),
        "validator": validator,
        "orchestrator": orchestrator,
    }, {
        "validator": validator_hits,
        "orchestrator": orchestrator_hits,
    }


def test_every_sample_shape_is_covered_by_the_pattern_table():
    """A new analyzer shape without a sample here would go unchecked."""
    assert set(SAMPLES) == {entry[0] for entry in ba.SECRET_PATTERNS}


def test_the_pattern_table_is_the_single_source_of_the_marker():
    for secret_id, _pattern, label, marker in ba.SECRET_PATTERNS:
        assert label != marker or label.isupper(), secret_id
        assert marker == marker.upper(), secret_id
        assert "[" not in marker and "]" not in marker, secret_id
        assert fm.shape_marker(marker) == "[REDACTED %s]" % marker, secret_id


def test_every_stage_writes_the_same_marker_for_the_same_shape():
    """The regression: three stages, one shape, one spelling."""
    for secret_id, marker in ((entry[0], entry[3]) for entry in ba.SECRET_PATTERNS):
        value = SAMPLES[secret_id]
        outputs, counts = _stage_outputs("before " + value + " after")
        assert len(set(outputs.values())) == 1, (secret_id, outputs)
        rendered = set(outputs.values()).pop()
        assert fm.shape_marker(marker) in rendered, (secret_id, rendered)
        assert value not in rendered, secret_id
        assert rendered.startswith("before ") and rendered.endswith(" after"), secret_id
        assert counts["validator"] >= 1 and counts["orchestrator"] >= 1, secret_id


def test_a_marker_survives_the_next_stage_unchanged():
    """A re-quote must not re-spell a marker the previous stage wrote."""
    for secret_id, marker in ((entry[0], entry[3]) for entry in ba.SECRET_PATTERNS):
        once = ba.redact_shapes("x " + SAMPLES[secret_id] + " y")
        assert fm.shape_marker(marker) in once, secret_id
        outputs, counts = _stage_outputs(once)
        assert set(outputs.values()) == {once}, (secret_id, outputs)
        assert counts == {"validator": 0, "orchestrator": 0}, secret_id


def test_structured_shapes_keep_their_surroundings():
    """A marker replaces the credential, not the code that carries it."""
    assignment = ba.redact_shapes(SAMPLES["generic-assignment"])
    assert assignment == 'client_secret = "%s"' % fm.shape_marker("CREDENTIAL")
    connection = ba.redact_shapes(SAMPLES["connection-string"])
    assert connection == "postgres://app:%s@db.internal:5432/app" % fm.shape_marker("PASSWORD")


def test_the_shape_replacement_docstring_is_complete():
    """A truncated docstring hid what the function keeps and what it loses."""
    doc = ba._shape_replacement.__doc__ or ""
    assert doc.count("``") % 2 == 0, doc
    assert "loses only the literal" in " ".join(doc.split()), doc
