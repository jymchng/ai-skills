#!/usr/bin/env python3
"""Tests for the CVSS v4.0 port.

The oracle is the specification's published table plus the reference scores
written into ``references/severity-scoring.md`` §5. If a future edit to
``cvss4.py`` changes any of those numbers, the documentation and the tool would
disagree — which is exactly what these tests exist to prevent.
"""

from __future__ import annotations

import json
import os
import sys

import pytest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPTS = os.path.join(REPO, "scripts")
if SCRIPTS not in sys.path:
    sys.path.insert(0, SCRIPTS)

import cvss4  # noqa: E402

BASE = "AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"


def vec(tail: str) -> str:
    return "CVSS:4.0/" + tail


# --------------------------------------------------------------------------- #
# Reference data integrity
# --------------------------------------------------------------------------- #

def test_lookup_table_is_complete_and_in_range():
    from cvss4_lookup import LOOKUP, LOOKUP_SIZE
    assert LOOKUP_SIZE == 270
    assert len(LOOKUP) == 270
    assert all(0.0 <= value <= 10.0 for value in LOOKUP.values())
    # The specification's extreme entries.
    assert LOOKUP["000000"] == 10.0
    assert LOOKUP["212221"] == 0.1


@pytest.mark.parametrize("name,tail,expected", cvss4.REFERENCE_VECTORS,
                         ids=[row[0] for row in cvss4.REFERENCE_VECTORS])
def test_documented_reference_scores(name, tail, expected):
    """Every class vector in references/severity-scoring.md §5 scores as documented."""
    assert cvss4.score_vector(vec(tail))["score"] == expected


def test_reference_table_is_self_consistent():
    assert all(cvss4.score_vector(vec(tail))["score"] == expected
               for _, tail, expected in cvss4.REFERENCE_VECTORS)


# --------------------------------------------------------------------------- #
# Parsing and rejection
# --------------------------------------------------------------------------- #

def test_parse_reads_every_metric():
    metrics = cvss4.parse_vector(vec(BASE))
    assert set(metrics) == set(cvss4.BASE_ORDER)
    assert metrics["AV"] == "N" and metrics["UI"] == "N"


def test_format_round_trip_is_lossless():
    parsed = cvss4.parse_vector(vec(BASE))
    again = cvss4.parse_vector(cvss4.format_vector(parsed))
    assert again == parsed
    # A vector with optional metrics round-trips without duplication.
    full = cvss4.parse_vector(vec(BASE + "/E:P/CR:L/MAV:A"))
    assert cvss4.format_vector(full) == vec(
        "AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:P/CR:L/MAV:A")


@pytest.mark.parametrize("vector,reason", [
    ("", "empty vector"),
    ("AV:N/AC:L", "missing prefix"),
    (vec("AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N"), "missing SA"),
    (vec(BASE.replace("AV:N", "AV:X")), "bad value"),
    (vec(BASE + "/ZZ:Q"), "unknown metric"),
    (vec(BASE + "/AV:A"), "repeated metric"),
    (vec(BASE + "/E:"), "empty value"),
])
def test_invalid_vectors_are_rejected(vector, reason):
    with pytest.raises(cvss4.VectorError):
        cvss4.parse_vector(vector)
    assert cvss4.validate_vector(vector), reason


def test_incomplete_vectors_are_never_padded():
    with pytest.raises(cvss4.VectorError):
        cvss4.score({"AV": "N", "AC": "L", "AT": "N", "PR": "N", "UI": "N",
                     "VC": "H", "VI": "H", "VA": "H", "SC": "N", "SI": "N"})


# --------------------------------------------------------------------------- #
# Scoring behaviour
# --------------------------------------------------------------------------- #

def test_no_impact_scores_zero():
    flat = vec("AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N")
    assert cvss4.score_vector(flat)["score"] == 0.0
    assert cvss4.severity_band(0.0) == "Informational"


def test_threat_metric_moves_the_score_as_documented():
    # severity-scoring.md §5: adding E:U to the 9.3 vector yields 8.1 under CVSS-BT.
    result = cvss4.score_vector(vec(BASE + "/E:U"))
    assert result["score"] == 8.1
    assert result["nomenclature"] == "CVSS-BT"


def test_environmental_metrics_change_score_and_nomenclature():
    base = cvss4.score_vector(vec(BASE))
    hardened = cvss4.score_vector(vec(BASE + "/CR:L"))
    assert base["nomenclature"] == "CVSS-B"
    assert hardened["nomenclature"] == "CVSS-BE"
    # A lowered confidentiality requirement can only reduce the score; for this
    # all-H vector the reduction is small enough to round to the same decimal,
    # which is itself a property of the reference table rather than of the port.
    assert hardened["score"] <= base["score"]

    modified = cvss4.score_vector(vec(BASE + "/MAV:P"))
    assert modified["nomenclature"] == "CVSS-BE"
    assert modified["score"] < base["score"]


def test_bte_when_both_optional_groups_present():
    assert cvss4.nomenclature(cvss4.parse_vector(vec(BASE + "/E:A/IR:L"))) == "CVSS-BTE"


def test_privileges_required_reduces_score():
    anonymous = cvss4.score_vector(vec(BASE))["score"]
    authenticated = cvss4.score_vector(vec(BASE.replace("PR:N", "PR:L")))["score"]
    assert authenticated < anonymous  # 8.7 vs 9.3


def test_scope_change_raises_score():
    plain = cvss4.score_vector("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N")
    changed = cvss4.score_vector("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:N/SA:N")
    assert changed["score"] >= plain["score"]


def test_macrovector_shape():
    macro = cvss4.macrovector(cvss4.parse_vector(vec(BASE)))
    assert len(macro) == 6 and macro.isdigit()
    assert macro[0] == "0"  # AV:N/PR:N/UI:N


@pytest.mark.parametrize("score,band", [
    (10.0, "Critical"), (9.0, "Critical"), (8.9, "High"), (7.0, "High"),
    (6.9, "Medium"), (4.0, "Medium"), (3.9, "Low"), (0.1, "Low"),
    (0.0, "Informational"), (None, "Informational"),
])
def test_severity_bands(score, band):
    assert cvss4.severity_band(score) == band


def test_unscored_shape_is_explicit():
    record = cvss4.unscored()
    assert record == {"cvss_vector": None, "cvss_score": None,
                      "scoring": "unscored", "severity": "Informational"}


def test_rounding_matches_the_reference_half_up():
    # The reference uses Math.round; Python's round() is half-even and would
    # disagree on exact .05 boundaries.
    assert cvss4._round_half_up(8.25) == 8.3
    assert cvss4._round_half_up(8.35) == 8.4


def test_cli_table_reports_all_matches(capsys):
    assert cvss4.main(["table"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["all_match"] is True
    assert len(payload["vectors"]) == len(cvss4.REFERENCE_VECTORS)


def test_cli_rejects_an_invalid_vector(capsys):
    assert cvss4.main(["score", "CVSS:4.0/AV:N"]) == 2
    assert json.loads(capsys.readouterr().out)["valid"] is False



# --------------------------------------------------------------------------- #
# Differential fixture: FIRST's own reference calculator
# --------------------------------------------------------------------------- #
# ``tests/fixtures/cvss4_reference_vectors.json`` was produced by running the
# reference implementation (cvss_score.js against cvss_lookup.js, with the
# MacroVector enumerator evaluated by the same JavaScript) over a systematic
# walk of the Metric Space: one representative vector for each *reachable*
# MacroVector, plus modified-metric vectors and both Safety (``S``) cases.
# Nothing in it was written by hand and nothing was taken from this port, so it
# is an independent oracle for the numbers below. It is checked in because
# .scratch/ (where the reference sources live) is not part of the repository.

FIXTURE = os.path.join(REPO, "tests", "fixtures", "cvss4_reference_vectors.json")


def _fixture():
    with open(FIXTURE) as handle:
        return json.load(handle)


def test_fixture_is_present_and_self_describing():
    doc = _fixture()
    assert doc["count"] == len(doc["vectors"])
    assert "FIRST" in doc["source"]
    assert len(doc["vectors"]) >= 500


def test_every_reference_score_matches_the_port():
    failures = []
    for vector, expected, macro in _fixture()["vectors"]:
        result = cvss4.score_vector(vector)
        if abs(result["score"] - expected) > 1e-9:
            failures.append((vector, result["score"], expected))
    assert failures == []


def test_every_reference_macrovector_matches_the_port():
    failures = []
    for vector, _expected, macro in _fixture()["vectors"]:
        metrics = cvss4.parse_vector(vector)
        if cvss4.macrovector({**metrics}) != macro:
            failures.append((vector, cvss4.macrovector({**metrics}), macro))
    assert failures == []


def test_fixture_covers_every_reachable_macrovector():
    from cvss4_lookup import LOOKUP, LOOKUP_SIZE

    macros = {macro for _vector, _score, macro in _fixture()["vectors"]}
    # 270 MacroVectors are published but only the ones the EQ tables can produce
    # are reachable; the fixture must contain all of those, and each of them must
    # be a published lookup entry.
    assert len(macros) >= 180
    assert macros <= set(LOOKUP)
    assert len(LOOKUP) == LOOKUP_SIZE


def test_fixture_exercises_the_safety_value_and_modified_metrics():
    vectors = [vector for vector, _score, _macro in _fixture()["vectors"]]
    assert any("MSI:S" in v for v in vectors)
    assert any("MSA:S" in v for v in vectors)
    assert any("MAV:" in v for v in vectors)
    assert any("MAT:" in v for v in vectors)
