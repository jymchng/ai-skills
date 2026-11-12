#!/usr/bin/env python3
"""CVSS v4.0 vector parsing and scoring — a faithful port of FIRST's reference.

Why a port instead of a formula: CVSS v4.0 base scores are **not** a closed-form
computation. The specification defines them as a lookup over 270 MacroVectors,
minus a normalised severity distance toward the next lower MacroVector. Anyone
who "implements the formula" from memory invents numbers. This module ports the
reference calculator line by line:

    cvss_lookup.js   -> scripts/cvss4_lookup.py   (vendored data, 270 entries)
    cvss_score.js    -> :func:`score`             (MacroVector + interpolation)
    max_severity.js  -> :data:`MAX_SEVERITY`
    max_composed.js  -> :data:`MAX_COMPOSED`

All four are BSD-2-Clause, (c) FIRST and Red Hat; the licence text ships in
``scripts/cvss4_LICENSE.txt`` and is reproduced in the module docstring of
``cvss4_lookup.py``. Nothing here is invented: every number traceable to
``LOOKUP`` is the published one, and ``tests/test_cvss4.py`` cross-checks a
corpus of vectors against the documented scores in
``references/severity-scoring.md`` §5.

It is also checked against the reference itself. ``tests/fixtures/cvss4_reference_vectors.json``
holds 517 vector/score/MacroVector triples produced by running FIRST's
calculator over a systematic walk of the Metric Space — one representative for
each *reachable* MacroVector (270 are published, 180 can actually occur) plus
modified-metric and Safety (``S``) vectors. The differential found the port
exact on all of them, and on a further 2,409 sampled vectors.

What this module refuses to do
------------------------------
* Score an incomplete base vector. All eleven base metrics are mandatory; a
  missing metric is an error, never a default.
* Accept a repeated metric, an unknown metric name, or an out-of-range value.
* Return a number for a finding that has no defensible vector. Scoring is
  opt-in: the caller writes ``cvss_score: null, cvss_vector: null,
  scoring: "unscored"`` and the reports say so (severity-scoring.md §4).

CLI
---
    python3 scripts/cvss4.py score CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N
    python3 scripts/cvss4.py parse  CVSS:4.0/AV:N/...
    python3 scripts/cvss4.py band 9.3
    python3 scripts/cvss4.py table        # every documented reference vector + score
"""

from __future__ import annotations

import argparse
import json
import math
import os
import sys
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

try:  # package-style import (``scripts`` on sys.path)
    from cvss4_lookup import LOOKUP
except ImportError:  # pragma: no cover - direct module loading
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from cvss4_lookup import LOOKUP  # type: ignore

VERSION = "1.0"
PREFIX = "CVSS:4.0"

#: The eleven mandatory base metrics, in specification order.
BASE_ORDER: Tuple[str, ...] = (
    "AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA",
)

#: Allowed values per metric, exactly as the specification defines them.
BASE_VALUES: Dict[str, Tuple[str, ...]] = {
    "AV": ("N", "A", "L", "P"),
    "AC": ("L", "H"),
    "AT": ("N", "P"),
    "PR": ("N", "L", "H"),
    "UI": ("N", "P", "A"),
    "VC": ("H", "L", "N"),
    "VI": ("H", "L", "N"),
    "VA": ("H", "L", "N"),
    "SC": ("H", "L", "N"),
    "SI": ("H", "L", "N"),
    "SA": ("H", "L", "N"),
}

#: Optional threat metric. ``X`` means "not defined" and scores as the worst case.
THREAT_VALUES: Dict[str, Tuple[str, ...]] = {"E": ("X", "A", "P", "U")}

#: Optional environmental metrics: security requirements plus modified base metrics.
ENV_VALUES: Dict[str, Tuple[str, ...]] = {
    "CR": ("X", "H", "M", "L"),
    "IR": ("X", "H", "M", "L"),
    "AR": ("X", "H", "M", "L"),
    "MAV": ("X", "N", "A", "L", "P"),
    "MAC": ("X", "L", "H"),
    "MAT": ("X", "N", "P"),
    "MPR": ("X", "N", "L", "H"),
    "MUI": ("X", "N", "P", "A"),
    "MVC": ("X", "H", "L", "N"),
    "MVI": ("X", "H", "L", "N"),
    "MVA": ("X", "H", "L", "N"),
    "MSC": ("X", "H", "L", "N"),
    "MSI": ("X", "S", "H", "L", "N"),
    "MSA": ("X", "S", "H", "L", "N"),
}

#: Reporting bands, lower bound first, highest band first (severity-scoring.md §1).
BANDS: Tuple[Tuple[float, str], ...] = (
    (9.0, "Critical"),
    (7.0, "High"),
    (4.0, "Medium"),
    (0.1, "Low"),
)

# --------------------------------------------------------------------------- #
# Reference data: max_severity.js and max_composed.js, transcribed
# --------------------------------------------------------------------------- #

#: ``maxSeverity.js`` — max severity distances in EQ MacroVectors (+1).
MAX_SEVERITY: Dict[str, Any] = {
    "eq1": {0: 1, 1: 4, 2: 5},
    "eq2": {0: 1, 1: 2},
    "eq3eq6": {0: {0: 7, 1: 6}, 1: {0: 8, 1: 8}, 2: {1: 10}},
    "eq4": {0: 6, 1: 5, 2: 4},
    "eq5": {0: 1, 1: 1, 2: 1},
}

#: ``max_composed.js`` — the highest-severity vector part per EQ value.
MAX_COMPOSED: Dict[str, Any] = {
    "eq1": {
        0: ["AV:N/PR:N/UI:N/"],
        1: ["AV:A/PR:N/UI:N/", "AV:N/PR:L/UI:N/", "AV:N/PR:N/UI:P/"],
        2: ["AV:P/PR:N/UI:N/", "AV:A/PR:L/UI:P/"],
    },
    "eq2": {
        0: ["AC:L/AT:N/"],
        1: ["AC:H/AT:N/", "AC:L/AT:P/"],
    },
    "eq3": {
        0: {
            "0": ["VC:H/VI:H/VA:H/CR:H/IR:H/AR:H/"],
            "1": ["VC:H/VI:H/VA:L/CR:M/IR:M/AR:H/",
                  "VC:H/VI:H/VA:H/CR:M/IR:M/AR:M/"],
        },
        1: {
            "0": ["VC:L/VI:H/VA:H/CR:H/IR:H/AR:H/",
                  "VC:H/VI:L/VA:H/CR:H/IR:H/AR:H/"],
            "1": ["VC:L/VI:H/VA:L/CR:H/IR:M/AR:H/",
                  "VC:L/VI:H/VA:H/CR:H/IR:M/AR:M/",
                  "VC:H/VI:L/VA:H/CR:M/IR:H/AR:M/",
                  "VC:H/VI:L/VA:L/CR:M/IR:H/AR:H/",
                  "VC:L/VI:L/VA:H/CR:H/IR:H/AR:M/"],
        },
        2: {"1": ["VC:L/VI:L/VA:L/CR:H/IR:H/AR:H/"]},
    },
    "eq4": {
        0: ["SC:H/SI:S/SA:S/"],
        1: ["SC:H/SI:H/SA:H/"],
        2: ["SC:L/SI:L/SA:L/"],
    },
    "eq5": {
        0: ["E:A/"],
        1: ["E:P/"],
        2: ["E:U/"],
    },
}

#: Severity-distance weights per metric (``cvss_score.js`` value tables).
_LEVELS: Dict[str, Dict[str, float]] = {
    "AV": {"N": 0.0, "A": 0.1, "L": 0.2, "P": 0.3},
    "PR": {"N": 0.0, "L": 0.1, "H": 0.2},
    "UI": {"N": 0.0, "P": 0.1, "A": 0.2},
    "AC": {"L": 0.0, "H": 0.1},
    "AT": {"N": 0.0, "P": 0.1},
    "VC": {"H": 0.0, "L": 0.1, "N": 0.2},
    "VI": {"H": 0.0, "L": 0.1, "N": 0.2},
    "VA": {"H": 0.0, "L": 0.1, "N": 0.2},
    "SC": {"H": 0.1, "L": 0.2, "N": 0.3},
    "SI": {"S": 0.0, "H": 0.1, "L": 0.2, "N": 0.3},
    "SA": {"S": 0.0, "H": 0.1, "L": 0.2, "N": 0.3},
    "CR": {"H": 0.0, "M": 0.1, "L": 0.2},
    "IR": {"H": 0.0, "M": 0.1, "L": 0.2},
    "AR": {"H": 0.0, "M": 0.1, "L": 0.2},
}

#: The metrics whose presence makes a vector CVSS-BT / CVSS-BE rather than CVSS-B.
_THREAT_KEYS: Tuple[str, ...] = ("E",)
_ENV_KEYS: Tuple[str, ...] = ("CR", "IR", "AR", "MAV", "MAC", "MAT", "MPR", "MUI",
                              "MVC", "MVI", "MVA", "MSC", "MSI", "MSA")


class VectorError(ValueError):
    """Raised when a vector string cannot be parsed or is not spec-conformant."""


# --------------------------------------------------------------------------- #
# Parsing and validation
# --------------------------------------------------------------------------- #

def _allowed(metric: str) -> Optional[Tuple[str, ...]]:
    if metric in BASE_VALUES:
        return BASE_VALUES[metric]
    if metric in THREAT_VALUES:
        return THREAT_VALUES[metric]
    if metric in ENV_VALUES:
        return ENV_VALUES[metric]
    return None


def parse_vector(text: str) -> Dict[str, str]:
    """Parse ``CVSS:4.0/AV:N/...`` into an ordered metric dict.

    Raises :class:`VectorError` on a missing prefix, an unknown metric, a
    repeated metric, an empty or out-of-range value, or a missing base metric.
    Nothing is defaulted and nothing is repaired: a vector is either exactly
    spec-conformant or it is rejected.
    """
    if not isinstance(text, str) or not text.strip():
        raise VectorError("empty vector")
    vector = text.strip()
    parts = vector.split("/")
    if parts[0] != PREFIX:
        raise VectorError("vector must start with %r, got %r" % (PREFIX, parts[0]))
    metrics: Dict[str, str] = {}
    for chunk in parts[1:]:
        if not chunk:
            raise VectorError("empty metric segment in %r" % vector)
        if ":" not in chunk:
            raise VectorError("segment %r is not METRIC:VALUE" % chunk)
        name, _, value = chunk.partition(":")
        name, value = name.strip(), value.strip()
        allowed = _allowed(name)
        if allowed is None:
            raise VectorError("unknown metric %r" % name)
        if name in metrics:
            raise VectorError("metric %r appears more than once" % name)
        if not value:
            raise VectorError("metric %r has an empty value" % name)
        if value not in allowed:
            raise VectorError("metric %s:%s is not one of %s"
                              % (name, value, "/".join(allowed)))
        metrics[name] = value
    missing = [m for m in BASE_ORDER if m not in metrics]
    if missing:
        raise VectorError("base vector is incomplete: missing %s" % ", ".join(missing))
    return metrics


def validate_vector(text: str) -> List[str]:
    """Return a list of problems; empty means valid. Never raises."""
    try:
        parse_vector(text)
    except VectorError as exc:
        return [str(exc)]
    return []


def format_vector(metrics: Mapping[str, str]) -> str:
    """Serialise metrics in specification order, with the version prefix."""
    ordered: List[str] = []
    emitted: set = set()
    for name in BASE_ORDER + tuple(THREAT_VALUES) + tuple(ENV_VALUES):
        if name in metrics:
            ordered.append("%s:%s" % (name, metrics[name]))
            emitted.add(name)
    for name in sorted(k for k in metrics if k not in emitted and _allowed(k)):
        ordered.append("%s:%s" % (name, metrics[name]))
        emitted.add(name)
    return "/".join([PREFIX] + ordered)


def nomenclature(metrics: Mapping[str, str]) -> str:
    """Return ``CVSS-B``, ``CVSS-BT``, ``CVSS-BE`` or ``CVSS-BTE`` for a vector.

    ``severity-scoring.md`` §2 requires the report to state which nomenclature a
    score uses; this report emits base scores, and only claims more when the
    optional metrics are actually present.
    """
    has_threat = any(k in metrics for k in _THREAT_KEYS)
    has_env = any(k in metrics for k in _ENV_KEYS)
    if has_threat and has_env:
        return "CVSS-BTE"
    if has_threat:
        return "CVSS-BT"
    if has_env:
        return "CVSS-BE"
    return "CVSS-B"


# --------------------------------------------------------------------------- #
# MacroVector
# --------------------------------------------------------------------------- #

def _m(metrics: Mapping[str, str], metric: str) -> Optional[str]:
    """Effective value of ``metric``, applying the specification's defaults.

    ``E:X`` behaves as ``E:A`` (worst case); ``CR/IR/AR:X`` behave as ``H``; and
    a modified metric that is present and not ``X`` overrides its base metric.
    """
    selected = metrics.get(metric)
    if metric == "E" and selected in (None, "X"):
        return "A"
    if metric in ("CR", "IR", "AR") and selected in (None, "X"):
        return "H"
    modified = metrics.get("M" + metric)
    if modified is not None and modified != "X":
        return modified
    return selected


def macrovector(metrics: Mapping[str, str]) -> str:
    """Return the six-digit MacroVector ``EQ1..EQ6`` for a full metric mapping."""
    av, pr, ui = _m(metrics, "AV"), _m(metrics, "PR"), _m(metrics, "UI")
    if av == "N" and pr == "N" and ui == "N":
        eq1 = "0"
    elif (av == "N" or pr == "N" or ui == "N") and not (av == "N" and pr == "N" and ui == "N") \
            and av != "P":
        eq1 = "1"
    elif av == "P" or not (av == "N" or pr == "N" or ui == "N"):
        eq1 = "2"
    else:  # pragma: no cover - the four branches above are exhaustive
        raise VectorError("unreachable EQ1 for AV=%s PR=%s UI=%s" % (av, pr, ui))

    eq2 = "0" if (_m(metrics, "AC") == "L" and _m(metrics, "AT") == "N") else "1"

    vc, vi, va = _m(metrics, "VC"), _m(metrics, "VI"), _m(metrics, "VA")
    if vc == "H" and vi == "H":
        eq3 = "0"
    elif (vc == "H" or vi == "H" or va == "H"):
        eq3 = "1"
    else:
        eq3 = "2"

    sc, si, sa = _m(metrics, "SC"), _m(metrics, "SI"), _m(metrics, "SA")
    msi, msa = _m(metrics, "MSI"), _m(metrics, "MSA")
    if msi == "S" or msa == "S":
        eq4 = "0"
    elif sc == "H" or si == "H" or sa == "H":
        eq4 = "1"
    else:
        eq4 = "2"

    e = _m(metrics, "E")
    if e == "A":
        eq5 = "0"
    elif e == "P":
        eq5 = "1"
    elif e == "U":
        eq5 = "2"
    else:  # pragma: no cover - E always resolves to A/P/U
        raise VectorError("unreachable EQ5 for E=%s" % e)

    if ((_m(metrics, "CR") == "H" and vc == "H")
            or (_m(metrics, "IR") == "H" and vi == "H")
            or (_m(metrics, "AR") == "H" and va == "H")):
        eq6 = "0"
    else:
        eq6 = "1"

    return eq1 + eq2 + eq3 + eq4 + eq5 + eq6


def _eq_maxes(macro: str, eq: int) -> Any:
    """``maxComposed["eq<eq>"][macro[eq-1]]`` — the composed highest vector parts."""
    return MAX_COMPOSED["eq%d" % eq][int(macro[eq - 1])]


def _extract(metric: str, vector_part: str) -> str:
    """Read a metric's value out of a composed ``"AV:N/PR:N/..."`` part."""
    tail = vector_part[vector_part.index(metric) + len(metric) + 1:]
    slash = tail.find("/")
    return tail if slash <= 0 else tail[:slash]


def _round_half_up(value: float) -> float:
    """``Math.round(value * 10) / 10`` — JS rounds half up, Python's round is half-even."""
    return math.floor(value * 10.0 + 0.5) / 10.0


def _nan_sub(value: float, other: Optional[float]) -> Optional[float]:
    """``value - lookup[key]`` where an absent key is JavaScript ``undefined`` -> NaN."""
    if other is None:
        return None
    return value - other


# --------------------------------------------------------------------------- #
# Scoring
# --------------------------------------------------------------------------- #

def score(metrics: Mapping[str, str]) -> float:
    """Score a full metric mapping with the reference algorithm. Range 0.0–10.0.

    ``metrics`` must contain all eleven base metrics; optional threat and
    environmental metrics are honoured when present. Raises :class:`VectorError`
    if the MacroVector is not in the published table (which only happens for an
    invalid combination).
    """
    missing = [m for m in BASE_ORDER if m not in metrics]
    if missing:
        raise VectorError("base vector is incomplete: missing %s" % ", ".join(missing))
    for name, value in metrics.items():
        allowed = _allowed(name)
        if allowed is None:
            raise VectorError("unknown metric %r" % name)
        if value not in allowed:
            raise VectorError("metric %s:%s is not one of %s"
                              % (name, value, "/".join(allowed)))

    # Shortcut: no impact anywhere means no score, regardless of the MacroVector.
    if all(_m(metrics, metric) == "N" for metric in ("VC", "VI", "VA", "SC", "SI", "SA")):
        return 0.0

    macro = macrovector(metrics)
    value = LOOKUP.get(macro)
    if value is None:
        raise VectorError("MacroVector %r is not in the reference table" % macro)

    eq1, eq2, eq3, eq4, eq5, eq6 = (int(digit) for digit in macro)

    # 1a. Maximal scoring difference = distance to the next lower MacroVector.
    lower: Dict[str, Optional[float]] = {}
    lower["eq1"] = LOOKUP.get("%d%d%d%d%d%d" % (eq1 + 1, eq2, eq3, eq4, eq5, eq6))
    lower["eq2"] = LOOKUP.get("%d%d%d%d%d%d" % (eq1, eq2 + 1, eq3, eq4, eq5, eq6))
    if eq3 == 1 and eq6 == 1:
        lower["eq3eq6"] = LOOKUP.get("%d%d%d%d%d%d" % (eq1, eq2, eq3 + 1, eq4, eq5, eq6))
    elif eq3 == 0 and eq6 == 1:
        lower["eq3eq6"] = LOOKUP.get("%d%d%d%d%d%d" % (eq1, eq2, eq3 + 1, eq4, eq5, eq6))
    elif eq3 == 1 and eq6 == 0:
        lower["eq3eq6"] = LOOKUP.get("%d%d%d%d%d%d" % (eq1, eq2, eq3, eq4, eq5, eq6 + 1))
    elif eq3 == 0 and eq6 == 0:
        left = LOOKUP.get("%d%d%d%d%d%d" % (eq1, eq2, eq3, eq4, eq5, eq6 + 1))
        right = LOOKUP.get("%d%d%d%d%d%d" % (eq1, eq2, eq3 + 1, eq4, eq5, eq6))
        if left is None and right is None:
            lower["eq3eq6"] = None
        else:
            lower["eq3eq6"] = max(x for x in (left, right) if x is not None)
    else:
        lower["eq3eq6"] = LOOKUP.get("%d%d%d%d%d%d" % (eq1, eq2, eq3 + 1, eq4, eq5, eq6 + 1))
    lower["eq4"] = LOOKUP.get("%d%d%d%d%d%d" % (eq1, eq2, eq3, eq4 + 1, eq5, eq6))
    lower["eq5"] = LOOKUP.get("%d%d%d%d%d%d" % (eq1, eq2, eq3, eq4, eq5 + 1, eq6))

    # 1b. Severity distance from the highest-severity vector in this MacroVector.
    parts: List[str] = []
    for eq1_max in _eq_maxes(macro, 1):
        for eq2_max in _eq_maxes(macro, 2):
            for eq3eq6_max in _eq_maxes(macro, 3)[macro[5]]:
                for eq4_max in _eq_maxes(macro, 4):
                    for eq5_max in _eq_maxes(macro, 5):
                        parts.append(eq1_max + eq2_max + eq3eq6_max + eq4_max + eq5_max)

    distances: List[float] = []
    chosen: Optional[str] = None
    for part in parts:
        distances = []
        valid = True
        for metric in ("AV", "PR", "UI", "AC", "AT", "VC", "VI", "VA",
                       "SC", "SI", "SA", "CR", "IR", "AR"):
            current = _m(metrics, metric)
            maximum = _extract(metric, part)
            if current is None or maximum not in _LEVELS[metric]:
                valid = False
                break
            distance = _LEVELS[metric][current] - _LEVELS[metric][maximum]
            if distance < 0:
                valid = False
                break
            distances.append(distance)
        if valid:
            chosen = part
            break
    if chosen is None:  # pragma: no cover - the composed maxima always cover the vector
        raise VectorError("no composed highest vector covers MacroVector %r" % macro)

    distance = dict(zip(("AV", "PR", "UI", "AC", "AT", "VC", "VI", "VA",
                         "SC", "SI", "SA", "CR", "IR", "AR"), distances))
    current_eq1 = distance["AV"] + distance["PR"] + distance["UI"]
    current_eq2 = distance["AC"] + distance["AT"]
    current_eq3eq6 = (distance["VC"] + distance["VI"] + distance["VA"]
                      + distance["CR"] + distance["IR"] + distance["AR"])
    current_eq4 = distance["SC"] + distance["SI"] + distance["SA"]

    step = 0.1
    max_eq1 = MAX_SEVERITY["eq1"][eq1] * step
    max_eq2 = MAX_SEVERITY["eq2"][eq2] * step
    max_eq3eq6 = MAX_SEVERITY["eq3eq6"][eq3][eq6] * step
    max_eq4 = MAX_SEVERITY["eq4"][eq4] * step

    names = ("eq1", "eq2", "eq3eq6", "eq4", "eq5")
    currents = (current_eq1, current_eq2, current_eq3eq6, current_eq4, 0.0)
    maximums = (max_eq1, max_eq2, max_eq3eq6, max_eq4, 1.0)

    available: Dict[str, Optional[float]] = {}
    for name in names:
        available[name] = _nan_sub(value, lower[name])

    existing = 0
    normalised: List[float] = []
    for index, name in enumerate(names):
        gap = available[name]
        if gap is None:
            normalised.append(0.0)
            continue
        existing += 1
        # EQ5's severity distance is always zero, by construction.
        proportion = 0.0 if name == "eq5" else currents[index] / maximums[index]
        normalised.append(gap * proportion)

    # 2. Mean of the proportional distances.
    mean_distance = 0.0 if existing == 0 else sum(normalised) / existing

    # 3. MacroVector score minus the mean distance, rounded to one decimal.
    result = value - mean_distance
    result = max(0.0, min(10.0, result))
    return _round_half_up(result)


def score_vector(text: str) -> Dict[str, Any]:
    """Parse and score a vector string. Returns a JSON-ready result dict.

    Raises :class:`VectorError` for anything the specification would reject;
    callers that cannot justify a vector must record ``scoring: "unscored"``
    instead of inventing one (severity-scoring.md §4).
    """
    metrics = parse_vector(text)
    value = score(metrics)
    return {
        "vector": format_vector(metrics),
        "score": value,
        "severity": severity_band(value),
        "nomenclature": nomenclature(metrics),
        "macrovector": macrovector(metrics),
        "metrics": metrics,
    }


def severity_band(value: Optional[float]) -> str:
    """Map a CVSS 4.0 score to the reporting band (severity-scoring.md §1).

    ``None`` (unscored) and ``0.0`` are ``Informational``: neither is presented
    as a vulnerability.
    """
    if value is None:
        return "Informational"
    score_value = float(value)
    if score_value <= 0.0:
        return "Informational"
    for threshold, band in BANDS:
        if score_value >= threshold:
            return band
    return "Low"


def unscored() -> Dict[str, Any]:
    """The explicit unscored record shape a finding must carry instead of a number."""
    return {"cvss_vector": None, "cvss_score": None, "scoring": "unscored",
            "severity": "Informational"}


#: Reference vectors from ``references/severity-scoring.md`` §5, with the score
#: each one must produce. Kept here so the CLI and the tests share one source.
REFERENCE_VECTORS: Tuple[Tuple[str, str, float], ...] = (
    ("sql_injection_unauthenticated",
     "AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 9.3),
    ("sql_injection_authenticated",
     "AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 8.7),
    ("stored_xss",
     "AV:N/AC:L/AT:N/PR:L/UI:P/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N", 5.1),
    ("reflected_xss",
     "AV:N/AC:L/AT:N/PR:N/UI:A/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N", 5.1),
    ("idor",
     "AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N", 7.1),
    ("path_traversal_read",
     "AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N", 7.1),
    ("insecure_deserialization",
     "AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 9.3),
    ("hardcoded_cloud_credential",
     "AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N", 9.3),
    ("ssrf_cloud_metadata",
     "AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:H/SI:N/SA:N", 9.9),
    ("weak_password_hashing_md5",
     "AV:N/AC:H/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N", 6.0),
    ("permissive_cors_credentials",
     "AV:N/AC:H/AT:N/PR:N/UI:P/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N", 6.0),
    ("missing_rate_limiting_login",
     "AV:N/AC:H/AT:N/PR:L/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N", 2.3),
    ("business_logic_price",
     "AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N", 7.1),
    ("container_runs_as_root",
     "AV:L/AC:H/AT:P/PR:L/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N", 2.0),
    ("ci_write_all_permissions",
     "AV:N/AC:L/AT:N/PR:L/UI:N/VC:L/VI:H/VA:N/SC:H/SI:H/SA:N", 8.4),
    ("injection_with_deployment_precondition",
     "AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 9.2),
)


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def _cmd_score(args: argparse.Namespace) -> int:
    try:
        result = score_vector(args.vector)
    except VectorError as exc:
        print(json.dumps({"valid": False, "error": str(exc)}))
        return 2
    print(json.dumps({"valid": True, **result}, indent=2))
    return 0


def _cmd_parse(args: argparse.Namespace) -> int:
    try:
        metrics = parse_vector(args.vector)
    except VectorError as exc:
        print(json.dumps({"valid": False, "error": str(exc)}))
        return 2
    print(json.dumps({"valid": True, "vector": format_vector(metrics),
                      "nomenclature": nomenclature(metrics),
                      "macrovector": macrovector(metrics), "metrics": metrics}, indent=2))
    return 0


def _cmd_band(args: argparse.Namespace) -> int:
    print(json.dumps({"score": args.score, "severity": severity_band(args.score)}))
    return 0


def _cmd_table(_: argparse.Namespace) -> int:
    rows = []
    for name, tail, expected in REFERENCE_VECTORS:
        actual = score_vector(PREFIX + "/" + tail)["score"]
        rows.append({"class": name, "vector": PREFIX + "/" + tail,
                     "expected": expected, "scored": actual,
                     "match": actual == expected})
    print(json.dumps({"vectors": rows,
                      "all_match": all(row["match"] for row in rows)}, indent=2))
    return 0 if all(row["match"] for row in rows) else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cvss4.py",
        description="Parse, validate and score CVSS v4.0 vectors with FIRST's "
                    "reference algorithm (vendored, BSD-2-Clause).",
        epilog="Every command prints JSON on stdout; an invalid vector exits 2.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("score", help="parse a vector and compute its score")
    p.add_argument("vector", help="CVSS:4.0/AV:N/... vector string")
    p.set_defaults(func=_cmd_score)

    p = sub.add_parser("parse", help="validate a vector and show its MacroVector")
    p.add_argument("vector")
    p.set_defaults(func=_cmd_parse)

    p = sub.add_parser("band", help="map a score to the reporting severity band")
    p.add_argument("score", type=float)
    p.set_defaults(func=_cmd_band)

    p = sub.add_parser("table", help="recompute every documented reference vector")
    p.set_defaults(func=_cmd_table)
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
