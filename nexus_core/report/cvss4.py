"""CVSS v4.0 base scoring, computed locally from the official MacroVector table.

The CVSS v4.0 base score is **not** a closed formula: the specification defines
it as a lookup over the six "equivalence classes" (EQ1..EQ6) that group vectors
of comparable severity, corrected by the severity distance to the next lower
MacroVector. Reimplementing that lookup from memory would amount to inventing
scores, so the authoritative table published by FIRST (BSD-2-Clause, Copyright
FIRST, Red Hat, and contributors) is vendored verbatim in
``data/cvss4_lookup.json`` and the algorithm in this module is a direct port of
the reference implementation ``cvss_score.js``:

    https://github.com/FIRSTdotorg/cvss-v4-calculator

Design rules (same as the v3.1 module):

* the *score* is always recomputed here, never taken from a model or a tool;
* a malformed vector returns ``None`` instead of a guess (fail-closed);
* nothing raises: a report that cannot compute CVSS must still be produced.

Base score scope: the CVSS v4.0 **Base** score assumes the worst case for the
Threat and Environmental metrics (``E:A``, ``CR:H``, ``IR:H``, ``AR:H``), so any
``E``/``CR``/``IR``/``AR`` metric present in the vector is deliberately ignored
here — they only matter for the Threat/Environmental scores, which this module
does not claim to compute.
"""

from __future__ import annotations

import json
import math
import re
from functools import lru_cache
from pathlib import Path
from typing import Any, Callable, Mapping

DATA_FILE = Path(__file__).with_name("data") / "cvss4_lookup.json"

#: Required base metrics of a CVSS v4.0 vector.
BASE_METRICS: tuple[str, ...] = (
    "AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA",
)

#: Accepted values per metric (base metrics are mandatory, the rest optional).
_ALLOWED_VALUES: dict[str, frozenset[str]] = {
    "AV": frozenset({"N", "A", "L", "P"}),
    "AC": frozenset({"L", "H"}),
    "AT": frozenset({"N", "P"}),
    "PR": frozenset({"N", "L", "H"}),
    "UI": frozenset({"N", "P", "A"}),
    "VC": frozenset({"H", "L", "N"}),
    "VI": frozenset({"H", "L", "N"}),
    "VA": frozenset({"H", "L", "N"}),
    "SC": frozenset({"H", "L", "N"}),
    "SI": frozenset({"H", "L", "N"}),
    "SA": frozenset({"H", "L", "N"}),
}

_METRIC_PATTERN = re.compile(r"([A-Z]{1,2}):([A-Z0-9]+)")
_VECTOR_PATTERN = re.compile(r"CVSS:4\.0/[A-Za-z0-9:/.\-]+")

#: Highest-severity vectors of each MacroVector component (official
#: ``maxComposed``). The strings concatenate into one vector per combination.
MAX_COMPOSED: dict[str, Any] = {
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
            "1": ["VC:H/VI:H/VA:L/CR:M/IR:M/AR:H/", "VC:H/VI:H/VA:H/CR:M/IR:M/AR:M/"],
        },
        1: {
            "0": ["VC:L/VI:H/VA:H/CR:H/IR:H/AR:H/", "VC:H/VI:L/VA:H/CR:H/IR:H/AR:H/"],
            "1": [
                "VC:L/VI:H/VA:L/CR:H/IR:M/AR:H/",
                "VC:L/VI:H/VA:H/CR:H/IR:M/AR:M/",
                "VC:H/VI:L/VA:H/CR:M/IR:H/AR:M/",
                "VC:H/VI:L/VA:L/CR:M/IR:H/AR:H/",
                "VC:L/VI:L/VA:H/CR:H/IR:H/AR:M/",
            ],
        },
        2: {"1": ["VC:L/VI:L/VA:L/CR:H/IR:H/AR:H/"]},
    },
    "eq4": {
        0: ["SC:H/SI:S/SA:S/"],
        1: ["SC:H/SI:H/SA:H/"],
        2: ["SC:L/SI:L/SA:L/"],
    },
    "eq5": {0: ["E:A/"], 1: ["E:P/"], 2: ["E:U/"]},
}

#: Maximum severity distance (+1) per MacroVector (official ``maxSeverity``).
MAX_SEVERITY: dict[str, Any] = {
    "eq1": {0: 1, 1: 4, 2: 5},
    "eq2": {0: 1, 1: 2},
    "eq3eq6": {0: {0: 7, 1: 6}, 1: {0: 8, 1: 8}, 2: {1: 10}},
    "eq4": {0: 6, 1: 5, 2: 4},
    "eq5": {0: 1, 1: 1, 2: 1},
}

#: Ordered "level" of each metric value, used for the severity distance.
AV_LEVELS = {"N": 0.0, "A": 0.1, "L": 0.2, "P": 0.3}
PR_LEVELS = {"N": 0.0, "L": 0.1, "H": 0.2}
UI_LEVELS = {"N": 0.0, "P": 0.1, "A": 0.2}
AC_LEVELS = {"L": 0.0, "H": 0.1}
AT_LEVELS = {"N": 0.0, "P": 0.1}
VC_LEVELS = {"H": 0.0, "L": 0.1, "N": 0.2}
VI_LEVELS = {"H": 0.0, "L": 0.1, "N": 0.2}
VA_LEVELS = {"H": 0.0, "L": 0.1, "N": 0.2}
SC_LEVELS = {"H": 0.1, "L": 0.2, "N": 0.3}
SI_LEVELS = {"S": 0.0, "H": 0.1, "L": 0.2, "N": 0.3}
SA_LEVELS = {"S": 0.0, "H": 0.1, "L": 0.2, "N": 0.3}
CR_LEVELS = {"H": 0.0, "M": 0.1, "L": 0.2}
IR_LEVELS = {"H": 0.0, "M": 0.1, "L": 0.2}
AR_LEVELS = {"H": 0.0, "M": 0.1, "L": 0.2}
E_LEVELS = {"U": 0.2, "P": 0.1, "A": 0.0}

_LEVELS = {
    "AV": AV_LEVELS, "PR": PR_LEVELS, "UI": UI_LEVELS, "AC": AC_LEVELS, "AT": AT_LEVELS,
    "VC": VC_LEVELS, "VI": VI_LEVELS, "VA": VA_LEVELS, "SC": SC_LEVELS,
    "SI": SI_LEVELS, "SA": SA_LEVELS, "CR": CR_LEVELS, "IR": IR_LEVELS, "AR": AR_LEVELS,
}

#: Representative deterministic vectors used when nothing better is available.
#: The score is always recomputed locally (:func:`parse_cvss4_vector`), so the
#: pair can never drift apart.
HEURISTIC_CVSS4: dict[str, str | None] = {
    "critical": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
    "high": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
    "medium": "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N",
    "low": "CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:P/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
    "info": None,
}

#: Prompt used when the operator asked for LLM-assisted CVSS 4.0.
LLM_PROMPT = (
    "Eres un analista de vulnerabilidades. Dada esta observación verificada de "
    "un pentesting autorizado, responde ÚNICAMENTE con un vector CVSS v4.0 base, "
    "sin explicación ni markdown, con exactamente este formato:\n"
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N\n"
    "Observación:\n"
    "  título: {title}\n"
    "  severidad declarada: {severity}\n"
    "  descripción: {description}\n"
    "  afectados: {targets}\n"
)


@lru_cache(maxsize=1)
def lookup_table() -> dict[str, float]:
    """Return the parsed ``{macro_vector: base_score}`` table (official data)."""
    data = json.loads(DATA_FILE.read_text(encoding="utf-8"))
    scores = data.get("scores") if isinstance(data, dict) else None
    if not isinstance(scores, dict) or not scores:
        raise ValueError("cvss4_lookup.json must carry a non-empty 'scores' object")
    table: dict[str, float] = {}
    for macro, value in scores.items():
        if not re.fullmatch(r"[0-2]{6}", str(macro)):
            raise ValueError(f"malformed MacroVector key: {macro!r}")
        table[str(macro)] = float(value)
    return table


def _select(metrics: Mapping[str, str], metric: str) -> str | None:
    """Return the value of ``metric`` honouring ``X`` defaults (base worst case).

    ``E`` uses the CVSS v4.0 base worst case ``A``; ``CR``/``IR``/``AR`` use
    ``H``. Environmental ``M``-prefixed overrides are intentionally not applied:
    the Base score ignores them.
    """
    value = metrics.get(metric)
    if value == "X" or value is None:
        return {"E": "A", "CR": "H", "IR": "H", "AR": "H"}.get(metric, value)
    return value


def macro_vector(metrics: Mapping[str, str]) -> str | None:
    """Compute the six-digit MacroVector of a base vector (``None`` if invalid)."""
    def m(metric: str) -> str | None:
        return _select(metrics, metric)

    av, pr, ui = m("AV"), m("PR"), m("UI")
    if av is None or pr is None or ui is None:
        return None
    if av == "N" and pr == "N" and ui == "N":
        eq1 = "0"
    elif (
        (av == "N" or pr == "N" or ui == "N")
        and not (av == "N" and pr == "N" and ui == "N")
        and av != "P"
    ):
        eq1 = "1"
    else:
        eq1 = "2"

    if m("AC") == "L" and m("AT") == "N":
        eq2 = "0"
    else:
        eq2 = "1"

    vc, vi, va = m("VC"), m("VI"), m("VA")
    if vc is None or vi is None or va is None:
        return None
    if vc == "H" and vi == "H":
        eq3 = 0
    elif not (vc == "H" and vi == "H") and (vc == "H" or vi == "H" or va == "H"):
        eq3 = 1
    else:
        eq3 = 2

    sc, si, sa = m("SC"), m("SI"), m("SA")
    if sc is None or si is None or sa is None:
        return None
    if m("MSI") == "S" or m("MSA") == "S":
        eq4 = 0
    elif (m("MSI") != "S" and m("MSA") != "S") and (sc == "H" or si == "H" or sa == "H"):
        eq4 = 1
    else:
        eq4 = 2

    eq5 = {"A": 0, "P": 1, "U": 2}.get(m("E") or "", 0)

    cr, ir, ar = m("CR"), m("IR"), m("AR")
    if (cr == "H" and vc == "H") or (ir == "H" and vi == "H") or (ar == "H" and va == "H"):
        eq6 = 0
    else:
        eq6 = 1

    return f"{eq1}{eq2}{eq3}{eq4}{eq5}{eq6}"


def _extract_metric_value(metric: str, vector: str) -> str | None:
    """Read ``metric`` out of a ``/``-separated vector fragment."""
    marker = metric + ":"
    index = vector.find(marker)
    if index < 0:
        return None
    rest = vector[index + len(marker):]
    slash = rest.find("/")
    return rest if slash < 0 else rest[:slash]


def _eq_maxes(macro: str, eq: int) -> Any:
    """``maxComposed`` entry for one EQ of a MacroVector (``None`` if absent)."""
    group = MAX_COMPOSED.get(f"eq{eq}")
    if group is None:
        return None
    return group.get(int(macro[eq - 1]))


def _base_score(metrics: Mapping[str, str]) -> float | None:
    """Score a base vector with the official MacroVector algorithm."""
    table = lookup_table()
    macro = macro_vector(metrics)
    if macro is None:
        return None

    selected: dict[str, str] = dict(metrics)
    # Base score assumes the worst case for the Threat/Environmental metrics.
    selected["E"] = "A"
    selected["CR"] = "H"
    selected["IR"] = "H"
    selected["AR"] = "H"

    if all(_select(selected, name) == "N" for name in ("VC", "VI", "VA", "SC", "SI", "SA")):
        return 0.0

    value = table.get(macro)
    if value is None:
        return None

    eq1, eq2, eq3, eq4, eq5, eq6 = (int(char) for char in macro)

    eq1_next = f"{eq1 + 1}{eq2}{eq3}{eq4}{eq5}{eq6}"
    eq2_next = f"{eq1}{eq2 + 1}{eq3}{eq4}{eq5}{eq6}"
    eq3eq6_left: str | None = None
    eq3eq6_right: str | None = None
    if eq3 == 1 and eq6 == 1:
        eq3eq6_next = f"{eq1}{eq2}{eq3 + 1}{eq4}{eq5}{eq6}"
    elif eq3 == 0 and eq6 == 1:
        eq3eq6_next = f"{eq1}{eq2}{eq3 + 1}{eq4}{eq5}{eq6}"
    elif eq3 == 1 and eq6 == 0:
        eq3eq6_next = f"{eq1}{eq2}{eq3}{eq4}{eq5}{eq6 + 1}"
    elif eq3 == 0 and eq6 == 0:
        eq3eq6_next = None
        eq3eq6_left = f"{eq1}{eq2}{eq3}{eq4}{eq5}{eq6 + 1}"
        eq3eq6_right = f"{eq1}{eq2}{eq3 + 1}{eq4}{eq5}{eq6}"
    else:
        eq3eq6_next = f"{eq1}{eq2}{eq3 + 1}{eq4}{eq5}{eq6 + 1}"
    eq4_next = f"{eq1}{eq2}{eq3}{eq4 + 1}{eq5}{eq6}"
    eq5_next = f"{eq1}{eq2}{eq3}{eq4}{eq5 + 1}{eq6}"

    score_eq1_next = table.get(eq1_next)
    score_eq2_next = table.get(eq2_next)
    if eq3eq6_next is not None:
        score_eq3eq6_next = table.get(eq3eq6_next)
    else:
        left = table.get(eq3eq6_left or "")
        right = table.get(eq3eq6_right or "")
        if left is None and right is None:
            score_eq3eq6_next = None
        else:
            score_eq3eq6_next = max(
                value for value in (left, right) if value is not None
            )
    score_eq4_next = table.get(eq4_next)
    score_eq5_next = table.get(eq5_next)

    # Build every "highest severity vector" of the MacroVector.
    eq1_maxes = _eq_maxes(macro, 1) or []
    eq2_maxes = _eq_maxes(macro, 2) or []
    eq3_eq6_group = _eq_maxes(macro, 3) or {}
    eq3_eq6_maxes = eq3_eq6_group.get(macro[5], []) if isinstance(eq3_eq6_group, dict) else []
    eq4_maxes = _eq_maxes(macro, 4) or []
    eq5_maxes = _eq_maxes(macro, 5) or []

    distances: dict[str, float] = {}
    chosen_max: str | None = None
    for eq1_max in eq1_maxes:
        for eq2_max in eq2_maxes:
            for eq3_eq6_max in eq3_eq6_maxes:
                for eq4_max in eq4_maxes:
                    for eq5_max in eq5_maxes:
                        candidate = eq1_max + eq2_max + eq3_eq6_max + eq4_max + eq5_max
                        candidate_distances = _severity_distances(selected, candidate)
                        if candidate_distances is None:
                            continue
                        if any(item < 0 for item in candidate_distances.values()):
                            continue
                        distances = candidate_distances
                        chosen_max = candidate
                        break
                    if chosen_max:
                        break
                if chosen_max:
                    break
            if chosen_max:
                break
        if chosen_max:
            break

    if chosen_max is None:
        # No comparable highest vector: the MacroVector score stands on its own.
        return _round(value)

    current_eq1 = distances["AV"] + distances["PR"] + distances["UI"]
    current_eq2 = distances["AC"] + distances["AT"]
    current_eq3eq6 = (
        distances["VC"] + distances["VI"] + distances["VA"]
        + distances["CR"] + distances["IR"] + distances["AR"]
    )
    current_eq4 = distances["SC"] + distances["SI"] + distances["SA"]
    current_eq5 = 0.0

    step = 0.1
    available = {
        "eq1": None if score_eq1_next is None else value - score_eq1_next,
        "eq2": None if score_eq2_next is None else value - score_eq2_next,
        "eq3eq6": None if score_eq3eq6_next is None else value - score_eq3eq6_next,
        "eq4": None if score_eq4_next is None else value - score_eq4_next,
        "eq5": None if score_eq5_next is None else value - score_eq5_next,
    }
    max_severity = {
        "eq1": MAX_SEVERITY["eq1"][eq1] * step,
        "eq2": MAX_SEVERITY["eq2"][eq2] * step,
        "eq3eq6": MAX_SEVERITY["eq3eq6"][eq3][eq6] * step,
        "eq4": MAX_SEVERITY["eq4"][eq4] * step,
    }
    current = {
        "eq1": current_eq1,
        "eq2": current_eq2,
        "eq3eq6": current_eq3eq6,
        "eq4": current_eq4,
        "eq5": current_eq5,
    }

    existing = 0
    normalized = 0.0
    for key in ("eq1", "eq2", "eq3eq6", "eq4", "eq5"):
        amount = available[key]
        if amount is None:
            continue
        if key == "eq5":
            percent = 0.0
        else:
            percent = current[key] / max_severity[key]
        existing += 1
        normalized += amount * percent

    mean_distance = 0.0 if existing == 0 else normalized / existing
    value -= mean_distance
    value = min(max(value, 0.0), 10.0)
    return _round(value)


def _severity_distances(
    selected: Mapping[str, str], candidate: str
) -> dict[str, float] | None:
    """Severity distance of ``selected`` from a highest-severity ``candidate``."""
    result: dict[str, float] = {}
    for metric, levels in _LEVELS.items():
        value = _select(selected, metric)
        candidate_value = _extract_metric_value(metric, candidate)
        if value is None or candidate_value is None:
            return None
        if value not in levels or candidate_value not in levels:
            return None
        result[metric] = levels[value] - levels[candidate_value]
    return result


def _round(value: float) -> float:
    """CVSS 4.0 rounding: half-up to one decimal place."""
    return math.floor(value * 10.0 + 0.5) / 10.0


def parse_cvss4_vector(vector: Any) -> float | None:
    """Compute the CVSS v4.0 base score of ``vector``; ``None`` when invalid.

    The score is computed locally with the official table. A vector missing a
    base metric, or carrying an out-of-range value, yields ``None`` — never a
    fabricated number.
    """
    text = str(vector or "").strip()
    if not text.startswith("CVSS:4.0/"):
        return None
    metrics: dict[str, str] = {}
    for key, value in _METRIC_PATTERN.findall(text):
        if key in metrics and metrics[key] != value:
            return None  # contradictory duplicate
        metrics[key] = value.upper()
    for name in BASE_METRICS:
        if name not in metrics:
            return None
    for name, allowed in _ALLOWED_VALUES.items():
        if name in metrics and metrics[name] not in allowed:
            return None
    # Environmental overrides still must be well-formed if present.
    for name in ("MAV", "MAC", "MAT", "MPR", "MUI", "MVC", "MVI", "MVA", "MSC", "MSI", "MSA"):
        if name in metrics:
            base = name[1:]
            allowed_override = _ALLOWED_VALUES.get(base)
            if (
                allowed_override is not None
                and metrics[name] != "X"
                and metrics[name] not in allowed_override
            ):
                return None
    return _base_score(metrics)


def severity_from_score4(score: Any) -> str:
    """CVSS v4.0 qualitative severity of a numeric score."""
    try:
        value = float(score)
    except (TypeError, ValueError):
        return "info"
    if value >= 9.0:
        return "critical"
    if value >= 7.0:
        return "high"
    if value >= 4.0:
        return "medium"
    if value > 0.0:
        return "low"
    return "info"


def heuristic_cvss4(severity: Any) -> tuple[float | None, str | None]:
    """Deterministic ``(score, vector)`` for a severity level.

    The vector is a representative, spec-approved scenario for the level and the
    score is computed from it locally, so the two never disagree.
    """
    level = str(severity or "").strip().lower()
    vector = HEURISTIC_CVSS4.get(level, HEURISTIC_CVSS4["info"])
    if vector is None:
        return 0.0, None
    return parse_cvss4_vector(vector), vector


def build_prompt(finding: Any) -> str:
    """Render the per-finding LLM prompt (deterministic for tests)."""
    targets = ""
    if getattr(finding, "affected_targets", None):
        targets = ", ".join(str(item) for item in finding.affected_targets)
    return LLM_PROMPT.format(
        title=getattr(finding, "title", ""),
        severity=getattr(finding, "severity", ""),
        description=str(getattr(finding, "description", ""))[:600],
        targets=targets,
    )


def extract_vector(answer: Any) -> str | None:
    """Return the first plausible CVSS v4.0 vector found in a model answer."""
    match = _VECTOR_PATTERN.search(str(answer or ""))
    return match.group(0) if match else None


def estimate_cvss4_with_source(
    finding: Any,
    llm_client: Callable[[str], str | None] | None = None,
) -> tuple[float | None, str | None, str]:
    """Return ``(score, vector, source)`` for CVSS v4.0.

    Priority:

    1. a vector the finding already carries (``tool``, or ``nvd`` when the CVE
       enricher attached one) — the *score* is always recomputed locally;
    2. an LLM-suggested vector, scored locally (``llm``);
    3. the deterministic heuristic (``heuristic``);
    4. ``none`` when no vector applies (e.g. informational findings).
    """
    explicit_score = getattr(finding, "cvss4_score", None)
    explicit_vector = getattr(finding, "cvss4_vector", None)
    declared_source = str(getattr(finding, "cvss4_source", "") or "")
    if isinstance(explicit_vector, str) and explicit_vector.strip():
        computed = parse_cvss4_vector(explicit_vector)
        if computed is not None:
            source = declared_source if declared_source in {"tool", "nvd"} else "tool"
            return computed, explicit_vector.strip(), source
    if isinstance(explicit_score, (int, float)) and not isinstance(explicit_score, bool):
        score = float(explicit_score)
        if score <= 0:
            return score, None, "tool"
        # A bare number with no vector is still a tool claim, never recomputed.
        return score, None, "tool"

    if callable(llm_client):
        try:
            answer = llm_client(build_prompt(finding))
        except Exception:  # noqa: BLE001 - a broken model must not break the report
            answer = None
        vector = extract_vector(answer)
        if vector is not None:
            computed = parse_cvss4_vector(vector)
            if computed is not None:
                return computed, vector, "llm"

    heuristic_score, heuristic_vector = heuristic_cvss4(
        getattr(finding, "severity", "info")
    )
    return heuristic_score, heuristic_vector, "heuristic"


__all__ = [
    "BASE_METRICS",
    "HEURISTIC_CVSS4",
    "LLM_PROMPT",
    "MAX_COMPOSED",
    "MAX_SEVERITY",
    "build_prompt",
    "estimate_cvss4_with_source",
    "extract_vector",
    "heuristic_cvss4",
    "lookup_table",
    "macro_vector",
    "parse_cvss4_vector",
    "severity_from_score4",
]
