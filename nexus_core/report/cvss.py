"""CVSS v3.1 base scoring with a deterministic, fail-safe fallback.

Resolution order per finding:

1. an explicit score/vector the tool itself produced (e.g. a nuclei template);
2. an LLM-suggested vector — the *score* is always recomputed locally with
   :func:`parse_cvss_vector`, so a hallucinated number can never reach the
   report;
3. the deterministic heuristic below, keyed on severity.

Nothing here raises on a bad input: a report that cannot compute CVSS must still
be produced.
"""

from __future__ import annotations

import math
import re
from typing import Any, Callable

#: ``severity -> (score, vector)`` used when nothing better is available.
#:
#: These are deliberately conservative, spec-approved defaults: they describe a
#: plausible remote scenario for the level, not a claim about the target.
HEURISTIC_CVSS: dict[str, tuple[float, str | None]] = {
    "critical": (9.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"),
    "high": (8.0, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "medium": (5.5, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L"),
    "low": (3.0, "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N"),
    "info": (0.0, None),
}

_VECTOR_PATTERN = re.compile(
    r"CVSS:3\.[01]/AV:[NALP]/AC:[LH]/PR:[NLH]/UI:[NR]/S:[UC]/C:[HLN]/I:[HLN]/A:[HLN]"
)
_METRIC_PATTERN = re.compile(r"([A-Z]{1,2}):([A-Z0-9.]+)")

_WEIGHTS: dict[str, dict[str, float]] = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.5}

#: Prompt used when the operator asked for LLM-assisted CVSS.
LLM_PROMPT = (
    "Eres un analista de vulnerabilidades. Dada esta observación verificada de "
    "un pentesting autorizado, responde ÚNICAMENTE con un vector CVSS v3.1 base, "
    "sin explicación ni markdown, con exactamente este formato:\n"
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H\n"
    "Observación:\n"
    "  título: {title}\n"
    "  severidad declarada: {severity}\n"
    "  descripción: {description}\n"
    "  afectados: {targets}\n"
)


def _round_up(value: float) -> float:
    """CVSS 3.1 ``Roundup``: ceiling to one decimal place."""
    return math.ceil(value * 10.0) / 10.0


def parse_cvss_vector(vector: Any) -> float | None:
    """Compute the CVSS v3.1 base score of ``vector``; ``None`` when invalid.

    The score is computed locally, never taken from a model's arithmetic. Both
    ``3.0`` and ``3.1`` prefixes are accepted.
    """
    text = str(vector or "").strip()
    if not text:
        return None
    metrics = {key: value for key, value in _METRIC_PATTERN.findall(text)}
    if not re.match(r"^CVSS:3\.[01]/", text) or not metrics:
        return None
    try:
        scope_changed = metrics["S"].upper() == "C"
        av = _WEIGHTS["AV"][metrics["AV"].upper()]
        ac = _WEIGHTS["AC"][metrics["AC"].upper()]
        ui = _WEIGHTS["UI"][metrics["UI"].upper()]
        pr = (_PR_CHANGED if scope_changed else _PR_UNCHANGED)[metrics["PR"].upper()]
        confidentiality = _WEIGHTS["C"][metrics["C"].upper()]
        integrity = _WEIGHTS["I"][metrics["I"].upper()]
        availability = _WEIGHTS["A"][metrics["A"].upper()]
    except KeyError:
        return None
    impact_base = 1 - (
        (1 - confidentiality) * (1 - integrity) * (1 - availability)
    )
    if scope_changed:
        impact = 7.52 * (impact_base - 0.029) - 3.25 * (impact_base - 0.02) ** 15
    else:
        impact = 6.42 * impact_base
    if impact <= 0:
        return 0.0
    exploitability = 8.22 * av * ac * pr * ui
    if scope_changed:
        return _round_up(min(1.08 * (impact + exploitability), 10.0))
    return _round_up(min(impact + exploitability, 10.0))


def heuristic_cvss(severity: Any) -> tuple[float, str | None]:
    """Deterministic ``(score, vector)`` for a severity level."""
    level = str(severity or "").strip().lower()
    return HEURISTIC_CVSS.get(level, HEURISTIC_CVSS["info"])


def build_prompt(finding: Any) -> str:
    """Render the per-finding LLM prompt (kept deterministic for tests)."""
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
    """Return the first plausible CVSS vector found in a model answer."""
    match = _VECTOR_PATTERN.search(str(answer or ""))
    return match.group(0) if match else None


def estimate_cvss_with_source(
    finding: Any,
    llm_client: Callable[[str], str | None] | None = None,
) -> tuple[float | None, str | None, str]:
    """Return ``(score, vector, source)`` where source is ``tool``/``llm``/``heuristic``.

    ``llm_client`` is an optional **synchronous** callable receiving the prompt
    and returning the model answer (or ``None``). Any failure degrades silently
    to the heuristic: the report is fail-safe by design.
    """
    explicit_score = getattr(finding, "cvss_score", None)
    explicit_vector = getattr(finding, "cvss_vector", None)
    if isinstance(explicit_score, (int, float)) and not isinstance(explicit_score, bool):
        score = float(explicit_score)
        if score <= 0 and not explicit_vector:
            return score, None, "tool"
        return score, (str(explicit_vector) if explicit_vector else None), "tool"
    if isinstance(explicit_vector, str) and explicit_vector.strip():
        computed = parse_cvss_vector(explicit_vector)
        if computed is not None:
            return computed, explicit_vector.strip(), "tool"

    if callable(llm_client):
        try:
            answer = llm_client(build_prompt(finding))
        except Exception:  # noqa: BLE001 - a broken model must not break the report
            answer = None
        vector = extract_vector(answer)
        if vector is not None:
            computed = parse_cvss_vector(vector)
            if computed is not None:
                return computed, vector, "llm"

    score, vector = heuristic_cvss(getattr(finding, "severity", "info"))
    return score, vector, "heuristic"


def estimate_cvss(
    finding: Any,
    llm_client: Callable[[str], str | None] | None = None,
) -> tuple[float | None, str | None]:
    """Return ``(score, vector)`` for one finding (see the ``_with_source`` form)."""
    score, vector, _source = estimate_cvss_with_source(finding, llm_client)
    return score, vector


__all__ = [
    "HEURISTIC_CVSS",
    "LLM_PROMPT",
    "build_prompt",
    "estimate_cvss",
    "estimate_cvss_with_source",
    "extract_vector",
    "heuristic_cvss",
    "parse_cvss_vector",
]
