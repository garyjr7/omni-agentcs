"""``nexus_core.report.cvss``: explicit, LLM-assisted and heuristic scoring."""

from __future__ import annotations

import math
from dataclasses import replace

import pytest

from nexus_core.report import cvss
from nexus_core.report.models import Evidence, Finding
from nexus_core.tests import report_support as support


def _finding(**overrides) -> Finding:
    base = Finding(
        finding_id="finding_x",
        title="Apache path traversal",
        description="d",
        severity="info",
        cvss_score=None,
        cvss_vector=None,
        cwe=None,
        cve=None,
        mitre_techniques=(),
        owasp_category=None,
        affected_targets=(support.LAB_TARGET,),
        evidence=(
            Evidence(
                kind="audit_event",
                ref_id="audit_1",
                sha256="a" * 64,
                excerpt="{}",
                created_at=support.iso(),
            ),
        ),
        discovered_by_tool="nexus.web.nuclei",
        discovered_at=support.iso(),
        reproduction_steps=(),
    )
    return replace(base, **overrides)


def test_cvss_from_nuclei_explicit():
    """A tool-provided value always wins, and is never recomputed."""
    explicit = _finding(cvss_score=9.8, cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    assert cvss.estimate_cvss(explicit) == (9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    assert cvss.estimate_cvss_with_source(explicit)[2] == "tool"

    # A vector without a score is scored locally (real CVSS 3.1 maths).
    vector_only = _finding(cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    assert cvss.estimate_cvss(vector_only) == (9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    assert cvss.estimate_cvss_with_source(vector_only)[2] == "tool"

    # A malformed provided vector is ignored rather than trusted.
    broken = _finding(cvss_vector="not-a-vector")
    assert cvss.estimate_cvss_with_source(broken)[2] == "heuristic"
    assert cvss.estimate_cvss_with_source(_finding(cvss_score=0.0))[2] == "tool"


def test_cvss_heuristic_critical():
    score, vector = cvss.estimate_cvss(_finding(severity="critical"))
    assert score == 9.5
    assert vector == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
    assert not math.isnan(score)


def test_cvss_heuristic_high():
    score, vector = cvss.estimate_cvss(_finding(severity="high"))
    assert score == 8.0
    assert vector == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"


def test_cvss_heuristic_medium_and_low():
    assert cvss.estimate_cvss(_finding(severity="medium")) == (
        5.5,
        "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L",
    )
    assert cvss.estimate_cvss(_finding(severity="low")) == (
        3.0,
        "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
    )


def test_cvss_heuristic_info_returns_zero():
    score, vector = cvss.estimate_cvss(_finding(severity="info"))
    assert score == 0.0
    assert vector is None


def test_cvss_llm_vector_is_scored_locally():
    """A model may propose a vector; the number is always ours."""
    finding = _finding(severity="info")

    def model(_prompt: str) -> str:
        return "El vector es CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H (crítico)."

    score, vector, source = cvss.estimate_cvss_with_source(finding, model)
    assert (score, vector) == (9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    assert source == "llm"

    # A hallucinated number in prose cannot reach the report.
    score, _vector, source = cvss.estimate_cvss_with_source(
        finding, lambda _p: "le pondría un 10.0"
    )
    assert (score, source) == (0.0, "heuristic")


@pytest.mark.parametrize(
    "broken",
    [
        lambda _p: None,
        lambda _p: "",
        lambda _p: "CVSS:3.1/AV:Z/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    ],
)
def test_cvss_llm_failure_is_fail_safe(broken):
    score, vector, source = cvss.estimate_cvss_with_source(_finding(severity="high"), broken)
    assert (score, source) == (8.0, "heuristic")
    assert vector is not None


def test_cvss_llm_exception_is_fail_safe():
    def exploding(_prompt: str) -> str:
        raise RuntimeError("provider down")

    score, _vector, source = cvss.estimate_cvss_with_source(_finding(severity="medium"), exploding)
    assert (score, source) == (5.5, "heuristic")


def test_parse_cvss_vector_matches_the_official_calculator():
    cases = {
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H": 9.8,
        "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L": 6.3,
        "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N": 3.1,
        "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N": 5.5,
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N": 0.0,
        "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H": 10.0,
    }
    for vector, expected in cases.items():
        assert cvss.parse_cvss_vector(vector) == expected, vector
    assert cvss.parse_cvss_vector("") is None
    assert cvss.parse_cvss_vector(None) is None
    assert cvss.parse_cvss_vector("CVSS:2.0/AV:N") is None


def test_build_prompt_contains_the_finding_facts():
    prompt = cvss.build_prompt(_finding(severity="high"))
    assert "Apache path traversal" in prompt
    assert support.LAB_TARGET in prompt
    assert "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" in prompt
