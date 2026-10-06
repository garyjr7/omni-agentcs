"""``nexus_core.report.cvss4``: local CVSS v4.0 base scoring.

The expected scores are the official ones published by FIRST in the CVSS v4.0
Examples document; the implementation must reproduce them exactly, otherwise it
is not CVSS v4.0.
"""

from __future__ import annotations

from dataclasses import replace

import pytest

from nexus_core.report import cvss4
from nexus_core.report.models import Finding
from nexus_core.tests import report_support as support

#: ``CVE -> (vector, official base score)`` from https://www.first.org/cvss/v4.0/examples
OFFICIAL_EXAMPLES: dict[str, tuple[str, float]] = {
    "CVE-2022-41741": ("CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 7.3),
    "CVE-2020-3549": ("CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 7.7),
    "CVE-2023-3089": ("CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:L/VA:L/SC:N/SI:N/SA:N", 8.3),
    "CVE-2021-44714": ("CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:A/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N", 4.6),
    "CVE-2022-21830": ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:N/VI:N/VA:N/SC:L/SI:L/SA:N", 5.1),
    "CVE-2022-22186": ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:L/SI:L/SA:N", 6.9),
    "CVE-2023-21989": ("CVSS:4.0/AV:L/AC:L/AT:N/PR:H/UI:N/VC:N/VI:N/VA:N/SC:H/SI:N/SA:N", 5.9),
}


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
        evidence=(),
        discovered_by_tool="nexus.web.nuclei",
        discovered_at=support.iso(),
        reproduction_steps=(),
    )
    return replace(base, **overrides)


@pytest.mark.parametrize("cve, case", sorted(OFFICIAL_EXAMPLES.items()))
def test_official_examples(cve, case):
    """Every FIRST CVSS v4.0 example scores exactly as published."""
    vector, expected = case
    assert cvss4.parse_cvss4_vector(vector) == expected, cve


def test_table_is_the_official_one():
    """The vendored lookup table carries all 270 published MacroVectors."""
    table = cvss4.lookup_table()
    assert len(table) == 270
    assert table["000000"] == 10.0
    assert table["000100"] == 10.0
    assert table["212221"] == 0.1


def test_full_impact_is_ten():
    vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"
    assert cvss4.parse_cvss4_vector(vector) == 10.0


def test_no_impact_is_zero():
    vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N"
    assert cvss4.parse_cvss4_vector(vector) == 0.0


@pytest.mark.parametrize(
    "broken",
    [
        "",
        None,
        "not-a-vector",
        # v3.1 vectors must not be accepted by the v4.0 parser.
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        # Missing a required base metric.
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N",
        # Out-of-range value.
        "CVSS:4.0/AV:Z/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
        # Contradictory duplicate metric.
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/AV:L",
    ],
)
def test_malformed_vector_is_fail_closed(broken):
    """A vector that is not exactly CVSS v4.0 yields no score at all."""
    assert cvss4.parse_cvss4_vector(broken) is None


def test_severity_bands():
    assert cvss4.severity_from_score4(9.3) == "critical"
    assert cvss4.severity_from_score4(8.0) == "high"
    assert cvss4.severity_from_score4(5.3) == "medium"
    assert cvss4.severity_from_score4(2.3) == "low"
    assert cvss4.severity_from_score4(0.0) == "info"
    assert cvss4.severity_from_score4("nonsense") == "info"


def test_heuristic_pairs_are_consistent_and_in_band():
    bands = {
        "critical": (9.0, 10.0), "high": (7.0, 8.9),
        "medium": (4.0, 6.9), "low": (0.1, 3.9),
    }
    for level, (low, high) in bands.items():
        score, vector = cvss4.heuristic_cvss4(level)
        assert vector is not None
        # The score is *recomputed* from the vector, never hand-written.
        assert score == cvss4.parse_cvss4_vector(vector)
        assert low <= score <= high, level
    assert cvss4.heuristic_cvss4("info") == (0.0, None)
    assert cvss4.heuristic_cvss4("unknown") == (0.0, None)


def test_explicit_tool_vector_wins_and_is_scored_locally():
    finding = _finding(
        cvss4_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
        cvss4_source="tool",
    )
    score, vector, source = cvss4.estimate_cvss4_with_source(finding)
    assert (score, source) == (9.3, "tool")
    assert vector == finding.cvss4_vector


def test_nvd_sourced_vector_keeps_its_source():
    finding = _finding(
        cvss4_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
        cvss4_source="nvd",
    )
    score, _vector, source = cvss4.estimate_cvss4_with_source(finding)
    assert (score, source) == (9.3, "nvd")


def test_bare_explicit_score_is_not_recomputed():
    finding = _finding(cvss4_score=8.0)
    score, vector, source = cvss4.estimate_cvss4_with_source(finding)
    assert (score, vector, source) == (8.0, None, "tool")


def test_llm_vector_is_scored_locally():
    finding = _finding(severity="info")

    def model(_prompt: str) -> str:
        return "Yo diría CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H (crítico)."

    score, vector, source = cvss4.estimate_cvss4_with_source(finding, model)
    assert (score, source) == (10.0, "llm")
    assert vector == "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"


@pytest.mark.parametrize(
    "broken",
    [lambda _p: None, lambda _p: "le pondría un 10", lambda _p: "CVSS:4.0/AV:N/AC:L"],
)
def test_llm_failure_degrades_to_heuristic(broken):
    score, vector, source = cvss4.estimate_cvss4_with_source(_finding(severity="high"), broken)
    assert source == "heuristic"
    assert vector is not None
    assert score == cvss4.parse_cvss4_vector(vector)


def test_llm_exception_is_fail_safe():
    def exploding(_prompt: str) -> str:
        raise RuntimeError("provider down")

    score, _vector, source = cvss4.estimate_cvss4_with_source(_finding(severity="medium"), exploding)
    assert (score, source) == (5.3, "heuristic")


def test_build_prompt_contains_the_finding_facts():
    prompt = cvss4.build_prompt(_finding(severity="high"))
    assert "Apache path traversal" in prompt
    assert support.LAB_TARGET in prompt
    assert "CVSS:4.0/" in prompt


def test_extract_vector():
    assert cvss4.extract_vector("nada") is None
    assert (
        cvss4.extract_vector("usa CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N")
        == "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
    )


def test_macro_vector_is_deterministic():
    metrics = dict(cvss4._METRIC_PATTERN.findall(
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
    ))
    assert cvss4.macro_vector(metrics) == "000200"
