"""``nexus_core.report.frameworks``: curated PTES/WSTG/NIST/D3FEND mappings."""

from __future__ import annotations

import re
from dataclasses import replace

from nexus_core.report import frameworks
from nexus_core.report.models import Finding
from nexus_core.tests import report_support as support

KINDS = tuple(sorted(frameworks.PTES_PHASES))
_D3FEND_ID = re.compile(r"^D3-[A-Z0-9]+$")
_WSTG_ID = re.compile(r"^WSTG-[A-Z]+-\d{2}$")


def _finding(**overrides) -> Finding:
    base = Finding(
        finding_id="f", title="t", description="d", severity="high",
        cvss_score=None, cvss_vector=None, cwe=None, cve=None,
        mitre_techniques=(), owasp_category=None,
        affected_targets=(support.LAB_TARGET,), evidence=(),
        discovered_by_tool="nexus.recon.nmap", discovered_at=support.iso(),
        reproduction_steps=(),
    )
    return replace(base, **overrides)


def test_every_kind_has_a_ptes_phase():
    for kind in KINDS:
        mappings = frameworks.map_for_kind(kind)
        assert any(item.framework == "PTES" for item in mappings), kind


def test_every_kind_has_a_nist_section():
    for kind in KINDS:
        mappings = frameworks.map_for_kind(kind)
        assert any(item.framework == "NIST-SP-800-115" for item in mappings), kind


def test_every_kind_has_a_d3fend_countermeasure():
    for kind in KINDS:
        mappings = frameworks.map_for_kind(kind)
        d3fend = [item for item in mappings if item.framework == "MITRE-D3FEND"]
        assert d3fend, kind
        assert all(_D3FEND_ID.match(item.technique_id) for item in d3fend), kind


def test_ptes_phase_names_are_the_standard_ones():
    assert frameworks.map_for_kind("subdomains")[0].technique_id == "PTES-2"
    assert frameworks.map_for_kind("session_opened")[0].name == "Exploitation"
    assert frameworks.map_for_kind("session_command")[0].name == "Post-Exploitation"


def test_wstg_ids_are_well_formed_and_web_only():
    web_kinds = {"subdomains", "http_surface", "endpoint_protected", "nuclei", "sqli", "xss"}
    for kind in KINDS:
        members = [item for item in frameworks.map_for_kind(kind) if item.framework == "OWASP-WSTG"]
        if kind in web_kinds:
            assert members, kind
            assert all(_WSTG_ID.match(item.technique_id) for item in members), kind
        else:
            assert not members, kind


def test_sqli_and_xss_point_at_the_right_wstg_tests():
    assert frameworks.map_for_kind("sqli")[1].technique_id == "WSTG-INPV-05"
    assert frameworks.map_for_kind("xss")[1].technique_id == "WSTG-INPV-01"


def test_technique_refinement_adds_d3fend():
    finding = _finding(kind="generic", mitre_techniques=("T1003",))
    ids = {item.technique_id for item in frameworks.map_finding(finding)}
    assert {"D3-AL", "D3-ANCI"} <= ids


def test_no_duplicate_mappings():
    for kind in KINDS:
        mappings = frameworks.map_for_kind(kind)
        keys = [(item.framework, item.technique_id) for item in mappings]
        assert len(keys) == len(set(keys)), kind


def test_attach_frameworks_sets_every_finding():
    findings = [_finding(kind="open_ports"), _finding(kind="nuclei")]
    attached = frameworks.attach_frameworks(findings)
    assert all(item.frameworks for item in attached)
    # The original frozen findings are untouched.
    assert all(not item.frameworks for item in findings)


def test_frameworks_present_is_ordered():
    mappings = frameworks.map_for_kind("sqli")
    assert frameworks.frameworks_present(mappings) == (
        "PTES", "OWASP-WSTG", "NIST-SP-800-115", "MITRE-D3FEND",
    )


def test_unknown_kind_is_conservative():
    """An unknown observation still maps conservatively (analysis phase)."""
    mappings = frameworks.map_for_kind("something-new")
    assert {item.framework for item in mappings} == {
        "PTES", "NIST-SP-800-115", "MITRE-D3FEND",
    }


def test_mapping_dataclass_serializes():
    item = frameworks.map_for_kind("sqli")[0]
    assert set(item.to_dict()) == {"framework", "technique_id", "name"}
