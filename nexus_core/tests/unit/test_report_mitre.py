"""``nexus_core.report.mitre``: offline ATT&CK mapping and enrichment."""

from __future__ import annotations

import json
from dataclasses import replace

import pytest

from nexus_core.report import mitre
from nexus_core.report.models import Evidence, Finding
from nexus_core.tests import report_support as support


def _finding(**overrides) -> Finding:
    base = Finding(
        finding_id="finding_x",
        title="t",
        description="d",
        severity="info",
        cvss_score=None,
        cvss_vector=None,
        cwe=None,
        cve=None,
        mitre_techniques=(),
        owasp_category=None,
        affected_targets=(),
        evidence=(
            Evidence(
                kind="audit_event",
                ref_id="audit_1",
                sha256="a" * 64,
                excerpt="{}",
                created_at=support.iso(),
            ),
        ),
        discovered_by_tool="nexus.recon.nmap",
        discovered_at=support.iso(),
        reproduction_steps=(),
    )
    return replace(base, **overrides)


def test_techniques_for_tool_nmap():
    assert mitre.techniques_for_tool("nexus.recon.nmap") == ("T1046", "T1595")
    assert mitre.techniques_for_tool("nexus.web.nuclei") == ("T1190",)
    assert mitre.techniques_for_tool("nexus.recon.subfinder") == ("T1595", "T1592")
    assert mitre.techniques_for_tool("nexus.session.interact") == ("T1059",)
    # A bookkeeping tool maps to nothing instead of guessing.
    assert mitre.techniques_for_tool("nexus.session.kill") == ()
    assert mitre.techniques_for_tool("nexus.unknown.tool") == ()


def test_techniques_for_command_hashdump():
    assert mitre.techniques_for_command("hashdump") == ("T1003",)
    assert mitre.techniques_for_command("HASHDUMP") == ("T1003",)
    assert mitre.techniques_for_command("hashdump; whoami") == ("T1003",)


def test_techniques_for_command_getsystem():
    assert mitre.techniques_for_command("getsystem") == ("T1068",)
    assert mitre.techniques_for_command("getprivs -a") == ("T1068",)


def test_techniques_for_command_migrate():
    assert mitre.techniques_for_command("migrate 1234") == ("T1055",)
    assert mitre.techniques_for_command("sysinfo") == ("T1082",)
    assert mitre.techniques_for_command("whoami") == ("T1033",)


def test_techniques_unknown_command_empty():
    assert mitre.techniques_for_command("") == ()
    assert mitre.techniques_for_command("   ") == ()
    assert mitre.techniques_for_command("some-unknown-binary --help") == ()


def test_mitre_data_file_valid_json():
    techniques = mitre.techniques()
    assert len(techniques) >= 40
    for technique_id, value in techniques.items():
        assert technique_id.startswith("T")
        assert value["name"] and value["tactic"]
    mapping = mitre.tool_map()
    known = set(techniques)
    for tool_id, ids in mapping.items():
        assert tool_id.startswith("nexus.")
        for technique_id in ids:
            assert technique_id in known, f"{tool_id} maps unknown {technique_id}"
    # The raw files really are JSON objects (not Python literals).
    for path in (mitre.TECHNIQUES_FILE, mitre.TOOL_MAP_FILE):
        assert isinstance(json.loads(path.read_text(encoding="utf-8")), dict)
    assert mitre.technique_name("T1046") == "Network Service Discovery"
    assert mitre.technique_tactic("T1046") == "Discovery"
    assert mitre.technique_name("T9999") == "T9999"
    assert mitre.technique_tactic("T9999") == ""


def test_enrich_finding_unions_command_and_tool_techniques():
    enriched = mitre.enrich_finding_with_mitre(
        _finding(discovered_by_tool="nexus.session.interact", mitre_techniques=("T1003",))
    )
    assert enriched.mitre_techniques == ("T1003", "T1059")
    assert mitre.merge_techniques(("T1",), ("T1", "T2"), ()) == ("T1", "T2")


@pytest.mark.parametrize("technique_id", ["T1003", "T1068", "T1055", "T1082", "T1059"])
def test_command_map_points_at_known_techniques(technique_id):
    assert technique_id in mitre.techniques()
