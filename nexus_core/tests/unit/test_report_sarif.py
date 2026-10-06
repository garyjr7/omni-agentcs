"""``nexus_core.report.sarif``: SARIF 2.1.0 export and structural validation."""

from __future__ import annotations

import json
from dataclasses import replace

import pytest

from nexus_core.report import frameworks
from nexus_core.report.models import EngagementReport, Finding
from nexus_core.report.sarif import (
    SARIF_SCHEMA_URL,
    SARIF_VERSION,
    build_sarif,
    render_sarif,
    validate_sarif,
    validate_with_schema,
)
from nexus_core.tests import report_support as support


def _finding(index: int, **overrides) -> Finding:
    base = Finding(
        finding_id=f"finding_{index}",
        title=f"Finding {index}",
        description="descripción verificada",
        severity="high",
        cvss_score=8.0,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        cvss_source="tool",
        cwe="CWE-22",
        cve=None,
        mitre_techniques=("T1190",),
        owasp_category="A01",
        affected_targets=(support.LAB_TARGET,),
        evidence=(),
        discovered_by_tool="nexus.web.nuclei",
        discovered_at=support.iso(),
        reproduction_steps=(),
        kind="nuclei",
    )
    return replace(base, **overrides)


def _report(findings) -> EngagementReport:
    return EngagementReport(
        engagement_id="eng-lab",
        engagement_name="lab-engagement",
        client="ACME",
        operator="operator-1",
        started_at=support.iso(),
        ended_at=support.iso(),
        scope_summary="lab",
        scope_full={},
        findings=tuple(findings),
        failed_attempts=(),
        tools_used=("nexus.web.nuclei",),
        sessions_opened=0,
        audit_events_total=3,
        audit_chain_valid=True,
        generated_at=support.iso(),
        report_sha256="a" * 64,
    )


def test_version_and_schema_are_declared():
    document = build_sarif(_report([_finding(1)]))
    assert document["version"] == SARIF_VERSION
    assert document["$schema"] == SARIF_SCHEMA_URL
    assert validate_sarif(document) == []


def test_one_result_per_finding():
    report = _report([_finding(1), _finding(2), _finding(3)])
    document = build_sarif(report)
    run = document["runs"][0]
    assert len(run["results"]) == 3
    assert validate_sarif(document) == []


def test_rule_deduplication_by_kind():
    report = _report([_finding(1), _finding(2), _finding(3, kind="open_ports")])
    document = build_sarif(report)
    rules = document["runs"][0]["tool"]["driver"]["rules"]
    assert [rule["id"] for rule in rules] == ["NEXUS/nuclei", "NEXUS/open_ports"]
    # Both nuclei results share one rule index.
    results = document["runs"][0]["results"]
    by_rule = {}
    for result in results:
        by_rule.setdefault(result["ruleId"], set()).add(result["ruleIndex"])
    assert all(len(indexes) == 1 for indexes in by_rule.values())


def test_levels_follow_severity():
    report = _report(
        [_finding(1, severity="critical"), _finding(2, severity="medium"), _finding(3, severity="info")]
    )
    levels = [result["level"] for result in build_sarif(report)["runs"][0]["results"]]
    assert levels == ["error", "warning", "note"]


def test_properties_carry_the_enrichment():
    finding = _finding(
        1,
        cvss4_score=9.3,
        cvss4_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
        cvss4_source="heuristic",
        cve="CVE-2021-41773",
        cve_description="path traversal",
        epss_score=0.97,
        kev=True,
        frameworks=frameworks.map_for_kind("nuclei"),
    )
    document = build_sarif(_report([finding]))
    properties = document["runs"][0]["results"][0]["properties"]
    assert properties["cvss"]["version"] == "3.1"
    assert properties["cvss4"]["score"] == 9.3
    assert properties["cve"] == "CVE-2021-41773"
    assert properties["epss"] == 0.97
    assert properties["kev"] is True
    assert properties["frameworks"]
    rule = document["runs"][0]["tool"]["driver"]["rules"][0]
    assert rule["properties"]["security-severity"] == 9.3


def test_render_sarif_is_valid_json():
    text = render_sarif(_report([_finding(1)]))
    document = json.loads(text)
    assert document["version"] == "2.1.0"
    assert text.endswith("\n")


def test_locations_use_targets():
    document = build_sarif(_report([_finding(1)]))
    location = document["runs"][0]["results"][0]["locations"][0]
    assert location["physicalLocation"]["artifactLocation"]["uri"] == support.LAB_TARGET


def test_finding_without_targets_uses_unknown():
    document = build_sarif(_report([_finding(1, affected_targets=())]))
    location = document["runs"][0]["results"][0]["locations"][0]
    assert location["physicalLocation"]["artifactLocation"]["uri"] == "unknown"


def test_empty_report_is_still_valid():
    document = build_sarif(_report([]))
    assert document["runs"][0]["results"] == []
    assert validate_sarif(document) == []


def test_validator_rejects_bad_version():
    document = build_sarif(_report([_finding(1)]))
    document["version"] = "2.0.0"
    assert any("version" in item for item in validate_sarif(document))


def test_validator_rejects_missing_message():
    document = build_sarif(_report([_finding(1)]))
    document["runs"][0]["results"][0].pop("message")
    assert any("message.text" in item for item in validate_sarif(document))


def test_validator_rejects_undeclared_rule():
    document = build_sarif(_report([_finding(1)]))
    document["runs"][0]["results"][0]["ruleId"] = "NEXUS/nope"
    assert any("not declared" in item for item in validate_sarif(document))


def test_validator_rejects_bad_level_and_uri():
    document = build_sarif(_report([_finding(1)]))
    document["runs"][0]["results"][0]["level"] = "fatal"
    document["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] = ""
    errors = validate_sarif(document)
    assert any("level" in item for item in errors)
    assert any("uri is required" in item for item in errors)


def test_validator_rejects_non_object():
    assert validate_sarif([]) == ["document must be a JSON object"]
    assert validate_sarif({}) != []


def test_optional_schema_validation(tmp_path, monkeypatch):
    """Strict validation runs only when a schema is provided (opt-in)."""
    jsonschema = pytest.importorskip("jsonschema")
    monkeypatch.delenv("NEXUS_SARIF_SCHEMA", raising=False)
    document = build_sarif(_report([_finding(1)]))
    assert validate_with_schema(document) == []  # no schema configured -> no check

    schema_path = tmp_path / "minimal-sarif.json"
    schema_path.write_text(
        json.dumps(
            {
                "type": "object",
                "required": ["version", "runs"],
                "properties": {"version": {"const": "2.1.0"}},
            }
        ),
        encoding="utf-8",
    )
    assert validate_with_schema(document, schema_path) == []
    broken = dict(document, version="2.0.0")
    assert validate_with_schema(broken, schema_path) != []

    # A missing path never turns into a failure either.
    assert validate_with_schema(document, tmp_path / "absent.json") == []
    assert jsonschema.__name__ == "jsonschema"


def test_security_severity_defaults_to_zero():
    finding = _finding(1, cvss_score=None, cvss_vector=None, cvss4_score=None)
    document = build_sarif(_report([finding]))
    rule = document["runs"][0]["tool"]["driver"]["rules"][0]
    assert rule["properties"]["security-severity"] == 0.0


def _mutated(**change):
    document = build_sarif(_report([_finding(1)]))
    for path, value in change.items():
        target = document
        parts = path.split(".")
        for part in parts[:-1]:
            target = target[int(part)] if part.isdigit() else target[part]
        key = parts[-1]
        if isinstance(target, list):
            target[int(key)] = value
        else:
            target[key] = value
    return document


def test_validator_reports_each_structural_defect():
    assert any("runs" in item for item in validate_sarif({"version": "2.1.0", "$schema": "x"}))
    assert any("must be an object" in item for item in validate_sarif(_mutated(**{"runs.0": 1})))
    # driver missing entirely
    assert any("tool.driver" in item for item in validate_sarif(_mutated(**{"runs.0.tool": {}})))
    # empty driver name
    assert any(
        "tool.driver.name" in item
        for item in validate_sarif(_mutated(**{"runs.0.tool.driver.name": ""}))
    )
    # rules not an array
    assert any(
        "driver.rules" in item
        for item in validate_sarif(_mutated(**{"runs.0.tool.driver.rules": "x"}))
    )
    # results not an array
    assert any(
        "results must" in item for item in validate_sarif(_mutated(**{"runs.0.results": "x"}))
    )
    # a result that is not an object
    assert any("must be an object" in item for item in validate_sarif(_mutated(**{"runs.0.results": [1]})))
    # empty rule id
    assert any(
        "ruleId" in item
        for item in validate_sarif(_mutated(**{"runs.0.results.0.ruleId": ""}))
    )
    # locations not an array
    assert any(
        "locations must" in item
        for item in validate_sarif(_mutated(**{"runs.0.results.0.locations": "x"}))
    )
    # physicalLocation not an object
    assert any(
        "physicalLocation" in item
        for item in validate_sarif(_mutated(**{"runs.0.results.0.locations": [{}]}))
    )
    # artifactLocation without a uri
    assert any(
        "uri is required" in item
        for item in validate_sarif(
            _mutated(**{"runs.0.results.0.locations.0.physicalLocation.artifactLocation": {}})
        )
    )
    # missing $schema
    assert any("$schema" in item for item in validate_sarif(_mutated(**{"$schema": ""})))
