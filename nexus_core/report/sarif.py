"""SARIF 2.1.0 export of an engagement report (pure stdlib, no dependency).

SARIF (Static Analysis Results Interchange Format) is the OASIS JSON format that
GitHub Advanced Security, SonarQube and the VS Code SARIF Viewer consume. Emitting
it lets a client drop the engagement findings straight into their code-scanning
pipeline instead of re-keying them.

Two honesty guarantees:

* we emit exactly the SARIF **2.1.0** required shape (``version``, ``$schema``,
  ``runs[].tool.driver``, ``runs[].results``) and declare the official schema URL;
* :func:`validate_sarif` performs a *structural* validation of what we emit. The
  full official JSON Schema is ~150 KiB; shipping it would bloat an offline-first
  CLI, so strict validation against it is opt-in: set ``NEXUS_SARIF_SCHEMA`` to a
  local copy of ``sarif-schema-2.1.0.json`` (with ``jsonschema`` installed) and
  :func:`validate_with_schema` will use it. This limitation is documented, not
  hidden.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Iterable

from .models import EngagementReport, Finding, severity_rank

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA_URL = "https://json.schemastore.org/sarif-2.1.0.json"
TOOL_NAME = "OmniAgentCS"
TOOL_VERSION = "3.0.0"
TOOL_INFORMATION_URI = "https://github.com/BAJIOWARE/omni-agentcs"
#: Environment variable pointing at a local official SARIF schema copy.
SCHEMA_ENV = "NEXUS_SARIF_SCHEMA"

_LEVELS = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}


def _level(severity: Any) -> str:
    return _LEVELS.get(str(severity or "info").lower(), "note")


def _rule_id(finding: Finding) -> str:
    kind = str(finding.kind or "generic")
    return f"NEXUS/{kind}"


def _security_severity(finding: Finding) -> float:
    """Numeric score GitHub uses to rank a rule (CVSS 4.0 wins, then 3.1)."""
    for value in (finding.cvss4_score, finding.cvss_score):
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            return float(value)
    return 0.0


def _rule_for(finding: Finding) -> dict[str, Any]:
    tags = ["security", str(finding.kind or "generic")]
    if finding.cwe:
        tags.append(str(finding.cwe))
    if finding.owasp_category:
        tags.append(str(finding.owasp_category))
    properties: dict[str, Any] = {"security-severity": _security_severity(finding), "tags": tags}
    if finding.cwe:
        properties["cwe"] = finding.cwe
    return {
        "id": _rule_id(finding),
        "name": str(finding.kind or "generic"),
        "shortDescription": {"text": _short_title(finding)},
        "fullDescription": {"text": finding.description or _short_title(finding)},
        "defaultConfiguration": {"level": _level(finding.severity)},
        "properties": properties,
    }


def _short_title(finding: Finding) -> str:
    return str(finding.title or finding.kind or "finding")[:120]


def _locations(finding: Finding) -> list[dict[str, Any]]:
    targets = [str(item) for item in finding.affected_targets if str(item)] or ["unknown"]
    return [
        {"physicalLocation": {"artifactLocation": {"uri": _uri(target)}}}
        for target in targets
    ]


def _uri(value: str) -> str:
    """Make a target safe as a SARIF ``uri`` (no scheme required)."""
    text = str(value or "unknown").strip().replace("\\", "/")
    return text or "unknown"


def _result_for(finding: Finding, rule_index: int) -> dict[str, Any]:
    properties: dict[str, Any] = {
        "findingId": finding.finding_id,
        "severity": finding.severity,
        "tool": finding.discovered_by_tool,
        "targets": list(finding.affected_targets),
    }
    if isinstance(finding.cvss_score, (int, float)):
        properties["cvss"] = {
            "version": "3.1",
            "score": finding.cvss_score,
            "vector": finding.cvss_vector,
            "source": finding.cvss_source,
        }
    if isinstance(finding.cvss4_score, (int, float)):
        properties["cvss4"] = {
            "version": "4.0",
            "score": finding.cvss4_score,
            "vector": finding.cvss4_vector,
            "source": finding.cvss4_source,
        }
    if finding.cwe:
        properties["cwe"] = finding.cwe
    if finding.cve:
        properties["cve"] = finding.cve
    if finding.cve_description:
        properties["cveDescription"] = finding.cve_description
    if isinstance(finding.epss_score, (int, float)):
        properties["epss"] = finding.epss_score
    if finding.kev:
        properties["kev"] = True
    if finding.mitre_techniques:
        properties["mitreTechniques"] = list(finding.mitre_techniques)
    if finding.frameworks:
        properties["frameworks"] = [item.to_dict() for item in finding.frameworks]

    message = _short_title(finding)
    if finding.cve:
        message = f"{message} ({finding.cve})"
    return {
        "ruleId": _rule_id(finding),
        "ruleIndex": rule_index,
        "level": _level(finding.severity),
        "message": {"text": message},
        "locations": _locations(finding),
        "partialFingerprints": {"omniFindingId": finding.finding_id},
        "properties": properties,
    }


def _build_rules(findings: Iterable[Finding]) -> tuple[list[dict[str, Any]], dict[str, int]]:
    """One rule per distinct rule id, in severity order."""
    ordered = sorted(findings, key=lambda item: (severity_rank(item.severity), item.title))
    rules: list[dict[str, Any]] = []
    index: dict[str, int] = {}
    for finding in ordered:
        rule_id = _rule_id(finding)
        if rule_id in index:
            continue
        index[rule_id] = len(rules)
        rules.append(_rule_for(finding))
    return rules, index


def build_sarif(report: EngagementReport) -> dict[str, Any]:
    """Build the SARIF 2.1.0 document for a report."""
    rules, index = _build_rules(report.findings)
    results = [
        _result_for(finding, index[_rule_id(finding)]) for finding in report.findings
    ]
    driver: dict[str, Any] = {
        "name": TOOL_NAME,
        "informationUri": TOOL_INFORMATION_URI,
        "version": TOOL_VERSION,
        "rules": rules,
    }
    run: dict[str, Any] = {
        "tool": {"driver": driver},
        "results": results,
        "properties": {
            "engagementId": report.engagement_id,
            "engagementName": report.engagement_name,
            "client": report.client,
            "operator": report.operator,
            "auditChainValid": report.audit_chain_valid,
            "auditEventsTotal": report.audit_events_total,
            "reportSha256": report.report_sha256,
        },
    }
    if report.started_at or report.generated_at:
        run["invocations"] = [
            {
                "executionSuccessful": True,
                "startTimeUtc": report.started_at or report.generated_at,
                "endTimeUtc": report.generated_at or report.started_at,
            }
        ]
    return {
        "$schema": SARIF_SCHEMA_URL,
        "version": SARIF_VERSION,
        "runs": [run],
    }


def render_sarif(report: EngagementReport) -> str:
    """Render the SARIF document as pretty-printed JSON."""
    document = build_sarif(report)
    return json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def validate_sarif(document: Any) -> list[str]:
    """Return a list of structural SARIF 2.1.0 violations (empty when valid)."""
    errors: list[str] = []
    if not isinstance(document, dict):
        return ["document must be a JSON object"]
    if document.get("version") != SARIF_VERSION:
        errors.append(f"version must be {SARIF_VERSION!r}")
    if not isinstance(document.get("$schema"), str) or not document["$schema"]:
        errors.append("$schema must be a non-empty string")
    runs = document.get("runs")
    if not isinstance(runs, list) or not runs:
        return errors + ["runs must be a non-empty array"]
    for index, run in enumerate(runs):
        prefix = f"runs[{index}]"
        if not isinstance(run, dict):
            errors.append(f"{prefix} must be an object")
            continue
        driver = (run.get("tool") or {}).get("driver") if isinstance(run.get("tool"), dict) else None
        if not isinstance(driver, dict):
            errors.append(f"{prefix}.tool.driver must be an object")
            driver = {}
        if not str(driver.get("name") or ""):
            errors.append(f"{prefix}.tool.driver.name must be a non-empty string")
        rules = driver.get("rules", [])
        if not isinstance(rules, list):
            errors.append(f"{prefix}.tool.driver.rules must be an array")
            rules = []
        rule_ids = {rule.get("id") for rule in rules if isinstance(rule, dict)}
        results = run.get("results")
        if not isinstance(results, list):
            errors.append(f"{prefix}.results must be an array")
            continue
        for rindex, result in enumerate(results):
            rprefix = f"{prefix}.results[{rindex}]"
            if not isinstance(result, dict):
                errors.append(f"{rprefix} must be an object")
                continue
            rule_id = result.get("ruleId")
            if not str(rule_id or ""):
                errors.append(f"{rprefix}.ruleId must be a non-empty string")
            elif rule_id not in rule_ids:
                errors.append(f"{rprefix}.ruleId {rule_id!r} is not declared in driver.rules")
            level = result.get("level", "warning")
            if level not in {"none", "note", "warning", "error"}:
                errors.append(f"{rprefix}.level {level!r} is invalid")
            message = result.get("message")
            if not isinstance(message, dict) or not str(message.get("text") or ""):
                errors.append(f"{rprefix}.message.text must be a non-empty string")
            locations = result.get("locations", [])
            if not isinstance(locations, list):
                errors.append(f"{rprefix}.locations must be an array")
                continue
            for lindex, location in enumerate(locations):
                lprefix = f"{rprefix}.locations[{lindex}]"
                physical = (location or {}).get("physicalLocation") if isinstance(location, dict) else None
                if not isinstance(physical, dict):
                    errors.append(f"{lprefix}.physicalLocation must be an object")
                    continue
                artifact = physical.get("artifactLocation")
                if not isinstance(artifact, dict) or not str(artifact.get("uri") or ""):
                    errors.append(f"{lprefix}.physicalLocation.artifactLocation.uri is required")
    return errors


def validate_with_schema(document: Any, schema_path: str | Path | None = None) -> list[str]:
    """Validate against the official schema when one is available locally.

    Returns ``[]`` (no strict check) when the ``jsonschema`` package or the schema
    file is absent: this never turns a missing optional dependency into a failure.
    """
    resolved = schema_path or os.environ.get(SCHEMA_ENV)
    if not resolved:
        return []
    try:
        import jsonschema  # noqa: PLC0415 - optional, only when a schema is given
    except ImportError:
        return []
    path = Path(resolved)
    if not path.is_file():
        return []
    schema = json.loads(path.read_text(encoding="utf-8"))
    validator = jsonschema.Draft7Validator(schema)
    return [
        f"{'/'.join(str(part) for part in error.absolute_path) or '<root>'}: {error.message}"
        for error in sorted(validator.iter_errors(document), key=lambda item: list(item.absolute_path))
    ]


__all__ = [
    "SARIF_SCHEMA_URL",
    "SARIF_VERSION",
    "SCHEMA_ENV",
    "TOOL_NAME",
    "TOOL_VERSION",
    "build_sarif",
    "render_sarif",
    "validate_sarif",
    "validate_with_schema",
]
