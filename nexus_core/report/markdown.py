"""Markdown renderer for an engagement report (pure string templates).

No Markdown library is used: the output is plain CommonMark, deterministic for a
given :class:`~nexus_core.report.models.EngagementReport` and safe to paste into
any ticket or deliverable.
"""

from __future__ import annotations

import json
from typing import Any, Iterable

from .models import (
    SEVERITY_ORDER,
    EngagementReport,
    Finding,
    severity_rank,
)
from .frameworks import FRAMEWORKS
from .mitre import technique_name, technique_tactic, techniques_for_tool

SEVERITY_LABEL = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "medium": "MEDIUM",
    "low": "LOW",
    "info": "INFO",
}


def _value(value: Any, default: str = "n/d") -> str:
    text = str(value or "").strip()
    return text or default


def _escape_cell(value: Any) -> str:
    """Escape a value so it cannot break a Markdown table row."""
    return _value(value).replace("|", "\\|").replace("\n", " ")


def _fence(text: str, language: str = "") -> list[str]:
    """Wrap output in a code fence, widening it if the body contains one."""
    body = str(text or "")
    ticks = "```"
    while ticks in body:
        ticks += "`"
    return [f"{ticks}{language}", body, ticks]


def render_markdown(report: EngagementReport) -> str:
    """Render the full report as Markdown."""
    counts = report.findings_by_severity
    lines: list[str] = [
        f"# Reporte de Pentesting — {_value(report.engagement_name)}",
        "",
        f"**Cliente:** {_value(report.client)}",
        f"**Operador:** {_value(report.operator)}",
        f"**Engagement:** `{_value(report.engagement_id)}`",
        f"**Período:** {_value(report.started_at)} — {_value(report.ended_at)}",
        f"**Generado:** {_value(report.generated_at)}",
        "",
    ]

    lines += ["## Resumen ejecutivo", ""]
    summary = counts
    lines.append(
        "- Registros (incluye hipótesis e inventario): "
        f"**{summary.get('critical', 0)} críticos**, "
        f"**{summary.get('high', 0)} altos**, "
        f"**{summary.get('medium', 0)} medios**, "
        f"**{summary.get('low', 0)} bajos**, "
        f"{summary.get('info', 0)} informativos "
        f"({len(report.findings)} en total)."
    )
    lines.append(f"- Estado de evidencia: {report.findings_by_verification}.")
    lines.append(f"- Intentos sin hallazgo: {len(report.failed_attempts)}.")
    lines.append(f"- Sesiones abiertas y verificadas: {report.sessions_opened}.")
    lines.append(f"- Eventos de auditoría considerados: {report.audit_events_total}.")
    lines.append(
        "- Cadena de auditoría: "
        + ("✓ válida" if report.audit_chain_valid else "✗ **NO VERIFICADA**")
        + "."
    )
    if report.notes:
        lines.append(f"- Nota: {report.notes}")
    lines.append("")

    priorities = [
        finding for finding in report.findings if finding.severity in {"critical", "high"} and finding.verification_status == "confirmed_finding"
    ]
    if priorities:
        lines += ["### Hallazgos prioritarios (para dirección)", ""]
        lines.append(
            "Los siguientes hallazgos requieren atención prioritaria; el detalle "
            "técnico está más abajo, en la sección *Hallazgos*."
        )
        lines.append("")
        for finding in sorted(
            priorities, key=lambda item: (severity_rank(item.severity), item.title)
        ):
            flags = []
            if finding.kev:
                flags.append("**explotado en el wild (CISA KEV)**")
            if finding.epss_score is not None:
                flags.append(f"EPSS {finding.epss_score:.2f}")
            suffix = f" — {', '.join(flags)}" if flags else ""
            lines.append(
                f"- **[{SEVERITY_LABEL.get(finding.severity, finding.severity.upper())}]** "
                f"{finding.title} (CVSS máx. {_max_cvss(finding)}){suffix}"
            )
        lines.append("")

    lines += ["## Alcance", "", f"Resumen: {_value(report.scope_summary)}.", ""]
    scope = report.scope_full or {}
    lines.append(f"- CIDRs: {_join(scope.get('cidrs'))}")
    lines.append(f"- Dominios: {_join(scope.get('domains'))}")
    lines.append(f"- URLs: {_join(scope.get('urls'))}")
    lines.append(f"- Exclusiones: {_join(scope.get('exclusions'))}")
    lines.append(
        f"- Ventana de autorización: {_value(scope.get('valid_from'))} — "
        f"{_value(scope.get('valid_until'))}"
    )
    if scope.get("signature"):
        lines.append(f"- Firma: `{scope['signature']}`")
    if report.scope_signature and not scope.get("signature"):
        lines.append(f"- Firma: `{report.scope_signature}`")
    if report.run_ids:
        lines.append(f"- Runs: {', '.join(f'`{item}`' for item in report.run_ids)}")
    lines.append("")

    lines += ["## Metodología", ""]
    if report.tools_used:
        lines.append(
            "Herramientas durables utilizadas, todas a través del gateway "
            "(política, scope, aprobación humana y auditoría):"
        )
        lines.append("")
        for tool_id in report.tools_used:
            lines.append(f"- `{tool_id}`")
    else:
        lines.append("_No se registró ninguna ejecución de herramientas para este engagement._")
    lines.append("")

    lines += ["## Hallazgos", ""]
    if not report.findings:
        lines.append("_No se registraron hallazgos verificados en el audit trail._")
        lines.append("")
    for finding in report.findings:
        lines += _render_finding(finding)

    lines += ["## Intentos fallidos", ""]
    if not report.failed_attempts:
        lines.append("_No hubo intentos fallidos ni denegaciones registradas._")
        lines.append("")
    else:
        lines.append("| Fecha | Tool | Objetivo | Motivo |")
        lines.append("| --- | --- | --- | --- |")
        for attempt in report.failed_attempts:
            lines.append(
                f"| {_escape_cell(attempt.attempted_at)} | `{_escape_cell(attempt.tool_id)}` "
                f"| {_escape_cell(attempt.target)} | {_escape_cell(attempt.reason)} |"
            )
        lines.append("")

    lines += _render_items_section(
        "Inventario",
        report.inventories,
        "_No se registró inventario (endpoints, stack) para este engagement._",
    )
    lines += _render_items_section(
        "Referencias",
        report.references,
        "_No se registraron referencias (Exploit-DB, AD) para este engagement._",
    )
    lines += _render_items_section(
        "Superficie expuesta",
        report.surfaces,
        "_No se registró superficie adicional para este engagement._",
    )
    lines += _render_items_section(
        "Evidencia adicional",
        report.evidences,
        "_No se registró evidencia adicional para este engagement._",
    )

    lines += ["## Cronología", ""]
    if not report.timeline:
        lines.append("_Sin eventos de auditoría para este engagement._")
        lines.append("")
    else:
        lines.append("| Fecha | Acción | Tool | Objetivo | Decisión | Detalle |")
        lines.append("| --- | --- | --- | --- | --- | --- |")
        for entry in report.timeline:
            lines.append(
                f"| {_escape_cell(entry.occurred_at)} | {_escape_cell(entry.action)} "
                f"| `{_escape_cell(entry.tool_id)}` | {_escape_cell(entry.target)} "
                f"| {_escape_cell(entry.decision)} | {_escape_cell(entry.detail)} |"
            )
        lines.append("")

    lines += ["## Chain of custody", ""]
    lines.append(
        "- Cada hallazgo referencia su `ToolResult` persistido, el evento de auditoría "
        "encadenado (`event_hash`) y los artefactos con `sha256`."
    )
    lines.append(f"- Hash de este reporte (canónico): `{_value(report.report_sha256)}`")
    lines.append("")

    lines += ["## Anexos", ""]
    lines.append("### Catálogo de herramientas usadas")
    lines.append("")
    lines.append("| Tool | Técnicas MITRE ATT&CK declaradas |")
    lines.append("| --- | --- |")
    for tool_id in report.tools_used:
        mapped = ", ".join(techniques_for_tool(tool_id)) or "—"
        lines.append(f"| `{_escape_cell(tool_id)}` | {_escape_cell(mapped)} |")
    lines.append("")
    lines.append("### Cobertura MITRE ATT&CK observada")
    lines.append("")
    observed = sorted(
        {item for finding in report.findings for item in finding.mitre_techniques}
    )
    if not observed:
        lines.append("_Ninguna técnica ATT&CK atribuible a los hallazgos._")
    else:
        lines.append("| Técnica | Nombre | Táctica |")
        lines.append("| --- | --- | --- |")
        for technique_id in observed:
            lines.append(
                f"| {_escape_cell(technique_id)} | {_escape_cell(technique_name(technique_id))} "
                f"| {_escape_cell(technique_tactic(technique_id))} |"
            )
    lines += ["", "### Cobertura de marcos", ""]
    coverage: dict[str, int] = {}
    for finding in report.findings:
        for mapping in finding.frameworks:
            coverage[mapping.framework] = coverage.get(mapping.framework, 0) + 1
    if not coverage:
        lines.append("_Ningún hallazgo mapeó a un marco de referencia._")
    else:
        lines.append("| Marco | Hallazgos mapeados |")
        lines.append("| --- | --- |")
        for name in FRAMEWORKS:
            if name in coverage:
                lines.append(f"| {name} | {coverage[name]} |")
    lines += ["", "### Distribución por severidad", ""]
    lines.append("| Severidad | Nº |")
    lines.append("| --- | --- |")
    for level in SEVERITY_ORDER:
        lines.append(f"| {SEVERITY_LABEL[level]} | {counts.get(level, 0)} |")
    lines.append("")
    lines.append(
        "_Este reporte es una transcripción del registro durable del engagement. "
        "Distingue confirmed_finding, hypothesis e inventory; una hipótesis no está verificada._"
    )
    lines.append("")
    return "\n".join(lines)


def _render_items_section(
    title: str, items: Iterable[Any], empty_message: str
) -> list[str]:
    """Render one group of non-finding items (inventory/reference/surface/...)."""
    lines = [f"## {title}", ""]
    items = tuple(items)
    if not items:
        lines.append(empty_message)
        lines.append("")
        return lines
    for item in items:
        lines += _render_report_item(item)
    return lines


def _render_report_item(item: Any) -> list[str]:
    lines = [
        f"### {_value(item.title)}",
        "",
        f"**Tipo:** {_value(item.kind)}",
        f"**Descubierto por:** `{_value(item.discovered_by_tool)}`",
        f"**Fecha:** {_value(item.discovered_at)}",
    ]
    if item.affected_targets:
        lines.append(f"**Objetivos:** {_join(item.affected_targets)}")
    if item.mitre_techniques:
        lines.append(f"**MITRE ATT&CK:** {', '.join(item.mitre_techniques)}")
    lines.append("")
    if item.detail:
        lines += _fence(
            json.dumps(item.detail, indent=2, sort_keys=True, ensure_ascii=False),
            "json",
        )
        lines.append("")
    if item.evidence:
        lines.append("**Evidencia (chain of custody):**")
        lines.append("")
        for evidence in item.evidence:
            digest = evidence.sha256 or "sin sha256"
            lines.append(
                f"- `{evidence.kind}` {evidence.ref_id} "
                f"(sha256: `{digest}`, {evidence.created_at})"
            )
        lines.append("")
    return lines


def _join(values: Any) -> str:
    if not values:
        return "(ninguno)"
    if isinstance(values, (list, tuple)):
        return ", ".join(f"`{item}`" for item in values) or "(ninguno)"
    return f"`{values}`"


def _render_finding(finding: Finding) -> list[str]:
    lines = [
        f"### [{SEVERITY_LABEL.get(finding.severity, finding.severity.upper())}] {finding.title}",
        "",
        f"**Estado de evidencia:** {finding.verification_status}",
        f"**CVSS v3.1:** {_cvss_text(finding)}",
        f"**CVSS v4.0:** {_cvss4_text(finding)}",
        f"**MITRE ATT&CK:** {', '.join(finding.mitre_techniques) or 'n/d'}",
    ]
    if finding.cwe:
        lines.append(f"**CWE:** {finding.cwe}")
    if finding.cve:
        lines.append(f"**CVE:** {finding.cve}")
    if finding.cve_description:
        lines.append(f"**Descripción CVE:** {finding.cve_description}")
    if finding.epss_score is not None:
        lines.append(
            f"**EPSS:** {finding.epss_score:.4f} (probabilidad de explotación a 30 días)"
        )
    if finding.kev:
        lines.append("**CISA KEV:** ✓ explotado en el wild (catálogo CISA)")
    if finding.owasp_category:
        lines.append(f"**OWASP Top 10:** {finding.owasp_category}")
    lines.append(f"**Afectados:** {_join(finding.affected_targets)}")
    if finding.frameworks:
        lines.append("")
        lines.append("**Mapeo de marcos:**")
        lines.append("")
        lines.append("| Marco | ID | Nombre |")
        lines.append("| --- | --- | --- |")
        for mapping in finding.frameworks:
            lines.append(
                f"| {_escape_cell(mapping.framework)} | {_escape_cell(mapping.technique_id)} "
                f"| {_escape_cell(mapping.name)} |"
            )
    lines.append(f"**Descubierto por:** `{_value(finding.discovered_by_tool)}`")
    lines.append(f"**Fecha:** {_value(finding.discovered_at)}")
    lines.append(f"**Finding id:** `{_value(finding.finding_id)}`")
    if finding.reproductions > 1:
        lines.append(f"**Reproducciones:** {finding.reproductions}")
    lines.append("")
    lines.append("**Descripción:**")
    lines.append("")
    lines.append(finding.description or "_sin descripción_")
    lines.append("")
    lines.append("**Evidencia (chain of custody):**")
    lines.append("")
    for item in finding.evidence:
        digest = item.sha256 or "sin sha256"
        lines.append(
            f"- `{item.kind}` {item.ref_id} (sha256: `{digest}`, {item.created_at})"
        )
        if item.excerpt:
            lines.append("")
            lines += ["  " + line for line in _quote(item.excerpt)]
            lines.append("")
    lines.append("")
    lines.append("**Reproducción:**")
    lines.append("")
    for index, step in enumerate(finding.reproduction_steps, start=1):
        lines.append(f"{index}. {step}")
    lines.append("")
    return lines


def _cvss_text(finding: Finding) -> str:
    if finding.cvss_vector is None:
        score = finding.cvss_score if finding.cvss_score is not None else 0.0
        return f"{score} (informativo, sin vector)"
    score = finding.cvss_score if finding.cvss_score is not None else "n/d"
    return f"{score} (`{finding.cvss_vector}`, origen: {finding.cvss_source})"


def _cvss4_text(finding: Finding) -> str:
    if finding.cvss4_vector is None:
        if finding.cvss4_score is None:
            return "no disponible (unknown)"
        return f"{finding.cvss4_score} (sin vector)"
    score = finding.cvss4_score if finding.cvss4_score is not None else "n/d"
    return f"{score} (`{finding.cvss4_vector}`, origen: {finding.cvss4_source})"


def _max_cvss(finding: Finding) -> str:
    """Highest locally-computed CVSS value across the supported versions."""
    candidates = [
        value for value in (finding.cvss4_score, finding.cvss_score)
        if isinstance(value, (int, float))
    ]
    return f"{max(candidates):.1f}" if candidates else "n/d"


def _quote(text: str, limit: int = 800) -> list[str]:
    body = str(text or "")[:limit]
    return [f"> {line}" for line in body.splitlines() or [""]]


def render_markdown_json(report: EngagementReport) -> str:
    """Render the report as pretty-printed JSON for programmatic consumption."""
    payload = report.to_dict()
    payload["findings_by_severity"] = {
        level: payload["findings_by_severity"].get(level, 0) for level in SEVERITY_ORDER
    }
    payload["schema"] = "nexus.engagement_report/2"
    return json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def findings_table(findings: Iterable[Finding]) -> str:
    """Compact table used by the ``/findings`` REPL command."""
    ordered = sorted(findings, key=lambda item: (severity_rank(item.severity), item.title))
    lines = [
        "  SEVERITY   TITLE                                         TARGETS            TOOL",
    ]
    for finding in ordered:
        targets = ", ".join(finding.affected_targets[:2]) or "-"
        lines.append(
            f"  {finding.severity.upper():<10} {finding.title[:44]:<44} "
            f"{targets[:18]:<18} {finding.discovered_by_tool.replace('nexus.', '')}"
        )
    return "\n".join(lines)


__all__ = ["SEVERITY_LABEL", "findings_table", "render_markdown", "render_markdown_json"]
