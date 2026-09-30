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
        "- Hallazgos: "
        f"**{summary.get('critical', 0)} críticos**, "
        f"**{summary.get('high', 0)} altos**, "
        f"**{summary.get('medium', 0)} medios**, "
        f"**{summary.get('low', 0)} bajos**, "
        f"{summary.get('info', 0)} informativos "
        f"({len(report.findings)} en total)."
    )
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
    lines += ["", "### Distribución por severidad", ""]
    lines.append("| Severidad | Nº |")
    lines.append("| --- | --- |")
    for level in SEVERITY_ORDER:
        lines.append(f"| {SEVERITY_LABEL[level]} | {counts.get(level, 0)} |")
    lines.append("")
    lines.append(
        "_Este reporte es una transcripción del registro durable del engagement. "
        "No incluye ninguna conclusión que el toolkit no haya verificado._"
    )
    lines.append("")
    return "\n".join(lines)


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
        f"**CVSS:** {_cvss_text(finding)}",
        f"**MITRE ATT&CK:** {', '.join(finding.mitre_techniques) or 'n/d'}",
    ]
    if finding.cwe:
        lines.append(f"**CWE:** {finding.cwe}")
    if finding.cve:
        lines.append(f"**CVE:** {finding.cve}")
    if finding.owasp_category:
        lines.append(f"**OWASP Top 10:** {finding.owasp_category}")
    lines.append(f"**Afectados:** {_join(finding.affected_targets)}")
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
        return f"{finding.cvss_score if finding.cvss_score is not None else 0.0} (informativo, sin vector)"
    score = finding.cvss_score if finding.cvss_score is not None else "n/d"
    return f"{score} (`{finding.cvss_vector}`, origen: {finding.cvss_source})"


def _quote(text: str, limit: int = 800) -> list[str]:
    body = str(text or "")[:limit]
    return [f"> {line}" for line in body.splitlines() or [""]]


def render_markdown_json(report: EngagementReport) -> str:
    """Render the report as pretty-printed JSON for programmatic consumption."""
    payload = report.to_dict()
    payload["findings_by_severity"] = {
        level: payload["findings_by_severity"].get(level, 0) for level in SEVERITY_ORDER
    }
    payload["schema"] = "nexus.engagement_report/1"
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
