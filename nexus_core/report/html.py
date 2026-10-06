"""Self-contained HTML renderer (embedded CSS, no JavaScript, no CDN).

The document is meant to be opened offline and printed to PDF: a single file, no
external requests, sober palette, print-friendly rules and a footer carrying the
report digest so a printed copy can be tied back to the durable record.
"""

from __future__ import annotations

import json
from html import escape
from typing import Any, Iterable

from .markdown import SEVERITY_LABEL
from .mitre import technique_name, technique_tactic, techniques_for_tool
from .frameworks import FRAMEWORKS
from .models import SEVERITY_ORDER, EngagementReport, FailedAttempt, Finding, severity_rank

BRAND = "Bajioware · OmniAgentCS"

CSS = """
:root {
  --bg: #ffffff; --fg: #14181f; --muted: #5b6472; --line: #d8dee7;
  --card: #f7f9fc; --mono: ui-monospace, "SFMono-Regular", Menlo, Consolas, monospace;
  --critical: #8b1a1a; --high: #b4451f; --medium: #9a6b00;
  --low: #2f6b57; --info: #46536b;
}
* { box-sizing: border-box; }
body { margin: 0; padding: 2rem 1.25rem 4rem; background: var(--bg); color: var(--fg);
  font: 15px/1.6 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; }
main { max-width: 60rem; margin: 0 auto; }
header { border-bottom: 3px solid var(--fg); padding-bottom: 1rem; margin-bottom: 1.5rem; }
header .brand { font-size: .78rem; letter-spacing: .18em; text-transform: uppercase; color: var(--muted); }
h1 { font-size: 1.6rem; margin: .4rem 0 .6rem; }
h2 { font-size: 1.2rem; margin: 2.2rem 0 .6rem; padding-bottom: .3rem; border-bottom: 1px solid var(--line); }
h3 { font-size: 1rem; margin: 1.4rem 0 .4rem; }
a { color: inherit; }
code, pre, .mono { font-family: var(--mono); font-size: .85em; }
dl.meta { display: grid; grid-template-columns: 10rem 1fr; gap: .25rem .75rem; margin: 0; }
dl.meta dt { color: var(--muted); }
dl.meta dd { margin: 0; word-break: break-word; }
table { width: 100%; border-collapse: collapse; margin: .6rem 0 1rem; font-size: .9rem; }
th, td { text-align: left; padding: .4rem .5rem; border-bottom: 1px solid var(--line); vertical-align: top; }
th { color: var(--muted); font-weight: 600; }
.cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(7.5rem, 1fr)); gap: .6rem; margin: 1rem 0; }
.card { background: var(--card); border: 1px solid var(--line); border-radius: .5rem; padding: .6rem .75rem; }
.card .n { font-size: 1.5rem; font-weight: 700; }
.card .l { font-size: .74rem; letter-spacing: .08em; text-transform: uppercase; color: var(--muted); }
.sev { display: inline-block; padding: .1rem .5rem; border-radius: .35rem; color: #fff;
  font-size: .72rem; letter-spacing: .08em; font-weight: 700; }
.sev-critical { background: var(--critical); }
.sev-high { background: var(--high); }
.sev-medium { background: var(--medium); }
.sev-low { background: var(--low); }
.sev-info { background: var(--info); }
.item { border: 1px solid var(--line); border-left: 5px solid var(--info); border-radius: .4rem;
  padding: .7rem .9rem; margin: .8rem 0; }
.item.inventory { border-left-color: var(--low); }
.item.reference { border-left-color: #2b6cb0; }
.item.surface { border-left-color: var(--medium); }
.item.evidence { border-left-color: var(--muted); }
.item h4 { margin: .1rem 0 .4rem; }
.item .kind { font-size: .72rem; letter-spacing: .08em; text-transform: uppercase; color: var(--muted); }
.finding { border: 1px solid var(--line); border-left: 5px solid var(--info); border-radius: .4rem;
  padding: .8rem 1rem; margin: 1rem 0; }
.finding.critical { border-left-color: var(--critical); }
.finding.high { border-left-color: var(--high); }
.finding.medium { border-left-color: var(--medium); }
.finding.low { border-left-color: var(--low); }
.finding > .head { display: flex; gap: .6rem; align-items: baseline; flex-wrap: wrap; }
.finding h3 { margin: 0; flex: 1 1 auto; }
dl.props { display: grid; grid-template-columns: 9rem 1fr; gap: .15rem .75rem; margin: .6rem 0; font-size: .88rem; }
dl.props dt { color: var(--muted); }
dl.props dd { margin: 0; word-break: break-word; }
pre { background: var(--card); border: 1px solid var(--line); border-radius: .35rem;
  padding: .6rem .75rem; overflow-x: auto; white-space: pre-wrap; }
details { border: 1px solid var(--line); border-radius: .4rem; padding: .4rem .7rem; margin: .6rem 0; }
details > summary { cursor: pointer; color: var(--muted); font-size: .85rem; }
footer { margin-top: 3rem; padding-top: 1rem; border-top: 1px solid var(--line);
  color: var(--muted); font-size: .8rem; word-break: break-all; }
@media (max-width: 34rem) {
  body { padding: 1rem .75rem 3rem; }
  dl.meta, dl.props { grid-template-columns: 1fr; }
  dl.meta dt, dl.props dt { margin-top: .4rem; }
}
@media print {
  body { padding: 0; font-size: 11pt; }
  details { break-inside: avoid; }
  details[open] > summary { display: none; }
  .finding { break-inside: avoid; }
}
"""


def _sev_class(severity: Any) -> str:
    level = str(severity or "info").lower()
    return level if level in SEVERITY_ORDER else "info"


def _e(value: Any) -> str:
    return escape(str(value if value is not None else ""), quote=True)


def _list(values: Iterable[Any]) -> str:
    items = [f"<code>{_e(item)}</code>" for item in values or ()]
    return ", ".join(items) if items else "<span class='mono'>—</span>"


def render_html(report: EngagementReport) -> str:
    """Render the report as one self-contained HTML document."""
    counts = report.findings_by_severity
    parts: list[str] = [
        "<!DOCTYPE html>",
        '<html lang="es">',
        "<head>",
        '<meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        f"<title>Reporte de pentesting — {_e(report.engagement_name)}</title>",
        f"<style>{CSS}</style>",
        "</head>",
        "<body>",
        "<main>",
        "<header>",
        f'<div class="brand">{_e(BRAND)}</div>',
        f"<h1>Reporte de Pentesting — {_e(report.engagement_name)}</h1>",
        '<dl class="meta">',
        f"<dt>Cliente</dt><dd>{_e(report.client)}</dd>",
        f"<dt>Operador</dt><dd>{_e(report.operator)}</dd>",
        f"<dt>Engagement</dt><dd><code>{_e(report.engagement_id)}</code></dd>",
        f"<dt>Período</dt><dd>{_e(report.started_at)} — {_e(report.ended_at)}</dd>",
        f"<dt>Generado</dt><dd>{_e(report.generated_at)}</dd>",
        "</dl>",
        "</header>",
    ]

    parts += ["<section id='resumen'><h2>Resumen ejecutivo</h2>", '<div class="cards">']
    for level in SEVERITY_ORDER:
        parts.append(
            f'<div class="card"><div class="n">{counts.get(level, 0)}</div>'
            f'<div class="l">{SEVERITY_LABEL[level]}</div></div>'
        )
    parts.append("</div>")
    parts += [
        "<ul>",
        f"<li>Hallazgos verificados: <strong>{len(report.findings)}</strong>.</li>",
        f"<li>Intentos sin hallazgo: {len(report.failed_attempts)}.</li>",
        f"<li>Sesiones abiertas: {report.sessions_opened}.</li>",
        f"<li>Eventos de auditoría considerados: {report.audit_events_total}.</li>",
        f"<li>Cadena de auditoría: "
        f"{'✓ válida' if report.audit_chain_valid else '✗ <strong>NO VERIFICADA</strong>'}.</li>",
    ]
    if report.notes:
        parts.append(f"<li>{_e(report.notes)}</li>")
    parts += ["</ul>"]
    priorities = [
        item for item in report.findings if item.severity in {"critical", "high"}
    ]
    if priorities:
        parts.append("<h3>Hallazgos prioritarios</h3><ul>")
        for finding in sorted(
            priorities, key=lambda item: (severity_rank(item.severity), item.title)
        ):
            flags = []
            if finding.kev:
                flags.append("<strong>explotado en el wild (CISA KEV)</strong>")
            if finding.epss_score is not None:
                flags.append(f"EPSS {finding.epss_score:.2f}")
            suffix = f" — {', '.join(flags)}" if flags else ""
            parts.append(
                f"<li><strong>{_e(finding.severity.upper())}</strong> "
                f"{_e(finding.title)} (CVSS máx. {_e(_max_cvss(finding))}){suffix}</li>"
            )
        parts.append("</ul>")
    parts += ["</section>"]

    scope = report.scope_full or {}
    parts += [
        "<section id='alcance'><h2>Alcance</h2>",
        f"<p>Resumen: {_e(report.scope_summary)}.</p>",
        '<dl class="props">',
        f"<dt>CIDRs</dt><dd>{_list(scope.get('cidrs'))}</dd>",
        f"<dt>Dominios</dt><dd>{_list(scope.get('domains'))}</dd>",
        f"<dt>URLs</dt><dd>{_list(scope.get('urls'))}</dd>",
        f"<dt>Exclusiones</dt><dd>{_list(scope.get('exclusions'))}</dd>",
        f"<dt>Autorización</dt><dd>{_e(scope.get('valid_from'))} — {_e(scope.get('valid_until'))}</dd>",
        "</dl>",
    ]
    if report.run_ids:
        parts.append(f"<p>Runs: {_list(report.run_ids)}</p>")
    parts.append("</section>")

    parts += ["<section id='metodologia'><h2>Metodología</h2>"]
    if report.tools_used:
        parts.append(
            "<p>Todas las herramientas se ejecutaron a través del gateway durable "
            "(política, scope, aprobación humana cuando aplica y auditoría).</p><ul>"
        )
        for tool_id in report.tools_used:
            parts.append(f"<li><code>{_e(tool_id)}</code></li>")
        parts.append("</ul>")
    else:
        parts.append("<p>No se registró ninguna ejecución de herramientas.</p>")
    parts.append("</section>")

    parts += ["<section id='hallazgos'><h2>Hallazgos</h2>"]
    if not report.findings:
        parts.append("<p>No se registraron hallazgos verificados en el audit trail.</p>")
    for finding in report.findings:
        parts.append(_render_finding(finding))
    parts.append("</section>")

    parts += ["<section id='intentos'><h2>Intentos fallidos</h2>"]
    if not report.failed_attempts:
        parts.append("<p>No hubo intentos fallidos ni denegaciones registradas.</p>")
    else:
        parts += ["<table><thead><tr><th>Fecha</th><th>Tool</th><th>Objetivo</th><th>Motivo</th></tr></thead><tbody>"]
        for attempt in report.failed_attempts:
            parts.append(_render_attempt_row(attempt))
        parts += ["</tbody></table>"]
    parts.append("</section>")

    parts += _render_items_section(
        "inventario",
        "Inventario",
        report.inventories,
        "No se registró inventario (endpoints, stack) para este engagement.",
    )
    parts += _render_items_section(
        "referencias",
        "Referencias",
        report.references,
        "No se registraron referencias (Exploit-DB, AD) para este engagement.",
    )
    parts += _render_items_section(
        "superficie",
        "Superficie expuesta",
        report.surfaces,
        "No se registró superficie adicional para este engagement.",
    )
    parts += _render_items_section(
        "evidencia",
        "Evidencia adicional",
        report.evidences,
        "No se registró evidencia adicional para este engagement.",
    )

    parts += ["<section id='cronologia'><h2>Cronología</h2>"]
    if not report.timeline:
        parts.append("<p>Sin eventos de auditoría para este engagement.</p>")
    else:
        parts.append(
            "<details><summary>Mostrar la cronología completa "
            f"({len(report.timeline)} eventos)</summary>"
            "<table><thead><tr><th>Fecha</th><th>Acción</th><th>Tool</th>"
            "<th>Objetivo</th><th>Decisión</th><th>Detalle</th></tr></thead><tbody>"
        )
        for entry in report.timeline:
            parts.append(
                "<tr>"
                f"<td><code>{_e(entry.occurred_at)}</code></td>"
                f"<td>{_e(entry.action)}</td>"
                f"<td><code>{_e(entry.tool_id)}</code></td>"
                f"<td>{_e(entry.target)}</td>"
                f"<td>{_e(entry.decision)}</td>"
                f"<td>{_e(entry.detail)}</td>"
                "</tr>"
            )
        parts.append("</tbody></table></details>")
    parts.append("</section>")

    parts += ["<section id='anexos'><h2>Anexos</h2>"]
    parts += ["<h3>Catálogo de herramientas usadas</h3>"]
    parts.append("<table><thead><tr><th>Tool</th><th>Técnicas ATT&CK declaradas</th></tr></thead><tbody>")
    for tool_id in report.tools_used:
        mapped = ", ".join(techniques_for_tool(tool_id)) or "—"
        parts.append(f"<tr><td><code>{_e(tool_id)}</code></td><td>{_e(mapped)}</td></tr>")
    parts += ["</tbody></table>"]

    observed = sorted({item for finding in report.findings for item in finding.mitre_techniques})
    parts += ["<h3>Cobertura MITRE ATT&CK observada</h3>"]
    if not observed:
        parts.append("<p>Ninguna técnica ATT&CK atribuible a los hallazgos.</p>")
    else:
        parts.append("<table><thead><tr><th>Técnica</th><th>Nombre</th><th>Táctica</th></tr></thead><tbody>")
        for technique_id in observed:
            parts.append(
                "<tr>"
                f"<td><code>{_e(technique_id)}</code></td>"
                f"<td>{_e(technique_name(technique_id))}</td>"
                f"<td>{_e(technique_tactic(technique_id))}</td>"
                "</tr>"
            )
        parts += ["</tbody></table>"]
    coverage: dict[str, int] = {}
    for finding in report.findings:
        for mapping in finding.frameworks:
            coverage[mapping.framework] = coverage.get(mapping.framework, 0) + 1
    parts.append("<h3>Cobertura de marcos</h3>")
    if not coverage:
        parts.append("<p>Ningún hallazgo mapeó a un marco de referencia.</p>")
    else:
        parts.append("<table><thead><tr><th>Marco</th><th>Hallazgos</th></tr></thead><tbody>")
        for name in FRAMEWORKS:
            if name in coverage:
                parts.append(f"<tr><td>{_e(name)}</td><td>{coverage[name]}</td></tr>")
        parts += ["</tbody></table>"]
    parts.append("</section>")

    parts += [
        "<footer>",
        f"<div>{_e(BRAND)} · reporte generado desde el registro durable del engagement</div>",
        f"<div>SHA-256 (canónico): <code>{_e(report.report_sha256)}</code></div>",
        f"<div>Generado: {_e(report.generated_at)} · engagement "
        f"<code>{_e(report.engagement_id)}</code></div>",
        "</footer>",
        "</main>",
        "</body>",
        "</html>",
        "",
    ]
    return "\n".join(parts)


def _render_items_section(
    anchor: str, title: str, items: Iterable[Any], empty_message: str
) -> list[str]:
    """Render one group of non-finding items with a per-kind left border."""
    items = tuple(items)
    parts = [f"<section id='{anchor}'><h2>{_e(title)}</h2>"]
    if not items:
        parts.append(f"<p>{_e(empty_message)}</p>")
    for item in items:
        parts.append(_render_item(item))
    parts.append("</section>")
    return parts


def _render_item(item: Any) -> str:
    kind = str(item.kind or "info")
    parts = [
        f'<article class="item {_e(kind)}">',
        f'<div class="kind">{_e(kind)}</div>',
        f"<h4>{_e(item.title)}</h4>",
        '<dl class="props">',
        f"<dt>Descubierto por</dt><dd><code>{_e(item.discovered_by_tool)}</code></dd>",
        f"<dt>Fecha</dt><dd>{_e(item.discovered_at)}</dd>",
    ]
    if item.affected_targets:
        parts.append(f"<dt>Objetivos</dt><dd>{_list(item.affected_targets)}</dd>")
    if item.mitre_techniques:
        parts.append(f"<dt>MITRE ATT&CK</dt><dd>{_list(item.mitre_techniques)}</dd>")
    parts.append("</dl>")
    if item.detail:
        parts.append(
            f"<pre>{_e(json.dumps(item.detail, indent=2, sort_keys=True, ensure_ascii=False))}</pre>"
        )
    if item.evidence:
        parts.append("<details><summary>Evidencia (chain of custody)</summary><ul>")
        for evidence in item.evidence:
            digest = evidence.sha256 or "sin sha256"
            parts.append(
                f"<li><code>{_e(evidence.kind)}</code> {_e(evidence.ref_id)} "
                f"(sha256: <code>{_e(digest)}</code>, {_e(evidence.created_at)})</li>"
            )
        parts.append("</ul></details>")
    parts.append("</article>")
    return "".join(parts)


def _max_cvss(finding: Finding) -> str:
    candidates = [
        value for value in (finding.cvss4_score, finding.cvss_score)
        if isinstance(value, (int, float))
    ]
    return f"{max(candidates):.1f}" if candidates else "n/d"


def _render_finding(finding: Finding) -> str:
    level = _sev_class(finding.severity)
    cvss31 = f"{_e(finding.cvss_score if finding.cvss_score is not None else 0.0)}"
    cvss31 += (
        f" <code>{_e(finding.cvss_vector)}</code> ({_e(finding.cvss_source)})"
        if finding.cvss_vector else " (informativo)"
    )
    cvss40 = (
        f"{_e(finding.cvss4_score if finding.cvss4_score is not None else 0.0)}"
        + f" <code>{_e(finding.cvss4_vector)}</code> ({_e(finding.cvss4_source)})"
        if finding.cvss4_vector
        else "no disponible (unknown)"
    )
    parts = [
        f'<article class="finding {level}" id="{_e(finding.finding_id)}">',
        '<div class="head">',
        f'<span class="sev sev-{level}">{SEVERITY_LABEL.get(level, level.upper())}</span>',
        f"<h3>{_e(finding.title)}</h3>",
        "</div>",
        '<dl class="props">',
        f"<dt>CVSS v3.1</dt><dd>{cvss31}</dd>",
        f"<dt>CVSS v4.0</dt><dd>{cvss40}</dd>",
        f"<dt>MITRE ATT&CK</dt><dd>{_list(finding.mitre_techniques)}</dd>",
    ]
    if finding.cwe:
        parts.append(f"<dt>CWE</dt><dd>{_e(finding.cwe)}</dd>")
    if finding.cve:
        parts.append(f"<dt>CVE</dt><dd>{_e(finding.cve)}</dd>")
    if finding.cve_description:
        parts.append(f"<dt>Descripción CVE</dt><dd>{_e(finding.cve_description)}</dd>")
    if finding.epss_score is not None:
        parts.append(
            f"<dt>EPSS</dt><dd>{finding.epss_score:.4f} "
            "(probabilidad de explotación)</dd>"
        )
    if finding.kev:
        parts.append("<dt>CISA KEV</dt><dd>✓ explotado en el wild</dd>")
    if finding.owasp_category:
        parts.append(f"<dt>OWASP Top 10</dt><dd>{_e(finding.owasp_category)}</dd>")
    parts += [
        f"<dt>Afectados</dt><dd>{_list(finding.affected_targets)}</dd>",
        f"<dt>Descubierto por</dt><dd><code>{_e(finding.discovered_by_tool)}</code></dd>",
        f"<dt>Fecha</dt><dd>{_e(finding.discovered_at)}</dd>",
        f"<dt>Finding id</dt><dd><code>{_e(finding.finding_id)}</code></dd>",
    ]
    if finding.reproductions > 1:
        parts.append(f"<dt>Reproducciones</dt><dd>{finding.reproductions}</dd>")
    parts += ["</dl>"]
    if finding.frameworks:
        parts.append("<h4>Mapeo de marcos</h4>")
        parts.append(
            "<table><thead><tr><th>Marco</th><th>ID</th><th>Nombre</th></tr></thead><tbody>"
        )
        for mapping in finding.frameworks:
            parts.append(
                f"<tr><td>{_e(mapping.framework)}</td>"
                f"<td><code>{_e(mapping.technique_id)}</code></td>"
                f"<td>{_e(mapping.name)}</td></tr>"
            )
        parts.append("</tbody></table>")
    parts.append(f"<p>{_e(finding.description)}</p>")
    steps = "".join(f"<li>{_e(step)}</li>" for step in finding.reproduction_steps)
    if steps:
        parts.append(f"<h4>Reproducción</h4><ol>{steps}</ol>")
    parts.append("<details><summary>Evidencia (chain of custody)</summary>")
    parts.append("<ul>")
    for item in finding.evidence:
        digest = item.sha256 or "sin sha256"
        parts.append(
            f"<li><code>{_e(item.kind)}</code> {_e(item.ref_id)} "
            f"(sha256: <code>{_e(digest)}</code>, {_e(item.created_at)})"
        )
        if item.excerpt:
            parts.append(f"<pre>{_e(item.excerpt[:1500])}</pre>")
        parts.append("</li>")
    parts.append("</ul></details>")
    parts.append("</article>")
    return "".join(parts)


def _render_attempt_row(attempt: FailedAttempt) -> str:
    return (
        "<tr>"
        f"<td><code>{_e(attempt.attempted_at)}</code></td>"
        f"<td><code>{_e(attempt.tool_id)}</code></td>"
        f"<td>{_e(attempt.target)}</td>"
        f"<td>{_e(attempt.reason)}</td>"
        "</tr>"
    )


__all__ = ["BRAND", "CSS", "render_html"]
