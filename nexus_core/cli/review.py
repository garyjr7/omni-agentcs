"""``/review``: validation pass over the accumulated engagement evidence.

The review is the operator's quality gate before closing an engagement. It is
deterministic and read-only by default (it never runs a tool) and answers four
questions, mirroring the validation subagent's checklist:

1. **Evidence** - how many verified facts and confirmed findings exist, by
   severity, so the operator sees what a report would actually contain.
2. **Data integrity** - does the global audit chain verify end to end? A broken
   chain invalidates every downstream deliverable.
3. **Clean-up status** - are there durable jobs still queued/running, or an
   attached session left open?
4. **Deliverables** - when asked (``--deliver``), it generates the
   executive/technical report through the governed ``nexus.report.generate``
   tool and reports the artifact digests.

Formatting the deliverables is the only action, and it happens through the
normal tool path, so it is audited and scope-checked like any other tool.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from nexus_core.cli import render

if TYPE_CHECKING:  # pragma: no cover - typing only
    from .session import OmniSession

#: Non-terminal job states: work the engagement still owes the operator.
_OPEN_JOB_STATES = ("queued", "running")
_SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")


@dataclass(frozen=True)
class ReviewReport:
    """Structured result of one ``/review`` pass."""

    engagement_id: str = ""
    engagement_name: str = ""
    facts_total: int = 0
    verified_facts: int = 0
    unverified_facts: int = 0
    counts: dict[str, int] = field(default_factory=dict)
    findings_count: int = 0
    findings_by_severity: dict[str, int] = field(default_factory=dict)
    failed_count: int = 0
    integrity_ok: bool = False
    integrity_detail: str = ""
    open_jobs: tuple[tuple[str, str], ...] = ()
    attached_session: str = ""
    deliverable: dict[str, Any] = field(default_factory=dict)
    warnings: tuple[str, ...] = ()

    @property
    def clean(self) -> bool:
        """True when the evidence is intact and nothing is left open."""
        return self.integrity_ok and not self.open_jobs and not self.attached_session


def _collect_evidence(session: "OmniSession") -> tuple[int, int, dict[str, int], int, int, dict[str, int]]:
    """Return ``(total, verified, counts, findings, failed, by_severity)``."""
    from nexus_core.kernel.blackboard import Blackboard, is_verified_fact

    facts = Blackboard(session.store).list_facts(
        session.tenant_id, str(session.engagement_id)
    )
    verified = [fact for fact in facts if is_verified_fact(fact)]
    summary = Blackboard(session.store).summary(
        session.tenant_id, str(session.engagement_id)
    )
    findings_count = 0
    failed_count = 0
    by_severity: dict[str, int] = {}
    try:
        from nexus_core.report import extractor as extractor_module

        findings, failed = extractor_module.extract_findings_sync(
            session.store, session.tenant_id, str(session.engagement_id)
        )
        findings_count = len(findings)
        failed_count = len(failed)
        for finding in findings:
            by_severity[finding.severity] = by_severity.get(finding.severity, 0) + 1
    except Exception:  # noqa: BLE001 - a review must survive an unreadable extractor
        pass
    return (
        len(facts),
        len(verified),
        dict(summary.get("counts") or {}),
        findings_count,
        failed_count,
        by_severity,
    )


def _check_integrity(session: "OmniSession") -> tuple[bool, str]:
    """Verify the global audit chain; report the first corrupt sequence."""
    from nexus_core.kernel.audit import AuditWriter

    try:
        valid, sequence = AuditWriter(session.store).verify_chain()
    except Exception as exc:  # noqa: BLE001 - an unreadable chain is not "valid"
        return False, f"{type(exc).__name__}: {exc}"
    if valid:
        return True, "cadena de auditoría válida"
    return False, f"primer evento corrupto: secuencia {sequence}"


def _open_jobs(session: "OmniSession") -> tuple[tuple[str, str], ...]:
    """Durable jobs still queued or running for this tenant."""
    try:
        with session.store.connect() as conn:
            rows = conn.execute(
                "SELECT id,status FROM kernel_tasks WHERE tenant_id=? "
                "AND status IN (?,?) ORDER BY created_at",
                (session.tenant_id, *_OPEN_JOB_STATES),
            ).fetchall()
    except Exception:  # noqa: BLE001 - a missing table is "unknown", not "open"
        return ()
    return tuple((str(row["id"]), str(row["status"])) for row in rows)


def run_review(
    session: "OmniSession",
    *,
    deliver: bool = False,
    output_format: str = "both",
    llm_cvss: bool = False,
) -> ReviewReport:
    """Collect the review; optionally generate the report deliverables."""
    engagement = session.engagement
    if engagement is None:
        return ReviewReport(warnings=("no hay engagement activo (usa /scope)",))

    total, verified, counts, findings, failed, by_severity = _collect_evidence(session)
    integrity_ok, integrity_detail = _check_integrity(session)
    open_jobs = _open_jobs(session)
    attached = str(session.active_session_uuid or "")

    warnings: list[str] = []
    if not integrity_ok:
        warnings.append("la cadena de auditoría NO verifica: los entregables no son fiables")
    if open_jobs:
        warnings.append(f"{len(open_jobs)} job(s) durable(s) sin cerrar")
    if attached:
        warnings.append(f"sesión {attached} sigue adjunta (ciérrala con /kill-session)")
    if findings == 0:
        warnings.append("sin findings confirmados: el reporte quedaría vacío")

    deliverable: dict[str, Any] = {}
    if deliver:
        from nexus_core.cli import commands as commands_module

        result = commands_module._run_report_tool(  # noqa: SLF001 - shared report helper
            session,
            {"engagement_id": session.engagement_id, "format": output_format}
            | ({"llm_cvss": True} if llm_cvss else {}),
        )
        if result is not None:
            output = result.get("output") or {}
            deliverable = {
                "directory": output.get("directory"),
                "report_sha256": output.get("report_sha256"),
                "markdown_size_bytes": output.get("markdown_size_bytes"),
                "html_size_bytes": output.get("html_size_bytes"),
            }
        else:
            warnings.append("no se pudieron generar los entregables del reporte")

    return ReviewReport(
        engagement_id=str(session.engagement_id),
        engagement_name=str(engagement.name),
        facts_total=total,
        verified_facts=verified,
        unverified_facts=total - verified,
        counts=counts,
        findings_count=findings,
        findings_by_severity=by_severity,
        failed_count=failed,
        integrity_ok=integrity_ok,
        integrity_detail=integrity_detail,
        open_jobs=open_jobs,
        attached_session=attached,
        deliverable=deliverable,
        warnings=tuple(warnings),
    )


def render_review(report: ReviewReport) -> None:
    """Print the executive summary and the technical detail of a review."""
    if not report.engagement_id:
        for warning in report.warnings:
            render.render_error(warning)
        return

    render.write(
        render.paint(
            f"REVISIÓN DEL ENGAGEMENT {report.engagement_id} — {report.engagement_name}",
            render.BOLD,
        )
    )
    verdict = "LISTO PARA CIERRE" if report.clean else "REVISAR ANTES DE CERRAR"
    color = render.GREEN if report.clean else render.YELLOW
    render.write("  veredicto: " + render.paint(verdict, color))

    render.write(render.paint("Resumen ejecutivo", render.BOLD))
    render.write(
        f"  evidencia: {report.verified_facts} hechos verificados "
        f"({report.unverified_facts} sin verificar) · "
        f"{report.findings_count} findings confirmados"
    )
    breakdown = ", ".join(
        f"{report.findings_by_severity.get(level, 0)} {level}"
        for level in _SEVERITY_ORDER
        if report.findings_by_severity.get(level)
    )
    render.write(f"  severidad: {breakdown or 'ninguna'}")
    render.write(
        "  integridad: "
        + (
            render.paint(report.integrity_detail, render.GREEN)
            if report.integrity_ok
            else render.paint(report.integrity_detail, render.RED)
        )
    )

    render.write(render.paint("Detalle técnico", render.BOLD))
    if report.counts:
        for fact_type in sorted(report.counts):
            render.write(f"  [{fact_type}] {report.counts[fact_type]}")
    else:
        render.write("  (sin hechos verificados)")
    if report.failed_count:
        render.write(f"  intentos sin hallazgo: {report.failed_count} (ver /report)")

    render.write(render.paint("Estado de limpieza", render.BOLD))
    if report.open_jobs:
        for job_id, status in report.open_jobs:
            render.write(f"  job {job_id} → {status}")
    else:
        render.write("  ✓ sin jobs durables abiertos")
    if report.attached_session:
        render.write(f"  sesión adjunta: {report.attached_session}")
    else:
        render.write("  ✓ sin sesión adjunta")

    if report.deliverable:
        render.write(render.paint("Entregables", render.BOLD))
        render.write(f"  directorio: {report.deliverable.get('directory')}")
        render.write(f"  sha256: {report.deliverable.get('report_sha256')}")
        render.write(
            f"  markdown={report.deliverable.get('markdown_size_bytes')}B "
            f"html={report.deliverable.get('html_size_bytes')}B"
        )

    for warning in report.warnings:
        render.write(render.paint(f"  ⚠ {warning}", render.YELLOW))


__all__ = ["ReviewReport", "render_review", "run_review"]
