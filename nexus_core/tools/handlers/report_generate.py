"""``nexus.report.generate``: turn the durable record into the client report.

Read-only with respect to the engagement: the handler reads the audit trail, the
persisted ToolResults and the artifact metadata, renders Markdown + HTML + JSON,
registers each deliverable as a content-addressed artifact and audits
``report.generated``. It never contacts a target, so it does not need a scope and
never executes a shell.

CVSS resolution is fail-safe: an explicit value wins, an LLM-suggested vector is
scored locally, and anything else falls back to the deterministic heuristic — so
the report is produced with or without a model provider.
"""

from __future__ import annotations

import asyncio
import re
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from nexus_core.kernel.artifacts import LocalArtifactStore
from nexus_core.kernel.audit import AuditWriter
from nexus_core.kernel.models import RiskLevel, RunContext, ToolDefinition, ToolResult
from nexus_core.kernel.schema_validation import validate
from nexus_core.report.extractor import attach_cvss, build_report
from nexus_core.report.html import render_html
from nexus_core.report.markdown import render_markdown, render_markdown_json

REPORT_AUDIT_ACTION = "report.generated"
FORMATS = ("markdown", "html", "both")
#: Per-finding budget for the optional LLM CVSS pass.
CVSS_LLM_TIMEOUT_SECONDS = 60
_ENGAGEMENT_PATTERN = r"[A-Za-z0-9._:-]{1,128}"


def report_generate_definition(tenant_id: str = "system") -> ToolDefinition:
    return ToolDefinition(
        tool_id="nexus.report.generate",
        name="Generate engagement report",
        tenant_id=tenant_id,
        description=(
            "Genera el reporte de pentesting del engagement actual desde el audit "
            "trail. Incluye findings con CVSS, MITRE ATT&CK y evidencia con chain "
            "of custody. Devuelve Markdown + HTML."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "engagement_id": {
                    "type": "string",
                    "pattern": "^" + _ENGAGEMENT_PATTERN + "$",
                    "minLength": 1,
                    "maxLength": 128,
                },
                "format": {"type": "string", "enum": list(FORMATS)},
                "include_failed_attempts": {"type": "boolean"},
                "output_dir": {"type": "string", "maxLength": 4096},
                "llm_cvss": {"type": "boolean"},
            },
            "required": ["engagement_id"],
            "additionalProperties": False,
        },
        risk=RiskLevel.READ_ONLY,
        effect="report",
        required_permissions=["execute:tool:nexus.report.generate"],
        timeout_seconds=180,
        max_output_bytes=50_000_000,
        scope_target_field=None,
        scope_required=False,
    )


def default_report_root() -> Path:
    """``$XDG_DATA_HOME/omni/reports`` (the operator-visible deliverable dir)."""
    from nexus_core.config.xdg import resolve_xdg_paths

    return resolve_xdg_paths().data_dir / "reports"


def default_artifact_root() -> Path:
    """``$XDG_DATA_HOME/omni/artifacts`` (content-addressed evidence store)."""
    from nexus_core.config.xdg import resolve_xdg_paths

    return resolve_xdg_paths().data_dir / "artifacts"


def report_directory(engagement_name: str, root: Path | None = None) -> Path:
    """Return a fresh, collision-free directory for one report generation."""
    base = Path(root) if root else default_report_root()
    slug = re.sub(r"[^A-Za-z0-9._-]+", "-", str(engagement_name or "engagement")).strip("-")
    slug = slug or "engagement"
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    candidate = base / f"{slug}-{stamp}"
    counter = 1
    while candidate.exists():
        candidate = base / f"{slug}-{stamp}-{counter}"
        counter += 1
    return candidate


def _threaded_llm(llm_client: Any) -> Callable[[str], str | None]:
    """Adapt an async LLM client into the sync callable the scorer expects.

    The model call runs in its own thread with its own event loop, so the handler
    can keep reusing :func:`nexus_core.report.extractor.attach_cvss`. Every
    failure (timeout, provider error, missing key) returns ``None`` and the
    finding keeps the deterministic heuristic score.
    """
    from nexus_core.llm.abstraction import LLMMessage

    def ask(prompt: str) -> str | None:
        async def _call() -> str:
            response = await llm_client.complete([LLMMessage(role="user", content=prompt)])
            return str(getattr(response, "content", "") or "")

        try:
            with ThreadPoolExecutor(max_workers=1) as pool:
                return pool.submit(lambda: asyncio.run(_call())).result(
                    timeout=CVSS_LLM_TIMEOUT_SECONDS
                )
        except Exception:  # noqa: BLE001 - CVSS is best-effort by contract
            return None

    return ask


def _select_llm() -> Any:
    try:
        from nexus_core.kernel.runtime import select_llm_client

        return select_llm_client()
    except Exception:  # noqa: BLE001 - no provider is a normal situation
        return None


async def report_generate_handler(arguments: dict, context: RunContext) -> ToolResult:
    validate(arguments, report_generate_definition().input_schema)
    engagement_id = str(arguments["engagement_id"])
    output_format = str(arguments.get("format") or "both")
    include_failed = bool(arguments.get("include_failed_attempts", True))
    requested_dir = arguments.get("output_dir")
    llm_cvss = bool(arguments.get("llm_cvss", False))
    store = context.store
    if store is None:
        return ToolResult(verification_method="report_store_missing")

    try:
        report = await build_report(
            store,
            context.tenant_id,
            engagement_id,
            include_failed_attempts=include_failed,
        )
    except KeyError:
        return ToolResult(
            output={"status": "unknown_engagement", "engagement_id": engagement_id},
            verification_method="report_unknown_engagement",
            evidence={"engagement_id": engagement_id},
        )

    if llm_cvss:
        client = _select_llm()
        if client is not None:
            scored = attach_cvss(report.findings, _threaded_llm(client))
            from dataclasses import replace

            report = replace(report, findings=scored)
            # The digest covers the findings, so it must be recomputed.
            from nexus_core.report.models import with_digest

            report = with_digest(report)

    markdown_text = render_markdown(report)
    html_text = render_html(report)
    json_text = render_markdown_json(report)

    directory = Path(requested_dir).expanduser() if requested_dir else report_directory(
        report.engagement_name
    )
    files: dict[str, Path] = {}
    artifacts: list[dict[str, Any]] = []
    try:
        directory.mkdir(parents=True, exist_ok=True)
        payloads: list[tuple[str, str, str]] = [
            ("report.json", json_text, "application/json"),
        ]
        if output_format in {"markdown", "both"}:
            payloads.append(("report.md", markdown_text, "text/markdown"))
        if output_format in {"html", "both"}:
            payloads.append(("report.html", html_text, "text/html"))
        artifact_store = LocalArtifactStore(store, default_artifact_root())
        for name, text, media_type in payloads:
            target = directory / name
            target.write_text(text, encoding="utf-8")
            files[name] = target
            recorded = artifact_store.put(
                context.tenant_id,
                text.encode("utf-8"),
                media_type,
                run_id=context.run_id or None,
                metadata={"engagement_id": engagement_id, "kind": "engagement_report"},
            )
            artifacts.append({"name": name, "path": str(target), **recorded})
    except OSError as exc:
        return ToolResult(
            output={"status": "write_failed", "error": type(exc).__name__},
            verification_method="report_write_failed",
            evidence={"engagement_id": engagement_id, "directory": str(directory)},
        )

    counts = report.findings_by_severity
    AuditWriter(store).append(
        tenant_id=context.tenant_id,
        trace_id=context.trace_id,
        actor_id=context.identity.subject_id,
        action=REPORT_AUDIT_ACTION,
        resource_type="engagement",
        resource_id=engagement_id,
        payload={
            "format": output_format,
            "include_failed_attempts": include_failed,
            "llm_cvss": llm_cvss,
            "findings_count": len(report.findings),
            "severity_breakdown": counts,
            "audit_events_used": report.audit_events_total,
            "audit_chain_valid": report.audit_chain_valid,
            "report_sha256": report.report_sha256,
            "directory": str(directory),
            "run_id": context.run_id,
        },
        decision="allow",
    )

    return ToolResult(
        output={
            "engagement_id": engagement_id,
            "report_path_md": str(files.get("report.md", "")),
            "report_path_html": str(files.get("report.html", "")),
            "report_path_json": str(files.get("report.json", "")),
            "directory": str(directory),
            "findings_count": len(report.findings),
            "severity_breakdown": counts,
            "failed_attempts": len(report.failed_attempts),
            "sessions_opened": report.sessions_opened,
            "tools_used": list(report.tools_used),
            "report_sha256": report.report_sha256,
            "json_size_bytes": len(json_text.encode("utf-8")),
            "markdown_size_bytes": len(markdown_text.encode("utf-8")),
            "html_size_bytes": len(html_text.encode("utf-8")),
        },
        # The post-condition is that the deliverables were produced from the
        # durable record and written to disk. Whether the trail itself still
        # verifies is a property of the source data, reported in evidence and
        # stamped into both renderings ("NO VERIFICADA"): a broken chain must
        # never suppress the report, it must be made visible in it.
        verified=True,
        verification_method="report_generated_from_audit",
        evidence={
            "engagement_id": engagement_id,
            "audit_events_used": report.audit_events_total,
            "audit_chain_valid": report.audit_chain_valid,
            "findings": len(report.findings),
            "sessions": report.sessions_opened,
            "report_sha256": report.report_sha256,
            "artifacts": [item["id"] for item in artifacts],
            "artifact_sha256": {item["name"]: item["sha256"] for item in artifacts},
            "files": {name: str(path) for name, path in files.items()},
            "llm_cvss": llm_cvss,
        },
    )


__all__ = [
    "CVSS_LLM_TIMEOUT_SECONDS",
    "FORMATS",
    "REPORT_AUDIT_ACTION",
    "default_artifact_root",
    "default_report_root",
    "report_directory",
    "report_generate_definition",
    "report_generate_handler",
]
