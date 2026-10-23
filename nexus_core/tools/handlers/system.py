"""Durable ``nexus.system.status`` tool (moved out of the runtime)."""

from __future__ import annotations

from nexus_core.kernel.models import RiskLevel, RunContext, ToolDefinition, ToolResult
from nexus_core.kernel.workspace_hygiene import spoiler_report


def system_status_definition(tenant_id: str = "system") -> ToolDefinition:
    """Return the durable ToolDefinition for ``nexus.system.status``."""
    return ToolDefinition(
        tool_id="nexus.system.status",
        effect="read_only",
        name="System status",
        tenant_id=tenant_id,
        input_schema={"type": "object", "additionalProperties": False},
        risk=RiskLevel.READ_ONLY,
        required_permissions=["execute:tool"],
    )


async def system_status_handler(arguments: dict, context: RunContext) -> ToolResult:
    """Report control-plane health and queued work for the caller's tenant."""
    with context.store.connect() as conn:
        queued = conn.execute(
            "SELECT COUNT(*) AS value FROM kernel_tasks"
            " WHERE tenant_id=? AND status='queued'",
            (context.tenant_id,),
        ).fetchone()["value"]
    # F3: a workspace that already holds the walkthrough cannot produce a run
    # that proves discovery. The operator asks here; nothing is blocked or moved
    # (and the model is never told which files they are).
    isolation = spoiler_report(getattr(context, "project_root", "") or None)
    output = {
        "status": "healthy",
        "queued_tasks": queued,
        "worker_id": context.worker_id,
        **isolation,
    }
    return ToolResult(
        output=output,
        verified=True,
        verification_method="control_store_query",
        evidence={"queued_tasks": queued, "worker_id": context.worker_id},
    )
