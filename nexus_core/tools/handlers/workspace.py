"""Durable ``nexus.workspace.search`` tool (moved out of the runtime)."""

from __future__ import annotations

import os

from nexus_core.kernel.models import RiskLevel, RunContext, ToolDefinition, ToolResult
from nexus_core.kernel.sandbox import sandbox_for_environment


def workspace_search_definition(tenant_id: str = "system") -> ToolDefinition:
    """Return the durable ToolDefinition for ``nexus.workspace.search``."""
    return ToolDefinition(
        tool_id="nexus.workspace.search",
        name="Workspace search",
        tenant_id=tenant_id,
        input_schema={
            "type": "object",
            "properties": {"query": {"type": "string"}},
            "required": ["query"],
            "additionalProperties": False,
        },
        risk=RiskLevel.READ_ONLY,
        required_permissions=["execute:tool"],
    )


async def workspace_search_handler(arguments: dict, context: RunContext) -> ToolResult:
    """Search the workspace through the sandbox and report verified matches."""
    query = str(arguments["query"])
    sandbox = sandbox_for_environment(os.getenv("NEXUS_WORKSPACE_ROOT", os.getcwd()))
    result = await sandbox.run(["rg", "-n", "--max-count", "100", "--", query, "."],
                               timeout_seconds=20)
    return ToolResult(
        output={"matches": result.stdout},
        verified=result.exit_code in {0, 1} and not result.timed_out,
        verification_method="sandbox_exit_code",
        evidence={"query": query, "exit_code": result.exit_code,
                  "timed_out": result.timed_out},
        exit_code=result.exit_code,
        accepted_exit_codes=(0, 1),  # rg uses 1 for a verified empty result
        stdout=result.stdout,
        stderr=result.stderr,
        timed_out=result.timed_out,
    )
