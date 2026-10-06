"""The only bridge between an MCP server and our governance.

An MCP tool becomes a **durable tool**, registered with ``replace=False`` so it
can never shadow a builtin. That is the whole trick: because the ReAct loop only
ever reaches a tool through ``execute_tool`` → ``ToolGateway``, an MCP tool
inherits policy, the signed scope boundary, durable approvals, the sandbox and
the audit chain for free. There is no side door, and this module is what makes
sure there is not: it never calls ``session.call_tool`` outside a handler that
the gateway invoked.

Three things the SDK cannot do for us, done here:

* **Allowlist at call time.** A tool is registered only when the config lists it,
  and the handler re-checks the allowlist on every call, so a config reload cannot
  widen a live session. A denial is audited as ``mcp.tool_denied``.
* **Descriptions are untrusted too.** An MCP server authors its own tool
  descriptions, and those land in the *system prompt* via the tool catalog. They
  are therefore neutralized and labelled, not pasted in raw — an injection there
  would be far more dangerous than one in an observation.
* **Timeouts are audited.** A wedged server fails closed and is recorded as
  ``mcp.timeout`` so the operator can see the engagement was not silently skipped.
"""

from __future__ import annotations

from typing import Any, Callable

from nexus_core.agent.injection import neutralize_delimiters
from nexus_core.kernel.audit import AuditWriter
from nexus_core.kernel.models import RiskLevel, RunContext, ToolDefinition, ToolResult
from nexus_core.tools import registration

from .client import (
    MCPError,
    MCPTimeout,
    MCPServerConfig,
    MCPTool,
)

#: Prefix that marks every MCP-sourced durable tool; used to re-sync the catalog.
TOOL_ID_PREFIX = "mcp."
#: Description text is clipped: a server can send a megabyte of prose.
MAX_DESCRIPTION_CHARS = 400
#: Hard cap on the text we hand back as an observation.
MAX_OUTPUT_CHARS = 200_000
#: Human-readable label prefixed to every server-authored description.
UNTRUSTED_LABEL = "[mcp · no confiable]"


def sanitize_description(value: Any) -> str:
    """Neutralize delimiters in an MCP-authored description and label it.

    Descriptions reach the system prompt through the tool catalog, so a hostile
    server could try to smuggle instructions there. Flattening whitespace also
    stops a "description" that is really a fake multi-turn transcript.
    """
    text = " ".join(str(value or "").split())
    if not text:
        return UNTRUSTED_LABEL
    cleaned = neutralize_delimiters(text)[:MAX_DESCRIPTION_CHARS]
    return f"{UNTRUSTED_LABEL} {cleaned}"


def _audit(
    context: RunContext,
    *,
    action: str,
    tool_id: str,
    decision: str,
    payload: dict[str, Any] | None = None,
) -> None:
    """Best-effort audit entry from inside a tool handler (never raises)."""
    store = getattr(context, "store", None)
    if store is None:
        return
    try:
        AuditWriter(store).append(
            tenant_id=context.tenant_id,
            trace_id=context.trace_id,
            actor_id=context.identity.subject_id,
            action=action,
            resource_type="tool",
            resource_id=tool_id,
            payload=dict(payload or {}),
            decision=decision,
        )
    except Exception:  # noqa: BLE001 - audit failure must not mask the real error
        return


def make_definition_factory(
    config: MCPServerConfig, tool: MCPTool
) -> Callable[[str], ToolDefinition]:
    """Build the per-tenant definition factory for one MCP tool."""

    def factory(tenant_id: str) -> ToolDefinition:
        # A tool the operator listed under ``requires_approval`` is HIGH, which is
        # exactly what makes PolicyEngine demand durable human approval. Everything
        # else is MEDIUM: an MCP server is a supply-chain boundary, so nothing it
        # exposes is READ_ONLY by default.
        risk = RiskLevel.HIGH if config.needs_approval(tool.name) else RiskLevel.MEDIUM
        return ToolDefinition(
            name=tool.tool_id,
            tenant_id=tenant_id,
            input_schema=tool.input_schema or {"type": "object"},
            tool_id=tool.tool_id,
            description=sanitize_description(tool.description or tool.title),
            risk=risk,
            # The gateway budget must exceed the MCP call timeout, otherwise the
            # gateway kills the call before the server can time out cleanly.
            timeout_seconds=int(config.call_timeout) + 5,
        )

    return factory


def make_handler(
    registry: Any, config: MCPServerConfig, tool: MCPTool
) -> registration.Handler:
    """Build the async handler the gateway will invoke for this MCP tool."""
    tool_id = tool.tool_id

    async def handler(arguments: dict[str, Any], context: RunContext) -> ToolResult:
        current = registry.server(config.name)
        # Defence in depth: the tool was registered because it was allowed, but
        # re-check so a config change cannot widen a live session.
        if current is None or not current.allows(tool.name):
            _audit(
                context,
                action="mcp.tool_denied",
                tool_id=tool_id,
                decision="deny",
                payload={"server": config.name, "tool": tool.name, "reason": "not_allowlisted"},
            )
            raise PermissionError(
                f"mcp_tool_denied: '{tool.name}' no está en allowed_tools de '{config.name}'"
            )
        try:
            async with registry.client(config.name) as client:
                result = await client.call_tool(tool.name, arguments or {})
        except MCPTimeout as exc:
            _audit(
                context,
                action="mcp.timeout",
                tool_id=tool_id,
                decision="deny",
                payload={
                    "server": config.name,
                    "tool": tool.name,
                    "timeout": config.call_timeout,
                    "detail": str(exc)[:200],
                },
            )
            raise
        except MCPError as exc:
            _audit(
                context,
                action="mcp.unavailable",
                tool_id=tool_id,
                decision="error",
                payload={"server": config.name, "tool": tool.name, "error": type(exc).__name__},
            )
            raise
        text = result.text
        truncated = len(text) > MAX_OUTPUT_CHARS
        return ToolResult(
            output={
                "text": text[:MAX_OUTPUT_CHARS],
                "truncated": truncated,
                "server": config.name,
                "tool": tool.name,
            },
            # Deterministic post-condition: the server answered. An explicit
            # ``is_error`` result is a failure, never a success with a sad message.
            verified=not result.is_error,
            verification_method="mcp_response_received",
            evidence={
                "server": config.name,
                "tool": tool.name,
                "is_error": bool(result.is_error),
                "chars": len(text),
            },
            stdout=text[:MAX_OUTPUT_CHARS],
        )

    return handler


def sync_registry(registry: Any, discovered: dict[str, list[MCPTool]]) -> list[str]:
    """Register every *allowed* discovered MCP tool; return the tool ids.

    Tools from a previous sync that are no longer allowlisted are unregistered
    first, so a down server or a removed allowlist entry cannot linger in the
    catalog. ``replace=False`` guarantees an MCP tool never shadows a builtin.
    """
    for tool_id in [
        tool_id
        for tool_id in registration.registered_tools()
        if tool_id.startswith(TOOL_ID_PREFIX)
    ]:
        registration.unregister(tool_id)
    registered: list[str] = []
    for server_name, tools in (discovered or {}).items():
        config = registry.server(server_name)
        if config is None:
            continue
        for tool in tools:
            if not config.allows(tool.name):
                continue
            registration.register(
                tool.tool_id,
                make_definition_factory(config, tool),
                make_handler(registry, config, tool),
                source="mcp",
                replace=False,
            )
            registered.append(tool.tool_id)
    return registered


async def sync_from_config(registry: Any) -> list[str]:
    """Discover every allowlisted server, then register its allowed tools."""
    discovered = await registry.discover_all()
    return sync_registry(registry, discovered)


__all__ = [
    "MAX_DESCRIPTION_CHARS",
    "MAX_OUTPUT_CHARS",
    "TOOL_ID_PREFIX",
    "UNTRUSTED_LABEL",
    "make_definition_factory",
    "make_handler",
    "sanitize_description",
    "sync_from_config",
    "sync_registry",
]
