"""Policy-enforced tool invocation shared by every gateway."""

from __future__ import annotations

import asyncio
import inspect
import json
import os
import time
from typing import Any, Awaitable, Callable, Dict

from .approvals import ApprovalService
from .audit import AuditWriter
from .models import Resource, RunContext, ToolDefinition, ToolResult
from .policy import PolicyEngine
from .schema_validation import validate
from .telemetry import metrics, telemetry

ToolHandler = Callable[[Dict[str, Any], RunContext], ToolResult | Awaitable[ToolResult]]


class ToolGateway:
    def __init__(
        self,
        policy: PolicyEngine,
        audit: AuditWriter,
        approvals: ApprovalService | None = None,
        scope_validator: Callable[[RunContext, ToolDefinition, Dict[str, Any]], None]
        | None = None,
    ):
        self.policy = policy
        self.audit = audit
        self.approvals = approvals
        self.scope_validator = scope_validator
        self._definitions: Dict[str, ToolDefinition] = {}
        self._handlers: Dict[str, ToolHandler] = {}

    def register(self, definition: ToolDefinition, handler: ToolHandler) -> None:
        if definition.tool_id in self._definitions:
            raise ValueError(f"tool already registered: {definition.tool_id}")
        if os.getenv("NEXUS_ENV", "development").lower() == "production" and not inspect.iscoroutinefunction(handler):
            raise TypeError("production tool handlers must be async and sandbox-backed")
        self._definitions[definition.tool_id] = definition
        self._handlers[definition.tool_id] = handler

    async def invoke(
        self,
        tool_id: str,
        arguments: Dict[str, Any],
        context: RunContext,
        permissions: tuple[str, ...] = (),
        approval_id: str | None = None,
    ) -> Any:
        with telemetry.span("nexus.tool.invoke", {
            "nexus.tenant.id": context.tenant_id,
            "nexus.run.id": context.run_id,
            "nexus.trace.id": context.trace_id,
            "nexus.tool.id": tool_id,
        }):
            definition = self._definitions.get(tool_id)
            if not definition or not definition.enabled:
                raise KeyError("tool is unavailable")
            validate(arguments, definition.input_schema or {"type": "object"})
            if definition.scope_required or definition.scope_target_field:
                if context.scope is None:
                    if definition.scope_required:
                        self.audit.append(
                            tenant_id=context.tenant_id,
                            trace_id=context.trace_id,
                            actor_id=context.identity.subject_id,
                            action="scope.denied",
                            resource_type="tool",
                            resource_id=tool_id,
                            payload={"reason": "no_scope"},
                            decision="deny",
                        )
                        raise PermissionError("scope is required but not provided")
                elif self.scope_validator is not None:
                    try:
                        self.scope_validator(context, definition, arguments)
                    except Exception as exc:
                        self.audit.append(
                            tenant_id=context.tenant_id,
                            trace_id=context.trace_id,
                            actor_id=context.identity.subject_id,
                            action="scope.denied",
                            resource_type="tool",
                            resource_id=tool_id,
                            payload={
                                "target_keys": [definition.scope_target_field],
                                "reason": str(exc)[:500],
                            },
                            decision="deny",
                        )
                        raise
            decision = self.policy.decide(
                context.identity,
                "execute:tool",
                Resource(tool_id, definition.tenant_id, "tool"),
                permissions,
                definition,
            )
            self.audit.append(
                tenant_id=context.tenant_id,
                trace_id=context.trace_id,
                actor_id=context.identity.subject_id,
                action="tool.invoke",
                resource_type="tool",
                resource_id=tool_id,
                payload={"argument_keys": sorted(arguments)},
                decision="allow" if decision.allowed else "deny",
            )
            if not decision.allowed:
                raise PermissionError(decision.reason)
            action = f"execute:tool:{tool_id}"
            if decision.requires_approval:
                if not self.approvals or not approval_id:
                    raise PermissionError("durable human approval is required")
                if not self.approvals.verify(approval_id, context, action):
                    raise PermissionError("approval does not authorize this tool invocation")

            store = self.audit.store
            store.record_usage(
                context.tenant_id, context.run_id, "tool", tool_id, "calls", 1,
                {"trace_id": context.trace_id},
            )
            handler = self._handlers[tool_id]
            started = time.monotonic()
            try:
                if inspect.iscoroutinefunction(handler):
                    result = await asyncio.wait_for(
                        handler(arguments, context), timeout=definition.timeout_seconds
                    )
                else:
                    result = handler(arguments, context)
                if not isinstance(result, ToolResult):
                    raise TypeError("tool handlers must return ToolResult with deterministic evidence")
                if not result.success:
                    raise RuntimeError(
                        "tool post-condition was not verified "
                        f"(method={result.verification_method})"
                    )
                result_value = result.to_dict()
                encoded = json.dumps(result_value, default=str).encode("utf-8")
                if len(encoded) > definition.max_output_bytes:
                    raise ValueError("tool output exceeds configured limit")
                self.audit.append(
                    tenant_id=context.tenant_id, trace_id=context.trace_id,
                    actor_id=context.identity.subject_id, action="tool.complete",
                    resource_type="tool", resource_id=tool_id,
                    payload={"duration_ms": round((time.monotonic() - started) * 1000, 3),
                             "output_bytes": len(encoded), "run_id": context.run_id},
                    decision="allow",
                )
                metrics.increment(
                    "nexus_tool_calls_total", tool_id=tool_id, status="success",
                    tenant_id=context.tenant_id,
                )
                metrics.increment(
                    "nexus_tool_duration_ms_total",
                    (time.monotonic() - started) * 1000,
                    tool_id=tool_id, tenant_id=context.tenant_id,
                )
                return result_value
            except Exception as exc:
                self.audit.append(
                    tenant_id=context.tenant_id, trace_id=context.trace_id,
                    actor_id=context.identity.subject_id, action="tool.failed",
                    resource_type="tool", resource_id=tool_id,
                    payload={"error_type": type(exc).__name__, "run_id": context.run_id},
                    decision="error",
                )
                metrics.increment(
                    "nexus_tool_calls_total", tool_id=tool_id, status="error",
                    tenant_id=context.tenant_id,
                )
                raise
