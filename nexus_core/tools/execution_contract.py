"""Invocation-local capture evidence for builtin handlers; no global mutable log."""

from __future__ import annotations

from contextvars import ContextVar
from dataclasses import asdict, replace
from functools import wraps
from typing import Any

from nexus_core.kernel.models import RunContext, ToolDefinition, ToolResult
from nexus_core.kernel.sandbox import SandboxResult
from nexus_core.tools.registration import Handler

_captures: ContextVar[list[dict[str, Any]] | None] = ContextVar("tool_captures", default=None)


def record_capture(result: SandboxResult, *, source: str = "process") -> None:
    """Record metadata only, never argv, output text or credentials."""
    captures = _captures.get()
    if captures is None:
        return
    streams = {}
    for name in ("stdout", "stderr"):
        manifest = getattr(result, f"{name}_manifest", None)
        streams[name] = asdict(manifest) if manifest is not None else None
    captures.append(
        {
            "source": source,
            "exit_code": result.exit_code,
            "timed_out": result.timed_out,
            "cancelled": result.cancelled,
            **streams,
        }
    )


def validate_target(value: object) -> str:
    """Reject argv-option and control-character injection without resolving DNS."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError("target must be a nonempty string")
    target = value.strip()
    if target.startswith("-") or any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ValueError("target contains an option or control character")
    if any(char.isspace() for char in target):
        raise ValueError("target must be a single token")
    return target


def with_execution_contract(definition: ToolDefinition, handler: Handler) -> Handler:
    """Keep the historical envelope, adding per-execution raw manifests.

    The gateway owns schema validation, authorization and scope. This layer
    additionally rejects target transport ambiguity before dispatch.
    Context tokens are reset on failures/cancellation and isolate concurrent calls.
    """

    @wraps(handler)
    async def invoke(arguments: dict[str, Any], context: RunContext) -> ToolResult:
        field = definition.scope_target_field
        if field and field in arguments:
            value = arguments[field]
            for target in value if isinstance(value, list) else [value]:
                validate_target(target)
        captures: list[dict[str, Any]] = []
        token = _captures.set(captures)
        try:
            result = await handler(arguments, context)
        except OSError as exc:
            result = ToolResult(
                verification_method="tool_execution_unavailable",
                evidence={"error_type": type(exc).__name__},
                outcome="unavailable",
            )
        finally:
            _captures.reset(token)
        if captures:
            incomplete = any(
                item["timed_out"]
                or item["cancelled"]
                or any(
                    stream is not None
                    and (stream["truncated"] or not stream["complete"] or stream["error"])
                    for stream in (item["stdout"], item["stderr"])
                )
                for item in captures
            )
            evidence = {
                **result.evidence,
                "execution_capture": {
                    "schema_version": 1,
                    "executions": captures,
                    "incomplete": incomplete,
                },
            }
            result = replace(
                result,
                evidence=evidence,
                verified=result.verified and not incomplete,
                outcome="" if incomplete else result.outcome,
            )
        result.to_dto()
        return result

    return invoke
