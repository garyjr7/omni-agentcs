"""Durable ``nexus.session.pty`` tool (WP1).

The model-facing surface of :class:`~nexus_core.kernel.pty_sessions.PtySessionManager`.
It exists so an agent can do what FreeBuff does: start ``msfconsole`` once, send
``sessions -l`` on a later turn and read the answer, instead of losing the
process at the end of every tool call.

Every action is scoped to the signed engagement, executed through the sandbox
(``tmux`` argv, never ``shell=True``) and audited as ``session.pty.<action>``.
"""

from __future__ import annotations

import time
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from nexus_core.kernel.audit import AuditWriter
from nexus_core.kernel.models import RiskLevel, RunContext, ToolDefinition, ToolResult
from nexus_core.kernel.pty_sessions import PTY_MAX_LINES, PTY_MAX_NAME, PtySessionManager
from nexus_core.kernel.redaction import sanitize_text
from nexus_core.kernel.sessions import validate_session_scope
from .workspace import workspace_root

#: Audit payloads never carry more than this many characters of model input.
_AUDIT_TEXT_CHARS = 500


class PtyRequest(BaseModel):
    """Strict contract of the persistent session tool."""

    model_config = ConfigDict(strict=True, frozen=True, extra="forbid")
    action: Literal["start", "send", "capture", "wait", "kill"]
    name: str = Field(min_length=1, max_length=PTY_MAX_NAME)
    cmd: str | None = Field(default=None, max_length=8192)
    text: str | None = Field(default=None, max_length=8192)
    pattern: str | None = Field(default=None, max_length=256)
    lines: int = Field(default=200, ge=1, le=PTY_MAX_LINES)
    timeout_seconds: int = Field(default=30, ge=1, le=900)


def session_pty_definition(tenant_id: str = "system") -> ToolDefinition:
    """Return the durable definition of ``nexus.session.pty``."""
    return ToolDefinition(
        tool_id="nexus.session.pty",
        tenant_id=tenant_id,
        name="Persistent PTY session",
        description="Sesión PTY persistente (tmux): start/send/capture/wait/kill.",
        input_schema=PtyRequest.model_json_schema(),
        risk=RiskLevel.HIGH,
        effect="execution",
        scope_required=True,
        sandbox_required=True,
        timeout_seconds=900 + 60,
        required_permissions=["execute:tool:nexus.session.pty"],
    )


def _audit(
    context: RunContext,
    *,
    action: str,
    name: str,
    session_id: str,
    alive: bool,
    duration_ms: int,
    error: str | None,
    detail: dict[str, Any],
) -> None:
    if context.store is None:
        return
    payload: dict[str, Any] = {
        "action": action,
        "name": name,
        "session_id": session_id,
        "alive": alive,
        "duration_ms": duration_ms,
        "run_id": context.run_id,
        **detail,
    }
    if error:
        payload["error"] = error
    AuditWriter(context.store).append(
        tenant_id=context.tenant_id,
        trace_id=context.trace_id,
        actor_id=context.identity.subject_id,
        action=f"session.pty.{action}",
        resource_type="session",
        resource_id=session_id,
        payload=payload,
        decision="allow",
    )


async def session_pty_handler(arguments: dict[str, Any], context: RunContext) -> ToolResult:
    """Drive one persistent tmux session, governed and audited like any tool."""
    request = PtyRequest.model_validate(arguments)
    validate_session_scope(context)
    manager = PtySessionManager(workspace_root(), context.run_id)
    started = time.monotonic()

    if request.action == "start":
        if not request.cmd:
            raise ValueError("action 'start' requires cmd")
        result = await manager.start(request.cmd, request.name)
        detail = {"cmd": sanitize_text(request.cmd)[:_AUDIT_TEXT_CHARS]}
    elif request.action == "send":
        if not request.text:
            raise ValueError("action 'send' requires text")
        result = await manager.send(request.name, request.text)
        detail = {"text": sanitize_text(request.text)[:_AUDIT_TEXT_CHARS]}
    elif request.action == "capture":
        result = await manager.capture(request.name, lines=request.lines)
        detail = {"lines": request.lines}
    elif request.action == "wait":
        if not request.pattern:
            raise ValueError("action 'wait' requires pattern")
        result = await manager.wait(
            request.name, request.pattern, timeout_seconds=request.timeout_seconds
        )
        detail = {"pattern": request.pattern, "timeout_seconds": request.timeout_seconds}
    else:  # kill
        result = await manager.kill(request.name)
        detail = {}

    duration_ms = int((time.monotonic() - started) * 1000)
    _audit(
        context,
        action=request.action,
        name=request.name,
        session_id=result.session_id,
        alive=result.alive,
        duration_ms=duration_ms,
        error=result.error,
        detail=detail,
    )
    verified = result.error is None and (result.alive or request.action == "kill")
    outcome = "" if verified else ("timeout" if result.timed_out else "error")
    return ToolResult(
        output={
            "action": request.action,
            **result.as_dict(),
            "duration_ms": duration_ms,
            "lines": len((result.output or "").splitlines()),
        },
        verified=verified,
        outcome=outcome,
        verification_method=f"pty_{request.action}",
        evidence={
            "action": request.action,
            "session_id": result.session_id,
            "alive": result.alive,
            "duration_ms": duration_ms,
        },
        exit_code=result.exit_code,
        stdout=(result.output or "")[:65536],
        stderr="",
        timed_out=result.timed_out,
    )


__all__ = ["PtyRequest", "session_pty_definition", "session_pty_handler"]
