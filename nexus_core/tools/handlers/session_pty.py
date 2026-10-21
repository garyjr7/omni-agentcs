"""Durable ``nexus.session.pty`` tool (WP1).

The model-facing surface of :class:`~nexus_core.kernel.pty_sessions.PtySessionManager`.
It exists so an agent can do what FreeBuff does: start ``msfconsole`` once, send
``sessions -l`` on a later turn and read the answer, instead of losing the
process at the end of every tool call.

Every action is scoped to the signed engagement, executed through the sandbox
(``tmux`` argv, never ``shell=True``) and audited as ``session.pty.<action>``.

P0 (2026-10-21)
---------------
A PTY is a command channel, so it carries the same obligations as
``nexus.shell.exec``: a persistent sandbox is required, a command that waits or
reaches an out-of-scope host is refused, the full capture goes to the artifact
CAS and only a bounded summary reaches the prompt, and known vault secrets are
redacted before either. Without these, enabling PTY would have opened a side
door around egress and the token budget.
"""

from __future__ import annotations

import hashlib
import re
import time
from contextlib import suppress
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from nexus_core.kernel.artifacts import configured_artifact_store
from nexus_core.kernel.audit import AuditWriter
from nexus_core.kernel.fact_verification import FLAG_RE
from nexus_core.kernel.models import RiskLevel, RunContext, ToolDefinition, ToolResult
from nexus_core.kernel.pty_sessions import (
    PTY_MAX_LINES,
    PTY_MAX_NAME,
    PTY_MAX_WAIT_SECONDS,
    PTY_SESSION_TTL_SECONDS,
    PtySessionManager,
)
from nexus_core.kernel.redaction import (
    redact_secret_values,
    sanitize_text,
    secrets_for_redaction,
)
from nexus_core.kernel.sandbox import OCISandbox
from nexus_core.kernel.sessions import validate_session_scope
from nexus_core.tools.passive_wait import PASSIVE_WAIT_GUIDANCE, passive_wait_reason
from .report_generate import default_artifact_root
from .workspace import workspace_root

#: Audit payloads never carry more than this many characters of model input.
_AUDIT_TEXT_CHARS = 500
#: Lines of pane scrollback returned to the model; the rest lives in the artifact.
PTY_SUMMARY_LINES = 20
_ROOT_IDENTITY = re.compile(r"uid=0\(root\) gid=\d+")
_NO_EVIDENCE = "unverified_observation"


class PtyRequest(BaseModel):
    """Strict contract of the persistent session tool."""

    model_config = ConfigDict(strict=True, frozen=True, extra="forbid")
    action: Literal["start", "send", "capture", "wait", "kill"]
    name: str = Field(min_length=1, max_length=PTY_MAX_NAME)
    cmd: str | None = Field(default=None, max_length=8192)
    text: str | None = Field(default=None, max_length=8192)
    pattern: str | None = Field(default=None, max_length=256)
    lines: int = Field(default=200, ge=1, le=PTY_MAX_LINES)
    #: A wait is a bounded observation, never a way to park the run. The schema
    #: rejects a longer request before it reaches the handler; the manager clamps
    #: it again for defense in depth.
    timeout_seconds: int = Field(default=30, ge=1, le=PTY_MAX_WAIT_SECONDS)


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
        timeout_seconds=PTY_MAX_WAIT_SECONDS + 60,
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


def command_denial(context: RunContext, text: str) -> dict[str, str] | None:
    """Refuse a PTY command with the same lexical rules as the local shell.

    ``send`` types into a live shell, so a ``sleep`` is the same non-action and a
    ``curl`` is the same egress attempt as in ``nexus.shell.exec``. The checks run
    before ``tmux send-keys``: nothing reaches the pane when the command is
    refused.
    """
    wait_reason = passive_wait_reason(text)
    if wait_reason is not None:
        return {
            "kind": "passive_wait",
            "reason": wait_reason,
            "method": "pty_passive_wait_denied",
            "outcome": "denied",
            "guidance": PASSIVE_WAIT_GUIDANCE,
        }
    # Imported lazily: the shell module owns the deny list and the fetch-target
    # parser, and duplicating either here would let the two channels drift.
    from .shell_exec_local import (
        SHELL_SCOPE_DENIED_GUIDANCE,
        out_of_scope_fetch_target,
        prohibited_reason,
    )

    rule = prohibited_reason(text)
    if rule is not None:
        return {
            "kind": "deny_list",
            "reason": rule,
            "method": "pty_command_denied",
            "outcome": "denied",
            "guidance": (
                "Reformula sin privilegios locales ni operaciones destructivas; "
                "el comando no se ha enviado al PTY."
            ),
        }
    violation = out_of_scope_fetch_target(text, context.scope)
    if violation is not None:
        return {
            "kind": "scope",
            "reason": f"ScopeViolation({violation.target}): {violation.reason}",
            "method": "pty_scope_denied",
            "outcome": "scope_denied",
            "guidance": SHELL_SCOPE_DENIED_GUIDANCE.format(target=violation.target),
        }
    return None


def _denied_result(
    context: RunContext,
    *,
    request: PtyRequest,
    manager: PtySessionManager,
    text: str,
    started: float,
    denial: dict[str, str],
) -> ToolResult:
    session_id = manager.session_id(request.name)
    duration_ms = int((time.monotonic() - started) * 1000)
    _audit(
        context,
        action=request.action,
        name=request.name,
        session_id=session_id,
        alive=False,
        duration_ms=duration_ms,
        error=denial["reason"],
        detail={denial["kind"]: denial["reason"]},
    )
    return ToolResult(
        output={
            "action": request.action,
            "error": "command refused before reaching the PTY",
            "reason": denial["reason"],
            "command": text,
            "guidance": denial["guidance"],
        },
        verified=False,
        outcome=denial["outcome"],
        verification_method=denial["method"],
        evidence={
            "session_id": session_id,
            denial["kind"]: denial["reason"],
            "duration_ms": duration_ms,
        },
    )


def _has_evidence(text: str) -> bool:
    return bool(FLAG_RE.search(text) or _ROOT_IDENTITY.search(text))


def _capture_summary(text: str) -> str:
    """Last lines plus every flag/root line, bounded for the prompt.

    The full capture is in the artifact; this is the compact observation. Evidence
    lines are surfaced even when they are older than the tail, otherwise a flag
    printed 200 lines above the prompt would be invisible and the model would keep
    searching.
    """
    lines = text.splitlines()
    # A pane is a screen, not a log: after the useful line it is usually blank.
    # Dropping the trailing blanks is what keeps the summary from being twenty
    # empty rows while the answer sits just above them.
    while lines and not lines[-1].strip():
        lines.pop()
    evidence = [
        line for line in lines if FLAG_RE.search(line) or _ROOT_IDENTITY.search(line)
    ]
    tail = lines[-PTY_SUMMARY_LINES:]
    parts: list[str] = []
    if evidence:
        unique_evidence = list(dict.fromkeys(evidence))
        parts.append("[evidence]\n" + "\n".join(unique_evidence))
    if tail:
        parts.append("[tail]\n" + "\n".join(tail))
    omitted = max(0, len(lines) - len(tail))
    if omitted:
        parts.append(f"… ({omitted} lines omitted; see artifact) …")
    return "\n".join(parts).strip()


def _observation_result(
    context: RunContext,
    request: PtyRequest,
    result: Any,
    *,
    started: float,
) -> ToolResult:
    """Redact, archive and summarize a capture before it reaches the model."""
    secrets = secrets_for_redaction(context, request.model_dump())
    redacted = redact_secret_values(result.output or "", secrets)
    artifact = None
    if context.store is not None and redacted:
        artifact = configured_artifact_store(
            context.store, default_artifact_root()
        ).put(
            context.tenant_id,
            redacted.encode("utf-8"),
            "text/plain; charset=utf-8",
            run_id=context.run_id,
            metadata={
                "engagement_id": context.engagement_id,
                "kind": "pty-capture",
                "session_id": result.session_id,
                "action": request.action,
            },
        )
    summary = _capture_summary(redacted)
    digest = hashlib.sha256(redacted.encode("utf-8")).hexdigest()
    duration_ms = int((time.monotonic() - started) * 1000)
    payload: dict[str, Any] = {
        "action": request.action,
        **result.as_dict(),
        "output": summary,
        "capture_chars": len(redacted),
        "capture_lines": len(redacted.splitlines()),
        "sha256": digest,
        "artifact": artifact,
        "artifact_ref": artifact.get("id") if artifact else None,
    }
    if not _has_evidence(redacted):
        # Not a failure: the channel worked and produced an observation, but no
        # flag/root line was found, so the verifier must not invent a fact.
        payload["observation_status"] = _NO_EVIDENCE
    verified = result.error is None and (result.alive or request.action == "kill")
    outcome = "" if verified else ("timeout" if result.timed_out else "error")
    _audit(
        context,
        action=request.action,
        name=request.name,
        session_id=result.session_id,
        alive=bool(result.alive),
        duration_ms=duration_ms,
        error=result.error,
        detail={
            "lines": payload["capture_lines"],
            "artifact_ref": payload["artifact_ref"],
            "sha256": digest,
        },
    )
    return ToolResult(
        output=payload,
        verified=verified,
        outcome=outcome,
        verification_method=f"pty_{request.action}",
        evidence={
            "action": request.action,
            "session_id": result.session_id,
            "alive": result.alive,
            "duration_ms": duration_ms,
            "artifact_ref": payload["artifact_ref"],
            "sha256": digest,
        },
        exit_code=result.exit_code,
        stdout=summary,
        stderr="",
        timed_out=result.timed_out,
    )


async def session_pty_handler(arguments: dict[str, Any], context: RunContext) -> ToolResult:
    """Drive one persistent tmux session, governed and audited like any tool."""
    request = PtyRequest.model_validate(arguments)
    validate_session_scope(context)
    manager = PtySessionManager(workspace_root(), context.run_id)
    started = time.monotonic()

    if isinstance(manager.sandbox(), OCISandbox):
        # An OCI call is an ephemeral container: the tmux server dies when the
        # call returns, so a PTY cannot be persistent. Fail explicitly instead of
        # reporting ``session_exited_immediately`` (the measured symptom).
        session_id = manager.session_id(request.name)
        _audit(
            context,
            action=request.action,
            name=request.name,
            session_id=session_id,
            alive=False,
            duration_ms=0,
            error="pty_requires_persistent_sandbox",
            detail={},
        )
        return ToolResult(
            output={
                "error": "PTY requires a persistent sandbox",
                "reason": "pty_requires_persistent_sandbox",
                "action": request.action,
                "session_id": session_id,
            },
            verified=False,
            outcome="unavailable",
            verification_method="pty_requires_persistent_sandbox",
        )

    command_text = ""
    if request.action == "start":
        if not request.cmd:
            raise ValueError("action 'start' requires cmd")
        command_text = request.cmd
    elif request.action == "send":
        if not request.text:
            raise ValueError("action 'send' requires text")
        command_text = request.text

    if command_text:
        denial = command_denial(context, command_text)
        if denial is not None:
            return _denied_result(
                context,
                request=request,
                manager=manager,
                text=command_text,
                started=started,
                denial=denial,
            )

    if request.action == "start":
        # TTL: a session created by a run that died without firing ``session_end``
        # must not live forever. The reaper only touches this run's prefix.
        with suppress(Exception):
            await manager.reap(older_than_seconds=PTY_SESSION_TTL_SECONDS)
        result = await manager.start(request.cmd or "", request.name)
        detail = {"cmd": sanitize_text(request.cmd or "")[:_AUDIT_TEXT_CHARS]}
    elif request.action == "send":
        result = await manager.send(request.name, request.text or "")
        detail = {"text": sanitize_text(request.text or "")[:_AUDIT_TEXT_CHARS]}
    elif request.action == "capture":
        result = await manager.capture(request.name, lines=request.lines)
        return _observation_result(context, request, result, started=started)
    elif request.action == "wait":
        if not request.pattern:
            raise ValueError("action 'wait' requires pattern")
        result = await manager.wait(
            request.name,
            request.pattern,
            timeout_seconds=request.timeout_seconds,
        )
        return _observation_result(context, request, result, started=started)
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


__all__ = [
    "PTY_SUMMARY_LINES",
    "PtyRequest",
    "session_pty_definition",
    "session_pty_handler",
]
