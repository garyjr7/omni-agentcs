"""Universal local shell (WP1): ``nexus.shell.exec``.

The measured problem
--------------------
OMNI had 68 rigid tools and no way to run ``jadx``, ``john``, ``git-dumper``,
a Python script or ``tmux``: the kill chain stopped exactly where FreeBuff
keeps going. This handler is the execution substrate that closes that gap.

What it guarantees (and what it does not)
-----------------------------------------
* **Every process goes through :func:`sandbox_for_environment`** - never
  ``shell=True`` and never a raw ``create_subprocess_exec``. The child is
  ``bash -lc <command>`` *inside* the governed sandbox, so workspace
  confinement, the ephemeral HOME and process-group cleanup still apply.
* **Everything is audited** with an explicit ``shell.exec`` event carrying the
  command, cwd, exit code, duration and bytes. The writer redacts named
  credential fields, so a ``password=...`` in the command does not become
  plaintext audit data.
* **The full output is an artifact** (sha256 included); the model only reads a
  bounded summary of ``<= 60`` lines plus the artifact reference. This is the
  token-budget contract of the plan: observations never paste 10 MB back.
* **A lexical deny list** (``NEXUS_SHELL_DENY`` can extend it) blocks the
  obviously destructive local commands. It is a guard-rail, not a security
  boundary: an arbitrary argv cannot be validated against the engagement
  scope, which is the documented trade-off of WP1. The compensating controls
  are the signed engagement, the confined workspace and the audit chain.
"""

from __future__ import annotations

import asyncio
import os
import re
import time
from contextlib import suppress
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from nexus_core.kernel.artifacts import configured_artifact_store
from nexus_core.kernel.audit import AuditWriter
from nexus_core.kernel.fact_verification import sshpass_channels
from nexus_core.kernel.models import RiskLevel, RunContext, ToolDefinition, ToolResult
from nexus_core.kernel.sandbox import OCISandbox, sandbox_for_environment
from nexus_core.kernel.sessions import validate_session_scope
from ._exec import run_in_sandbox
from .report_generate import default_artifact_root
from .workspace import workspace_root

#: Programs the sandbox is allowed to start. ``bash``/``sh`` are the only
#: entry points: everything the command itself launches is its own argv.
SHELL_ALLOWED_PROGRAMS: tuple[str, ...] = ("bash", "sh")

#: Hard caps from the plan (WP1): 10 MB of output, 900 s, 64 KiB of stdin.
SHELL_MAX_OUTPUT_BYTES = 10_000_000
SHELL_MAX_STDIN_BYTES = 65_536
SHELL_MIN_TIMEOUT_SECONDS = 5
SHELL_MAX_TIMEOUT_SECONDS = 900

#: The model never receives more than this many lines of an observation.
SHELL_SUMMARY_LINES = 60

#: Local guard-rail patterns; ``NEXUS_SHELL_DENY`` can only add more.
_DENY_PATTERNS: tuple[re.Pattern[str], ...] = tuple(
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        # Local privilege changes are not part of a remote engagement and the
        # sandbox has no password channel (the plan's "sin sudo" mitigation).
        r"(?:^|[;&|]\s*)(?:sudo|doas)\b",
        r"(?:^|[;&|]\s*)su\s",
        # Recursive deletion of the workspace root or the host root.
        r"\brm\s+(?:-[A-Za-z]*[rf][A-Za-z]*\s+)+(?:/|/\*|~|\$HOME)(?:\s|$|;)",
        r"\bfind\s+/(?:\s|$).*-delete\b",
        # Raw device writes and filesystem formatting.
        r"\bmkfs(?:\.\w+)?\b",
        r"\bdd\b[^\n;|]*\bof=/dev/(?:sd|nvme|vd|hd)",
        r">\s*/dev/(?:sd|nvme|vd|hd)",
        # Host power management.
        r"(?:^|[;&|]\s*)(?:shutdown|reboot|poweroff|halt)\b",
        # Classic fork bomb.
        r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:",
        # Blanket permissions on the host root.
        r"\bchmod\s+-R\s+777\s+/(?:\s|$|;)",
    )
)


class ShellExecRequest(BaseModel):
    """Strict contract of the universal shell."""

    model_config = ConfigDict(strict=True, frozen=True, extra="forbid")
    command: str = Field(min_length=1, max_length=8192)
    cwd: str = Field(default=".", max_length=4096)
    timeout_seconds: int = Field(
        default=60,
        ge=SHELL_MIN_TIMEOUT_SECONDS,
        le=SHELL_MAX_TIMEOUT_SECONDS,
    )
    stdin: str | None = Field(default=None, max_length=SHELL_MAX_STDIN_BYTES)


def shell_exec_definition(tenant_id: str = "system") -> ToolDefinition:
    """Return the durable definition of ``nexus.shell.exec``."""
    return ToolDefinition(
        tool_id="nexus.shell.exec",
        tenant_id=tenant_id,
        name="Universal shell",
        description="Ejecuta comandos shell en el sandbox y archiva la salida.",
        input_schema=ShellExecRequest.model_json_schema(),
        risk=RiskLevel.HIGH,
        effect="execution",
        scope_required=True,
        sandbox_required=True,
        timeout_seconds=SHELL_MAX_TIMEOUT_SECONDS + 60,
        max_output_bytes=SHELL_MAX_OUTPUT_BYTES,
        required_permissions=["execute:tool:nexus.shell.exec"],
    )


def prohibited_reason(command: str) -> str | None:
    """Return the deny-list rule a command matches, or ``None``.

    ``NEXUS_SHELL_DENY`` appends operator rules separated by ``;;`` so a regex
    can contain ``|`` without ambiguity. Additional rules can only *widen* the
    guard-rail, never remove a built-in one.
    """
    extra = os.getenv("NEXUS_SHELL_DENY", "")
    patterns = list(_DENY_PATTERNS)
    for raw in extra.split(";;"):
        text = raw.strip()
        if not text:
            continue
        with suppress(re.error):
            patterns.append(re.compile(text, re.IGNORECASE))
    for pattern in patterns:
        if pattern.search(command):
            return pattern.pattern
    return None


def resolve_cwd(root: str | Path, cwd: str) -> tuple[str, str]:
    """Resolve the model's relative ``cwd`` inside the workspace.

    Returns ``(absolute, relative)``; the relative form is what the sandbox
    receives and what the audit records. ``..``, absolute paths, symlinks that
    escape and non-directories are refused.
    """
    root_path = Path(root).resolve()
    text = str(cwd or ".").strip() or "."
    candidate = Path(text)
    if candidate.is_absolute():
        raise ValueError("cwd must be relative to the engagement workspace")
    resolved = (root_path / candidate).resolve()
    if resolved != root_path and root_path not in resolved.parents:
        raise ValueError("cwd escapes the engagement workspace")
    if not resolved.is_dir():
        raise ValueError("cwd is not a directory in the engagement workspace")
    return str(resolved), str(resolved.relative_to(root_path))


def summarize(stdout: str, stderr: str, *, limit: int = SHELL_SUMMARY_LINES) -> str:
    """Return at most ``limit`` lines of output (head + tail when truncated)."""
    text = stdout
    if stderr:
        text = f"{stdout}\n[stderr]\n{stderr}" if stdout else f"[stderr]\n{stderr}"
    lines = text.splitlines()
    if len(lines) <= limit:
        return "\n".join(lines)
    head = (limit + 1) // 2
    tail = limit - head
    omitted = len(lines) - limit
    return "\n".join(
        [*lines[:head], f"… ({omitted} lines omitted; see artifact) …", *lines[-tail:]]
    )


def _combined_output(
    command: str, stdout: str, stderr: str, exit_code: int | None, timed_out: bool
) -> bytes:
    """Build the artifact payload: the full, unabridged stdout+stderr."""
    parts = [f"$ {command}\n", stdout]
    if stderr:
        parts.extend(("\n[stderr]\n", stderr))
    parts.append(f"\n[exit={exit_code} timed_out={timed_out}]\n")
    data = "".join(parts).encode("utf-8", errors="replace")
    if len(data) > SHELL_MAX_OUTPUT_BYTES:
        data = data[:SHELL_MAX_OUTPUT_BYTES] + b"\n[artifact truncated at 10 MB]\n"
    return data


#: One in-flight shell command per run. The plan's limit is one concurrent
#: process per session; this serializes the handler inside a process (the
#: durable job/task layer already serializes across workers).
_RUN_LOCKS: dict[str, asyncio.Lock] = {}


def _run_lock(run_id: str) -> asyncio.Lock:
    lock = _RUN_LOCKS.get(run_id)
    if lock is None:
        lock = _RUN_LOCKS.setdefault(run_id, asyncio.Lock())
    return lock


def _audit(
    context: RunContext,
    *,
    command: str,
    cwd: str,
    exit_code: int | None,
    duration_ms: int,
    bytes_written: int,
    timed_out: bool,
    decision: str = "allow",
    reason: str | None = None,
) -> None:
    """Append the mandatory ``shell.exec`` audit event (best effort on no store)."""
    if context.store is None:
        return
    payload: dict[str, Any] = {
        "command": command,
        "cwd": cwd,
        "exit_code": exit_code,
        "duration_ms": duration_ms,
        "bytes": bytes_written,
        "timed_out": timed_out,
        "run_id": context.run_id,
    }
    if reason:
        payload["reason"] = reason
    AuditWriter(context.store).append(
        tenant_id=context.tenant_id,
        trace_id=context.trace_id,
        actor_id=context.identity.subject_id,
        action="shell.exec",
        resource_type="process",
        resource_id=context.run_id,
        payload=payload,
        decision=decision,
    )


async def shell_exec_handler(arguments: dict[str, Any], context: RunContext) -> ToolResult:
    """Run one sandboxed command, archive its output and return a summary."""
    request = ShellExecRequest.model_validate(arguments)
    validate_session_scope(context)
    root = workspace_root()
    _, cwd_relative = resolve_cwd(root, request.cwd)
    started = time.monotonic()

    reason = prohibited_reason(request.command)
    if reason is not None:
        duration_ms = int((time.monotonic() - started) * 1000)
        _audit(
            context, command=request.command, cwd=cwd_relative,
            exit_code=None, duration_ms=duration_ms, bytes_written=0,
            timed_out=False, decision="deny", reason=reason,
        )
        return ToolResult(
            output={
                "error": "command refused by the local shell deny list",
                "rule": reason,
                "command": request.command,
                "guidance": (
                    "Reformula sin privilegios locales ni operaciones destructivas; "
                    "el comando no se ha ejecutado."
                ),
            },
            verified=False,
            outcome="denied",
            verification_method="shell_command_denied",
            evidence={"cwd": cwd_relative, "deny_rule": reason},
        )

    stdin_data = request.stdin.encode("utf-8") if request.stdin is not None else None
    if stdin_data is not None and len(stdin_data) > SHELL_MAX_STDIN_BYTES:
        raise ValueError("stdin exceeds the local shell limit")

    sandbox = sandbox_for_environment(root, allowed_programs=SHELL_ALLOWED_PROGRAMS)
    # The plan's 10 MB ceiling is per shell invocation, not the 1 MB default of
    # the shared recon sandbox. Both LocalSandbox and OCISandbox expose it.
    with suppress(AttributeError):
        sandbox.max_output_bytes = SHELL_MAX_OUTPUT_BYTES
    program = "sh" if isinstance(sandbox, OCISandbox) else "bash"
    try:
        async with _run_lock(context.run_id):
            result = await run_in_sandbox(
                sandbox,
                [program, "-lc", request.command],
                timeout_seconds=request.timeout_seconds,
                image_env="NEXUS_SHELL_IMAGE",
                default_image="python:3.12-alpine",
                input_data=stdin_data,
            )
    except (FileNotFoundError, PermissionError) as exc:
        duration_ms = int((time.monotonic() - started) * 1000)
        _audit(
            context, command=request.command, cwd=cwd_relative,
            exit_code=None, duration_ms=duration_ms, bytes_written=0,
            timed_out=False, decision="deny", reason=type(exc).__name__,
        )
        return ToolResult(
            output={"error": f"shell unavailable: {type(exc).__name__}", "cwd": cwd_relative},
            verified=False,
            outcome="unavailable",
            verification_method="shell_unavailable",
        )

    duration_ms = int((time.monotonic() - started) * 1000)
    content = _combined_output(
        request.command, result.stdout, result.stderr, result.exit_code, result.timed_out
    )
    artifact = configured_artifact_store(context.store, default_artifact_root()).put(
        context.tenant_id,
        content,
        "text/plain; charset=utf-8",
        run_id=context.run_id,
        metadata={
            "engagement_id": context.engagement_id,
            "kind": "shell-output",
            "exit_code": result.exit_code,
            "timed_out": result.timed_out,
        },
    )
    summary = summarize(result.stdout, result.stderr)
    # An ``sshpass``-wrapped client is an authenticated channel, not an opaque
    # local process: the same login ``nexus.post.ssh_exec`` makes, started by the
    # generic shell. It is recorded here (target/user/port, never the secret) so
    # the run's evidence says which host this command really reached; the facts
    # are derived by ``kernel.fact_verification`` from the same parsed command.
    channels = sshpass_channels(request.command)
    _audit(
        context, command=request.command, cwd=cwd_relative,
        exit_code=result.exit_code, duration_ms=duration_ms,
        bytes_written=len(content), timed_out=result.timed_out,
    )
    verified = result.exit_code == 0 and not result.timed_out and not result.cancelled
    return ToolResult(
        output={
            "summary": summary,
            "artifact": artifact,
            "artifact_ref": artifact.get("id"),
            "sha256": artifact.get("sha256"),
            "exit_code": result.exit_code,
            "timed_out": result.timed_out,
            "cancelled": result.cancelled,
            "duration_ms": duration_ms,
            "output_bytes": len(content),
            "stdout_lines": result.stdout.count("\n") + (1 if result.stdout else 0),
            "stderr_lines": result.stderr.count("\n") + (1 if result.stderr else 0),
            "cwd": cwd_relative,
        },
        verified=verified,
        outcome="timeout" if result.timed_out else "",
        verification_method="shell_exit_code",
        evidence={
            "cwd": cwd_relative,
            "exit_code": result.exit_code,
            "duration_ms": duration_ms,
            "timed_out": result.timed_out,
            "sha256": artifact.get("sha256"),
            "artifact_ref": artifact.get("id"),
            **(
                {"ssh_channels": [channel.descriptor() for channel in channels]}
                if channels else {}
            ),
        },
        exit_code=result.exit_code,
        stdout=summary,
        stderr="",
        timed_out=result.timed_out,
    )


__all__ = [
    "SHELL_ALLOWED_PROGRAMS",
    "SHELL_MAX_OUTPUT_BYTES",
    "SHELL_MAX_STDIN_BYTES",
    "SHELL_MAX_TIMEOUT_SECONDS",
    "SHELL_MIN_TIMEOUT_SECONDS",
    "SHELL_SUMMARY_LINES",
    "ShellExecRequest",
    "prohibited_reason",
    "resolve_cwd",
    "shell_exec_definition",
    "shell_exec_handler",
    "summarize",
]
