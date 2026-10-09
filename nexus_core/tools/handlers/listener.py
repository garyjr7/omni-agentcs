"""Durable ``nexus.post.listener`` handler: catch ONE reverse shell (governed).

The manual chain often ends on a foothold whose only output channel is a reverse
connection (a vulnerable service spawning ``bash -i >& /dev/tcp/...`` or a
binary exploit). Until now the catalogue could *open* sessions through Metasploit
but had no governed way to receive a raw shell without it (B-ROOTME-2). The
operator had to leave OMNI and run ``nc -lvnp`` by hand, which breaks the
scope/policy/audit chain.

This tool closes that gap without inventing a background daemon: it is a
**one-shot catch**. The operator runs it (normally backgrounded in the shell) and
then triggers the reverse connection from another governed tool; on
``accept()`` it sends the provided commands, captures the transcript to a
workspace artifact and returns it.

Design notes
------------
* Execution stays inside the sandbox contract: the handler runs a stdlib
  ``socket`` client through ``sandbox_for_environment`` (``python3`` is already in
  the recon allowlist); it never spawns a process directly.
* ``risk=HIGH`` + ``effect=post_exploitation``: catching a shell and running
  commands is post-exploitation, so the gateway forces human approval unless the
  operator opted into trust mode — exactly like ``nexus.session.interact``.
* It is engagement-scoped (``scope_target_field=None``): the *peer* is only known
  after the connection arrives, so the handler validates the connecting host
  against the signed scope itself and refuses (and records nothing usable) when
  the peer is out of scope.
"""

from __future__ import annotations

import json
import os
from typing import Any

from nexus_core.kernel.models import RiskLevel, RunContext, ToolDefinition, ToolResult
from nexus_core.kernel.sandbox import sandbox_for_environment
from nexus_core.kernel.sessions import validate_session_scope
from nexus_core.scope import ScopeValidator, ScopeViolation
from nexus_core.kernel.scope_loader import scope_signing_secret

from ._exec import RECON_ALLOWED_PROGRAMS, run_in_sandbox, safe_run_id

LISTENER_ALLOWED_PROGRAMS = RECON_ALLOWED_PROGRAMS

LISTENER_DEFAULT_BIND = "0.0.0.0"
LISTENER_DEFAULT_TIMEOUT_SECONDS = 120
LISTENER_MAX_TIMEOUT_SECONDS = 1800
LISTENER_DEFAULT_IDLE_SECONDS = 3
LISTENER_MAX_IDLE_SECONDS = 60
#: Response bytes carried back in the observation.
LISTENER_DEFAULT_MAX_OUTPUT_BYTES = 1_000_000
LISTENER_MAX_OUTPUT_BYTES = 10_000_000
#: Cap on how many commands one catch may send.
LISTENER_MAX_COMMANDS = 50
LISTENER_MAX_COMMAND_CHARS = 2000

#: stdlib listener executed inside the sandbox. argv layout (after ``-c``):
#: bind_host port timeout idle max_bytes commands_json.
LISTENER_CLIENT_SCRIPT = r"""
import hashlib, json, socket, sys, time


def emit(payload):
    print(json.dumps(payload))
    sys.stdout.flush()


def main():
    bind_host, port, timeout, idle, max_bytes, commands_json = sys.argv[1:7]
    commands = json.loads(commands_json or "[]")
    timeout = float(timeout)
    idle = float(idle)
    max_bytes = int(max_bytes)

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    started = time.time()
    try:
        server.bind((bind_host, int(port)))
        server.listen(1)
        server.settimeout(timeout)
    except OSError as exc:
        emit({"ok": False, "bound": False, "port": int(port),
              "error": "%s: %s" % (type(exc).__name__, exc)})
        return
    try:
        conn, peer = server.accept()
    except socket.timeout:
        emit({"ok": False, "bound": True, "listened_seconds": int(time.time() - started),
              "port": int(port), "error": "no connection within timeout"})
        return
    finally:
        server.close()

    peer_host = peer[0] if isinstance(peer, tuple) else str(peer)
    buffer = bytearray()
    truncated = False

    def pump(wait_for_output):
        # Read whatever is available; stop on idle timeout or when we hit the cap.
        nonlocal truncated
        conn.settimeout(idle if wait_for_output else 0.5)
        while len(buffer) < max_bytes:
            try:
                data = conn.recv(4096)
            except socket.timeout:
                break
            except OSError as exc:
                return "err:%s" % type(exc).__name__
            if not data:
                return "closed"
            buffer.extend(data[: max_bytes - len(buffer)])
        if len(buffer) >= max_bytes:
            truncated = True
        return "ok"

    status = pump(True)
    sent = []
    for command in commands:
        if status in ("closed", "err:ConnectionResetError", "err:BrokenPipeError"):
            break
        try:
            conn.sendall((command + "\n").encode("utf-8"))
        except OSError as exc:
            status = "err:%s" % type(exc).__name__
            break
        sent.append(command)
        status = pump(True)

    try:
        conn.close()
    except OSError:
        pass

    raw = bytes(buffer)
    emit({
        "ok": True,
        "bound": True,
        "peer": peer_host,
        "port": int(port),
        "commands_sent": sent,
        "status": status,
        "bytes": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "transcript": raw.decode("utf-8", "replace"),
        "truncated": truncated,
        "elapsed_ms": int((time.time() - started) * 1000),
    })


main()
"""


def listener_definition(tenant_id: str = "system") -> ToolDefinition:
    """Return the durable ToolDefinition for ``nexus.post.listener``."""
    return ToolDefinition(
        tool_id="nexus.post.listener",
        name="Reverse shell listener",
        tenant_id=tenant_id,
        description=(
            "Escucha UNA conexión entrante (reverse shell), envía una lista de "
            "comandos y devuelve la transcripción con sha256. Es el canal "
            "gobernado para footholds que solo devuelven una conexión inversa "
            "cuando no se usa Metasploit. Ejecútala en segundo plano y dispara la "
            "conexión con otra tool. HIGH: requiere aprobación salvo trust mode."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "port": {"type": "integer", "minimum": 1, "maximum": 65535},
                "bind_host": {"type": "string", "minLength": 1, "maxLength": 255},
                "timeout_seconds": {
                    "type": "integer",
                    "minimum": 5,
                    "maximum": LISTENER_MAX_TIMEOUT_SECONDS,
                },
                "idle_seconds": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": LISTENER_MAX_IDLE_SECONDS,
                },
                "commands": {
                    "type": "array",
                    "items": {"type": "string", "minLength": 1, "maxLength": LISTENER_MAX_COMMAND_CHARS},
                    "maxItems": LISTENER_MAX_COMMANDS,
                },
                "max_output_bytes": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": LISTENER_MAX_OUTPUT_BYTES,
                },
            },
            "required": ["port"],
            "additionalProperties": False,
        },
        risk=RiskLevel.HIGH,
        effect="post_exploitation",
        required_permissions=["execute:tool:nexus.post.listener"],
        timeout_seconds=LISTENER_MAX_TIMEOUT_SECONDS + 120,
        max_output_bytes=LISTENER_MAX_OUTPUT_BYTES + 1_000_000,
        scope_target_field=None,
        scope_required=True,
    )


def _validate_commands(value: Any) -> list[str]:
    """Return a bounded, control-character-checked list of commands."""
    if value in (None, ""):
        return []
    if not isinstance(value, list):
        raise ValueError("commands must be an array")
    if len(value) > LISTENER_MAX_COMMANDS:
        raise ValueError(f"too many commands: {len(value)} > {LISTENER_MAX_COMMANDS}")
    cleaned: list[str] = []
    for item in value:
        text = str(item)
        if not text.strip():
            raise ValueError("command must not be empty")
        if len(text) > LISTENER_MAX_COMMAND_CHARS:
            raise ValueError("command is too long")
        if "\x00" in text:
            raise ValueError("command must not contain null bytes")
        cleaned.append(text)
    return cleaned


def _parse_last_json(stdout: str) -> dict[str, Any]:
    """Return the last JSON object printed by the client, else raise ``ValueError``."""
    for line in reversed(stdout.splitlines()):
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(payload, dict):
            return payload
    raise ValueError("listener client did not return a JSON result")


def _peer_in_scope(context: RunContext, peer: str) -> bool:
    """True when ``peer`` is covered by the signed engagement scope."""
    try:
        ScopeValidator(context.scope, signing_secret=scope_signing_secret()).validate(peer)
        return True
    except ScopeViolation:
        return False


async def listener_handler(arguments: dict, context: RunContext) -> ToolResult:
    """Bind, catch one reverse connection, drive it and return the transcript."""
    try:
        validate_session_scope(context)
    except PermissionError:
        return ToolResult(verification_method="listener_scope_required")

    port = int(arguments.get("port") or 0)
    if not 1 <= port <= 65535:
        raise ValueError("port out of range")
    bind_host = str(arguments.get("bind_host") or LISTENER_DEFAULT_BIND).strip()
    if not bind_host or any(ord(ch) < 0x20 for ch in bind_host):
        raise ValueError("bind_host is invalid")
    commands = _validate_commands(arguments.get("commands"))

    requested_timeout = arguments.get("timeout_seconds")
    timeout_seconds = min(
        LISTENER_MAX_TIMEOUT_SECONDS,
        max(5, int(requested_timeout) if requested_timeout else LISTENER_DEFAULT_TIMEOUT_SECONDS),
    )
    requested_idle = arguments.get("idle_seconds")
    idle_seconds = min(
        LISTENER_MAX_IDLE_SECONDS,
        max(1, int(requested_idle) if requested_idle else LISTENER_DEFAULT_IDLE_SECONDS),
    )
    requested_max = arguments.get("max_output_bytes")
    max_bytes = min(
        LISTENER_MAX_OUTPUT_BYTES,
        max(1, int(requested_max) if requested_max else LISTENER_DEFAULT_MAX_OUTPUT_BYTES),
    )

    workspace_root = os.getenv("NEXUS_WORKSPACE_ROOT", os.getcwd())
    argv = [
        "python3",
        "-c",
        LISTENER_CLIENT_SCRIPT,
        bind_host,
        str(port),
        str(timeout_seconds),
        str(idle_seconds),
        str(max_bytes),
        json.dumps(commands),
    ]
    sandbox = sandbox_for_environment(workspace_root, allowed_programs=LISTENER_ALLOWED_PROGRAMS)
    result = await run_in_sandbox(
        sandbox,
        argv,
        timeout_seconds=timeout_seconds + idle_seconds + 30,
        image_env="NEXUS_LISTENER_IMAGE",
        default_image="python:3.12-alpine",
    )

    evidence: dict[str, Any] = {
        "port": port,
        "bind_host": bind_host,
        "commands_requested": len(commands),
        "timeout_seconds": timeout_seconds,
        "idle_seconds": idle_seconds,
        "noise_level": "high",
    }
    if result.timed_out:
        return ToolResult(
            output={"error": "listener timed out", "port": port},
            verified=False,
            verification_method="listener_timeout",
            evidence=evidence,
            exit_code=result.exit_code,
            accepted_exit_codes=(0,),
            stdout=result.stdout,
            stderr=result.stderr,
            timed_out=True,
        )

    try:
        payload = _parse_last_json(result.stdout)
    except ValueError as exc:
        return ToolResult(
            output={"error": str(exc), "port": port},
            verified=False,
            verification_method="listener_parse_failed",
            evidence=evidence,
            exit_code=result.exit_code,
            accepted_exit_codes=(0,),
            stdout=result.stdout,
            stderr=result.stderr,
        )

    if not payload.get("ok"):
        # Distinguish "nothing connected" from "could not bind".
        method = "listener_no_connection" if payload.get("bound") else "listener_bind_failed"
        evidence["error"] = payload.get("error")
        return ToolResult(
            output={"error": payload.get("error"), "port": port},
            verified=False,
            verification_method=method,
            evidence=evidence,
            exit_code=result.exit_code,
            accepted_exit_codes=(0,),
            stdout=result.stdout,
            stderr=result.stderr,
        )

    peer = str(payload.get("peer") or "")
    # The peer is only known now: fail closed when the connecting host is not in
    # the signed scope, so a catch can never become an out-of-scope interaction.
    if not peer or not _peer_in_scope(context, peer):
        evidence["peer"] = peer
        return ToolResult(
            output={"error": "reverse connection from out-of-scope host", "peer": peer, "port": port},
            verified=False,
            verification_method="listener_peer_out_of_scope",
            evidence=evidence,
            exit_code=result.exit_code,
            accepted_exit_codes=(0,),
            stdout=result.stdout,
            stderr=result.stderr,
        )

    transcript = str(payload.get("transcript") or "")
    # Persist the transcript as a workspace artifact so it can be read back with
    # nexus.workspace.read and referenced by the report with its sha256.
    artifact = os.path.join(workspace_root, f"listener_{safe_run_id(context)}_{port}.txt")
    try:
        with open(artifact, "w", encoding="utf-8") as handle:
            handle.write(transcript)
    except OSError:
        artifact = ""

    evidence.update(
        {
            "peer": peer,
            "commands_sent": len(payload.get("commands_sent") or []),
            "bytes": payload.get("bytes"),
            "sha256": payload.get("sha256"),
            "status": payload.get("status"),
            "truncated": payload.get("truncated"),
            "elapsed_ms": payload.get("elapsed_ms"),
            "artifact": artifact or None,
        }
    )
    return ToolResult(
        output={
            "peer": peer,
            "port": port,
            "commands_sent": payload.get("commands_sent") or [],
            "status": payload.get("status"),
            "bytes": payload.get("bytes"),
            "sha256": payload.get("sha256"),
            "truncated": payload.get("truncated"),
            "transcript": transcript,
        },
        verified=True,
        verification_method="listener_session_captured",
        evidence=evidence,
        exit_code=result.exit_code,
        accepted_exit_codes=(0,),
        stdout=result.stdout,
        stderr=result.stderr,
    )


__all__ = [
    "LISTENER_CLIENT_SCRIPT",
    "listener_definition",
    "listener_handler",
]
