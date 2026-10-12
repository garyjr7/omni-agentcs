"""Durable ``nexus.post.tftp`` handler: governed TFTP payload delivery (put/get).

Why this tool exists (the synthetic run / the synthetic lab): the tryhackme *Osiris* box exposes
**only** a TFTP server (UDP/69, SolarWinds Free tftpd) — every TCP port is
filtered on purpose "to simulate" the CEO's laptop being off-network. The room's
whole initial-access vector is *uploading a RubberDucky script to that TFTP
server* so the simulated ducky types it on the target. Until now no governed
primitive spoke TFTP, so the operator had to leave OMNI and run the ``tftp``
client by hand, which breaks the scope/approval/audit chain.

The sandbox runs every process with ``stdin=DEVNULL`` and the interactive
``tftp`` client is not on the allowlist, so the handler embeds a minimal
RFC 1350 client (stdlib ``socket``/``struct``) and runs it **through the
sandbox** like the rest of the durable tools. The post-condition is the
**server's own answer**: a ``WRQ``/``RRQ`` accepted and the final block acked
means the target really took the file (``tftp_upload_completed``), not that the
handler believed it sent one.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any

from nexus_core.kernel.models import RiskLevel, RunContext, ToolDefinition, ToolResult
from nexus_core.kernel.sandbox import sandbox_for_environment

from ._ad import validate_host
from ._exec import RECON_ALLOWED_PROGRAMS, run_in_sandbox, safe_run_id
from .workspace import resolve_workspace_path, workspace_root

#: TFTP opcodes (RFC 1350) and the octet-mode block size.
TFTP_OP_RRQ = 1
TFTP_OP_WRQ = 2
TFTP_OP_DATA = 3
TFTP_OP_ACK = 4
TFTP_OP_ERROR = 5
TFTP_BLOCK_BYTES = 512

TFTP_ACTIONS = ("put", "get")
TFTP_MODES = ("octet", "netascii")
TFTP_DEFAULT_PORT = 69
TFTP_DEFAULT_MODE = "octet"
TFTP_DEFAULT_TIMEOUT_SECONDS = 30
TFTP_MAX_TIMEOUT_SECONDS = 300
TFTP_MAX_RETRIES = 5
#: Hard cap on the file this tool will ship to the target.
TFTP_MAX_BYTES = 262_144

#: Error codes the embedded client reports (kept in one place for the handler).
TFTP_ERROR_CODES = {
    1: "file_not_found",
    2: "access_violation",
    3: "disk_full",
    4: "illegal_operation",
    5: "unknown_transfer_id",
    6: "file_exists",
    7: "no_such_user",
    8: "option_negotiation_failed",
}

#: stdlib-only client executed inside the sandbox. argv (after ``-c``):
#: action server port remote_name mode data_b64 timeout.
TFTP_SCRIPT = r"""
import base64, hashlib, json, socket, struct, sys

OP_RRQ, OP_WRQ, OP_DATA, OP_ACK, OP_ERROR = 1, 2, 3, 4, 5
BLOCK = 512


def emit(payload):
    print(json.dumps(payload))
    sys.stdout.flush()


def request(op, remote, mode):
    return struct.pack("!H", op) + remote.encode("ascii") + b"\x00" + mode.encode("ascii") + b"\x00"


def parse_op(pkt):
    if len(pkt) < 4:
        return None
    return struct.unpack_from("!H", pkt, 0)[0]


def error_payload(pkt):
    code = struct.unpack_from("!H", pkt, 2)[0] if len(pkt) >= 4 else -1
    message = pkt[4:].split(b"\x00", 1)[0].decode("utf-8", "replace")
    return {"code": code, "message": message}


def do_put(server, port, remote, mode, data, timeout):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(request(OP_WRQ, remote, mode), (server, port))
        pkt, peer = sock.recvfrom(1024)
    except OSError as exc:
        sock.close()
        return {"ok": False, "stage": "wrq", "error": "%s: %s" % (type(exc).__name__, exc)}
    op = parse_op(pkt)
    if op == OP_ERROR:
        sock.close()
        return {"ok": False, "stage": "wrq", "server_error": error_payload(pkt)}
    if op != OP_ACK or struct.unpack_from("!H", pkt, 2)[0] != 0:
        sock.close()
        return {"ok": False, "stage": "wrq", "error": "unexpected reply to WRQ"}
    sent = 0
    block = 0
    while True:
        chunk = data[sent:sent + BLOCK]
        block = (block + 1) & 0xFFFF
        packet = struct.pack("!HH", OP_DATA, block) + chunk
        tries = 0
        while True:
            try:
                sock.sendto(packet, peer)
                ack, _p = sock.recvfrom(1024)
            except OSError as exc:
                tries += 1
                if tries > 6:
                    sock.close()
                    return {"ok": False, "stage": "data", "bytes_sent": sent,
                            "error": "%s: %s" % (type(exc).__name__, exc)}
                continue
            ack_op = parse_op(ack)
            if ack_op == OP_ERROR:
                sock.close()
                return {"ok": False, "stage": "data", "bytes_sent": sent,
                        "server_error": error_payload(ack)}
            if ack_op == OP_ACK and struct.unpack_from("!H", ack, 2)[0] == block:
                break
        sent += len(chunk)
        if len(chunk) < BLOCK:
            break
    sock.close()
    return {"ok": True, "action": "put", "bytes": sent, "blocks": block,
            "sha256": hashlib.sha256(data).hexdigest()}


def do_get(server, port, remote, mode, timeout):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(request(OP_RRQ, remote, mode), (server, port))
    except OSError as exc:
        sock.close()
        return {"ok": False, "stage": "rrq", "error": "%s: %s" % (type(exc).__name__, exc)}
    buf = bytearray()
    expected = 1
    peer = None
    while True:
        try:
            pkt, peer = sock.recvfrom(4 + BLOCK)
        except OSError as exc:
            sock.close()
            return {"ok": False, "stage": "data", "bytes": len(buf),
                    "error": "%s: %s" % (type(exc).__name__, exc)}
        op = parse_op(pkt)
        if op == OP_ERROR:
            sock.close()
            return {"ok": False, "stage": "data", "bytes": len(buf),
                    "server_error": error_payload(pkt)}
        if op != OP_DATA:
            continue
        block = struct.unpack_from("!H", pkt, 2)[0]
        if block != expected:
            try:
                sock.sendto(struct.pack("!HH", OP_ACK, (expected - 1) & 0xFFFF), peer)
            except OSError:
                pass
            continue
        chunk = pkt[4:]
        buf.extend(chunk)
        sock.sendto(struct.pack("!HH", OP_ACK, block), peer)
        expected = (expected + 1) & 0xFFFF
        if len(chunk) < BLOCK:
            break
    sock.close()
    return {"ok": True, "action": "get", "bytes": len(buf),
            "sha256": hashlib.sha256(bytes(buf)).hexdigest(),
            "content_b64": base64.b64encode(bytes(buf)).decode("ascii")}


def main():
    action, server, port, remote, mode, data_b64, timeout = sys.argv[1:8]
    timeout = float(timeout)
    try:
        if action == "put":
            data = base64.b64decode(data_b64 or "")
            emit(do_put(server, int(port), remote, mode, data, timeout))
        else:
            emit(do_get(server, int(port), remote, mode, timeout))
    except Exception as exc:
        emit({"ok": False, "stage": "client", "error": "%s: %s" % (type(exc).__name__, exc)})


main()
"""


def validate_remote_name(value: Any) -> str:
    """Return a bare TFTP filename, refusing any path or control character."""
    text = str(value or "").strip()
    if not text:
        raise ValueError("remote_file is required")
    if len(text) > 128:
        raise ValueError("remote_file is too long")
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in text):
        raise ValueError("remote_file contains control characters")
    if "/" in text or "\\" in text or ".." in text:
        raise ValueError("remote_file must be a bare filename (no path)")
    if text.startswith("."):
        raise ValueError("remote_file must not start with a dot")
    return text


def _validate_action(value: Any) -> str:
    action = str(value or "put").strip().lower()
    if action not in TFTP_ACTIONS:
        raise ValueError(f"unsupported action: {action!r}")
    return action


def _validate_mode(value: Any) -> str:
    mode = str(value or TFTP_DEFAULT_MODE).strip().lower()
    if mode not in TFTP_MODES:
        raise ValueError(f"unsupported transfer mode: {mode!r}")
    return mode


def tftp_definition(tenant_id: str = "system") -> ToolDefinition:
    """Return the durable ToolDefinition for ``nexus.post.tftp``."""
    return ToolDefinition(
        tool_id="nexus.post.tftp",
        idempotent=False,
        name="TFTP payload delivery",
        tenant_id=tenant_id,
        description=(
            "Sube (put) o descarga (get) UN fichero por TFTP (UDP/69, RFC 1350) "
            "contra un servidor dentro del scope. Es el canal de entrega de "
            "payloads cuando el objetivo solo expone TFTP (p.ej. un RubberDucky "
            "simulado). Verifica el ACK del último bloque: 'accepted' significa "
            "que el servidor RECIBIÓ el fichero, no que se intentó enviarlo. "
            "HIGH: entrega de payload."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "minLength": 1, "maxLength": 255},
                "port": {"type": "integer", "minimum": 1, "maximum": 65535},
                "action": {"type": "string", "enum": list(TFTP_ACTIONS), "default": "put"},
                "remote_file": {"type": "string", "minLength": 1, "maxLength": 128},
                "local_file": {"type": "string", "minLength": 1, "maxLength": 4096},
                "mode": {"type": "string", "enum": list(TFTP_MODES), "default": "octet"},
                "timeout_seconds": {
                    "type": "integer",
                    "minimum": 5,
                    "maximum": TFTP_MAX_TIMEOUT_SECONDS,
                },
            },
            "required": ["target", "remote_file"],
            "additionalProperties": False,
        },
        risk=RiskLevel.HIGH,
        effect="exploit",
        required_permissions=["execute:tool:nexus.post.tftp"],
        timeout_seconds=TFTP_MAX_TIMEOUT_SECONDS + 60,
        max_output_bytes=1_000_000,
        scope_target_field="target",
        scope_required=True,
        sandbox_required=True,
    )


async def tftp_handler(arguments: dict, context: RunContext) -> ToolResult:
    """Ship or fetch one file over TFTP and report the server's own answer."""
    target = validate_host(arguments.get("target"))
    action = _validate_action(arguments.get("action"))
    remote = validate_remote_name(arguments.get("remote_file"))
    mode = _validate_mode(arguments.get("mode"))

    requested_port = arguments.get("port")
    port = int(requested_port) if requested_port else TFTP_DEFAULT_PORT
    if not 1 <= port <= 65535:
        raise ValueError("port out of range")

    requested_timeout = arguments.get("timeout_seconds")
    timeout_seconds = min(
        TFTP_MAX_TIMEOUT_SECONDS,
        max(5, int(requested_timeout) if requested_timeout else TFTP_DEFAULT_TIMEOUT_SECONDS),
    )

    data_b64 = ""
    local_detail: dict[str, Any] = {}
    if action == "put":
        raw_local = str(arguments.get("local_file") or "").strip()
        if not raw_local:
            raise ValueError("local_file is required for put")
        path = resolve_workspace_path(raw_local)
        data = path.read_bytes()
        if len(data) > TFTP_MAX_BYTES:
            raise ValueError(f"file is too large to ship over TFTP: {len(data)} bytes")
        data_b64 = base64.b64encode(data).decode("ascii")
        local_detail = {"local_file": str(path), "size_bytes": len(data)}

    argv = [
        "python3",
        "-c",
        TFTP_SCRIPT,
        action,
        target,
        str(port),
        remote,
        mode,
        data_b64,
        str(timeout_seconds),
    ]
    evidence: dict[str, Any] = {
        "server": target,
        "port": port,
        "action": action,
        "remote_file": remote,
        "mode": mode,
        "timeout_seconds": timeout_seconds,
        "noise_level": "medium",
        **local_detail,
    }
    sandbox = sandbox_for_environment(workspace_root(), allowed_programs=RECON_ALLOWED_PROGRAMS)
    result = await run_in_sandbox(
        sandbox,
        argv,
        timeout_seconds=timeout_seconds + 30,
        image_env="NEXUS_TFTP_IMAGE",
        default_image="python:3.12-alpine",
    )

    payload = _parse_payload(result.stdout or "")
    if result.timed_out:
        return ToolResult(
            output=payload | {"error": "tftp run timed out"},
            verified=False,
            verification_method="tftp_timeout",
            evidence=evidence,
            exit_code=result.exit_code,
            accepted_exit_codes=(0,),
            stdout=result.stdout,
            stderr=result.stderr,
            timed_out=True,
        )

    server_error = payload.get("server_error")
    if server_error:
        evidence["server_error"] = server_error
        evidence["server_error_code"] = server_error.get("code")
        return ToolResult(
            output=payload,
            verified=False,
            verification_method="tftp_server_error",
            evidence=evidence,
            exit_code=result.exit_code,
            accepted_exit_codes=(0,),
            stdout=result.stdout,
            stderr=result.stderr,
        )

    if payload.get("error") and not payload.get("ok"):
        return ToolResult(
            output=payload,
            verified=False,
            verification_method="tftp_failed",
            evidence=evidence,
            exit_code=result.exit_code,
            accepted_exit_codes=(0,),
            stdout=result.stdout,
            stderr=result.stderr,
        )

    if action == "get":
        content = base64.b64decode(str(payload.get("content_b64") or ""))
        artifact = ""
        if content:
            artifact = str(
                (Path(workspace_root()) / f"tftp_{safe_run_id(context)}_{remote}").resolve()
            )
            try:
                Path(artifact).write_bytes(content)
            except OSError:
                artifact = ""
        evidence.update(
            {"bytes": payload.get("bytes"), "sha256": payload.get("sha256"),
             "artifact": artifact or None}
        )
        return ToolResult(
            output={
                "action": "get",
                "remote_file": remote,
                "bytes": payload.get("bytes"),
                "sha256": payload.get("sha256"),
                "artifact": artifact or None,
                "server": target,
            },
            verified=True,
            verification_method="tftp_download_completed",
            evidence=evidence,
            exit_code=result.exit_code,
            accepted_exit_codes=(0,),
            stdout=result.stdout,
            stderr=result.stderr,
        )

    verified = bool(payload.get("ok"))
    evidence.update(
        {"bytes": payload.get("bytes"), "blocks": payload.get("blocks"),
         "sha256": payload.get("sha256")}
    )
    return ToolResult(
        output=payload,
        verified=verified,
        verification_method="tftp_upload_completed",
        evidence=evidence,
        exit_code=result.exit_code,
        accepted_exit_codes=(0,),
        stdout=result.stdout,
        stderr=result.stderr,
    )


def _parse_payload(stdout: str) -> dict[str, Any]:
    """Return the last JSON object printed by the embedded client."""
    for line in reversed((stdout or "").splitlines()):
        line = line.strip()
        if line.startswith("{"):
            try:
                value = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(value, dict):
                return value
    return {"error": "tftp client produced no result"}


__all__ = [
    "TFTP_ACTIONS",
    "TFTP_ERROR_CODES",
    "TFTP_MODES",
    "TFTP_SCRIPT",
    "tftp_definition",
    "tftp_handler",
    "validate_remote_name",
]
