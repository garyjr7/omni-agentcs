"""Durable ``nexus.recon.ftp`` handler: anonymous/list/download recon.

The handler never talks to the network itself: it runs a tiny stdlib ``ftplib``
client through ``sandbox_for_environment`` (``python3`` is already in the recon
program allowlist), so execution stays inside the same contract as the rest of
the durable tools. It is read-only from the target's point of view (``LIST`` /
``RETR``), hence ``LOW`` risk.

This is the first link of the classic chain: an anonymous FTP login exposes
file names (wordlists, notes signed by a user) that feed the next step.

Limitations: downloads land in the workspace root of a *local* sandbox. Under
the OCI sandbox the container filesystem is ephemeral, so the reported path may
not exist on the host; the ``sha256``/``size`` in the output still describe the
retrieved bytes.
"""

from __future__ import annotations

import json
import os
from typing import Any

from nexus_core.kernel.models import RiskLevel, RunContext, ToolDefinition, ToolResult
from nexus_core.kernel.sandbox import sandbox_for_environment

from ._exec import RECON_ALLOWED_PROGRAMS, run_in_sandbox, safe_run_id
from ._loot import loot_summary

FTP_ALLOWED_PROGRAMS = RECON_ALLOWED_PROGRAMS
FTP_DEFAULT_PORT = 21
FTP_DEFAULT_TIMEOUT_SECONDS = 60
FTP_MAX_TIMEOUT_SECONDS = 300
#: Cap on listing lines persisted per scan (defensive against huge directories).
FTP_MAX_LISTING_LINES = 500

#: How many leading bytes of a downloaded file travel back in the result.
#: Rationale (B7): without it the agent has to learn that a second tool exists
#: and read the file itself; with it the immediately useful content (``locks``
#: wordlists, ``task.txt`` user names) is in the same observation as the
#: download, while the full bytes stay in the workspace for
#: ``nexus.workspace.read``. Injected into the client script below so the number
#: has exactly one definition.
FTP_PREVIEW_BYTES = 4096

#: Auto-loot: a listing also brings the first bytes of the small text files in
#: it. Measured in Hijack (2026-10-30): the FTP account holds the password/hash
#: notes the next step needs, and listing without reading them cost a turn per
#: guessed file name. Five files, 64 KB each: one bounded answer.
FTP_LOOT_MAX_FILES = 5
FTP_LOOT_MAX_BYTES = 65_536

FTP_ACTIONS = ("list", "download")

#: Anonymous login credentials; the model must not invent other accounts.
FTP_ANONYMOUS_USER = "anonymous"
FTP_ANONYMOUS_PASSWORD = "anonymous@"

#: stdlib client executed inside the sandbox. argv layout (after ``-c``):
#: action host port user password remote local_dir.
#: Many anonymous servers reject passive-mode data connections (``550``) but
#: answer in active mode, so the client retries PASV -> PORT before giving up.
FTP_CLIENT_SCRIPT = r"""
import ftplib, hashlib, json, os, sys

PREVIEW_BYTES = __PREVIEW_BYTES__
LOOT_MAX_FILES = __LOOT_MAX_FILES__
LOOT_MAX_BYTES = __LOOT_MAX_BYTES__

def run_op(ftp, action, remote, local_dir):
    info = {}
    if action == "list":
        lines = []
        try:
            ftp.retrlines("LIST " + remote, lines.append)
        except Exception as exc:
            info["list_error"] = "%s: %s" % (type(exc).__name__, exc)
        names = []
        try:
            names = ftp.nlst(remote)
        except Exception as exc:
            info["nlst_error"] = "%s: %s" % (type(exc).__name__, exc)
        info["listing"] = lines
        info["names"] = names
        # Auto-loot: read the small text files the listing just revealed.
        info["files"] = []
        seen = set()
        for name in names:
            base = str(name).rstrip("/").rsplit("/", 1)[-1]
            if not base or base in (".", "..") or base in seen:
                continue
            seen.add(base)
            if len(info["files"]) >= LOOT_MAX_FILES:
                break
            try:
                size = ftp.size(name)
            except Exception:
                size = None
            if size is not None and size > LOOT_MAX_BYTES:
                continue
            buf = bytearray()
            def writer(chunk, buf=buf):
                if len(buf) < LOOT_MAX_BYTES:
                    buf.extend(chunk[: LOOT_MAX_BYTES - len(buf)])
            try:
                ftp.retrbinary("RETR " + name, writer)
            except Exception:
                continue
            text = bytes(buf).decode("utf-8", "replace")
            printable = sum(c.isprintable() or c in "\n\r\t" for c in text)
            if not text.strip() or printable < len(text) * 0.85:
                continue
            info["files"].append({
                "name": name,
                "size": size if size is not None else len(buf),
                "preview": text[:PREVIEW_BYTES],
            })
    elif action == "download":
        os.makedirs(local_dir, exist_ok=True)
        name = os.path.basename(remote.rstrip("/")) or "download.bin"
        path = os.path.join(local_dir, name)
        digest = hashlib.sha256()
        size = 0
        head = bytearray()
        handle = open(path, "wb")
        try:
            def writer(chunk):
                nonlocal size
                handle.write(chunk)
                digest.update(chunk)
                size += len(chunk)
                if len(head) < PREVIEW_BYTES:
                    head.extend(chunk[: PREVIEW_BYTES - len(head)])
            ftp.retrbinary("RETR " + remote, writer)
        finally:
            handle.close()
        info["file"] = name
        info["path"] = path
        info["size"] = size
        info["sha256"] = digest.hexdigest()
        info["preview"] = bytes(head).decode("utf-8", "replace")
        info["preview_bytes"] = len(head)
        info["preview_truncated"] = size > len(head)
    return info

def has_data(action, info):
    if action == "list":
        return bool(info.get("listing") or info.get("names"))
    return int(info.get("size") or 0) > 0

def main():
    action, host, port, user, password, remote, local_dir = sys.argv[1:8]
    attempts = []
    for pasv in (True, False):
        info = {"mode": "passive" if pasv else "active", "login_ok": False}
        ftp = None
        try:
            ftp = ftplib.FTP()
            ftp.set_pasv(pasv)
            ftp.connect(host, int(port), timeout=20)
            ftp.login(user, password)
            info["login_ok"] = True
            info.update(run_op(ftp, action, remote, local_dir))
        except Exception as exc:
            info["error"] = "%s: %s" % (type(exc).__name__, exc)
        finally:
            if ftp is not None:
                try:
                    ftp.quit()
                except Exception:
                    try:
                        ftp.close()
                    except Exception:
                        pass
        attempts.append(info)
        if has_data(action, info):
            break
    best = next((a for a in attempts if has_data(action, a)), None)
    if best is None:
        best = attempts[0] if attempts else {"login_ok": False}
    result = {
        "ok": bool(best.get("login_ok")),
        "action": action,
        "host": host,
        "port": int(port),
        "username": user,
        "anonymous": user == "anonymous",
    }
    result.update(best)
    if not result["ok"]:
        result["error"] = best.get("error") or "login failed"
    result["attempts"] = [
        {
            k: v
            for k, v in a.items()
            if k in (
                "mode", "login_ok", "error", "list_error", "nlst_error", "size",
                "preview_bytes", "preview_truncated",
            )
        }
        for a in attempts
    ]
    print(json.dumps(result))

main()
""".replace("__PREVIEW_BYTES__", str(FTP_PREVIEW_BYTES)).replace(
    "__LOOT_MAX_FILES__", str(FTP_LOOT_MAX_FILES)
).replace("__LOOT_MAX_BYTES__", str(FTP_LOOT_MAX_BYTES))


def ftp_definition(tenant_id: str = "system") -> ToolDefinition:
    """Return the durable ToolDefinition for ``nexus.recon.ftp``."""
    return ToolDefinition(
        tool_id="nexus.recon.ftp",
        effect="read_only",
        name="FTP recon",
        tenant_id=tenant_id,
        description=(
            "Conecta a un servicio FTP, prueba login (anónimo por defecto; si ya "
            "hay credenciales FTP en la pizarra, pásalas con username/password), "
            "lista un directorio -y devuelve el contenido de los ficheros de "
            "texto pequeños, que es donde suelen estar las credenciales y las "
            "listas de contraseñas- o descarga un archivo. Read-only. En "
            "'download' el fichero se guarda siempre en el workspace del "
            "engagement (<workspace>/ftp_<run>/): no se elige ruta local."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "minLength": 1, "maxLength": 255},
                "action": {"type": "string", "enum": list(FTP_ACTIONS)},
                # ``""`` is the anonymous root, and the handler already reads it
                # as ``/``. Requiring a non-empty string made the model's
                # ``remote_path=""`` a rejection instead of a listing of ``/``
                # (hijack_v7, iteration 20).
                "remote_path": {"type": "string", "maxLength": 1024},
                "port": {"type": "integer", "minimum": 1, "maximum": 65535},
                "username": {"type": "string", "minLength": 1, "maxLength": 128},
                "password": {"type": "string", "maxLength": 256},
                "timeout_seconds": {"type": "integer", "minimum": 10, "maximum": 600},
                # Legacy argument kept only so an older model that still sends
                # it is not rejected by the closed schema (Simple CTF: it cost
                # an iteration). The handler drops it: the download path is
                # always the workspace, so there is nothing to choose.
                "local_path": {
                    "type": "string",
                    "maxLength": 1024,
                    "description": (
                        "IGNORADO. La descarga va siempre al workspace "
                        "(<workspace>/ftp_<run>/). No lo envíes."
                    ),
                },
            },
            "required": ["target"],
            "additionalProperties": False,
        },
        risk=RiskLevel.LOW,
        required_permissions=["execute:tool:nexus.recon.ftp"],
        timeout_seconds=300,
        max_output_bytes=2_000_000,
        scope_target_field="target",
        scope_required=True,
    )


def _validate_text(value: Any, field: str, *, max_length: int) -> str:
    """Return a stripped, control-character-free string for an argv field."""
    text = str(value or "").strip()
    if not text:
        raise ValueError(f"{field} is required")
    if len(text) > max_length:
        raise ValueError(f"{field} is too long")
    if any(ord(ch) < 0x20 for ch in text):
        raise ValueError(f"{field} contains control characters")
    return text


def _parse_last_json(stdout: str) -> dict[str, Any]:
    """Return the last JSON object printed by the client, else raise ValueError."""
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
    raise ValueError("ftp client did not return a JSON result")


async def ftp_handler(arguments: dict, context: RunContext) -> ToolResult:
    """Run an allowlisted FTP listing/download inside a sandbox."""
    # ``local_path`` is not part of the contract (the client always writes to
    # the workspace); dropping it here keeps a legacy call working instead of
    # failing on an argument that has no effect either way.
    arguments = {key: value for key, value in arguments.items() if key != "local_path"}
    target = _validate_text(arguments.get("target"), "target", max_length=255)
    action = str(arguments.get("action") or "list").strip().lower()
    if action not in FTP_ACTIONS:
        raise ValueError(f"unsupported ftp action: {action!r}")
    remote_path = _validate_text(
        arguments.get("remote_path") or "/", "remote_path", max_length=1024
    )
    username = _validate_text(
        arguments.get("username") or FTP_ANONYMOUS_USER, "username", max_length=128
    )
    password = str(arguments.get("password") or FTP_ANONYMOUS_PASSWORD)
    if any(ord(ch) < 0x20 for ch in password):
        raise ValueError("password contains control characters")

    port = int(arguments.get("port") or FTP_DEFAULT_PORT)
    if not 1 <= port <= 65535:
        raise ValueError("port out of range")
    requested_timeout = arguments.get("timeout_seconds")
    timeout_seconds = min(
        FTP_MAX_TIMEOUT_SECONDS,
        max(10, int(requested_timeout) if requested_timeout else FTP_DEFAULT_TIMEOUT_SECONDS),
    )

    workspace_root = os.getenv("NEXUS_WORKSPACE_ROOT", os.getcwd())
    local_dir = os.path.join(workspace_root, f"ftp_{safe_run_id(context)}")

    argv = [
        "python3",
        "-c",
        FTP_CLIENT_SCRIPT,
        action,
        target,
        str(port),
        username,
        password,
        remote_path,
        local_dir,
    ]
    sandbox = sandbox_for_environment(workspace_root, allowed_programs=FTP_ALLOWED_PROGRAMS)
    result = await run_in_sandbox(
        sandbox,
        argv,
        timeout_seconds=timeout_seconds,
        image_env="NEXUS_FTP_IMAGE",
        default_image="python:3.12-alpine",
    )

    evidence: dict[str, Any] = {
        "action": action,
        "port": port,
        "username": username,
        "anonymous": username == FTP_ANONYMOUS_USER,
        "remote_path": remote_path,
        "noise_level": "low",
        "timeout_seconds": timeout_seconds,
    }
    if result.timed_out:
        return ToolResult(
            output={"error": "ftp connection timed out", "target": target, "action": action},
            verified=False,
            verification_method="ftp_timeout",
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
            output={"error": str(exc), "target": target, "action": action},
            verified=False,
            verification_method="ftp_parse_failed",
            evidence=evidence,
            exit_code=result.exit_code,
            accepted_exit_codes=(0,),
            stdout=result.stdout,
            stderr=result.stderr,
        )

    ok = bool(payload.get("ok")) and result.exit_code == 0
    evidence["mode"] = payload.get("mode")
    # A refused login is a verdict from the server, not a broken tool: without
    # this the gateway raised "post-condition was not verified" and the loop
    # counted the branch as a *failed tool* (hijack_v7, iterations 13 and 23).
    outcome = ""
    if not ok:
        error = str(payload.get("error") or "")
        if "530" in error or "login" in error.lower():
            outcome = "denied"
    loot = loot_summary(
        [item for item in (payload.get("files") or []) if isinstance(item, dict)]
    )
    evidence["files_total"] = int(loot.get("files_total") or 0)
    evidence["credentials_found"] = len(loot.get("credentials") or [])
    if action == "list":
        listing = list(payload.get("listing") or [])
        names = list(payload.get("names") or [])
        evidence.update(
            {
                "entries_total": len(listing) or len(names),
                "entries_truncated": len(listing) > FTP_MAX_LISTING_LINES,
                "list_error": payload.get("list_error"),
            }
        )
        payload["listing"] = listing[:FTP_MAX_LISTING_LINES]
        payload["names"] = names[:FTP_MAX_LISTING_LINES]
        verification_method = "ftp_listing_parsed" if ok else "ftp_list_failed"
    else:
        if ok:
            evidence.update(
                {
                    "file": payload.get("file"),
                    "size": payload.get("size"),
                    "sha256": payload.get("sha256"),
                    "preview_bytes": payload.get("preview_bytes"),
                    "preview_truncated": payload.get("preview_truncated"),
                }
            )
        verification_method = "ftp_download_verified" if ok else "ftp_download_failed"

    return ToolResult(
        output={
            "target": target,
            "action": action,
            "port": port,
            "username": username,
            "anonymous": username == FTP_ANONYMOUS_USER,
            "result": payload,
            **loot,
        },
        verified=ok,
        outcome=outcome,
        verification_method=verification_method,
        evidence=evidence,
        exit_code=result.exit_code,
        accepted_exit_codes=(0,),
        stdout=result.stdout,
        stderr=result.stderr,
    )
