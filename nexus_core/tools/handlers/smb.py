"""Durable SMB handlers: share enumeration and governed file transfer.

Two tools, split by *effect* so governance stays honest:

* ``nexus.recon.smb`` — read-only: list shares and list/download files from a
  share (anonymous or with validated credentials). ``risk=LOW``.
* ``nexus.post.smb_upload`` — uploads a workspace file into a share. This is the
  primitive that turns a writable share into code execution when that share is
  also served to a web server; ``risk=MEDIUM`` and ``effect=exploit``.

Neither handler spawns a process itself: they resolve the ``smbclient`` binary
and run it through the same sandbox contract as the rest of the durable recon
handlers (the unit tests assert ``asyncio.create_subprocess_exec`` is untouched).
"""

from __future__ import annotations

import hashlib
import os
import re
from pathlib import Path
from typing import Any

from nexus_core.kernel.models import RiskLevel, RunContext, ToolDefinition, ToolResult

from ._ad import ad_sandbox, resolve_ad_binary, validate_host, validate_username
from ._exec import run_in_sandbox, safe_run_id

SMB_BINARY_CANDIDATES = ("smbclient",)
SMB_MAX_TIMEOUT_SECONDS = 600
SMB_DEFAULT_TIMEOUT_SECONDS = 120
#: Cap on listing lines returned in one observation.
SMB_MAX_LISTING_LINES = 1000

SMB_RECON_ACTIONS = ("shares", "list", "get")

_SHARE_RE = re.compile(r"^\s*(\S+)\s+(Disk|IPC|Printer)\s*(.*)$")
_DIR_RE = re.compile(r"^\s*(.+?)\s+([ADN])\s+(\d+)\s+(.*)$")
#: ``NT_STATUS_...`` failures that ``smbclient`` prints while exiting 0.
_NT_STATUS_RE = re.compile(r"NT_STATUS_[A-Z_]+")


def _validate_share(value: Any) -> str:
    """Return a share name (no separators or traversal)."""
    text = str(value or "").strip()
    if not text or len(text) > 128:
        raise ValueError("share is required and must be at most 128 characters")
    if any(ch.isspace() for ch in text) or "/" in text or "\\" in text:
        raise ValueError("share must not contain spaces, slashes or backslashes")
    if text in {".", ".."}:
        raise ValueError("share is invalid")
    return text


def _validate_remote_path(value: Any, *, required: bool) -> str:
    """Return a remote path free of control characters and traversal."""
    text = str(value or "").strip()
    if not text:
        if required:
            raise ValueError("remote_path is required")
        return ""
    if len(text) > 1024:
        raise ValueError("remote_path is too long")
    if any(ord(ch) < 0x20 for ch in text):
        raise ValueError("remote_path contains control characters")
    normalized = text.replace("\\", "/")
    if any(part == ".." for part in normalized.split("/")):
        raise ValueError("remote_path must not contain '..'")
    return text


def _smbclients_argv(binary: str, target: str, username: str, password: str) -> list[str]:
    """Build the binary + auth prefix for an ``smbclient`` invocation."""
    argv = [binary]
    if username:
        secret = str(password or "")
        argv.extend(["-U", f"{username}%{secret}"])
    else:
        argv.append("-N")
    return argv


def _connection_failed(stdout: str, stderr: str) -> str | None:
    """Return the first ``NT_STATUS`` failure token, or ``None`` when clean."""
    for text in (stdout, stderr):
        match = _NT_STATUS_RE.search(text or "")
        if match:
            return match.group(0)
    return None


def _parse_shares(stdout: str) -> list[dict[str, Any]]:
    shares: list[dict[str, Any]] = []
    for line in stdout.splitlines():
        match = _SHARE_RE.match(line)
        if not match:
            continue
        name = match.group(1)
        if name in {"Sharename", "---------"}:
            continue
        shares.append({"name": name, "type": match.group(2), "comment": match.group(3).strip()})
    return shares


def _parse_directory(stdout: str) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for line in stdout.splitlines():
        match = _DIR_RE.match(line)
        if not match:
            continue
        name = match.group(1).strip()
        if name.startswith("."):
            continue
        entries.append(
            {
                "name": name,
                "attrs": match.group(2),
                "size": int(match.group(3)),
                "modified": match.group(4).strip(),
            }
        )
    return entries


def smb_definition(tenant_id: str = "system") -> ToolDefinition:
    """Return the durable ToolDefinition for ``nexus.recon.smb``."""
    return ToolDefinition(
        tool_id="nexus.recon.smb",
        name="SMB share enumeration",
        tenant_id=tenant_id,
        description=(
            "Enumera un servicio SMB: lista shares, lista el contenido de un "
            "share o descarga un archivo (anónimo/guest por defecto o con "
            "credenciales validadas). Read-only. Es el primitivo para detectar "
            "shares accesibles o escribibles y leer notas/credenciales."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "minLength": 1, "maxLength": 255},
                "action": {"type": "string", "enum": list(SMB_RECON_ACTIONS), "default": "shares"},
                "share": {"type": "string", "minLength": 1, "maxLength": 128},
                "remote_path": {"type": "string", "maxLength": 1024},
                "local_path": {"type": "string", "maxLength": 1024},
                "username": {"type": "string", "maxLength": 128},
                "password": {"type": "string", "maxLength": 512},
                "timeout_seconds": {"type": "integer", "minimum": 10, "maximum": SMB_MAX_TIMEOUT_SECONDS},
            },
            "required": ["target"],
            "additionalProperties": False,
        },
        risk=RiskLevel.LOW,
        effect="read_only",
        required_permissions=["execute:tool:nexus.recon.smb"],
        timeout_seconds=SMB_MAX_TIMEOUT_SECONDS,
        max_output_bytes=2_000_000,
        scope_target_field="target",
        scope_required=True,
    )


def smb_upload_definition(tenant_id: str = "system") -> ToolDefinition:
    """Return the durable ToolDefinition for ``nexus.post.smb_upload``."""
    return ToolDefinition(
        tool_id="nexus.post.smb_upload",
        name="SMB file upload (share write)",
        tenant_id=tenant_id,
        description=(
            "Sube un archivo del workspace a un share SMB con acceso de "
            "escritura (p. ej. un webshell .aspx en un share mapeado a la "
            "webroot de IIS). Requiere credencial que autentique contra el "
            "servicio. Escribe en el objetivo."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "minLength": 1, "maxLength": 255},
                "share": {"type": "string", "minLength": 1, "maxLength": 128},
                "local_path": {"type": "string", "minLength": 1, "maxLength": 1024},
                "remote_path": {"type": "string", "minLength": 1, "maxLength": 1024},
                "username": {"type": "string", "maxLength": 128},
                "password": {"type": "string", "maxLength": 512},
                "timeout_seconds": {"type": "integer", "minimum": 10, "maximum": SMB_MAX_TIMEOUT_SECONDS},
            },
            "required": ["target", "share", "local_path", "remote_path"],
            "additionalProperties": False,
        },
        risk=RiskLevel.MEDIUM,
        effect="exploit",
        required_permissions=["execute:tool:nexus.post.smb_upload"],
        timeout_seconds=SMB_MAX_TIMEOUT_SECONDS,
        max_output_bytes=2_000_000,
        scope_target_field="target",
        scope_required=True,
    )


def _bounded_timeout(arguments: dict) -> int:
    requested = arguments.get("timeout_seconds")
    return min(
        SMB_MAX_TIMEOUT_SECONDS,
        max(10, int(requested) if requested else SMB_DEFAULT_TIMEOUT_SECONDS),
    )


def _workspace_root() -> str:
    return os.getenv("NEXUS_WORKSPACE_ROOT", os.getcwd())


def _resolve_local(value: Any, *, required: bool) -> str:
    """Return a workspace-confined absolute path for a local file."""
    text = str(value or "").strip()
    if not text:
        if required:
            raise ValueError("local_path is required")
        return ""
    if any(ord(ch) < 0x20 for ch in text):
        raise ValueError("local_path contains control characters")
    root = Path(_workspace_root()).resolve()
    candidate = (root / text).resolve()
    if candidate != root and root not in candidate.parents:
        raise ValueError("local_path must stay inside the workspace")
    return str(candidate)


async def smb_handler(arguments: dict, context: RunContext) -> ToolResult:
    """Run an allowlisted read-only SMB enumeration/download via ``smbclient``."""
    target = validate_host(arguments.get("target"))
    action = str(arguments.get("action") or "shares").strip().lower()
    if action not in SMB_RECON_ACTIONS:
        raise ValueError(f"unsupported smb action: {action!r}")
    share = _validate_share(arguments.get("share")) if action in {"list", "get"} else ""
    remote_path = _validate_remote_path(arguments.get("remote_path"), required=action == "get")
    username = validate_username(arguments["username"]) if arguments.get("username") else ""
    password = str(arguments.get("password") or "")
    if password and not username:
        raise ValueError("password authentication requires a username")
    timeout_seconds = _bounded_timeout(arguments)

    binary = resolve_ad_binary(*SMB_BINARY_CANDIDATES)
    if not binary:
        return ToolResult(verification_method="smbclient_unavailable")

    local_target = ""
    if action == "get":
        default_name = Path(remote_path.replace("\\", "/")).name or "download.bin"
        local_target = _resolve_local(arguments.get("local_path") or default_name, required=True)

    argv = _smbclients_argv(binary, target, username, password)
    if action == "shares":
        argv.extend(["-L", f"//{target}"])
    else:
        argv.append(f"//{target}/{share}")
        if action == "list":
            argv.extend(["-c", "ls"])
        else:
            argv.extend(["-c", f'get "{remote_path}" "{local_target}"'])

    workspace_root = _workspace_root()
    sandbox = ad_sandbox(workspace_root, binary)
    result = await run_in_sandbox(
        sandbox,
        argv,
        timeout_seconds=timeout_seconds,
        image_env="NEXUS_SMB_IMAGE",
        default_image="smbclient",
    )

    evidence: dict[str, Any] = {
        "target": target,
        "action": action,
        "share": share,
        "anonymous": not username,
        "timeout_seconds": timeout_seconds,
    }
    if result.timed_out:
        return ToolResult(
            output={"error": "smbclient run timed out", "target": target, "action": action},
            verified=False,
            verification_method="smb_timeout",
            evidence=evidence,
            exit_code=result.exit_code,
            accepted_exit_codes=(0,),
            stdout=result.stdout,
            stderr=result.stderr,
            timed_out=True,
        )

    output: dict[str, Any] = {
        "target": target,
        "action": action,
        "share": share or None,
        "username": username or None,
        "anonymous": not username,
    }

    if action == "shares":
        shares = _parse_shares(result.stdout)
        output["shares"] = shares
        output["count"] = len(shares)
        evidence["count"] = len(shares)
        return ToolResult(
            output=output,
            verified=bool(shares) and result.exit_code == 0,
            verification_method="smb_shares_parsed" if shares else "smb_shares_empty",
            evidence=evidence,
            exit_code=result.exit_code,
            accepted_exit_codes=(0,),
            stdout=result.stdout,
            stderr=result.stderr,
        )

    if action == "list":
        entries = _parse_directory(result.stdout)
        failure = _connection_failed(result.stdout, result.stderr)
        output["entries"] = entries[:SMB_MAX_LISTING_LINES]
        output["count"] = len(entries)
        output["error"] = failure
        evidence["count"] = len(entries)
        evidence["nt_status"] = failure
        return ToolResult(
            output=output,
            verified=failure is None and result.exit_code == 0,
            verification_method="smb_listing_parsed" if failure is None else "smb_listing_failed",
            evidence=evidence,
            exit_code=result.exit_code,
            accepted_exit_codes=(0,),
            stdout=result.stdout,
            stderr=result.stderr,
        )

    # action == "get"
    failure = _connection_failed(result.stdout, result.stderr)
    path = Path(local_target)
    size = path.stat().st_size if path.is_file() else 0
    digest = ""
    head = b""
    if size:
        with path.open("rb") as handle:
            digest = hashlib.sha256()
            head = handle.read(4096)
            digest.update(head)
            for chunk in iter(lambda: handle.read(65536), b""):
                digest.update(chunk)
        digest = digest.hexdigest()
    output.update(
        {
            "file": path.name,
            "path": str(path),
            "size": size,
            "sha256": digest,
            "preview": head.decode("utf-8", "replace"),
            "error": failure,
        }
    )
    evidence.update({"file": path.name, "size": size, "sha256": digest})
    ok = failure is None and result.exit_code == 0 and size > 0
    return ToolResult(
        output=output,
        verified=ok,
        verification_method="smb_download_verified" if ok else "smb_download_failed",
        evidence=evidence,
        exit_code=result.exit_code,
        accepted_exit_codes=(0,),
        stdout=result.stdout,
        stderr=result.stderr,
    )


async def smb_upload_handler(arguments: dict, context: RunContext) -> ToolResult:
    """Upload one workspace file into a share via ``smbclient``."""
    target = validate_host(arguments.get("target"))
    share = _validate_share(arguments.get("share"))
    local_path = _resolve_local(arguments.get("local_path"), required=True)
    remote_path = _validate_remote_path(arguments.get("remote_path"), required=True)
    username = validate_username(arguments["username"]) if arguments.get("username") else ""
    password = str(arguments.get("password") or "")
    if password and not username:
        raise ValueError("password authentication requires a username")
    timeout_seconds = _bounded_timeout(arguments)

    source = Path(local_path)
    if not source.is_file():
        raise ValueError("local_path must point to an existing workspace file")

    binary = resolve_ad_binary(*SMB_BINARY_CANDIDATES)
    if not binary:
        return ToolResult(verification_method="smbclient_unavailable")

    argv = _smbclients_argv(binary, target, username, password)
    argv.append(f"//{target}/{share}")
    argv.extend(["-c", f'put "{local_path}" "{remote_path}"'])

    workspace_root = _workspace_root()
    sandbox = ad_sandbox(workspace_root, binary)
    result = await run_in_sandbox(
        sandbox,
        argv,
        timeout_seconds=timeout_seconds,
        image_env="NEXUS_SMB_IMAGE",
        default_image="smbclient",
    )

    failure = _connection_failed(result.stdout, result.stderr)
    evidence: dict[str, Any] = {
        "target": target,
        "share": share,
        "local_path": local_path,
        "remote_path": remote_path,
        "uploaded_bytes": source.stat().st_size,
        "anonymous": not username,
        "nt_status": failure,
        "timeout_seconds": timeout_seconds,
    }
    if result.timed_out:
        return ToolResult(
            output={"error": "smbclient upload timed out", "target": target},
            verified=False,
            verification_method="smb_upload_timeout",
            evidence=evidence,
            exit_code=result.exit_code,
            accepted_exit_codes=(0,),
            stdout=result.stdout,
            stderr=result.stderr,
            timed_out=True,
        )

    ok = failure is None and result.exit_code == 0
    return ToolResult(
        output={
            "target": target,
            "share": share,
            "remote_path": remote_path,
            "local_path": local_path,
            "uploaded_bytes": source.stat().st_size,
            "anonymous": not username,
            "error": failure,
        },
        verified=ok,
        verification_method="smb_upload_done" if ok else "smb_upload_failed",
        evidence=evidence,
        exit_code=result.exit_code,
        accepted_exit_codes=(0,),
        stdout=result.stdout,
        stderr=result.stderr,
    )
