"""Durable ``nexus.attack.impacket_psexec`` handler (DESTRUCTIVE risk).

Remote command execution with Impacket's ``psexec.py``. Impacket identifies this
tool as **RemComSvc-based** (not a fixed ``PSEXESVC.exe`` service), so evidence
must not assume that binary name. It uploads a service binary, runs the command
as SYSTEM and leaves service/registry traces. DESTRUCTIVE: the gateway always
requires a foreground human approval, even inside ``--trust-mode``.

Impacket's psexec is a one-shot execution, not a persistent session, so no
``kernel_sessions`` record is opened here.
"""

from __future__ import annotations

import os
from typing import Any

from nexus_core.kernel.models import RiskLevel, RunContext, ToolDefinition, ToolResult
from nexus_core.tools.parsers.impacket_psexec import parse_psexec_output

from ._ad import (
    ad_sandbox,
    canonicalize_flags,
    validate_domain,
    validate_host,
    validate_username,
)
from ._exec import run_in_sandbox, safe_run_id
from ._impacket_resolver import resolve_impacket_binary
from ._proxy import ensure_proxy_in_scope, parse_proxy, resolve_proxychains, wrap_argv

PSEXEC_ALLOWED_FLAGS: dict[str, bool] = {
    "-hashes": True,
    "-no-pass": False,
    "-k": False,
    "-aesKey": True,
    "-keytab": True,
    "-dc-ip": True,
    "-target-ip": True,
    "-port": True,
    "-service-name": True,
    "-remote-binary-name": True,
    "-codec": True,
    "-ts": False,
    "-debug": False,
}

PSEXEC_MANAGED_FLAGS: set[str] = set()
PSEXEC_FORBIDDEN_FLAGS: set[str] = {
    "-path",
    "-file",
    "-c",
}

PSEXEC_DEFAULT_TIMEOUT_SECONDS = 300
PSEXEC_MAX_TIMEOUT_SECONDS = 900
PSEXEC_MAX_COMMAND_CHARS = 4000


def psexec_definition(tenant_id: str = "system") -> ToolDefinition:
    """Return the durable ToolDefinition for the psexec tool."""
    return ToolDefinition(
        tool_id="nexus.attack.impacket_psexec",
        name="Impacket psexec (RemComSvc)",
        tenant_id=tenant_id,
        description=(
            "Ejecución remota de comandos con psexec de Impacket (basado en "
            "RemComSvc, propietario de la herramienta). Sube un binario de "
            "servicio y ejecuta como SYSTEM; deja rastros. DESTRUCTIVE: siempre "
            "requiere aprobación humana explícita."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "minLength": 1, "maxLength": 255},
                "domain": {"type": "string", "maxLength": 255},
                "username": {"type": "string", "minLength": 1, "maxLength": 128},
                "password": {"type": "string", "maxLength": 512},
                "hash": {"type": "string", "maxLength": 65},
                "command": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": PSEXEC_MAX_COMMAND_CHARS,
                },
                "port": {"type": "integer", "minimum": 1, "maximum": 65535},
                "service_name": {"type": "string", "maxLength": 128},
                "target_ip": {"type": "string", "maxLength": 255},
                "timeout_seconds": {
                    "type": "integer",
                    "minimum": 30,
                    "maximum": PSEXEC_MAX_TIMEOUT_SECONDS,
                },
                "proxy": {
                    "type": "string",
                    "maxLength": 255,
                    "description": (
                        "Túnel SOCKS por el que sale psexec (ej. "
                        "socks5://127.0.0.1:1080). Se ejecuta con proxychains4 "
                        "dentro de la tool: la salida se parsea y el canal queda "
                        "verificado. Sin credenciales en la URL."
                    ),
                },
                "flags": {
                    "type": "array",
                    "items": {"type": "string", "maxLength": 256},
                    "maxItems": 20,
                },
            },
            "required": ["target", "username", "command"],
            "additionalProperties": False,
        },
        risk=RiskLevel.DESTRUCTIVE,
        effect="execution",
        required_permissions=["execute:tool:nexus.attack.impacket_psexec"],
        timeout_seconds=PSEXEC_MAX_TIMEOUT_SECONDS,
        max_output_bytes=5_000_000,
        scope_target_field="target",
        scope_required=True,
    )


def validate_psexec_command(command: object) -> str:
    """Reject null bytes and enforce a bounded command string."""
    if not isinstance(command, str) or not command.strip():
        raise ValueError("command must be a non-empty string")
    if len(command) > PSEXEC_MAX_COMMAND_CHARS:
        raise ValueError("command is too long")
    if "\x00" in command:
        raise ValueError("command must not contain null bytes")
    return command


async def impacket_psexec_handler(arguments: dict, context: RunContext) -> ToolResult:
    """Run an allowlisted Impacket psexec through the sandbox."""
    target = validate_host(arguments.get("target"))
    username = validate_username(arguments.get("username"))
    domain = validate_domain(arguments["domain"]) if arguments.get("domain") else ""
    password = str(arguments["password"]) if arguments.get("password") else None
    ntlm_hash = str(arguments["hash"]) if arguments.get("hash") else None
    if not password and not ntlm_hash:
        raise ValueError("psexec requires a password or a hash")
    command = validate_psexec_command(arguments.get("command"))

    requested_timeout = arguments.get("timeout_seconds")
    timeout_seconds = min(
        PSEXEC_MAX_TIMEOUT_SECONDS,
        max(
            30,
            int(requested_timeout)
            if requested_timeout
            else PSEXEC_DEFAULT_TIMEOUT_SECONDS,
        ),
    )

    user_flags = canonicalize_flags(
        arguments.get("flags"), PSEXEC_ALLOWED_FLAGS, PSEXEC_FORBIDDEN_FLAGS
    )

    binary = resolve_impacket_binary("psexec")
    if not binary:
        return ToolResult(verification_method="psexec_unavailable")

    auth = f"{domain}/" if domain else ""
    auth += username
    if password:
        auth += f":{password}"
    positional = f"{auth}@{target}"

    argv = [binary]
    if ntlm_hash:
        argv.extend(["-hashes", ntlm_hash])
    if arguments.get("target_ip"):
        argv.extend(
            ["-target-ip", validate_host(arguments["target_ip"], field="target_ip")]
        )
    if arguments.get("port"):
        argv.extend(["-port", str(int(arguments["port"]))])
    if arguments.get("service_name"):
        argv.extend(["-service-name", str(arguments["service_name"])])
    argv.extend(user_flags)
    argv.extend([positional, command])

    workspace_root = os.getenv("NEXUS_WORKSPACE_ROOT", os.getcwd())
    # F1: the tunnel is applied here so the handler still parses the remote
    # command's output (a ``shell.exec`` wrapper derives no fact).
    proxy_value = arguments.get("proxy")
    proxy = parse_proxy(proxy_value) if proxy_value else None
    proxychains = ""
    if proxy is not None:
        ensure_proxy_in_scope(proxy, getattr(context, "scope", None))
        proxychains = resolve_proxychains() or ""
        if not proxychains:
            return ToolResult(
                output={
                    "error": "proxychains4 is not installed",
                    "proxy": proxy.address,
                    "guidance": (
                        "Instala proxychains4 (`sudo apt install proxychains4`) "
                        "o exporta NEXUS_PROXYCHAINS_BINARY=<ruta>."
                    ),
                },
                verified=False,
                outcome="unavailable",
                verification_method="proxychains_unavailable",
                evidence={"proxy": proxy.describe()},
            )

    proxy_evidence: dict[str, Any] = {}
    if proxy is not None:
        argv, proxy_evidence = wrap_argv(
            argv,
            proxy,
            binary=proxychains,
            root=workspace_root,
            run_id=safe_run_id(context),
        )

    sandbox = ad_sandbox(workspace_root, binary, proxychains)
    result = await run_in_sandbox(
        sandbox,
        argv,
        timeout_seconds=timeout_seconds,
        image_env="NEXUS_IMPACKET_IMAGE",
        default_image="impacket",
    )

    evidence: dict[str, Any] = {
        "target": target,
        "domain": domain,
        "username": username,
        "command": command,
        "timeout_seconds": timeout_seconds,
        "flags": list(user_flags),
        **proxy_evidence,
    }
    if result.timed_out:
        return ToolResult(
            output={"error": "psexec run timed out", "target": target},
            verified=False,
            verification_method="psexec_timeout",
            evidence=evidence,
            exit_code=result.exit_code,
            accepted_exit_codes=(0,),
            stdout=result.stdout,
            stderr=result.stderr,
            timed_out=True,
        )

    parsed = parse_psexec_output(result.stdout, command)
    evidence.update(
        {
            "line_count": len(parsed.lines),
            "connected": parsed.connected,
            "raw_sha256": parsed.raw_output_sha256,
        }
    )
    return ToolResult(
        output={"target": target, **parsed.to_dict()},
        verified=result.exit_code == 0,
        verification_method="psexec_output_parsed",
        evidence=evidence,
        exit_code=result.exit_code,
        accepted_exit_codes=(0,),
        stdout=result.stdout,
        stderr=result.stderr,
    )
