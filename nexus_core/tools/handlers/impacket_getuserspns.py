"""Durable ``nexus.attack.impacket_getuserspns`` handler (MEDIUM risk).

Kerberoasting with Impacket's ``GetUserSPNs``. This tool takes
``domain/username:password`` as its positional argument (not the
``...@host`` form of secretsdump/psexec); the domain controller is selected with
``-dc-ip``/``-dc-host``. Requires durable human approval (MEDIUM is below the
forced-approval threshold, so the gateway applies the operator's policy).
"""

from __future__ import annotations

from nexus_core.tools.output_files import read_output_text

import os
from pathlib import Path
from typing import Any

from nexus_core.kernel.models import RiskLevel, RunContext, ToolDefinition, ToolResult
from nexus_core.tools.parsers.impacket_getuserspns import parse_getuserspns_output

from ._ad import (
    ad_sandbox,
    canonicalize_flags,
    validate_domain,
    validate_host,
    validate_username,
)
from ._exec import run_in_sandbox, safe_run_id
from ._impacket_resolver import resolve_impacket_binary

GETUSERSPNS_ALLOWED_FLAGS: dict[str, bool] = {
    "-target-domain": True,
    "-no-preauth": True,
    "-stealth": False,
    "-machine-only": False,
    "-usersfile": True,
    "-request": False,
    "-request-user": True,
    "-request-machine": True,
    "-save": False,
    "-no-rc4": False,
    "-ts": False,
    "-debug": False,
    "-hashes": True,
    "-no-pass": False,
    "-k": False,
    "-aesKey": True,
    "-dc-ip": True,
    "-dc-host": True,
}

GETUSERSPNS_MANAGED_FLAGS: set[str] = {"-outputfile", "-request"}
GETUSERSPNS_FORBIDDEN_FLAGS: set[str] = set()

GETUSERSPNS_DEFAULT_TIMEOUT_SECONDS = 600
GETUSERSPNS_MAX_TIMEOUT_SECONDS = 1800


def getuserspns_definition(tenant_id: str = "system") -> ToolDefinition:
    """Return the durable ToolDefinition for the GetUserSPNs tool."""
    return ToolDefinition(
        tool_id="nexus.attack.impacket_getuserspns",
        name="Impacket GetUserSPNs (Kerberoasting)",
        tenant_id=tenant_id,
        description=(
            "Enumera cuentas con SPN y solicita tickets de servicio (Kerberoasting) "
            "con GetUserSPNs de Impacket. El positional es domain/username:password; "
            "el DC se indica con -dc-ip. Requiere aprobación según política."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "dc_ip": {"type": "string", "minLength": 1, "maxLength": 255},
                "domain": {"type": "string", "minLength": 1, "maxLength": 255},
                "username": {"type": "string", "minLength": 1, "maxLength": 128},
                "password": {"type": "string", "maxLength": 512},
                "hash": {"type": "string", "maxLength": 65},
                "request": {"type": "boolean", "default": False},
                "request_user": {"type": "string", "maxLength": 128},
                "dc_host": {"type": "string", "maxLength": 255},
                "timeout_seconds": {
                    "type": "integer",
                    "minimum": 30,
                    "maximum": GETUSERSPNS_MAX_TIMEOUT_SECONDS,
                },
                "flags": {
                    "type": "array",
                    "items": {"type": "string", "maxLength": 256},
                    "maxItems": 20,
                },
            },
            "required": ["dc_ip", "domain", "username"],
            "additionalProperties": False,
        },
        risk=RiskLevel.MEDIUM,
        effect="credential_access",
        required_permissions=["execute:tool:nexus.attack.impacket_getuserspns"],
        timeout_seconds=GETUSERSPNS_MAX_TIMEOUT_SECONDS,
        max_output_bytes=10_000_000,
        scope_target_field="dc_ip",
        scope_required=True,
    )


async def impacket_getuserspns_handler(arguments: dict, context: RunContext) -> ToolResult:
    """Run an allowlisted GetUserSPNs through the sandbox."""
    dc_ip = validate_host(arguments.get("dc_ip"), field="dc_ip")
    domain = validate_domain(arguments.get("domain"))
    username = validate_username(arguments.get("username"))
    password = str(arguments["password"]) if arguments.get("password") else None
    ntlm_hash = str(arguments["hash"]) if arguments.get("hash") else None
    if not password and not ntlm_hash:
        raise ValueError("GetUserSPNs requires a password or a hash")

    requested_timeout = arguments.get("timeout_seconds")
    timeout_seconds = min(
        GETUSERSPNS_MAX_TIMEOUT_SECONDS,
        max(
            30,
            int(requested_timeout)
            if requested_timeout
            else GETUSERSPNS_DEFAULT_TIMEOUT_SECONDS,
        ),
    )

    user_flags = canonicalize_flags(
        arguments.get("flags"),
        GETUSERSPNS_ALLOWED_FLAGS,
        GETUSERSPNS_FORBIDDEN_FLAGS,
    )
    user_flags = [token for token in user_flags if token not in GETUSERSPNS_MANAGED_FLAGS]

    binary = resolve_impacket_binary("GetUserSPNs")
    if not binary:
        return ToolResult(verification_method="getuserspns_unavailable")

    workspace_root = os.getenv("NEXUS_WORKSPACE_ROOT", os.getcwd())
    run_id = safe_run_id(context)
    output_path = Path(workspace_root).resolve() / f"guspns_{run_id}.txt"

    request = bool(arguments.get("request")) or bool(arguments.get("request_user"))
    # GetUserSPNs takes domain/username[:password] as a single positional arg.
    positional = f"{domain}/{username}"
    if password:
        positional += f":{password}"

    argv = [binary, "-dc-ip", dc_ip]
    if arguments.get("dc_host"):
        argv.extend(["-dc-host", validate_host(arguments["dc_host"], field="dc_host")])
    if ntlm_hash:
        argv.extend(["-hashes", ntlm_hash])
    if request:
        argv.extend(["-request", "-outputfile", str(output_path)])
    if requested_user := arguments.get("request_user"):
        argv.extend(["-request-user", validate_username(requested_user, field="request_user")])
    argv.extend(user_flags)
    argv.append(positional)

    sandbox = ad_sandbox(workspace_root, binary)
    result = await run_in_sandbox(
        sandbox,
        argv,
        timeout_seconds=timeout_seconds,
        image_env="NEXUS_IMPACKET_IMAGE",
        default_image="impacket",
    )

    evidence: dict[str, Any] = {
        "dc_ip": dc_ip,
        "domain": domain,
        "username": username,
        "request": request,
        "timeout_seconds": timeout_seconds,
        "flags": list(user_flags),
    }
    if result.timed_out:
        return ToolResult(
            output={"error": "GetUserSPNs run timed out", "dc_ip": dc_ip},
            verified=False,
            verification_method="getuserspns_timeout",
            evidence=evidence,
            exit_code=result.exit_code,
            accepted_exit_codes=(0,),
            stdout=result.stdout,
            stderr=result.stderr,
            timed_out=True,
        )

    text = result.stdout
    try:
        if output_path.exists():
            text = text + "\n" + read_output_text(output_path)
    except OSError:
        pass

    parsed = parse_getuserspns_output(text)
    evidence.update(
        {
            "spn_count": len(parsed.service_principals),
            "hash_count": len(parsed.hashes),
            "raw_sha256": parsed.raw_sha256,
        }
    )
    return ToolResult(
        output={"dc_ip": dc_ip, "domain": domain, **parsed.to_dict()},
        verified=result.exit_code == 0,
        verification_method="getuserspns_text_parsed",
        evidence=evidence,
        exit_code=result.exit_code,
        accepted_exit_codes=(0,),
        stdout=result.stdout,
        stderr=result.stderr,
    )
