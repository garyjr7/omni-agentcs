"""Durable ``nexus.recon.netexec`` handler: SMB/LDAP enumeration with NetExec.

Recon only. The handler runs the resolved ``nxc`` binary through the sandbox
allowlist, always forces ``--no-progress`` (the flag the binary actually
exposes; it has no ``-q``), and maps the model's ``operation`` to the real
enumeration flags (``--shares``, ``--users``, ``--groups``, ``--smb-sessions``,
``--disks``). Command execution, module loading and credential dumping are
forbidden: this tool does not run ``-x``/``-X``/``-M``/``--sam``.
"""

from __future__ import annotations

import os
from typing import Any

from nexus_core.kernel.models import RiskLevel, RunContext, ToolDefinition, ToolResult
from nexus_core.tools.parsers.netexec import parse_netexec_output

from ._ad import (
    ad_sandbox,
    canonicalize_flags,
    resolve_ad_binary,
    validate_domain,
    validate_host,
    validate_username,
)
from ._exec import run_in_sandbox

NETEXEC_PROTOCOLS = ("smb", "ldap")

#: operation name -> the real NetExec enumeration flag ('' = fingerprint only).
NETEXEC_OPERATIONS: dict[str, str] = {
    "fingerprint": "",
    "shares": "--shares",
    "users": "--users",
    "groups": "--groups",
    "smb_sessions": "--smb-sessions",
    "disks": "--disks",
    "pass_pol": "--pass-pol",
    "loggedon_users": "--loggedon-users",
    "computers": "--computers",
    "dc_list": "--dc-list",
    "active_users": "--active-users",
    "rid_brute": "--rid-brute",
    "delegation": "--find-delegation",
}

NETEXEC_SMB_ONLY = frozenset(
    {"shares", "smb_sessions", "disks", "loggedon_users", "pass_pol", "computers"}
)
NETEXEC_LDAP_ONLY = frozenset(
    {"dc_list", "active_users", "delegation", "computers", "pass_pol"}
)

#: Non-structural flags the model may add: ``flag -> consumes a value``.
NETEXEC_ALLOWED_FLAGS: dict[str, bool] = {
    "-d": True,
    "--domain": True,
    "--port": True,
    "-t": True,
    "--threads": True,
    "--timeout": True,
    "--verbose": False,
    "--debug": False,
    "--no-bruteforce": False,
    "--continue-on-success": False,
    "--no-smbv1": False,
    "--no-admin-check": False,
    "--no-write-check": False,
    "-k": False,
    "--kerberos": False,
    "--pass-pol": False,
    "-H": True,
    "--hash": True,
}

#: Execution, dumping, module and file-transfer flags are refused outright.
NETEXEC_FORBIDDEN_FLAGS: set[str] = {
    "-x",
    "-X",
    "-M",
    "--module",
    "-o",
    "--options",
    "-L",
    "--list-modules",
    "-id",
    "--sam",
    "--lsa",
    "--ntds",
    "--dpapi",
    "--sccm",
    "--put-file",
    "--get-file",
    "--taskkill",
    "--wmi",
    "--amsi-bypass",
    "--obfs",
    "--log",
    "--gfail-limit",
    "--ufail-limit",
    "--fail-limit",
}

NETEXEC_DEFAULT_THREADS = 10
NETEXEC_MAX_THREADS = 50
NETEXEC_DEFAULT_TIMEOUT_SECONDS = 600
NETEXEC_MAX_TIMEOUT_SECONDS = 1800

NOISE_LEVELS = {"low": 0, "medium": 1, "high": 2}
NOISE_NAMES = ("low", "medium", "high")


def netexec_noise_level(threads: int) -> str:
    """Map a thread count to the aggregate noise level."""
    if threads <= 5:
        return "low"
    if threads <= 20:
        return "medium"
    return "high"


def netexec_definition(tenant_id: str = "system") -> ToolDefinition:
    """Return the durable ToolDefinition for ``nexus.recon.netexec``."""
    return ToolDefinition(
        tool_id="nexus.recon.netexec",
        name="NetExec SMB/LDAP enumeration",
        tenant_id=tenant_id,
        description=(
            "Enumera hosts AD por SMB o LDAP con NetExec: fingerprint, shares, "
            "usuarios, grupos, sesiones SMB, discos y política de contraseñas. "
            "No ejecuta comandos ni vuelca credenciales."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "protocol": {
                    "type": "string",
                    "enum": list(NETEXEC_PROTOCOLS),
                    "default": "smb",
                },
                "target": {"type": "string", "minLength": 1, "maxLength": 255},
                "operation": {
                    "type": "string",
                    "enum": list(NETEXEC_OPERATIONS),
                    "default": "fingerprint",
                },
                "domain": {"type": "string", "maxLength": 255},
                "username": {"type": "string", "maxLength": 128},
                "password": {"type": "string", "maxLength": 512},
                "hash": {"type": "string", "maxLength": 65},
                "threads": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": NETEXEC_MAX_THREADS,
                },
                "timeout_seconds": {
                    "type": "integer",
                    "minimum": 30,
                    "maximum": NETEXEC_MAX_TIMEOUT_SECONDS,
                },
                "flags": {
                    "type": "array",
                    "items": {"type": "string", "maxLength": 256},
                    "maxItems": 20,
                },
            },
            "required": ["protocol", "target"],
            "additionalProperties": False,
        },
        risk=RiskLevel.MEDIUM,
        effect="recon",
        required_permissions=["execute:tool:nexus.recon.netexec"],
        timeout_seconds=NETEXEC_MAX_TIMEOUT_SECONDS,
        max_output_bytes=5_000_000,
        scope_target_field="target",
        scope_required=True,
    )


async def netexec_handler(arguments: dict, context: RunContext) -> ToolResult:
    """Run an allowlisted NetExec enumeration through the sandbox."""
    protocol = str(arguments.get("protocol") or "smb").strip().lower()
    if protocol not in NETEXEC_PROTOCOLS:
        raise ValueError(f"netexec protocol is not allowed: {protocol!r}")
    target = validate_host(arguments.get("target"))
    operation = str(arguments.get("operation") or "fingerprint").strip().lower()
    if operation not in NETEXEC_OPERATIONS:
        raise ValueError(f"netexec operation is not allowed: {operation!r}")
    if operation in NETEXEC_SMB_ONLY and protocol != "smb":
        raise ValueError(f"operation {operation!r} is only available over smb")
    if operation in NETEXEC_LDAP_ONLY and protocol != "ldap":
        raise ValueError(f"operation {operation!r} is only available over ldap")

    raw_threads = arguments.get("threads")
    threads = min(
        NETEXEC_MAX_THREADS,
        max(1, int(raw_threads) if raw_threads else NETEXEC_DEFAULT_THREADS),
    )
    requested_timeout = arguments.get("timeout_seconds")
    timeout_seconds = min(
        NETEXEC_MAX_TIMEOUT_SECONDS,
        max(
            30,
            int(requested_timeout)
            if requested_timeout
            else NETEXEC_DEFAULT_TIMEOUT_SECONDS,
        ),
    )

    user_flags = canonicalize_flags(
        arguments.get("flags"), NETEXEC_ALLOWED_FLAGS, NETEXEC_FORBIDDEN_FLAGS
    )

    binary = resolve_ad_binary("nxc", "netexec")
    if not binary:
        return ToolResult(
            verification_method="netexec_unavailable",
        )

    domain = validate_domain(arguments["domain"]) if arguments.get("domain") else ""
    username = (
        validate_username(arguments["username"]) if arguments.get("username") else ""
    )
    password = arguments.get("password")
    ntlm_hash = arguments.get("hash")
    if ntlm_hash and not arguments.get("username"):
        raise ValueError("hash authentication requires a username")
    if password and not arguments.get("username"):
        raise ValueError("password authentication requires a username")

    # Several netexec options take ``nargs='+'``/``'*'`` (``-u``, ``-p``,
    # ``--users``, ``--groups`` ...). The positional target must therefore be
    # emitted *before* them or argparse consumes it as a value of the option
    # (measured: ``-p ChangeMe#1234 10.66.164.10 --users`` makes nxc exit 2 with
    # "the following arguments are required: target" — a false tool failure).
    argv = [binary, protocol, "--no-progress", "-t", str(threads), target]
    if domain:
        argv.extend(["-d", domain])
    if username:
        argv.extend(["-u", username])
    if password:
        argv.extend(["-p", str(password)])
    if ntlm_hash:
        argv.extend(["-H", str(ntlm_hash)])
    argv.extend(user_flags)
    operation_flag = NETEXEC_OPERATIONS[operation]
    if operation_flag:
        argv.append(operation_flag)

    noise_level = netexec_noise_level(threads)
    warnings: list[str] = []
    if noise_level == "high":
        warnings.append(f"high noise profile: {threads} threads")

    workspace_root = os.getenv("NEXUS_WORKSPACE_ROOT", os.getcwd())
    sandbox = ad_sandbox(workspace_root, binary)
    result = await run_in_sandbox(
        sandbox,
        argv,
        timeout_seconds=timeout_seconds,
        image_env="NEXUS_NETEXEC_IMAGE",
        default_image="netexec",
    )

    evidence: dict[str, Any] = {
        "protocol": protocol,
        "target": target,
        "operation": operation,
        "threads": threads,
        "noise_level": noise_level,
        "timeout_seconds": timeout_seconds,
        "flags": list(user_flags),
        "warnings": warnings,
    }
    if result.timed_out:
        return ToolResult(
            output={
                "error": "netexec run timed out",
                "target": target,
                "protocol": protocol,
            },
            verified=False,
            verification_method="netexec_timeout",
            evidence=evidence,
            exit_code=result.exit_code,
            accepted_exit_codes=(0, 1),
            stdout=result.stdout,
            stderr=result.stderr,
            timed_out=True,
        )

    parsed = parse_netexec_output(result.stdout, protocol=protocol)
    evidence.update(
        {"count": len(parsed.entries), "raw_output_sha256": parsed.raw_output_sha256}
    )
    return ToolResult(
        output={
            "protocol": protocol,
            "target": target,
            "operation": operation,
            "noise_level": noise_level,
            "count": len(parsed.entries),
            **parsed.to_dict(),
        },
        verified=result.exit_code in {0, 1},
        verification_method="netexec_text_parsed",
        evidence=evidence,
        exit_code=result.exit_code,
        accepted_exit_codes=(0, 1),
        stdout=result.stdout,
        stderr=result.stderr,
    )
