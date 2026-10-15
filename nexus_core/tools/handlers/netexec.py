"""Durable ``nexus.recon.netexec`` handler: SMB/LDAP enumeration with NetExec.

Recon only. The handler runs the resolved ``nxc`` binary through the sandbox
allowlist, always forces ``--no-progress`` (the flag the binary actually
exposes; it has no ``-q``), and maps the model's ``operation`` to the real
enumeration flags (``--shares``, ``--users``, ``--groups``, ``--smb-sessions``,
``--disks``). Command execution, module loading and credential dumping are
forbidden: this tool does not run ``-x``/``-X``/``-M``/``--sam``.

The post-condition separates *the operation ran and the target answered* from
*the body failed*: a determinate answer netexec prints with an exit code
outside ``{0, 1}`` (a refusal, a share that is not there) completes with its
outcome instead of raising (V0-31). An answer the handler cannot classify keeps
failing closed.
"""

from __future__ import annotations

import os
import re
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

#: Determinate answers the target sends back, printed by netexec in place of a
#: crash. Measured negatives in RUN_sala10 (``smb shares``, ``rid_brute``,
#: ``ldap users``): ``STATUS_USER_SESSION_DELETED``, ``0xc0000022`` and
#: ``operationsError`` ("bind must be completed"). Each maps to the outcome
#: recorded instead of a ``RuntimeError`` (V0-31); a token that is not listed
#: here stays unclassified and the invocation keeps failing closed.
NETEXEC_STATUS_OUTCOMES: dict[str, str] = {
    # The target refused the request, or the operation needs a credential the
    # caller did not present (SMB ``STATUS_*`` and the LDAP errors netexec
    # surfaces after parsing the answer).
    "STATUS_ACCESS_DENIED": "denied",
    "0XC0000022": "denied",
    "STATUS_LOGON_FAILURE": "denied",
    "STATUS_WRONG_PASSWORD": "denied",
    "STATUS_ACCOUNT_DISABLED": "denied",
    "STATUS_ACCOUNT_LOCKED_OUT": "denied",
    "STATUS_ACCOUNT_EXPIRED": "denied",
    "STATUS_PASSWORD_MUST_CHANGE": "denied",
    "STATUS_PASSWORD_EXPIRED": "denied",
    "STATUS_USER_SESSION_DELETED": "denied",
    "STATUS_INVALID_LOGON_HOURS": "denied",
    "STATUS_NOT_SUPPORTED": "unsupported",
    "STATUS_NOT_IMPLEMENTED": "unsupported",
    "OPERATIONSERROR": "denied",
    "INSUFFICIENTACCESSRIGHTS": "denied",
    "STRONGERAUTHREQUIRED": "denied",
    "INVALIDCREDENTIALS": "denied",
    # The target answered that what was asked for is not here / not spoken.
    "STATUS_BAD_NETWORK_NAME": "unsupported",
    "0XC00000CC": "unsupported",
    "STATUS_BAD_NETWORK_PATH": "unsupported",
    "STATUS_OBJECT_NAME_NOT_FOUND": "unsupported",
    "STATUS_OBJECT_PATH_NOT_FOUND": "unsupported",
    "STATUS_NO_SUCH_FILE": "unsupported",
    "STATUS_INVALID_PARAMETER": "unsupported",
    "STATUS_SMB_BAD_TID": "unsupported",
}

#: The tokens above as netexec prints them: ``NT_STATUS_x``/``STATUS_x``, the
#: raw ``0x``-hex HRESULT, or the LDAP error name.
_NXC_STATUS_RE = re.compile(
    r"NT_STATUS_[A-Z_]+|STATUS_[A-Z_]+|0[xX][0-9a-fA-F]{8}"
    r"|operationsError|insufficientAccessRights|strongerAuthRequired|invalidCredentials"
)


def netexec_status_outcome(text: str) -> tuple[str, str]:
    """Return ``(token, outcome)`` for the first determinate answer in *text*.

    An empty outcome means the handler cannot classify what it saw; the caller
    must then fail closed instead of reporting an observation (V0-31).
    """
    match = _NXC_STATUS_RE.search(text or "")
    if match is None:
        return "", ""
    token = match.group(0)
    key = token.upper()
    if key.startswith("NT_"):
        key = key[3:]
    return token, NETEXEC_STATUS_OUTCOMES.get(key, "")


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
    verified = result.exit_code in {0, 1}
    nt_status, status_outcome = netexec_status_outcome(result.stdout)
    # netexec closes with an exit code outside ``{0, 1}`` while still printing a
    # determinate answer from the target (measured: ``STATUS_ACCESS_DENIED`` on
    # ``rid_brute``, ``operationsError`` on ``ldap users``). That is an answer,
    # not a broken body: it completes with its outcome and derives nothing
    # (V0-31). Anything the vocabulary does not cover keeps failing closed.
    outcome = "" if verified else status_outcome
    evidence.update(
        {
            "count": len(parsed.entries),
            "raw_output_sha256": parsed.raw_output_sha256,
            "nt_status": nt_status or None,
        }
    )
    if outcome:
        evidence["reason"] = f"{operation} answered {nt_status} on {target}"
    return ToolResult(
        output={
            "protocol": protocol,
            "target": target,
            "operation": operation,
            "noise_level": noise_level,
            "count": len(parsed.entries),
            **parsed.to_dict(),
        },
        verified=verified,
        verification_method="netexec_text_parsed",
        outcome=outcome,
        evidence=evidence,
        exit_code=result.exit_code,
        accepted_exit_codes=(0, 1),
        stdout=result.stdout,
        stderr=result.stderr,
    )
