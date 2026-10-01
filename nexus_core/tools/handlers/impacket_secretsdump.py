"""Durable ``nexus.attack.impacket_secretsdump`` handler (HIGH risk).

Dumps SAM/LSA/NTDS secrets with Impacket's ``secretsdump``. The handler treats
``-outputfile`` as the prefix the binary documents (extensions ``.sam``,
``.secrets``, ``.cached`` and ``.ntds`` are appended) and reads those files from
the workspace. ``-just-dc`` extracts only NTDS; it is not a SAM/LSA mode. The
resolver locates either the Kali ``impacket-secretsdump`` name or the pipx
``secretsdump.py`` script. Requires durable human approval (HIGH).
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from nexus_core.kernel.models import RiskLevel, RunContext, ToolDefinition, ToolResult
from nexus_core.tools.parsers.impacket_secretsdump import parse_secretsdump_files

from ._ad import (
    ad_sandbox,
    canonicalize_flags,
    validate_domain,
    validate_host,
    validate_username,
)
from ._exec import run_in_sandbox, safe_run_id
from ._impacket_resolver import resolve_impacket_binary

SECRETSDUMP_METHODS = ("all", "ntds", "ntds_ntlm")

SECRETSDUMP_ALLOWED_FLAGS: dict[str, bool] = {
    "-ts": False,
    "-debug": False,
    "-skip-sam": False,
    "-skip-security": False,
    "-history": False,
    "-user-status": False,
    "-pwd-last-set": False,
    "-use-vss": False,
    "-just-dc": False,
    "-just-dc-ntlm": False,
    "-just-dc-user": True,
    "-ldapfilter": True,
    "-hashes": True,
    "-no-pass": False,
    "-k": False,
    "-aesKey": True,
    "-keytab": True,
    "-dc-ip": True,
    "-target-ip": True,
    "-use-keylist": False,
    "-exec-method": True,
}

#: Handled by the handler itself; a model copy would fight the managed argv.
SECRETSDUMP_MANAGED_FLAGS: set[str] = {"-outputfile"}

SECRETSDUMP_FORBIDDEN_FLAGS: set[str] = {
    "-system",
    "-bootkey",
    "-security",
    "-sam",
    "-ntds",
    "-resumefile",
    "-rodcNo",
    "-rodcKey",
    "-remoteSSWMI-local-path",
}

SECRETSDUMP_DEFAULT_TIMEOUT_SECONDS = 1800
SECRETSDUMP_MAX_TIMEOUT_SECONDS = 3600
SECRETSDUMP_SOURCES = ("sam", "secrets", "cached", "ntds")


def impacket_secretsdump_definition(tenant_id: str = "system") -> ToolDefinition:
    """Return the durable ToolDefinition for the secretsdump tool."""
    return ToolDefinition(
        tool_id="nexus.attack.impacket_secretsdump",
        name="Impacket secretsdump",
        tenant_id=tenant_id,
        description=(
            "Vuelca credenciales de SAM, LSA y NTDS con secretsdump de Impacket. "
            "-outputfile es un PREFIJO: se generan .sam, .secrets, .cached y .ntds. "
            "-just-dc extrae solo NTDS. REQUIERE aprobación humana explícita."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "minLength": 1, "maxLength": 255},
                "domain": {"type": "string", "maxLength": 255},
                "username": {"type": "string", "maxLength": 128},
                "password": {"type": "string", "maxLength": 512},
                "hash": {"type": "string", "maxLength": 65},
                "method": {
                    "type": "string",
                    "enum": list(SECRETSDUMP_METHODS),
                    "default": "all",
                },
                "just_dc_user": {"type": "string", "maxLength": 128},
                "dc_ip": {"type": "string", "maxLength": 255},
                "target_ip": {"type": "string", "maxLength": 255},
                "skip_sam": {"type": "boolean"},
                "skip_security": {"type": "boolean"},
                "history": {"type": "boolean"},
                "timeout_seconds": {
                    "type": "integer",
                    "minimum": 60,
                    "maximum": SECRETSDUMP_MAX_TIMEOUT_SECONDS,
                },
                "flags": {
                    "type": "array",
                    "items": {"type": "string", "maxLength": 256},
                    "maxItems": 25,
                },
            },
            "required": ["target"],
            "additionalProperties": False,
        },
        risk=RiskLevel.HIGH,
        effect="credential_dump",
        required_permissions=["execute:tool:nexus.attack.impacket_secretsdump"],
        timeout_seconds=SECRETSDUMP_MAX_TIMEOUT_SECONDS,
        max_output_bytes=10_000_000,
        scope_target_field="target",
        scope_required=True,
    )


def build_impacket_target(
    *,
    target: str,
    domain: str,
    username: str,
    password: str | None,
) -> str:
    """Build ``[domain/]username[:password]@host`` for secretsdump/psexec."""
    auth = ""
    if domain:
        auth += f"{domain}/"
    if username:
        auth += username
    if username and password:
        auth += f":{password}"
    return f"{auth}@{target}" if auth else target


def secretsdump_method_flags(method: str) -> list[str]:
    """Map the method enum to the real secretsdump flags."""
    if method == "ntds":
        return ["-just-dc"]
    if method == "ntds_ntlm":
        return ["-just-dc-ntlm"]
    return []


async def impacket_secretsdump_handler(
    arguments: dict, context: RunContext
) -> ToolResult:
    """Run an allowlisted secretsdump through the sandbox."""
    target = validate_host(arguments.get("target"))
    username = (
        validate_username(arguments["username"]) if arguments.get("username") else ""
    )
    domain = validate_domain(arguments["domain"]) if arguments.get("domain") else ""
    password = str(arguments["password"]) if arguments.get("password") else None
    ntlm_hash = str(arguments["hash"]) if arguments.get("hash") else None
    method = str(arguments.get("method") or "all").strip().lower()
    if method not in SECRETSDUMP_METHODS:
        raise ValueError(f"method is not allowed: {method!r}")
    if (password or ntlm_hash) and not username:
        raise ValueError("authentication requires a username")

    requested_timeout = arguments.get("timeout_seconds")
    timeout_seconds = min(
        SECRETSDUMP_MAX_TIMEOUT_SECONDS,
        max(
            60,
            int(requested_timeout)
            if requested_timeout
            else SECRETSDUMP_DEFAULT_TIMEOUT_SECONDS,
        ),
    )

    user_flags = canonicalize_flags(
        arguments.get("flags"),
        SECRETSDUMP_ALLOWED_FLAGS,
        SECRETSDUMP_FORBIDDEN_FLAGS,
    )
    user_flags = [
        token for token in user_flags if token not in SECRETSDUMP_MANAGED_FLAGS
    ]

    binary = resolve_impacket_binary("secretsdump")
    if not binary:
        return ToolResult(verification_method="secretsdump_unavailable")

    workspace_root = os.getenv("NEXUS_WORKSPACE_ROOT", os.getcwd())
    run_id = safe_run_id(context)
    prefix = str(Path(workspace_root).resolve() / f"sd_{run_id}")

    working_flags = list(secretsdump_method_flags(method))
    if arguments.get("skip_sam"):
        working_flags.append("-skip-sam")
    if arguments.get("skip_security"):
        working_flags.append("-skip-security")
    if arguments.get("history"):
        working_flags.append("-history")
    if to_dc_user := arguments.get("just_dc_user"):
        working_flags.extend(["-just-dc-user", str(to_dc_user)])

    argv = [binary, "-outputfile", prefix, *working_flags]
    if ntlm_hash:
        argv.extend(["-hashes", ntlm_hash])
    elif username and not password:
        argv.append("-no-pass")
    if arguments.get("dc_ip"):
        argv.extend(["-dc-ip", validate_host(arguments["dc_ip"], field="dc_ip")])
    if arguments.get("target_ip"):
        argv.extend(
            ["-target-ip", validate_host(arguments["target_ip"], field="target_ip")]
        )
    argv.extend(user_flags)
    argv.append(
        build_impacket_target(
            target=target, domain=domain, username=username, password=password
        )
    )

    sandbox = ad_sandbox(workspace_root, binary)
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
        "method": method,
        "timeout_seconds": timeout_seconds,
        "flags": list(user_flags),
        "output_prefix": prefix,
    }
    if result.timed_out:
        return ToolResult(
            output={"error": "secretsdump run timed out", "target": target},
            verified=False,
            verification_method="secretsdump_timeout",
            evidence=evidence,
            exit_code=result.exit_code,
            accepted_exit_codes=(0,),
            stdout=result.stdout,
            stderr=result.stderr,
            timed_out=True,
        )

    files: dict[str, str] = {}
    for source in SECRETSDUMP_SOURCES:
        path = Path(f"{prefix}.{source}")
        if not path.exists():
            continue
        try:
            files[source] = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
    if not files:
        return ToolResult(
            output={
                "error": "secretsdump produced no output file",
                "target": target,
            },
            verified=False,
            verification_method="secretsdump_no_output",
            evidence=evidence,
            exit_code=result.exit_code,
            accepted_exit_codes=(0,),
            stdout=result.stdout,
            stderr=result.stderr,
        )

    parsed = parse_secretsdump_files(files)
    evidence.update(
        {
            "count": len(parsed.entries),
            "secret_count": len(parsed.secrets),
            "sources": list(parsed.sources),
            "raw_sha256": parsed.raw_sha256,
        }
    )
    return ToolResult(
        output={"target": target, "method": method, **parsed.to_dict()},
        verified=result.exit_code == 0,
        verification_method="secretsdump_files_parsed",
        evidence=evidence,
        exit_code=result.exit_code,
        accepted_exit_codes=(0,),
        stdout=result.stdout,
        stderr=result.stderr,
    )
