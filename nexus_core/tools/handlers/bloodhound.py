"""Durable ``nexus.recon.bloodhound_python`` handler: AD graph collection.

Runs ``bloodhound-python`` through the sandbox and reads the JSON files it
writes into the workspace. The handler forces ``--auth-method`` (``ntlm`` by
default; this build accepts lowercase values), uses ``-dc HOST`` for the domain
controller and ``-ns NAMESERVER`` for DNS, and never sends the unsupported
``ComputerOnly`` collection.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from nexus_core.kernel.models import RiskLevel, RunContext, ToolDefinition, ToolResult
from nexus_core.tools.parsers.bloodhound import parse_bloodhound_outputs

from ._ad import (
    ad_sandbox,
    canonicalize_flags,
    resolve_ad_binary,
    validate_domain,
    validate_host,
    validate_username,
)
from ._exec import run_in_sandbox, safe_run_id

BLOODHOUND_COLLECTIONS = (
    "Default",
    "DCOnly",
    "Group",
    "LocalAdmin",
    "Session",
    "Trusts",
    "DCOM",
    "RDP",
    "PSRemote",
    "LoggedOn",
    "Container",
    "ObjectProps",
    "ACL",
    "All",
)

BLOODHOUND_AUTH_METHODS = ("ntlm", "kerberos", "auto")

#: Non-structural flags the model may add: ``flag -> consumes a value``.
BLOODHOUND_ALLOWED_FLAGS: dict[str, bool] = {
    "-ns": True,
    "--nameserver": True,
    "-gc": True,
    "-w": True,
    "--workers": True,
    "--dns-tcp": False,
    "--dns-timeout": True,
    "--disable-pooling": False,
    "--disable-autogc": False,
    "--ldap-channel-binding": False,
    "--use-ldaps": False,
    "--exclude-dcs": False,
    "-v": False,
    "--zip": False,
}

#: The handler manages these itself; a model copy is redundant/dangerous.
BLOODHOUND_MANAGED_FLAGS: set[str] = {
    "-d",
    "--domain",
    "-u",
    "--username",
    "-p",
    "--password",
    "--hashes",
    "--auth-method",
    "-dc",
    "--domain-controller",
    "-c",
    "--collectionmethod",
    "-op",
    "--outputprefix",
    "-k",
    "--kerberos",
    "-no-pass",
}

BLOODHOUND_FORBIDDEN_FLAGS: set[str] = {
    "--computerfile",
    "--cachefile",
}

BLOODHOUND_DEFAULT_TIMEOUT_SECONDS = 1800
BLOODHOUND_MAX_TIMEOUT_SECONDS = 3600
BLOODHOUND_MAX_WORKERS = 50


def bloodhound_definition(tenant_id: str = "system") -> ToolDefinition:
    """Return the durable ToolDefinition for ``nexus.recon.bloodhound_python``."""
    return ToolDefinition(
        tool_id="nexus.recon.bloodhound_python",
        name="BloodHound.py AD graph collection",
        tenant_id=tenant_id,
        description=(
            "Recolecta el grafo de Active Directory con bloodhound-python "
            "(usuarios, equipos, grupos, sesiones, ACLs) y deja los JSON en el "
            "workspace. Autenticación NTLM por defecto."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "domain": {"type": "string", "minLength": 1, "maxLength": 255},
                "dc": {"type": "string", "minLength": 1, "maxLength": 255},
                "collection": {
                    "type": "array",
                    "items": {"type": "string", "enum": list(BLOODHOUND_COLLECTIONS)},
                    "maxItems": 8,
                },
                "username": {"type": "string", "maxLength": 128},
                "password": {"type": "string", "maxLength": 512},
                "hash": {"type": "string", "maxLength": 65},
                "auth_method": {
                    "type": "string",
                    "enum": list(BLOODHOUND_AUTH_METHODS),
                    "default": "ntlm",
                },
                "nameserver": {"type": "string", "maxLength": 255},
                "workers": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": BLOODHOUND_MAX_WORKERS,
                },
                "timeout_seconds": {
                    "type": "integer",
                    "minimum": 60,
                    "maximum": BLOODHOUND_MAX_TIMEOUT_SECONDS,
                },
                "flags": {
                    "type": "array",
                    "items": {"type": "string", "maxLength": 256},
                    "maxItems": 20,
                },
            },
            "required": ["domain", "dc"],
            "additionalProperties": False,
        },
        risk=RiskLevel.MEDIUM,
        effect="recon",
        required_permissions=["execute:tool:nexus.recon.bloodhound_python"],
        timeout_seconds=BLOODHOUND_MAX_TIMEOUT_SECONDS,
        max_output_bytes=5_000_000,
        scope_target_field="dc",
        scope_required=True,
    )


async def bloodhound_handler(arguments: dict, context: RunContext) -> ToolResult:
    """Run an allowlisted bloodhound-python collection through the sandbox."""
    domain = validate_domain(arguments.get("domain"))
    dc = validate_host(arguments.get("dc"), field="dc")
    auth_method = str(arguments.get("auth_method") or "ntlm").strip().lower()
    if auth_method not in BLOODHOUND_AUTH_METHODS:
        raise ValueError(f"auth_method is not allowed: {auth_method!r}")

    raw_collection = arguments.get("collection") or []
    collection: list[str] = []
    for item in raw_collection:
        value = str(item)
        if value not in BLOODHOUND_COLLECTIONS:
            raise ValueError(f"collection is not allowed: {value!r}")
        if value not in collection:
            collection.append(value)

    user_flags = canonicalize_flags(
        arguments.get("flags"), BLOODHOUND_ALLOWED_FLAGS, BLOODHOUND_FORBIDDEN_FLAGS
    )
    user_flags = [token for token in user_flags if token not in BLOODHOUND_MANAGED_FLAGS]

    username = (
        validate_username(arguments["username"]) if arguments.get("username") else ""
    )
    password = arguments.get("password")
    ntlm_hash = arguments.get("hash")
    if (password or ntlm_hash) and not username:
        raise ValueError("authentication requires a username")

    requested_timeout = arguments.get("timeout_seconds")
    timeout_seconds = min(
        BLOODHOUND_MAX_TIMEOUT_SECONDS,
        max(
            60,
            int(requested_timeout)
            if requested_timeout
            else BLOODHOUND_DEFAULT_TIMEOUT_SECONDS,
        ),
    )

    binary = resolve_ad_binary("bloodhound-python", "bloodhound.py")
    if not binary:
        return ToolResult(verification_method="bloodhound_unavailable")

    workspace_root = os.getenv("NEXUS_WORKSPACE_ROOT", os.getcwd())
    run_id = safe_run_id(context)
    prefix = str(Path(workspace_root).resolve() / f"bh_{run_id}_")

    argv = [binary, "-d", domain, "-dc", dc, "-op", prefix]
    if auth_method == "kerberos":
        argv.append("-k")
    else:
        argv.extend(["--auth-method", auth_method])
    if username:
        argv.extend(["-u", username])
    if password:
        argv.extend(["-p", str(password)])
    if ntlm_hash:
        argv.extend(["--hashes", str(ntlm_hash)])
    if username and not password and not ntlm_hash:
        argv.append("-no-pass")
    if collection:
        argv.extend(["-c", ",".join(collection)])
    argv.extend(user_flags)

    sandbox = ad_sandbox(workspace_root, binary)
    result = await run_in_sandbox(
        sandbox,
        argv,
        timeout_seconds=timeout_seconds,
        image_env="NEXUS_BLOODHOUND_IMAGE",
        default_image="bloodhound",
    )

    evidence: dict[str, Any] = {
        "domain": domain,
        "dc": dc,
        "auth_method": auth_method,
        "collection": collection,
        "timeout_seconds": timeout_seconds,
        "flags": list(user_flags),
        "output_prefix": prefix,
    }
    if result.timed_out:
        return ToolResult(
            output={"error": "bloodhound run timed out", "domain": domain, "dc": dc},
            verified=False,
            verification_method="bloodhound_timeout",
            evidence=evidence,
            exit_code=result.exit_code,
            accepted_exit_codes=(0,),
            stdout=result.stdout,
            stderr=result.stderr,
            timed_out=True,
        )

    output_files = sorted(Path(workspace_root).glob(f"bh_{run_id}_*.json"))
    if not output_files:
        return ToolResult(
            output={
                "error": "bloodhound produced no JSON output",
                "domain": domain,
                "dc": dc,
            },
            verified=False,
            verification_method="bloodhound_no_output",
            # The collector ran to completion and produced nothing to collect:
            # a negative about the target/credentials, not a failure (V0-22).
            outcome="negative",
            evidence=evidence,
            exit_code=result.exit_code,
            accepted_exit_codes=(0,),
            stdout=result.stdout,
            stderr=result.stderr,
        )

    files: dict[str, str] = {}
    for path in output_files:
        try:
            files[path.name] = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
    if not files:
        return ToolResult(
            output={"error": "bloodhound output was unreadable", "dc": dc},
            verified=False,
            # Distinct from "no output": the collector *wrote* files and none of
            # them could be read, which is a failure of the body, not an answer
            # about the target (V0-22).
            verification_method="bloodhound_output_unreadable",
            evidence=evidence,
            exit_code=result.exit_code,
            accepted_exit_codes=(0,),
            stdout=result.stdout,
            stderr=result.stderr,
        )

    try:
        parsed = parse_bloodhound_outputs(files)
    except ValueError as exc:
        return ToolResult(
            output={"error": str(exc), "domain": domain, "dc": dc},
            verified=False,
            verification_method="bloodhound_parse_failed",
            evidence=evidence,
            exit_code=result.exit_code,
            accepted_exit_codes=(0,),
            stdout=result.stdout,
            stderr=result.stderr,
        )

    evidence.update(
        {
            "file_count": len(parsed.files),
            "total_records": parsed.total_records,
            "raw_json_sha256": parsed.raw_json_sha256,
        }
    )
    return ToolResult(
        output={
            "domain": domain,
            "dc": dc,
            **parsed.to_dict(),
        },
        verified=result.exit_code == 0,
        verification_method="bloodhound_json_parsed",
        evidence=evidence,
        exit_code=result.exit_code,
        accepted_exit_codes=(0,),
        stdout=result.stdout,
        stderr=result.stderr,
    )
