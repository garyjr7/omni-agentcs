"""Durable ``nexus.recon.subfinder`` handler: passive subdomain enumeration.

subfinder queries public OSINT sources; it never sends traffic to the target,
so its risk is READ_ONLY and its noise level is always ``low``.
"""

from __future__ import annotations

import os

from nexus_core.kernel.models import RiskLevel, RunContext, ToolDefinition, ToolResult
from nexus_core.kernel.sandbox import sandbox_for_environment
from nexus_core.tools.parsers.subfinder import parse_subfinder_jsonl

from ._exec import RECON_ALLOWED_PROGRAMS, run_in_sandbox

SUBFINDER_ALLOWED_PROGRAMS = RECON_ALLOWED_PROGRAMS
SUBFINDER_DEFAULT_TIMEOUT_SECONDS = 60
SUBFINDER_MAX_TIMEOUT_SECONDS = 600

#: subfinder only reads public sources; it produces no direct target traffic.
SUBFINDER_NOISE_LEVEL = "low"

SUBFINDER_SAMPLE_SIZE = 5


def subfinder_definition(tenant_id: str = "system") -> ToolDefinition:
    """Return the durable ToolDefinition for ``nexus.recon.subfinder``."""
    return ToolDefinition(
        tool_id="nexus.recon.subfinder",
        effect="read_only",
        name="Subfinder passive subdomain enumeration",
        tenant_id=tenant_id,
        description="Enumera subdominios pasivamente usando fuentes OSINT.",
        input_schema={
            "type": "object",
            "properties": {
                "domain": {"type": "string", "minLength": 3, "maxLength": 253},
                "timeout_seconds": {"type": "integer", "minimum": 10, "maximum": 600},
            },
            "required": ["domain"],
            "additionalProperties": False,
        },
        risk=RiskLevel.READ_ONLY,
        required_permissions=["execute:tool:nexus.recon.subfinder"],
        timeout_seconds=300,
        max_output_bytes=2_000_000,
        scope_target_field="domain",
        scope_required=True,
    )


async def subfinder_handler(arguments: dict, context: RunContext) -> ToolResult:
    """Enumerate subdomains passively through the sandbox."""
    domain = str(arguments["domain"]).strip()
    requested_timeout = arguments.get("timeout_seconds")
    timeout_seconds = min(
        SUBFINDER_MAX_TIMEOUT_SECONDS,
        max(
            10,
            int(requested_timeout)
            if requested_timeout
            else SUBFINDER_DEFAULT_TIMEOUT_SECONDS,
        ),
    )

    argv = [
        "subfinder",
        "-d",
        domain,
        "-silent",
        "-json",
        "-nc",
        "-timeout",
        str(timeout_seconds),
    ]
    workspace_root = os.getenv("NEXUS_WORKSPACE_ROOT", os.getcwd())
    sandbox = sandbox_for_environment(
        workspace_root, allowed_programs=SUBFINDER_ALLOWED_PROGRAMS
    )
    result = await run_in_sandbox(
        sandbox,
        argv,
        timeout_seconds=timeout_seconds,
        image_env="NEXUS_SUBFINDER_IMAGE",
        default_image="projectdiscovery/subfinder",
    )

    evidence: dict = {
        "noise_level": SUBFINDER_NOISE_LEVEL,
        "passive": True,
        "timeout_seconds": timeout_seconds,
    }
    if result.timed_out:
        return ToolResult(
            output={"error": "subfinder run timed out", "domain": domain},
            verified=False,
            verification_method="subfinder_timeout",
            evidence=evidence,
            exit_code=result.exit_code,
            accepted_exit_codes=(0, 1),
            stdout=result.stdout,
            stderr=result.stderr,
            timed_out=True,
        )

    try:
        enumeration = parse_subfinder_jsonl(result.stdout, domain)
    except ValueError as exc:
        return ToolResult(
            output={"error": str(exc), "domain": domain},
            verified=False,
            verification_method="subfinder_parse_failed",
            evidence=evidence,
            exit_code=result.exit_code,
            accepted_exit_codes=(0, 1),
            stdout=result.stdout,
            stderr=result.stderr,
        )

    evidence.update(
        {
            "count": len(enumeration.subdomains),
            "domains_sample": list(enumeration.subdomains[:SUBFINDER_SAMPLE_SIZE]),
            "sources": list(enumeration.sources[:10]),
            "raw_sha256": enumeration.raw_sha256,
            "malformed_lines": enumeration.malformed_lines,
        }
    )
    # A plain `-silent` run that finds nothing exits 1; that is a valid
    # "no subdomains" answer, not a failure of the tool.
    verified = not result.timed_out and (
        result.exit_code in {0, 1} or bool(enumeration.subdomains)
    )
    return ToolResult(
        output={
            "domain": domain,
            "noise_level": SUBFINDER_NOISE_LEVEL,
            "count": len(enumeration.subdomains),
            "subdomains": list(enumeration.subdomains),
            "sources": list(enumeration.sources),
        },
        verified=verified,
        verification_method="subfinder_jsonl_parsed",
        evidence=evidence,
        exit_code=result.exit_code,
        accepted_exit_codes=(0, 1),
        stdout=result.stdout,
        stderr=result.stderr,
    )
