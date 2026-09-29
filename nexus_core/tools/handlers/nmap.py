"""Durable nmap handler: allowlisted flags, sandbox execution, XML parsing."""

from __future__ import annotations

import os
from typing import Any

from nexus_core.kernel.models import RiskLevel, RunContext, ToolDefinition, ToolResult
from nexus_core.kernel.sandbox import OCISandbox, sandbox_for_environment
from nexus_core.tools.parsers.nmap import parse_nmap_xml

# Cada entrada: flag -> (nivel_ruido, requiere_valor)
# Nivel: "low" | "medium" | "high"
NMAP_ALLOWED_FLAGS: dict[str, tuple[str, bool]] = {
    "-sV": ("medium", False),
    "-sC": ("medium", False),
    "-sS": ("medium", False),
    "-sT": ("high", False),
    "-sU": ("high", False),
    "-sn": ("low", False),
    "-Pn": ("low", False),
    "-n": ("low", False),
    "-O": ("high", False),
    "--open": ("low", False),
    "-F": ("low", False),
    "-p": ("low", True),
    "-p-": ("medium", False),
    "--top-ports": ("medium", True),
    "-T0": ("low", False),
    "-T1": ("low", False),
    "-T2": ("medium", False),
    "-T3": ("medium", False),
    "-T4": ("high", False),
    "-T5": ("high", False),
    "--max-retries": ("low", True),
    "--host-timeout": ("low", True),
}

# Flags PROHIBIDOS siempre, sin importar el scope.
NMAP_FORBIDDEN_FLAGS: set[str] = {
    "--script",
    "-sV --version-all",
    "-A",
    "--osscan-guess",
    "--traceroute",
    "-sO",
    "-sW",
    "-sM",
    "-sN",
    "-sF",
    "-sX",
    "--script-args",
    "-oS",
    "-oN",
    "-oG",
}

NOISE_LEVELS = {"low": 0, "medium": 1, "high": 2}
NOISE_NAMES = ("low", "medium", "high")

NMAP_ALLOWED_PROGRAMS = ("python3", "git", "rg", "nmap")
NMAP_DEFAULT_TIMEOUT_SECONDS = 120
NMAP_MAX_TIMEOUT_SECONDS = 600


def validate_and_canonicalize_flags(raw_flags: list[str]) -> tuple[list[str], str, set[str]]:
    """Validate raw LLM-provided flags and compute the aggregate noise level.

    Returns ``(canonical_flags, noise_level, warnings)``. Raises ``ValueError``
    for empty, malformed, unknown or forbidden flags.
    """
    canonical: list[str] = []
    warnings: set[str] = set()
    noise_rank = 0
    index = 0
    while index < len(raw_flags):
        token = str(raw_flags[index]).strip()
        index += 1
        if not token:
            raise ValueError("empty nmap flag is not allowed")
        if not token.startswith("-"):
            raise ValueError(f"nmap flag must start with '-': {token!r}")

        name, separator, inline_value = token.partition("=")
        if token in NMAP_FORBIDDEN_FLAGS or name in NMAP_FORBIDDEN_FLAGS:
            raise ValueError(f"nmap flag is forbidden: {token!r}")

        spec = NMAP_ALLOWED_FLAGS.get(token) or NMAP_ALLOWED_FLAGS.get(name)
        if spec is None:
            raise ValueError(f"nmap flag is not allowed: {token!r}")
        level, requires_value = spec
        noise_rank = max(noise_rank, NOISE_LEVELS[level])

        if requires_value:
            if separator:
                value = inline_value.strip()
            else:
                if index >= len(raw_flags):
                    raise ValueError(f"nmap flag requires a value: {token!r}")
                value = str(raw_flags[index]).strip()
                index += 1
            if not value or value.startswith("-"):
                raise ValueError(f"invalid value for nmap flag {token!r}: {value!r}")
            canonical.extend([name, value])
        else:
            if separator:
                raise ValueError(f"nmap flag does not take a value: {token!r}")
            canonical.append(token)

    if noise_rank == NOISE_LEVELS["high"]:
        warnings.add("high noise profile: flags generate significant traffic")
    if "-sS" in canonical:
        warnings.add("SYN scan may require elevated privileges inside the sandbox")
    return canonical, NOISE_NAMES[noise_rank], warnings


def nmap_definition(tenant_id: str = "system") -> ToolDefinition:
    """Return the durable ToolDefinition for ``nexus.recon.nmap``."""
    return ToolDefinition(
        tool_id="nexus.recon.nmap",
        name="Nmap scan",
        tenant_id=tenant_id,
        description="Ejecuta nmap contra un target dentro del scope.",
        input_schema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "minLength": 1, "maxLength": 255},
                "flags": {
                    "type": "array",
                    "items": {"type": "string", "maxLength": 64},
                    "maxItems": 20,
                },
                "timeout_seconds": {"type": "integer", "minimum": 10, "maximum": 1800},
            },
            "required": ["target"],
            "additionalProperties": False,
        },
        risk=RiskLevel.MEDIUM,
        required_permissions=["execute:tool:nexus.recon.nmap"],
        timeout_seconds=600,
        max_output_bytes=4_000_000,
        scope_target_field="target",
        scope_required=True,
    )


async def _run_nmap(sandbox: Any, argv: list[str], timeout_seconds: int):
    """Run nmap through the given sandbox, normalizing the OCI signature."""
    if isinstance(sandbox, OCISandbox):
        image = os.getenv("NEXUS_NMAP_IMAGE", "instrumentisto/nmap")
        return await sandbox.run(image, argv, timeout_seconds=timeout_seconds)
    return await sandbox.run(argv, timeout_seconds=timeout_seconds)


async def nmap_handler(arguments: dict, context: RunContext) -> ToolResult:
    """Execute an allowlisted nmap scan inside a sandbox and parse its XML."""
    target = str(arguments["target"]).strip()
    raw_flags = arguments.get("flags") or []
    flags, noise_level, warnings = validate_and_canonicalize_flags(list(raw_flags))
    requested_timeout = arguments.get("timeout_seconds")
    timeout_seconds = min(
        NMAP_MAX_TIMEOUT_SECONDS,
        max(10, int(requested_timeout) if requested_timeout else NMAP_DEFAULT_TIMEOUT_SECONDS),
    )

    argv = ["nmap", *flags, "-oX", "-", target]
    workspace_root = os.getenv("NEXUS_WORKSPACE_ROOT", os.getcwd())
    sandbox = sandbox_for_environment(workspace_root, allowed_programs=NMAP_ALLOWED_PROGRAMS)
    result = await _run_nmap(sandbox, argv, timeout_seconds)

    if result.timed_out:
        return ToolResult(
            output={"error": "nmap scan timed out", "target": target},
            verified=False,
            verification_method="nmap_timeout",
            evidence={"noise_level": noise_level, "timeout_seconds": timeout_seconds},
            exit_code=result.exit_code,
            accepted_exit_codes=(0, 1),
            stdout=result.stdout,
            stderr=result.stderr,
            timed_out=True,
        )

    try:
        scan = parse_nmap_xml(result.stdout)
    except ValueError as exc:
        return ToolResult(
            output={"error": str(exc), "target": target},
            verified=False,
            verification_method="nmap_xml_parse_failed",
            evidence={"noise_level": noise_level},
            exit_code=result.exit_code,
            accepted_exit_codes=(0, 1),
            stdout=result.stdout,
            stderr=result.stderr,
        )

    open_ports_total = sum(
        1 for host in scan.hosts for port in host.ports if port["state"] == "open"
    )
    verified = result.exit_code in {0, 1}
    return ToolResult(
        output={
            "target": target,
            "noise_level": noise_level,
            "scan": scan.to_dict(),
        },
        verified=verified,
        verification_method="nmap_xml_parsed",
        evidence={
            "noise_level": noise_level,
            "host_count": len(scan.hosts),
            "hosts_up": scan.hosts_up,
            "ports_open_total": open_ports_total,
            "elapsed_seconds": scan.elapsed_seconds,
            "raw_xml_sha256": scan.raw_xml_sha256,
            "warnings": sorted(warnings),
        },
        exit_code=result.exit_code,
        accepted_exit_codes=(0, 1),
        stdout=result.stdout,
        stderr=result.stderr,
    )
