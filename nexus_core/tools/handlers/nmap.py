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
    # Rate controls: the operator opts into a faster (noisier) scan. Without
    # them a full ``-p-`` scan against a ~90 ms RTT host spends most of its time
    # in nmap's conservative default pacing (measured: 43.8 s vs 23 s with
    # ``--min-rate 5000 -n`` on the RootMe target).
    "--min-rate": ("medium", True),
    "--max-rate": ("low", True),
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
#: Hard cap on the raw XML handed back in ``stdout`` once it has been parsed.
#: The full XML averages ~30 KB and only floods the agent context: the parsed
#: ``output.scan`` + ``raw_xml_sha256`` carry the whole finding, so the raw text
#: is kept only as a short forensic prefix (H1 of the RUN7 report).
NMAP_STDOUT_MAX_BYTES = 500

# Perfiles de reconocimiento: nombre -> (flags base, timeout recomendado).
# El perfil se expande server-side, así que el modelo nunca inventa flags: pide
# un nombre conocido. ``full_tcp`` cubre los 65535 puertos TCP (-p-), que es el
# paso que descubre servicios fuera de la lista "común" (p. ej. FTP en 21).
NMAP_PROFILES: dict[str, dict[str, Any]] = {
    "quick": {"flags": ["-Pn", "-n", "-F", "-T4"], "timeout_seconds": 120},
    "full_tcp": {"flags": ["-Pn", "-n", "-p-", "-T4", "--open"], "timeout_seconds": 600},
    "service": {
        "flags": ["-Pn", "-n", "-p-", "-sV", "-sC", "-T4", "--open"],
        "timeout_seconds": 600,
    },
    "top_udp": {
        "flags": ["-Pn", "-sU", "--top-ports", "100", "-T4"],
        "timeout_seconds": 600,
    },
}


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


def truncate_stdout(
    stdout: str, limit: int = NMAP_STDOUT_MAX_BYTES
) -> tuple[str, bool]:
    """Clip raw stdout to ``limit`` UTF-8 bytes.

    Returns ``(text, truncated)``. The cut is done on bytes and decoded
    leniently so a multi-byte character straddling the boundary never raises and
    the result is never longer than ``limit`` bytes.
    """
    raw = str(stdout or "")
    encoded = raw.encode("utf-8", "replace")
    if len(encoded) <= limit:
        return raw, False
    return encoded[:limit].decode("utf-8", "ignore"), True


def nmap_definition(tenant_id: str = "system") -> ToolDefinition:
    """Return the durable ToolDefinition for ``nexus.recon.nmap``."""
    return ToolDefinition(
        tool_id="nexus.recon.nmap",
        idempotent=True,
        name="Nmap scan",
        tenant_id=tenant_id,
        description="Ejecuta nmap contra un target dentro del scope.",
        input_schema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "minLength": 1, "maxLength": 255},
                "profile": {
                    "type": "string",
                    "enum": sorted(NMAP_PROFILES),
                    "description": (
                        "Perfil de escaneo predefinido. Usa 'full_tcp' para "
                        "descubrimiento completo de puertos (-p-) y 'service' "
                        "para detección de versiones sobre todos los puertos."
                    ),
                },
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
    raw_flags = list(arguments.get("flags") or [])

    profile = arguments.get("profile")
    profile_name: str | None = None
    base_flags: list[str] = []
    profile_timeout: int | None = None
    if profile not in (None, ""):
        profile_name = str(profile).strip()
        spec = NMAP_PROFILES.get(profile_name)
        if spec is None:
            raise ValueError(f"unknown nmap profile: {profile_name!r}")
        base_flags = list(spec["flags"])
        profile_timeout = int(spec["timeout_seconds"])

    flags, noise_level, warnings = validate_and_canonicalize_flags([*base_flags, *raw_flags])
    if "-p-" in flags and "-p" in flags:
        raise ValueError("conflicting nmap flags: '-p-' (all ports) and '-p <ports>'")
    if profile_name:
        warnings = set(warnings)
        warnings.add(f"profile: {profile_name}")

    requested_timeout = arguments.get("timeout_seconds")
    if requested_timeout:
        timeout_seconds = min(NMAP_MAX_TIMEOUT_SECONDS, max(10, int(requested_timeout)))
    elif profile_timeout:
        timeout_seconds = min(NMAP_MAX_TIMEOUT_SECONDS, max(10, profile_timeout))
    else:
        timeout_seconds = NMAP_DEFAULT_TIMEOUT_SECONDS

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
    # The XML is already parsed into ``output.scan``; do not ship the raw ~30 KB
    # back in stdout (it only inflates the agent's context). Keep a short prefix
    # and flag the truncation (H1).
    stdout_text, stdout_truncated = truncate_stdout(result.stdout)
    output: dict[str, Any] = {
        "target": target,
        "noise_level": noise_level,
        "profile": profile_name,
        "scan": scan.to_dict(),
    }
    if stdout_truncated:
        output["stdout_truncated"] = True
    return ToolResult(
        output=output,
        verified=verified,
        verification_method="nmap_xml_parsed",
        evidence={
                "noise_level": noise_level,
                "profile": profile_name,
                "host_count": len(scan.hosts),
            "hosts_up": scan.hosts_up,
            "ports_open_total": open_ports_total,
            "elapsed_seconds": scan.elapsed_seconds,
            "raw_xml_sha256": scan.raw_xml_sha256,
            "warnings": sorted(warnings),
            "stdout_truncated": stdout_truncated,
        },
        exit_code=result.exit_code,
        accepted_exit_codes=(0, 1),
        stdout=stdout_text,
        stderr=result.stderr,
    )
