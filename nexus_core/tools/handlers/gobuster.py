"""Durable ``nexus.recon.gobuster`` handler: directory/DNS/VHOST busting.

gobuster is loud: the noise level is derived from the thread count. The
wordlist is resolved with the same workspace-confined helper ffuf uses, so it
can never become an arbitrary-file reader.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from nexus_core.kernel.models import RiskLevel, RunContext, ToolDefinition, ToolResult
from nexus_core.kernel.sandbox import sandbox_for_environment
from nexus_core.tools.parsers.gobuster import parse_gobuster_output

from ._exec import RECON_ALLOWED_PROGRAMS, run_in_sandbox, safe_run_id
from .ffuf import resolve_wordlist

GOBUSTER_ALLOWED_PROGRAMS = RECON_ALLOWED_PROGRAMS + ("gobuster",)

GOBUSTER_DEFAULT_TIMEOUT_SECONDS = 1800
GOBUSTER_DEFAULT_THREADS = 10
GOBUSTER_MAX_THREADS = 50
GOBUSTER_ALLOWED_MODES = ("dir", "dns", "vhost")

#: Non-structural flags the model may add: ``(baseline_noise, takes_value)``.
GOBUSTER_ALLOWED_FLAGS: dict[str, tuple[str, bool]] = {
    "-u": ("medium", True),
    "-w": ("medium", True),
    "-t": ("medium", True),
    "-x": ("medium", True),
    "-s": ("low", True),
    "-b": ("low", True),
    "-k": ("low", False),
    "-r": ("low", False),
    "-q": ("low", False),
    "--no-error": ("low", False),
    "--timeout": ("low", True),
    "-e": ("low", False),
    "--random-agent": ("low", False),
    "-d": ("low", True),
    "--exclude-length": ("low", True),
}

#: Output control, proxies, cookies and header/method injection are refused.
GOBUSTER_FORBIDDEN_FLAGS: set[str] = {
    "-o",
    "-of",
    "-z",
    "--proxy",
    "-p",
    "-c",
    "--pattern",
    "-m",
    "-H",
    "--header",
    "--headers",
    "-U",
    "-P",
}

#: The handler always sets these itself; model copies are dropped as no-ops.
GOBUSTER_MANAGED_FLAGS: set[str] = {"-o", "-q", "--no-error", "-u", "-w", "-t", "-x", "-s"}

NOISE_LEVELS = {"low": 0, "medium": 1, "high": 2}
NOISE_NAMES = ("low", "medium", "high")


def gobuster_noise_level(threads: int) -> str:
    """Map a thread count to the aggregate noise level."""
    if threads <= 5:
        return "low"
    if threads <= 20:
        return "medium"
    return "high"


def validate_and_canonicalize_gobuster_flags(
    raw_flags: list[str],
) -> tuple[list[str], str, set[str]]:
    """Validate model-provided gobuster flags.

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
            raise ValueError("empty gobuster flag is not allowed")
        if not token.startswith("-"):
            raise ValueError(f"gobuster flag must start with '-': {token!r}")

        name, separator, inline_value = token.partition("=")
        if token in GOBUSTER_FORBIDDEN_FLAGS or name in GOBUSTER_FORBIDDEN_FLAGS:
            raise ValueError(f"gobuster flag is forbidden: {token!r}")

        spec = GOBUSTER_ALLOWED_FLAGS.get(token) or GOBUSTER_ALLOWED_FLAGS.get(name)
        if spec is None:
            raise ValueError(f"gobuster flag is not allowed: {token!r}")
        level, requires_value = spec
        noise_rank = max(noise_rank, NOISE_LEVELS[level])

        if requires_value:
            if separator:
                value = inline_value.strip()
            else:
                if index >= len(raw_flags):
                    raise ValueError(f"gobuster flag requires a value: {token!r}")
                value = str(raw_flags[index]).strip()
                index += 1
            if not value or value.startswith("-"):
                raise ValueError(f"invalid value for gobuster flag {token!r}: {value!r}")
            canonical.extend([name, value])
        else:
            if separator:
                raise ValueError(f"gobuster flag does not take a value: {token!r}")
            canonical.append(name)

    if noise_rank == NOISE_LEVELS["high"]:
        warnings.add("high noise profile: flags generate significant traffic")
    return canonical, NOISE_NAMES[noise_rank], warnings


def gobuster_definition(tenant_id: str = "system") -> ToolDefinition:
    """Return the durable ToolDefinition for ``nexus.recon.gobuster``."""
    return ToolDefinition(
        tool_id="nexus.recon.gobuster",
        effect="read_only",
        name="Gobuster directory and DNS busting",
        tenant_id=tenant_id,
        description=(
            "Brute force de directorios/ficheros o subdominios. Requiere "
            "wordlist (en el workspace o en un directorio de sistema, p. ej. "
            "/usr/share/dirb/wordlists/common.txt). Reemplaza/complementa a ffuf "
            "con mejor detección de backups y extensiones comunes."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "mode": {
                    "type": "string",
                    "enum": list(GOBUSTER_ALLOWED_MODES),
                    "default": "dir",
                },
                "target": {"type": "string", "minLength": 3, "maxLength": 512},
                "wordlist": {"type": "string", "minLength": 1, "maxLength": 512},
                "extensions": {
                    "type": "array",
                    "items": {"type": "string", "maxLength": 16},
                    "maxItems": 20,
                },
                "threads": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": GOBUSTER_MAX_THREADS,
                },
                "status_codes": {"type": "string", "maxLength": 64},
                "exclude_length": {"type": "string", "maxLength": 64},
                "timeout_seconds": {"type": "integer", "minimum": 30, "maximum": 1800},
            },
            "required": ["mode", "target", "wordlist"],
            "additionalProperties": False,
        },
        risk=RiskLevel.MEDIUM,
        required_permissions=["execute:tool:nexus.recon.gobuster"],
        timeout_seconds=1800,
        max_output_bytes=5_000_000,
        scope_target_field="target",
        scope_required=True,
    )


async def gobuster_handler(arguments: dict, context: RunContext) -> ToolResult:
    """Run an allowlisted gobuster scan through the sandbox."""
    mode = str(arguments.get("mode") or "dir").strip().lower()
    if mode not in GOBUSTER_ALLOWED_MODES:
        raise ValueError(f"gobuster mode is not allowed: {mode!r}")
    target = str(arguments["target"]).strip()
    if not target:
        raise ValueError("gobuster target is required")

    raw_threads = arguments.get("threads")
    threads = min(
        GOBUSTER_MAX_THREADS,
        max(1, int(raw_threads) if raw_threads else GOBUSTER_DEFAULT_THREADS),
    )
    requested_timeout = arguments.get("timeout_seconds")
    timeout_seconds = min(
        1800,
        max(30, int(requested_timeout) if requested_timeout else GOBUSTER_DEFAULT_TIMEOUT_SECONDS),
    )

    user_flags, flag_noise, warnings = validate_and_canonicalize_gobuster_flags(
        list(arguments.get("flags") or [])
    )
    user_flags = [token for token in user_flags if token not in GOBUSTER_MANAGED_FLAGS]
    noise_level = gobuster_noise_level(threads)
    if NOISE_LEVELS[flag_noise] > NOISE_LEVELS[noise_level]:
        noise_level = flag_noise
    if noise_level == "high":
        warnings.add(f"high noise profile: {threads} threads against {target}")

    workspace_root = os.getenv("NEXUS_WORKSPACE_ROOT", os.getcwd())
    wordlist = resolve_wordlist(workspace_root, str(arguments["wordlist"]))
    run_id = safe_run_id(context)
    output_path = Path(workspace_root).resolve() / f"gobuster_out_{run_id}.txt"

    if mode == "dns":
        argv = ["gobuster", "dns", "-d", target, "-w", wordlist]
    else:
        argv = ["gobuster", mode, "-u", target, "-w", wordlist]
    argv.extend(["-t", str(threads), "-q", "--no-error", "-o", str(output_path)])

    extensions = [
        str(item).strip() for item in arguments.get("extensions") or [] if str(item).strip()
    ]
    if extensions:
        argv.extend(["-x", ",".join(extensions)])
    status_codes = arguments.get("status_codes")
    if status_codes:
        argv.extend(["-s", str(status_codes)])
    exclude_length = arguments.get("exclude_length")
    if exclude_length:
        argv.extend(["--exclude-length", str(exclude_length)])
    argv.extend(user_flags)

    sandbox = sandbox_for_environment(
        workspace_root, allowed_programs=GOBUSTER_ALLOWED_PROGRAMS
    )
    result = await run_in_sandbox(
        sandbox,
        argv,
        timeout_seconds=timeout_seconds,
        image_env="NEXUS_GOBUSTER_IMAGE",
        default_image="ghcr.io/oj/gobuster",
    )

    evidence: dict[str, Any] = {
        "noise_level": noise_level,
        "mode": mode,
        "target": target,
        "wordlist": wordlist,
        "threads": threads,
        "timeout_seconds": timeout_seconds,
        "flags": list(user_flags),
        "warnings": sorted(warnings),
    }
    if result.timed_out:
        return ToolResult(
            output={"error": "gobuster run timed out", "target": target, "mode": mode},
            verified=False,
            verification_method="gobuster_timeout",
            evidence=evidence,
            exit_code=result.exit_code,
            accepted_exit_codes=(0, 1),
            stdout=result.stdout,
            stderr=result.stderr,
            timed_out=True,
        )

    try:
        scan = parse_gobuster_output(result.stdout, mode=mode, target=target)
    except ValueError as exc:
        return ToolResult(
            output={"error": str(exc), "target": target, "mode": mode},
            verified=False,
            verification_method="gobuster_parse_failed",
            evidence=evidence,
            exit_code=result.exit_code,
            accepted_exit_codes=(0, 1),
            stdout=result.stdout,
            stderr=result.stderr,
        )

    evidence.update(
        {
            "count": len(scan.hits),
            "raw_output_sha256": scan.raw_output_sha256,
        }
    )
    return ToolResult(
        output={
            "target": target,
            "mode": mode,
            "noise_level": noise_level,
            "count": len(scan.hits),
            "hits": [hit.to_dict() for hit in scan.hits],
        },
        verified=result.exit_code in {0, 1},
        verification_method="gobuster_text_parsed",
        evidence=evidence,
        exit_code=result.exit_code,
        accepted_exit_codes=(0, 1),
        stdout=result.stdout,
        stderr=result.stderr,
    )
