"""Durable ``nexus.recon.whatweb`` handler: deep web fingerprinting.

whatweb only emits machine-readable output through ``--log-json``, which it
writes to a file (``--quiet`` suppresses stdout). The handler therefore runs the
binary through the sandbox and then parses the workspace file, never shell
output.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from nexus_core.kernel.models import RiskLevel, RunContext, ToolDefinition, ToolResult
from nexus_core.kernel.sandbox import sandbox_for_environment
from nexus_core.tools.parsers.whatweb import parse_whatweb_json

from ._exec import RECON_ALLOWED_PROGRAMS, normalize_targets, run_in_sandbox, safe_run_id

WHATWEB_ALLOWED_PROGRAMS = RECON_ALLOWED_PROGRAMS + ("whatweb",)

WHATWEB_DEFAULT_TIMEOUT_SECONDS = 600
WHATWEB_MIN_TIMEOUT_SECONDS = 10
WHATWEB_MAX_TIMEOUT_SECONDS = 600
WHATWEB_DEFAULT_AGGRESSION = 1
WHATWEB_MAX_AGGRESSION = 4
WHATWEB_EFFECTIVE_AGGRESSION = 3
WHATWEB_MAX_TARGETS = 50
WHATWEB_MAX_THREADS = 10

NOISE_LEVELS = {"low": 0, "medium": 1, "high": 2}
NOISE_NAMES = ("low", "medium", "high")


def whatweb_noise_level(aggression: int) -> str:
    """Map an aggression level to the aggregate noise level."""
    if aggression <= 1:
        return "low"
    if aggression == 2:
        return "medium"
    return "high"


def whatweb_definition(tenant_id: str = "system") -> ToolDefinition:
    """Return the durable ToolDefinition for ``nexus.recon.whatweb``."""
    return ToolDefinition(
        tool_id="nexus.recon.whatweb",
        name="WhatWeb deep fingerprinting",
        tenant_id=tenant_id,
        description=(
            "Fingerprinting profundo de aplicaciones web: CMS, frameworks, "
            "servidores, librerías JS, versiones. Complementa a httpx -td."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "targets": {
                    "type": "array",
                    "items": {"type": "string", "minLength": 3},
                    "minItems": 1,
                    "maxItems": WHATWEB_MAX_TARGETS,
                },
                "aggression": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": WHATWEB_MAX_AGGRESSION,
                    "default": WHATWEB_DEFAULT_AGGRESSION,
                },
                "timeout_seconds": {
                    "type": "integer",
                    "minimum": WHATWEB_MIN_TIMEOUT_SECONDS,
                    "maximum": WHATWEB_MAX_TIMEOUT_SECONDS,
                },
                "user_agent": {"type": "string", "maxLength": 256},
            },
            "required": ["targets"],
            "additionalProperties": False,
        },
        risk=RiskLevel.LOW,
        required_permissions=["execute:tool:nexus.recon.whatweb"],
        timeout_seconds=600,
        max_output_bytes=2_000_000,
        scope_target_field="targets",
        scope_required=True,
    )


async def whatweb_handler(arguments: dict, context: RunContext) -> ToolResult:
    """Run an allowlisted whatweb scan and parse its JSON log."""
    targets = normalize_targets(arguments.get("targets"), limit=WHATWEB_MAX_TARGETS)

    raw_aggression = arguments.get("aggression")
    aggression = int(raw_aggression) if raw_aggression else WHATWEB_DEFAULT_AGGRESSION
    aggression = max(1, min(WHATWEB_MAX_AGGRESSION, aggression))
    warnings: set[str] = set()
    if aggression > WHATWEB_EFFECTIVE_AGGRESSION:
        aggression = WHATWEB_EFFECTIVE_AGGRESSION
        warnings.add(
            "aggression 4 forced to 3: level 4 makes heavy raw HTTP requests"
        )

    requested_timeout = arguments.get("timeout_seconds")
    timeout_seconds = min(
        WHATWEB_MAX_TIMEOUT_SECONDS,
        max(
            WHATWEB_MIN_TIMEOUT_SECONDS,
            int(requested_timeout) if requested_timeout else WHATWEB_DEFAULT_TIMEOUT_SECONDS,
        ),
    )

    workspace_root = os.getenv("NEXUS_WORKSPACE_ROOT", os.getcwd())
    run_id = safe_run_id(context)
    output_path = Path(workspace_root).resolve() / f"whatweb_{run_id}.json"
    # whatweb *appends* to --log-json. Reusing the per-run path across ReAct
    # iterations concatenates JSON documents and breaks the parser, so every
    # invocation must start from a clean file.
    try:
        output_path.unlink(missing_ok=True)
    except OSError:
        pass

    argv = [
        "whatweb",
        f"--log-json={output_path}",
        "--no-errors",
        "--color=never",
        f"--max-threads={WHATWEB_MAX_THREADS}",
        f"--aggression={aggression}",
    ]
    if len(targets) == 1:
        argv.append("--quiet")
    user_agent = arguments.get("user_agent")
    if user_agent:
        argv.extend(["--user-agent", str(user_agent)])
    argv.extend(targets)

    noise_level = whatweb_noise_level(aggression)
    if noise_level == "high":
        warnings.add(f"high noise profile: aggression {aggression}")
    evidence: dict[str, Any] = {
        "noise_level": noise_level,
        "targets": list(targets),
        "aggression": aggression,
        "timeout_seconds": timeout_seconds,
        "output_path": str(output_path),
        "warnings": sorted(warnings),
    }

    sandbox = sandbox_for_environment(
        workspace_root, allowed_programs=WHATWEB_ALLOWED_PROGRAMS
    )
    result = await run_in_sandbox(
        sandbox,
        argv,
        timeout_seconds=timeout_seconds,
        image_env="NEXUS_WHATWEB_IMAGE",
        default_image="secsi/whatweb",
    )

    if result.timed_out:
        return ToolResult(
            output={"error": "whatweb run timed out", "targets": list(targets)},
            verified=False,
            verification_method="whatweb_timeout",
            evidence=evidence,
            exit_code=result.exit_code,
            accepted_exit_codes=(0, 1),
            stdout=result.stdout,
            stderr=result.stderr,
            timed_out=True,
        )

    try:
        raw_json = output_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ToolResult(
            output={
                "error": "whatweb produced no JSON log",
                "targets": list(targets),
                "noise_level": noise_level,
            },
            verified=False,
            verification_method="whatweb_no_log",
            evidence=evidence,
            exit_code=result.exit_code,
            accepted_exit_codes=(0, 1),
            stdout=result.stdout,
            stderr=result.stderr,
        )

    try:
        scan = parse_whatweb_json(raw_json)
    except ValueError as exc:
        return ToolResult(
            output={"error": str(exc), "targets": list(targets), "noise_level": noise_level},
            verified=False,
            verification_method="whatweb_parse_failed",
            evidence=evidence,
            exit_code=result.exit_code,
            accepted_exit_codes=(0, 1),
            stdout=result.stdout,
            stderr=result.stderr,
        )

    fingerprint_count = sum(len(target.fingerprints) for target in scan.targets)
    evidence.update(
        {
            "target_count": len(scan.targets),
            "fingerprint_count": fingerprint_count,
            "raw_json_sha256": scan.raw_json_sha256,
        }
    )
    return ToolResult(
        output={
            "noise_level": noise_level,
            "targets": list(targets),
            "count": len(scan.targets),
            "fingerprints": [target.to_dict() for target in scan.targets],
        },
        verified=result.exit_code in {0, 1},
        verification_method="whatweb_json_parsed",
        evidence=evidence,
        exit_code=result.exit_code,
        accepted_exit_codes=(0, 1),
        stdout=result.stdout,
        stderr=result.stderr,
    )
