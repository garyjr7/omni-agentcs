"""Durable ``nexus.recon.httpx`` handler: HTTP fingerprinting.

httpx probes live HTTP(S) endpoints (status, title, technologies). It only
issues read-only requests, so the risk is LOW; the noise level scales with the
size of the batch because every target generates direct traffic.
"""

from __future__ import annotations

import os

from nexus_core.kernel.models import RiskLevel, RunContext, ToolDefinition, ToolResult
from nexus_core.kernel.sandbox import sandbox_for_environment
from nexus_core.tools.parsers.httpx import parse_httpx_jsonl

from ._exec import (
    MAX_BATCH_TARGETS,
    RECON_ALLOWED_PROGRAMS,
    append_repeated,
    normalize_targets,
    run_in_sandbox,
)

HTTPX_ALLOWED_PROGRAMS = RECON_ALLOWED_PROGRAMS
HTTPX_DEFAULT_TIMEOUT_SECONDS = 120
HTTPX_MAX_TIMEOUT_SECONDS = 600

#: Per-request timeout handed to httpx itself.
HTTPX_REQUEST_TIMEOUT_SECONDS = 10

#: Batch size from which each noise level kicks in.
HTTPX_MEDIUM_NOISE_TARGETS = 20
HTTPX_HIGH_NOISE_TARGETS = 100


def httpx_noise_level(target_count: int) -> str:
    """Return the aggregate noise level for a batch of ``target_count`` hosts."""
    if target_count > HTTPX_HIGH_NOISE_TARGETS:
        return "high"
    if target_count > HTTPX_MEDIUM_NOISE_TARGETS:
        return "medium"
    return "low"


def httpx_definition(tenant_id: str = "system") -> ToolDefinition:
    """Return the durable ToolDefinition for ``nexus.recon.httpx``."""
    return ToolDefinition(
        tool_id="nexus.recon.httpx",
        name="HTTPX web fingerprinting",
        tenant_id=tenant_id,
        description="Fingerprinting HTTP: status, título, tecnologías, headers.",
        input_schema={
            "type": "object",
            "properties": {
                "targets": {
                    "type": "array",
                    "items": {"type": "string", "minLength": 3, "maxLength": 2048},
                    "minItems": 1,
                    "maxItems": MAX_BATCH_TARGETS,
                },
                "probe": {"type": "boolean"},
                "tech_detect": {"type": "boolean"},
                "timeout_seconds": {"type": "integer", "minimum": 10, "maximum": 600},
            },
            "required": ["targets"],
            "additionalProperties": False,
        },
        risk=RiskLevel.LOW,
        required_permissions=["execute:tool:nexus.recon.httpx"],
        timeout_seconds=600,
        max_output_bytes=5_000_000,
        scope_target_field="targets",
        scope_required=True,
    )


async def httpx_handler(arguments: dict, context: RunContext) -> ToolResult:
    """Probe HTTP endpoints through the sandbox and parse the JSONL output."""
    targets = normalize_targets(arguments.get("targets"))
    noise_level = httpx_noise_level(len(targets))
    requested_timeout = arguments.get("timeout_seconds")
    timeout_seconds = min(
        HTTPX_MAX_TIMEOUT_SECONDS,
        max(
            10,
            int(requested_timeout) if requested_timeout else HTTPX_DEFAULT_TIMEOUT_SECONDS,
        ),
    )

    argv = [
        "httpx",
        "-json",
        "-silent",
        "-nc",
        "-sc",
        "-title",
        "-cl",
        "-timeout",
        str(HTTPX_REQUEST_TIMEOUT_SECONDS),
    ]
    if arguments.get("tech_detect"):
        argv.append("-td")
    if arguments.get("probe"):
        argv.append("-probe")
    argv.extend(append_repeated("-u", targets))

    workspace_root = os.getenv("NEXUS_WORKSPACE_ROOT", os.getcwd())
    sandbox = sandbox_for_environment(
        workspace_root, allowed_programs=HTTPX_ALLOWED_PROGRAMS
    )
    result = await run_in_sandbox(
        sandbox,
        argv,
        timeout_seconds=timeout_seconds,
        image_env="NEXUS_HTTPX_IMAGE",
        default_image="projectdiscovery/httpx",
    )

    evidence: dict = {
        "noise_level": noise_level,
        "targets_requested": len(targets),
        "timeout_seconds": timeout_seconds,
        "tech_detect": bool(arguments.get("tech_detect")),
    }
    if result.timed_out:
        return ToolResult(
            output={
                "error": "httpx run timed out",
                "targets_requested": len(targets),
                "noise_level": noise_level,
            },
            verified=False,
            verification_method="httpx_timeout",
            evidence=evidence,
            exit_code=result.exit_code,
            accepted_exit_codes=(0, 1),
            stdout=result.stdout,
            stderr=result.stderr,
            timed_out=True,
        )

    try:
        fingerprint = parse_httpx_jsonl(result.stdout)
    except ValueError as exc:
        return ToolResult(
            output={
                "error": str(exc),
                "targets_requested": len(targets),
                "noise_level": noise_level,
            },
            verified=False,
            verification_method="httpx_parse_failed",
            evidence=evidence,
            exit_code=result.exit_code,
            accepted_exit_codes=(0, 1),
            stdout=result.stdout,
            stderr=result.stderr,
        )

    evidence.update(
        {
            "count": len(fingerprint.probes),
            "hosts_alive": fingerprint.hosts_alive,
            "status_counts": dict(fingerprint.status_counts),
            "tech": list(fingerprint.tech[:20]),
            "raw_sha256": fingerprint.raw_sha256,
            "malformed_lines": fingerprint.malformed_lines,
        }
    )
    return ToolResult(
        output={
            "targets_requested": len(targets),
            "noise_level": noise_level,
            "count": len(fingerprint.probes),
            "probes": [probe.to_dict() for probe in fingerprint.probes],
        },
        verified=result.exit_code in {0, 1},
        verification_method="httpx_jsonl_parsed",
        evidence=evidence,
        exit_code=result.exit_code,
        accepted_exit_codes=(0, 1),
        stdout=result.stdout,
        stderr=result.stderr,
    )
