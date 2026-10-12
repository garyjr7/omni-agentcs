"""Durable ``nexus.recon.httpx`` handler: HTTP fingerprinting.

httpx probes live HTTP(S) endpoints (status, title, technologies). It only
issues read-only requests, so the risk is LOW; the noise level scales with the
size of the batch because every target generates direct traffic.
"""

from __future__ import annotations

import os
from typing import Any

from nexus_core.kernel.models import RiskLevel, RunContext, ToolDefinition, ToolResult
from nexus_core.kernel.sandbox import sandbox_for_environment
from nexus_core.provisioner.binaries import BINARY_IDENTITIES_BY_NAME
from nexus_core.tools.parsers.httpx import empty_httpx_result, parse_httpx_jsonl

from ._exec import (
    MAX_BATCH_TARGETS,
    RECON_ALLOWED_PROGRAMS,
    append_repeated,
    normalize_targets,
    probe_identity_in_sandbox,
    run_in_sandbox,
)

#: Image env for both the scan and the identity probe (kept in one place).
HTTPX_IMAGE_ENV = "NEXUS_HTTPX_IMAGE"
HTTPX_DEFAULT_IMAGE = "projectdiscovery/httpx"

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
        effect="read_only",
        idempotent=True,
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


async def _diagnose_wrong_binary(sandbox: Any, exit_code: int | None) -> ToolResult | None:
    """Return a clear mismatch result when the ``httpx`` found is not PD's."""
    identity = BINARY_IDENTITIES_BY_NAME.get("httpx")
    if identity is None:  # pragma: no cover - defensive
        return None
    check = await probe_identity_in_sandbox(
        sandbox,
        identity,
        image_env=HTTPX_IMAGE_ENV,
        default_image=HTTPX_DEFAULT_IMAGE,
    )
    if check.ok:
        return None
    return ToolResult(
        output={
            "error": (
                "httpx binario equivocado: el 'httpx' del PATH no es el de "
                f"ProjectDiscovery ({check.detail})."
            ),
            "binary_path": check.binary_path,
            "install": check.install,
        },
        verified=False,
        verification_method="httpx_binary_mismatch",
        evidence={"binary_identity": check.to_dict()},
        exit_code=exit_code,
        accepted_exit_codes=(0, 1),
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
        image_env=HTTPX_IMAGE_ENV,
        default_image=HTTPX_DEFAULT_IMAGE,
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

    parse_error: str | None = None
    fingerprint = empty_httpx_result()
    try:
        fingerprint = parse_httpx_jsonl(result.stdout)
    except ValueError as exc:
        parse_error = str(exc)

    # Directly diagnose the classic environment failure: ``/usr/bin/httpx`` is
    # the Python HTTP client, not ProjectDiscovery's scanner. It exits non-zero
    # with empty stdout, so the handler used to report an opaque
    # ``httpx_jsonl_parsed`` post-condition error. Probing identity turns it
    # into an actionable, distinct outcome (B1).
    if parse_error is not None or (
        result.exit_code not in {0, 1} and not fingerprint.probes
    ):
        mismatch = await _diagnose_wrong_binary(sandbox, result.exit_code)
        if mismatch is not None:
            return mismatch
        if parse_error is not None:
            return ToolResult(
                output={
                    "error": parse_error,
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
        return ToolResult(
            output={
                "error": "httpx produced no probe output",
                "targets_requested": len(targets),
                "noise_level": noise_level,
            },
            verified=False,
            verification_method="httpx_no_output",
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
