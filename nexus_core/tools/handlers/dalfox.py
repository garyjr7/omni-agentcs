"""Durable ``nexus.web.dalfox`` handler: XSS scanning.

dalfox runs non-interactively, without blind-XSS callbacks and without remote
payload/wordlist downloads by default. Command-executing and scope-bypassing
flags (``--found-action``, ``--waf-evasion``, ``--custom-payload``, custom
``Host``/``X-Forwarded-For`` headers) are refused.
"""

from __future__ import annotations

from nexus_core.tools.output_files import read_output_text

import os
import re
from pathlib import Path
from typing import Any

from nexus_core.kernel.models import RiskLevel, RunContext, ToolDefinition, ToolResult
from nexus_core.kernel.sandbox import sandbox_for_environment
from nexus_core.tools.parsers.dalfox import parse_dalfox_json

from ._exec import RECON_ALLOWED_PROGRAMS, run_in_sandbox, safe_run_id

DALFOX_ALLOWED_PROGRAMS = RECON_ALLOWED_PROGRAMS + ("dalfox",)

DALFOX_DEFAULT_TIMEOUT_SECONDS = 600
DALFOX_MIN_TIMEOUT_SECONDS = 30
DALFOX_MAX_TIMEOUT_SECONDS = 600
DALFOX_DEFAULT_WORKERS = 5
DALFOX_MAX_WORKERS = 20
DALFOX_REQUEST_TIMEOUT_SECONDS = 10
DALFOX_ALLOWED_METHODS = ("GET", "POST")
DALFOX_MAX_HEADERS = 10
DALFOX_MAX_HEADER_VALUE = 512

#: Non-structural flags the model may add: ``(baseline_noise, takes_value)``.
DALFOX_ALLOWED_FLAGS: dict[str, tuple[str, bool]] = {
    "--url": ("medium", True),
    "--data": ("medium", True),
    "--cookie": ("low", True),
    "--header": ("low", True),
    "--method": ("low", True),
    "--worker": ("medium", True),
    "--timeout": ("low", True),
    "--delay": ("low", True),
    "--skip-bav": ("low", False),
    "--deep-domxss": ("high", False),
    "--format": ("low", True),
    "--silence": ("low", False),
    "--no-color": ("low", False),
    "--output": ("low", True),
}

#: Command execution, remote payloads and scope-bypass: always refused.
DALFOX_FORBIDDEN_FLAGS: set[str] = {
    "--blind",
    "-b",
    "--grep",
    "--mining-dict",
    "--mining-dom",
    "--mining-dict-word",
    "-W",
    "--mass",
    "--remote-payloads",
    "--remote-wordlists",
    "--custom-payload",
    "--custom-blind-xss-payload",
    "--only-custom-payload",
    "--found-action",
    "--found-action-shell",
    "--payload",
    "--proxy",
    "--waf-evasion",
}

#: Headers that would redefine the request destination or forge the origin.
DALFOX_FORBIDDEN_HEADERS = {"host", "x-forwarded-for", "x-forwarded-host", "via"}

NOISE_LEVELS = {"low": 0, "medium": 1, "high": 2}
NOISE_NAMES = ("low", "medium", "high")

_CONTROL_CHARS_RE = re.compile(r"[\x00\r\n]")


def validate_and_canonicalize_dalfox_flags(
    raw_flags: list[str],
) -> tuple[list[str], str, set[str]]:
    """Validate model-provided dalfox flags.

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
            raise ValueError("empty dalfox flag is not allowed")
        if not token.startswith("-"):
            raise ValueError(f"dalfox flag must start with '-': {token!r}")

        name, separator, inline_value = token.partition("=")
        if token in DALFOX_FORBIDDEN_FLAGS or name in DALFOX_FORBIDDEN_FLAGS:
            raise ValueError(f"dalfox flag is forbidden: {token!r}")

        spec = DALFOX_ALLOWED_FLAGS.get(token) or DALFOX_ALLOWED_FLAGS.get(name)
        if spec is None:
            raise ValueError(f"dalfox flag is not allowed: {token!r}")
        level, requires_value = spec
        noise_rank = max(noise_rank, NOISE_LEVELS[level])

        if requires_value:
            if separator:
                value = inline_value.strip()
            else:
                if index >= len(raw_flags):
                    raise ValueError(f"dalfox flag requires a value: {token!r}")
                value = str(raw_flags[index]).strip()
                index += 1
            if not value or value.startswith("-"):
                raise ValueError(f"invalid value for dalfox flag {token!r}: {value!r}")
            canonical.extend([name, value])
        else:
            if separator:
                raise ValueError(f"dalfox flag does not take a value: {token!r}")
            canonical.append(name)

    if noise_rank == NOISE_LEVELS["high"]:
        warnings.add("high noise profile: deep DOM XSS enabled")
    return canonical, NOISE_NAMES[noise_rank], warnings


def validate_dalfox_headers(headers: Any) -> dict[str, str]:
    """Validate custom headers (no Host spoofing, bounded count/size)."""
    if headers is None:
        return {}
    if not isinstance(headers, dict):
        raise ValueError("dalfox headers must be an object")
    if len(headers) > DALFOX_MAX_HEADERS:
        raise ValueError(f"too many dalfox headers: {len(headers)} > {DALFOX_MAX_HEADERS}")
    validated: dict[str, str] = {}
    for raw_name, raw_value in headers.items():
        name = str(raw_name).strip()
        value = str(raw_value)
        if not name:
            raise ValueError("dalfox header name is empty")
        if name.lower() in DALFOX_FORBIDDEN_HEADERS:
            raise ValueError(f"dalfox header is forbidden: {name!r}")
        if _CONTROL_CHARS_RE.search(name) or _CONTROL_CHARS_RE.search(value):
            raise ValueError(f"dalfox header contains control characters: {name!r}")
        if len(value) > DALFOX_MAX_HEADER_VALUE:
            raise ValueError(f"dalfox header value too long: {name!r}")
        validated[name] = value
    return validated


def dalfox_definition(tenant_id: str = "system") -> ToolDefinition:
    """Return the durable ToolDefinition for ``nexus.web.dalfox``."""
    return ToolDefinition(
        tool_id="nexus.web.dalfox",
        effect="read_only",
        name="Dalfox XSS scanner",
        tenant_id=tenant_id,
        description=(
            "Detección de XSS reflected/stored en parámetros de URL. "
            "Modo no interactivo, sin blind-XSS callbacks por defecto."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "minLength": 8, "maxLength": 2048},
                "method": {
                    "type": "string",
                    "enum": list(DALFOX_ALLOWED_METHODS),
                    "default": "GET",
                },
                "data": {"type": "string", "maxLength": 4096},
                "cookies": {"type": "string", "maxLength": 2048},
                "headers": {
                    "type": "object",
                    "additionalProperties": {"type": "string", "maxLength": DALFOX_MAX_HEADER_VALUE},
                    "maxProperties": DALFOX_MAX_HEADERS,
                },
                "workers": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": DALFOX_MAX_WORKERS,
                },
                "timeout_seconds": {
                    "type": "integer",
                    "minimum": DALFOX_MIN_TIMEOUT_SECONDS,
                    "maximum": DALFOX_MAX_TIMEOUT_SECONDS,
                },
                "blind": {"type": "boolean"},
                "deep_domxss": {"type": "boolean"},
            },
            "required": ["target"],
            "additionalProperties": False,
        },
        risk=RiskLevel.MEDIUM,
        required_permissions=["execute:tool:nexus.web.dalfox"],
        timeout_seconds=900,
        max_output_bytes=5_000_000,
        scope_target_field="target",
        scope_required=True,
    )


async def dalfox_handler(arguments: dict, context: RunContext) -> ToolResult:
    """Run an allowlisted dalfox scan through the sandbox and parse its JSON."""
    target = str(arguments["target"]).strip()
    if not target.startswith(("http://", "https://")):
        raise ValueError("dalfox target must be an http(s) URL")

    method = str(arguments.get("method") or "GET").strip().upper()
    if method not in DALFOX_ALLOWED_METHODS:
        raise ValueError(f"dalfox method is not allowed: {method!r}")

    raw_workers = arguments.get("workers")
    workers = min(
        DALFOX_MAX_WORKERS,
        max(1, int(raw_workers) if raw_workers else DALFOX_DEFAULT_WORKERS),
    )
    requested_timeout = arguments.get("timeout_seconds")
    timeout_seconds = min(
        DALFOX_MAX_TIMEOUT_SECONDS,
        max(
            DALFOX_MIN_TIMEOUT_SECONDS,
            int(requested_timeout) if requested_timeout else DALFOX_DEFAULT_TIMEOUT_SECONDS,
        ),
    )

    headers = validate_dalfox_headers(arguments.get("headers"))
    blind = bool(arguments.get("blind", False))
    deep_domxss = bool(arguments.get("deep_domxss", False))
    user_flags, flag_noise, warnings = validate_and_canonicalize_dalfox_flags(
        list(arguments.get("flags") or [])
    )

    workspace_root = os.getenv("NEXUS_WORKSPACE_ROOT", os.getcwd())
    run_id = safe_run_id(context)
    output_path = Path(workspace_root).resolve() / f"dalfox_{run_id}.json"

    argv = [
        "dalfox",
        "url",
        target,
        "--format",
        "json",
        "--no-color",
        "--silence",
        "--worker",
        str(workers),
        "--timeout",
        str(DALFOX_REQUEST_TIMEOUT_SECONDS),
        "--output",
        str(output_path),
    ]
    if method == "POST":
        argv.extend(["--method", "POST"])
    data = arguments.get("data")
    if data:
        argv.extend(["--data", str(data)])
    cookies = arguments.get("cookies")
    if cookies:
        argv.extend(["--cookie", str(cookies)])
    if not blind:
        argv.append("--skip-bav")
    if deep_domxss:
        argv.append("--deep-domxss")
    for name, value in headers.items():
        argv.extend(["--header", f"{name}: {value}"])
    argv.extend(user_flags)

    noise_level = flag_noise
    if deep_domxss:
        noise_level = "high"
    if noise_level == "high":
        warnings.add("high noise profile: deep DOM XSS / heavy testing enabled")
    evidence: dict[str, Any] = {
        "noise_level": noise_level,
        "target": target,
        "method": method,
        "workers": workers,
        "blind": blind,
        "deep_domxss": deep_domxss,
        "headers": sorted(headers),
        "timeout_seconds": timeout_seconds,
        "warnings": sorted(warnings),
    }

    sandbox = sandbox_for_environment(
        workspace_root, allowed_programs=DALFOX_ALLOWED_PROGRAMS
    )
    result = await run_in_sandbox(
        sandbox,
        argv,
        timeout_seconds=timeout_seconds,
        image_env="NEXUS_DALFOX_IMAGE",
        default_image="hahwul/dalfox",
    )

    if result.timed_out:
        return ToolResult(
            output={"error": "dalfox run timed out", "target": target},
            verified=False,
            verification_method="dalfox_timeout",
            evidence=evidence,
            exit_code=result.exit_code,
            accepted_exit_codes=(0, 1),
            stdout=result.stdout,
            stderr=result.stderr,
            timed_out=True,
        )

    raw_json = result.stdout
    if not raw_json.strip():
        try:
            raw_json = read_output_text(output_path)
        except OSError:
            raw_json = ""

    try:
        scan = parse_dalfox_json(raw_json, target=target)
    except ValueError as exc:
        return ToolResult(
            output={"error": str(exc), "target": target, "noise_level": noise_level},
            verified=False,
            verification_method="dalfox_parse_failed",
            evidence=evidence,
            exit_code=result.exit_code,
            accepted_exit_codes=(0, 1),
            stdout=result.stdout,
            stderr=result.stderr,
        )

    evidence.update(
        {
            "findings_count": len(scan.findings),
            "raw_json_sha256": scan.raw_json_sha256,
        }
    )
    # Zero findings is a valid completed scan (no XSS on the target).
    return ToolResult(
        output={
            "target": target,
            "noise_level": noise_level,
            "count": len(scan.findings),
            "findings": [finding.to_dict() for finding in scan.findings],
        },
        verified=result.exit_code in {0, 1},
        verification_method="dalfox_json_parsed",
        evidence=evidence,
        exit_code=result.exit_code,
        accepted_exit_codes=(0, 1),
        stdout=result.stdout,
        stderr=result.stderr,
    )
