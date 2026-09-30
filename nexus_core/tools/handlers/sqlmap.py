"""Durable ``nexus.web.sqlmap`` handler: SQL injection detection.

sqlmap is run in **batch** mode only, through the sandbox, with a closed
allowlist. Post-exploitation flags (``--os-shell``, ``--file-read``,
``--file-write``, ``--sql-shell``, ...) are forbidden outright: this tool
detects injection, it does not take over the database.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

from nexus_core.kernel.models import RiskLevel, RunContext, ToolDefinition, ToolResult
from nexus_core.kernel.sandbox import sandbox_for_environment
from nexus_core.tools.parsers.sqlmap import parse_sqlmap_output

from ._exec import RECON_ALLOWED_PROGRAMS, run_in_sandbox, safe_run_id

SQLMAP_ALLOWED_PROGRAMS = RECON_ALLOWED_PROGRAMS + ("sqlmap",)

SQLMAP_DEFAULT_TIMEOUT_SECONDS = 1800
SQLMAP_MIN_TIMEOUT_SECONDS = 30
SQLMAP_MAX_TIMEOUT_SECONDS = 3600
SQLMAP_DEFAULT_LEVEL = 1
SQLMAP_DEFAULT_RISK = 1
SQLMAP_THREADS = 1
SQLMAP_STOP_LIMIT = 100
SQLMAP_DEFAULT_ANSWERS = "quit=N,follow=N,keep testing=N,redirect=N"

#: Flags sqlmap always receives from the handler (never model-controlled).
SQLMAP_MANAGED_FLAGS: set[str] = {
    "--url",
    "--data",
    "--cookie",
    "--batch",
    "--flush-session",
    "--output-dir",
    "--answers",
    "--no-cast",
    "--no-escape",
    "--threads",
}

#: Non-structural flags the model may add: ``(baseline_noise, takes_value)``.
SQLMAP_ALLOWED_FLAGS: dict[str, tuple[str, bool]] = {
    "--url": ("medium", True),
    "--data": ("medium", True),
    "--cookie": ("low", True),
    "--level": ("medium", True),
    "--risk": ("medium", True),
    "--technique": ("low", True),
    "--dbms": ("low", True),
    "--tamper": ("medium", True),
    "--random-agent": ("low", False),
    "--batch": ("low", False),
    "--flush-session": ("low", False),
    "--threads": ("medium", True),
    "--timeout": ("low", True),
    "--time-sec": ("medium", True),
    "--output-dir": ("low", True),
    "--answers": ("low", True),
    "--no-cast": ("low", False),
    "--no-escape": ("low", False),
    # Only reachable with ``safe_mode=False`` (see ``SQLMAP_SAFE_MODE_FLAGS``).
    "--dump": ("high", False),
    "--dump-all": ("high", False),
    "--dbs": ("high", False),
    "--tables": ("high", False),
    "--columns": ("high", False),
    "--current-db": ("high", False),
    "--current-user": ("high", False),
    "--is-dba": ("high", False),
    "--stop": ("low", True),
}

#: Flags that only make sense after an explicit ``safe_mode=False`` opt-in.
SQLMAP_SAFE_MODE_FLAGS: set[str] = {
    "--dump",
    "--dump-all",
    "--dbs",
    "--tables",
    "--columns",
    "--current-db",
    "--current-user",
    "--is-dba",
}

SQLMAP_DUMP_FLAGS: set[str] = {"--dump", "--dump-all"}

#: Post-exploitation / arbitrary file access. Never accepted, at any level.
SQLMAP_FORBIDDEN_FLAGS: set[str] = {
    "--os-shell",
    "--os-pwn",
    "--os-smbrelay",
    "--sql-shell",
    "--sql-query",
    "--file-read",
    "--file-write",
    "--file-dest",
    "--priv-esc",
    "--reg-read",
    "--reg-add",
    "--reg-del",
}

NOISE_LEVELS = {"low": 0, "medium": 1, "high": 2}
NOISE_NAMES = ("low", "medium", "high")

_CONTROL_CHARS_RE = re.compile(r"[\x00\r\n]")
_METACHAR_RE = re.compile(r"[;&|`$()<>]")
_TECHNIQUE_RE = re.compile(r"^[BEUSTQ]+$")


def _validate_text(value: Any, field: str, *, reject_metachars: bool = False) -> str:
    text = str(value)
    if _CONTROL_CHARS_RE.search(text):
        raise ValueError(f"sqlmap {field} contains control characters")
    if reject_metachars and _METACHAR_RE.search(text):
        raise ValueError(f"sqlmap {field} contains shell metacharacters: {text!r}")
    return text


def validate_and_canonicalize_sqlmap_flags(
    raw_flags: list[str], safe_mode: bool = True
) -> tuple[list[str], str, set[str]]:
    """Validate model-provided sqlmap flags.

    Returns ``(canonical_flags, noise_level, warnings)``. Raises ``ValueError``
    for empty, malformed, unknown, forbidden or unsafe-mode-gated flags.
    """
    canonical: list[str] = []
    warnings: set[str] = set()
    noise_rank = 0
    index = 0
    while index < len(raw_flags):
        token = str(raw_flags[index]).strip()
        index += 1
        if not token:
            raise ValueError("empty sqlmap flag is not allowed")
        if not token.startswith("-"):
            raise ValueError(f"sqlmap flag must start with '-': {token!r}")

        name, separator, inline_value = token.partition("=")
        if token in SQLMAP_FORBIDDEN_FLAGS or name in SQLMAP_FORBIDDEN_FLAGS:
            raise ValueError(f"sqlmap flag is forbidden: {token!r}")
        if (token in SQLMAP_SAFE_MODE_FLAGS or name in SQLMAP_SAFE_MODE_FLAGS) and safe_mode:
            raise ValueError(
                f"sqlmap flag requires safe_mode=False: {token!r}"
            )

        spec = SQLMAP_ALLOWED_FLAGS.get(token) or SQLMAP_ALLOWED_FLAGS.get(name)
        if spec is None:
            raise ValueError(f"sqlmap flag is not allowed: {token!r}")
        level, requires_value = spec
        noise_rank = max(noise_rank, NOISE_LEVELS[level])

        if requires_value:
            if separator:
                value = inline_value.strip()
            else:
                if index >= len(raw_flags):
                    raise ValueError(f"sqlmap flag requires a value: {token!r}")
                value = str(raw_flags[index]).strip()
                index += 1
            if not value or value.startswith("-"):
                raise ValueError(f"invalid value for sqlmap flag {token!r}: {value!r}")
            canonical.extend([name, value])
        else:
            if separator:
                raise ValueError(f"sqlmap flag does not take a value: {token!r}")
            canonical.append(name)

    if noise_rank == NOISE_LEVELS["high"]:
        warnings.add("high noise profile: post-exploitation flags requested")
    return canonical, NOISE_NAMES[noise_rank], warnings


def sqlmap_definition(tenant_id: str = "system") -> ToolDefinition:
    """Return the durable ToolDefinition for ``nexus.web.sqlmap``."""
    return ToolDefinition(
        tool_id="nexus.web.sqlmap",
        name="SQLMap SQL injection scanner",
        tenant_id=tenant_id,
        description=(
            "Detección y explotación de SQL injection en URLs/parámetros. "
            "Modo batch obligatorio (no interactivo). Solo detección por "
            "defecto; explotación (--dump, --os-shell) requiere autorización."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "url": {"type": "string", "minLength": 8, "maxLength": 2048},
                "data": {"type": "string", "maxLength": 4096},
                "cookie": {"type": "string", "maxLength": 2048},
                "level": {"type": "integer", "minimum": 1, "maximum": 5},
                "risk": {"type": "integer", "minimum": 1, "maximum": 3},
                "technique": {
                    "type": "string",
                    "pattern": "^[BEUSTQ]+$",
                    "maxLength": 6,
                },
                "dbms": {"type": "string", "maxLength": 32},
                "tamper": {"type": "string", "maxLength": 128},
                "timeout_seconds": {
                    "type": "integer",
                    "minimum": SQLMAP_MIN_TIMEOUT_SECONDS,
                    "maximum": SQLMAP_MAX_TIMEOUT_SECONDS,
                },
                "safe_mode": {"type": "boolean"},
            },
            "required": ["url"],
            "additionalProperties": False,
        },
        risk=RiskLevel.MEDIUM,
        required_permissions=["execute:tool:nexus.web.sqlmap"],
        timeout_seconds=1800,
        max_output_bytes=10_000_000,
        scope_target_field="url",
        scope_required=True,
    )


def _build_sqlmap_flags(arguments: dict, safe_mode: bool) -> tuple[list[str], str, set[str]]:
    raw_flags = list(arguments.get("flags") or [])
    canonical, noise, warnings = validate_and_canonicalize_sqlmap_flags(
        raw_flags, safe_mode=safe_mode
    )
    # Drop managed flags supplied by the model: the handler owns them.
    user_flags = [
        token
        for index, token in enumerate(canonical)
        if token not in SQLMAP_MANAGED_FLAGS
        and not (index and canonical[index - 1] in SQLMAP_MANAGED_FLAGS)
    ]
    # Bare ``--dump``/``--dump-all`` are bounded to a fixed row limit.
    if any(token in SQLMAP_DUMP_FLAGS for token in canonical) and "--stop" not in canonical:
        user_flags.extend(["--stop", str(SQLMAP_STOP_LIMIT)])
    return user_flags, noise, warnings


async def sqlmap_handler(arguments: dict, context: RunContext) -> ToolResult:
    """Run an allowlisted, batch-mode sqlmap scan through the sandbox."""
    url = _validate_text(arguments["url"], "url")
    if not url.startswith(("http://", "https://")):
        raise ValueError("sqlmap url must be an http(s) URL")

    data = arguments.get("data")
    cookie = arguments.get("cookie")
    if data is not None:
        data = _validate_text(data, "data")
    if cookie is not None:
        cookie = _validate_text(cookie, "cookie")

    technique = arguments.get("technique")
    if technique is not None and not _TECHNIQUE_RE.match(str(technique).strip()):
        raise ValueError(f"sqlmap technique is invalid: {technique!r}")
    dbms = arguments.get("dbms")
    if dbms is not None:
        dbms = _validate_text(dbms, "dbms", reject_metachars=True)
    tamper = arguments.get("tamper")
    if tamper is not None:
        tamper = _validate_text(tamper, "tamper", reject_metachars=True)

    safe_mode = bool(arguments.get("safe_mode", True))
    user_flags, flag_noise, warnings = _build_sqlmap_flags(arguments, safe_mode)

    requested_timeout = arguments.get("timeout_seconds")
    timeout_seconds = min(
        SQLMAP_MAX_TIMEOUT_SECONDS,
        max(
            SQLMAP_MIN_TIMEOUT_SECONDS,
            int(requested_timeout) if requested_timeout else SQLMAP_DEFAULT_TIMEOUT_SECONDS,
        ),
    )

    workspace_root = os.getenv("NEXUS_WORKSPACE_ROOT", os.getcwd())
    run_id = safe_run_id(context)
    output_dir = Path(workspace_root).resolve() / f"sqlmap_out_{run_id}"

    argv = ["sqlmap", "-u", url]
    if data:
        argv.extend(["--data", data])
    if cookie:
        argv.extend(["--cookie", cookie])
    argv.extend(
        [
            "--batch",
            "--flush-session",
            "--threads",
            str(SQLMAP_THREADS),
            "--no-cast",
            "--no-escape",
            "--output-dir",
            str(output_dir),
            "--answers",
            SQLMAP_DEFAULT_ANSWERS,
        ]
    )
    for flag, value in (
        ("--level", arguments.get("level")),
        ("--risk", arguments.get("risk")),
        ("--technique", technique),
        ("--dbms", dbms),
        ("--tamper", tamper),
    ):
        if value is not None:
            argv.extend([flag, str(value)])
    argv.extend(user_flags)

    sandbox = sandbox_for_environment(
        workspace_root, allowed_programs=SQLMAP_ALLOWED_PROGRAMS
    )
    result = await run_in_sandbox(
        sandbox,
        argv,
        timeout_seconds=timeout_seconds,
        image_env="NEXUS_SQLMAP_IMAGE",
        default_image="secsi/sqlmap",
    )

    noise_level = "high" if not safe_mode else flag_noise
    if noise_level == "high":
        warnings.add("high noise profile: post-exploitation flags requested")
    evidence: dict[str, Any] = {
        "noise_level": noise_level,
        "url": url,
        "safe_mode": safe_mode,
        "timeout_seconds": timeout_seconds,
        "flags": list(user_flags),
        "warnings": sorted(warnings),
    }

    if result.timed_out:
        return ToolResult(
            output={"error": "sqlmap run timed out", "url": url, "noise_level": noise_level},
            verified=False,
            verification_method="sqlmap_timeout",
            evidence=evidence,
            exit_code=result.exit_code,
            accepted_exit_codes=(0, 1),
            stdout=result.stdout,
            stderr=result.stderr,
            timed_out=True,
        )

    try:
        scan = parse_sqlmap_output(result.stdout, target_url=url)
    except ValueError as exc:
        return ToolResult(
            output={"error": str(exc), "url": url, "noise_level": noise_level},
            verified=False,
            verification_method="sqlmap_parse_failed",
            evidence=evidence,
            exit_code=result.exit_code,
            accepted_exit_codes=(0, 1),
            stdout=result.stdout,
            stderr=result.stderr,
        )

    evidence.update(
        {
            "vulnerable": scan.vulnerable,
            "findings_count": len(scan.findings),
            "dbms_detected": scan.dbms_detected,
            "raw_log_sha256": scan.raw_log_sha256,
        }
    )
    return ToolResult(
        output={
            "url": url,
            "noise_level": noise_level,
            "vulnerable": scan.vulnerable,
            "findings": [finding.to_dict() for finding in scan.findings],
        },
        verified=result.exit_code in {0, 1},
        verification_method="sqlmap_stdout_parsed",
        evidence=evidence,
        exit_code=result.exit_code,
        accepted_exit_codes=(0, 1),
        stdout=result.stdout,
        stderr=result.stderr,
    )
