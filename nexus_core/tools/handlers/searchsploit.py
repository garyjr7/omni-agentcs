"""Durable ``nexus.exploit.searchsploit`` handler: local Exploit-DB lookup.

SearchSploit reads the local Exploit-DB copy; it performs no network traffic and
needs no scope. Availability is probed with ``searchsploit -h`` because the
installed build does not accept ``--version`` (``illegal option -- -``).
"""

from __future__ import annotations

import os
import re
from typing import Any

from nexus_core.kernel.models import RiskLevel, RunContext, ToolDefinition, ToolResult
from nexus_core.kernel.sandbox import sandbox_for_environment
from nexus_core.tools.parsers.searchsploit import parse_searchsploit_json

from ._exec import RECON_ALLOWED_PROGRAMS, run_in_sandbox

SEARCHSPLOIT_ALLOWED_PROGRAMS = RECON_ALLOWED_PROGRAMS + ("searchsploit",)

SEARCHSPLOIT_TIMEOUT_SECONDS = 30
SEARCHSPLOIT_PROBE_TIMEOUT_SECONDS = 10

#: ``searchsploit -h`` is the availability probe (no ``--version`` on this build).
SEARCHSPLOIT_VERIFY_ARGV = ("searchsploit", "-h")
#: ``searchsploit -h`` prints help and exits with code 2, so that is accepted.
SEARCHSPLOIT_PROBE_OK_CODES = (0, 1, 2)

#: Copying an exploit to disk or opening it in $PAGER is never allowed.
SEARCHSPLOIT_FORBIDDEN_FLAGS = {"-m", "--mirror", "-x", "--examine"}

_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.IGNORECASE)
_CONTROL_CHARS_RE = re.compile(r"[\x00\r\n]")


def searchsploit_definition(tenant_id: str = "system") -> ToolDefinition:
    """Return the durable ToolDefinition for ``nexus.exploit.searchsploit``."""
    return ToolDefinition(
        tool_id="nexus.exploit.searchsploit",
        name="SearchSploit local Exploit-DB lookup",
        tenant_id=tenant_id,
        description=(
            "Búsqueda en la base de datos local de Exploit-DB. Permite "
            "encontrar exploits conocidos por CVE, producto, versión o "
            "términos libres. Solo lee la base local; no hace red."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "query": {"type": "string", "minLength": 2, "maxLength": 200},
                "cve": {"type": "string", "pattern": "^CVE-\\d{4}-\\d{4,7}$"},
                "exact": {"type": "boolean"},
                "json": {"type": "boolean"},
                "exclude": {"type": "string", "maxLength": 100},
            },
            "additionalProperties": False,
        },
        risk=RiskLevel.READ_ONLY,
        required_permissions=["execute:tool:nexus.exploit.searchsploit"],
        timeout_seconds=30,
        max_output_bytes=1_000_000,
        scope_target_field=None,
        scope_required=False,
    )


def _validate_token(value: Any, field: str, *, allow_empty: bool = True) -> str:
    text = str(value).strip()
    if not allow_empty and not text:
        raise ValueError(f"searchsploit {field} is required")
    if _CONTROL_CHARS_RE.search(text):
        raise ValueError(f"searchsploit {field} contains control characters")
    if text.startswith("-"):
        raise ValueError(f"searchsploit {field} must not look like a flag: {text!r}")
    return text


def _build_argv(arguments: dict) -> list[str]:
    query = arguments.get("query")
    cve = arguments.get("cve")
    query = _validate_token(query, "query") if query is not None else ""
    cve = _validate_token(cve, "cve") if cve is not None else ""
    if not query and not cve:
        raise ValueError("searchsploit requires a query or a cve")
    if cve and not _CVE_RE.match(cve):
        raise ValueError(f"searchsploit cve is invalid: {cve!r}")

    argv = ["searchsploit", "--json"]
    if cve:
        argv.extend(["--cve", cve.upper()])
    else:
        argv.append(query)
    if arguments.get("exact"):
        argv.append("--exact")
    exclude = arguments.get("exclude")
    if exclude is not None:
        exclude = _validate_token(exclude, "exclude")
        if exclude:
            argv.append(f"--exclude={exclude}")
    return argv


async def searchsploit_handler(arguments: dict, context: RunContext) -> ToolResult:
    """Run a local Exploit-DB lookup through the sandbox and parse its JSON."""
    argv = _build_argv(arguments)
    query = str(arguments.get("query") or arguments.get("cve") or "").strip()

    workspace_root = os.getenv("NEXUS_WORKSPACE_ROOT", os.getcwd())
    sandbox = sandbox_for_environment(
        workspace_root, allowed_programs=SEARCHSPLOIT_ALLOWED_PROGRAMS
    )

    probe = await run_in_sandbox(
        sandbox,
        list(SEARCHSPLOIT_VERIFY_ARGV),
        timeout_seconds=SEARCHSPLOIT_PROBE_TIMEOUT_SECONDS,
        image_env="NEXUS_SEARCHSPLOIT_IMAGE",
        default_image="secsi/searchsploit",
    )
    if probe.exit_code not in SEARCHSPLOIT_PROBE_OK_CODES:
        return ToolResult(
            output={"error": "searchsploit is not available", "query": query},
            verified=False,
            verification_method="searchsploit_unavailable",
            evidence={"query": query, "probe_exit_code": probe.exit_code},
            exit_code=probe.exit_code,
            accepted_exit_codes=SEARCHSPLOIT_PROBE_OK_CODES,
            stdout=probe.stdout,
            stderr=probe.stderr,
        )

    result = await run_in_sandbox(
        sandbox,
        argv,
        timeout_seconds=SEARCHSPLOIT_TIMEOUT_SECONDS,
        image_env="NEXUS_SEARCHSPLOIT_IMAGE",
        default_image="secsi/searchsploit",
    )

    evidence: dict[str, Any] = {"query": query}
    if result.timed_out:
        return ToolResult(
            output={"error": "searchsploit run timed out", "query": query},
            verified=False,
            verification_method="searchsploit_timeout",
            evidence=evidence,
            exit_code=result.exit_code,
            accepted_exit_codes=(0, 1),
            stdout=result.stdout,
            stderr=result.stderr,
            timed_out=True,
        )
    if result.exit_code not in {0, 1}:
        return ToolResult(
            output={"error": "searchsploit failed", "query": query},
            verified=False,
            verification_method="searchsploit_failed",
            evidence={**evidence, "exit_code": result.exit_code},
            exit_code=result.exit_code,
            accepted_exit_codes=(0, 1),
            stdout=result.stdout,
            stderr=result.stderr,
        )

    try:
        lookup = parse_searchsploit_json(result.stdout, query=query)
    except ValueError as exc:
        return ToolResult(
            output={"error": str(exc), "query": query},
            verified=False,
            verification_method="searchsploit_parse_failed",
            evidence=evidence,
            exit_code=result.exit_code,
            accepted_exit_codes=(0, 1),
            stdout=result.stdout,
            stderr=result.stderr,
        )

    evidence.update(
        {
            "total": lookup.total,
            "exploits": len(lookup.exploits),
            "shellcodes": len(lookup.shellcodes),
            "raw_json_sha256": lookup.raw_json_sha256,
        }
    )
    # No result is a valid completed lookup: the local DB simply had no match.
    return ToolResult(
        output={
            "query": lookup.query,
            "total": lookup.total,
            "exploits": [entry.to_dict() for entry in lookup.exploits],
            "shellcodes": [entry.to_dict() for entry in lookup.shellcodes],
        },
        verified=result.exit_code in {0, 1},
        verification_method="searchsploit_json_parsed",
        evidence=evidence,
        exit_code=result.exit_code,
        accepted_exit_codes=(0, 1),
        stdout=result.stdout,
        stderr=result.stderr,
    )
