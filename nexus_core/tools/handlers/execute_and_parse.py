"""``nexus.system.execute_and_parse``: run a command and return parsed output.

The measured gap
----------------
``nexus.shell.exec`` runs anything but hands the model 60 lines of text, so any
tool whose value is its structure (``nmap -oX -``, ``nuclei -json``) needs a
dedicated handler to become evidence. The agent then either re-ran the tool
through the rigid handler or lost the parse. This tool is the bridge: it uses
**the same** governed shell substrate — sandbox, workspace confinement, deny
list, scope check, audit and artifact — and adds a parser from the closed
registry in :mod:`nexus_core.tools.output_parsers`.

The parse reads the *artifact* (the full capture), never the bounded summary,
so a 10 MB nmap XML is parsed completely while the observation stays small.

Failure semantics are inherited on purpose: a denied/out-of-scope/timed-out
command returns the shell's own observation untouched (the loop already knows
how to read those), and a parser failure is a correctable ``error`` that names
every accepted parser.
"""

from __future__ import annotations

import re
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from nexus_core.kernel.artifacts import configured_artifact_store
from nexus_core.kernel.models import RiskLevel, RunContext, ToolDefinition, ToolResult
from nexus_core.tools.output_parsers import (
    PARSER_NAMES,
    parse_output,
    summarize,
)
from .report_generate import default_artifact_root
from .shell_exec_local import (
    SHELL_MAX_OUTPUT_BYTES,
    SHELL_MAX_STDIN_BYTES,
    SHELL_MAX_TIMEOUT_SECONDS,
    SHELL_MIN_TIMEOUT_SECONDS,
    shell_exec_handler,
)

TOOL_ID = "nexus.system.execute_and_parse"

#: The artifact header/``[exit=…]`` trailer :func:`shell_exec_local.summarize`
#: writes around the capture. They are stripped before parsing so the parser
#: receives the command's real stdout.
_HEADER_RE = re.compile(r"^\$ [^\n]*\n")
_TRAILER_RE = re.compile(r"\n\[exit=[^\]]*\]\n?\Z")
_STDERR_MARKER = "\n[stderr]\n"

#: What the model reads when ``parser_name`` is not in the closed registry.
UNKNOWN_PARSER_GUIDANCE = (
    "parser_name no pertenece al registro cerrado: elige uno de "
    f"{', '.join(PARSER_NAMES)}. Si la salida no tiene parser propio, usa "
    'parser_name="text" y trabaja con el artifact.'
)


class ExecuteAndParseRequest(BaseModel):
    """Strict contract: a command plus one parser from the closed registry."""

    model_config = ConfigDict(strict=True, frozen=True, extra="forbid")
    command: str = Field(min_length=1, max_length=8192)
    parser_name: str = Field(min_length=1, max_length=40)
    cwd: str = Field(default=".", max_length=4096)
    timeout_seconds: int = Field(
        default=60,
        ge=SHELL_MIN_TIMEOUT_SECONDS,
        le=SHELL_MAX_TIMEOUT_SECONDS,
    )
    stdin: str | None = Field(default=None, max_length=SHELL_MAX_STDIN_BYTES)


def execute_and_parse_definition(tenant_id: str = "system") -> ToolDefinition:
    """Return the durable definition of ``nexus.system.execute_and_parse``."""
    return ToolDefinition(
        tool_id=TOOL_ID,
        tenant_id=tenant_id,
        name="Execute and parse",
        description=(
            "Ejecuta un comando en el sandbox y devuelve su salida parseada. "
            "parser_name: nmap (XML de `nmap -oX -`) o text (cualquier salida). "
            "Mismo gobierno que nexus.shell.exec: scope, auditoría y artifact."
        ),
        input_schema=ExecuteAndParseRequest.model_json_schema(),
        risk=RiskLevel.HIGH,
        effect="execution",
        scope_required=True,
        sandbox_required=True,
        timeout_seconds=SHELL_MAX_TIMEOUT_SECONDS + 60,
        max_output_bytes=SHELL_MAX_OUTPUT_BYTES,
        required_permissions=[f"execute:tool:{TOOL_ID}"],
    )


def split_capture(text: str) -> tuple[str, str]:
    """``(stdout, stderr)`` of a ``shell.exec`` artifact, without its markers."""
    body = str(text or "")
    body = _HEADER_RE.sub("", body, count=1)
    body = _TRAILER_RE.sub("", body, count=1)
    if _STDERR_MARKER in body:
        stdout, stderr = body.split(_STDERR_MARKER, 1)
        return stdout, stderr
    return body, ""


def _captured_stdout(result: ToolResult, context: RunContext) -> str:
    """The command's full stdout, from the artifact (``""`` when unreadable)."""
    output = result.output if isinstance(result.output, dict) else {}
    artifact_id = str(output.get("artifact_ref") or "")
    if not artifact_id or context.store is None:
        return ""
    try:
        payload = configured_artifact_store(
            context.store, default_artifact_root()
        ).get(context.tenant_id, artifact_id)
    except Exception:  # noqa: BLE001 - fall back to the bounded summary
        return ""
    return split_capture(payload.decode("utf-8", errors="replace"))[0]


async def execute_and_parse_handler(
    arguments: dict[str, Any], context: RunContext
) -> ToolResult:
    """Run the command through the governed shell, then parse its stdout."""
    request = ExecuteAndParseRequest.model_validate(arguments)
    shell_arguments: dict[str, Any] = {
        "command": request.command,
        "cwd": request.cwd,
        "timeout_seconds": request.timeout_seconds,
    }
    if request.stdin is not None:
        shell_arguments["stdin"] = request.stdin
    shell = await shell_exec_handler(shell_arguments, context)
    if not shell.success:
        # Denial, scope violation, timeout and command failure keep the shell's
        # own honest outcome and guidance; parsing nothing is not an error.
        return shell

    raw = _captured_stdout(shell, context) or str(shell.stdout or "")
    try:
        parsed = parse_output(request.parser_name, raw)
    except ValueError as exc:
        output = dict(shell.output if isinstance(shell.output, dict) else {})
        output.update(
            {
                "error": str(exc),
                "parser_name": request.parser_name,
                "available_parsers": list(PARSER_NAMES),
                "command": request.command,
                "guidance": UNKNOWN_PARSER_GUIDANCE,
            }
        )
        return ToolResult(
            output=output,
            verified=False,
            outcome="error",
            verification_method="execute_and_parse_failed",
            evidence={
                "parser": request.parser_name,
                "parser_error": str(exc)[:300],
                "artifact_ref": output.get("artifact_ref"),
            },
            exit_code=shell.exit_code,
            stdout=str(shell.stdout or ""),
            stderr="",
            timed_out=shell.timed_out,
        )

    summary = summarize(parsed)
    output = dict(shell.output if isinstance(shell.output, dict) else {})
    output.update(
        {
            "parser": parsed["parser"],
            "parsed": parsed,
            "summary": summary,
            "command": request.command,
            # Reuse the TUI's nmap renderer: the same scan shape the dedicated
            # tool returns, so a parsed nmap reads exactly the same.
            **({"scan": parsed["scan"]} if "scan" in parsed else {}),
        }
    )
    evidence = dict(shell.evidence if isinstance(shell.evidence, dict) else {})
    evidence.update(
        {
            "parser": parsed["parser"],
            "parsed_keys": sorted(parsed),
            "summary": summary,
        }
    )
    if "ports_open_total" in parsed:
        evidence["ports_open_total"] = parsed["ports_open_total"]
        evidence["open_ports"] = list(parsed.get("open_ports") or [])
    if "line_count" in parsed:
        evidence["line_count"] = parsed["line_count"]
    return ToolResult(
        output=output,
        verified=bool(shell.verified),
        verification_method="execute_and_parse",
        evidence=evidence,
        exit_code=shell.exit_code,
        stdout=summary,
        stderr="",
        timed_out=shell.timed_out,
    )


__all__ = [
    "ExecuteAndParseRequest",
    "TOOL_ID",
    "UNKNOWN_PARSER_GUIDANCE",
    "execute_and_parse_definition",
    "execute_and_parse_handler",
    "split_capture",
]
