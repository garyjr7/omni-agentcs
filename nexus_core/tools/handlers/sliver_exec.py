"""``nexus.c2.sliver_exec``: run one command in a Sliver session/beacon (HIGH).

Post-exploitation is HIGH risk: the gateway forces human approval unless the
operator opted into trust mode. The handler never runs a shell locally — it
only sends one command to a session that the engagement already owns, and that
session must be registered in ``kernel_sessions`` for the *current* engagement.

The command is additionally de-fanged: shell metacharacters (chaining,
redirection, substitution) and a curated set of destructive first tokens are
rejected before any RPC.
"""

from __future__ import annotations

import re

from nexus_core.integrations.sliver.client import SliverError
from nexus_core.kernel.models import RiskLevel, RunContext, ToolDefinition, ToolResult
from nexus_core.kernel.schema_validation import validate
from nexus_core.kernel.sessions import SessionRegistry, validate_session_scope
from nexus_core.tools.handlers.sliver_common import build_client, error_result
from nexus_core.tools.parsers.sliver import parse_sliver_exec

TOOL_ID = "nexus.c2.sliver_exec"
SESSION_ID_PATTERN = r"[A-Za-z0-9_-]{1,64}"
MAX_COMMAND_CHARS = 2000

#: Characters that would let one "single command" become several, redirect I/O
#: or expand a substitution. The command must stay a single argv-like line.
SHELL_METACHARACTERS = (";", "|", "&", "`", "$", ">", "<", "\n", "\r", "\x00")

#: First tokens (after path normalisation) that are inherently destructive.
DESTRUCTIVE_COMMANDS = frozenset(
    {
        "format",
        "shutdown",
        "reboot",
        "halt",
        "poweroff",
        "init",
        "mkfs",
        "fdisk",
        "diskpart",
        "wipefs",
        "mkswap",
        "bcdedit",
        "vssadmin",
        "cipher",
        "sdelete",
    }
)

KINDS = ("session", "beacon")


def sliver_exec_definition(tenant_id: str = "system") -> ToolDefinition:
    return ToolDefinition(
        tool_id=TOOL_ID,
        name="Execute command on Sliver session",
        tenant_id=tenant_id,
        description=(
            "Ejecuta UN comando en una session o beacon Sliver. Requiere aprobación "
            "humana (HIGH). El comando se valida contra una lista de operaciones "
            "destructivas y no admite metacaracteres de shell."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "session_id": {
                    "type": "string",
                    "pattern": "^" + SESSION_ID_PATTERN + "$",
                    "minLength": 1,
                    "maxLength": 64,
                },
                "command": {"type": "string", "minLength": 1, "maxLength": MAX_COMMAND_CHARS},
                "kind": {"type": "string", "enum": list(KINDS), "default": "session"},
                "timeout_seconds": {"type": "integer", "minimum": 5, "maximum": 300},
            },
            "required": ["session_id", "command"],
            "additionalProperties": False,
        },
        risk=RiskLevel.HIGH,
        effect="post_exploitation",
        required_permissions=[f"execute:tool:{TOOL_ID}"],
        timeout_seconds=360,
        max_output_bytes=10_000_000,
        scope_target_field=None,
        scope_required=True,
    )


def _command_token(command: str) -> str:
    """Base name of the first token, so ``/sbin/reboot`` == ``reboot``."""
    head = command.strip().splitlines()[0].strip()
    if not head:
        return ""
    raw = re.split(r"\s+", head, maxsplit=1)[0]
    return raw.replace("\\", "/").rsplit("/", 1)[-1].lower()


def validated_command(command: object) -> str:
    """Reject null bytes, shell metacharacters and destructive commands."""
    if not isinstance(command, str) or not command.strip():
        raise ValueError("command must be a non-empty string")
    if len(command) > MAX_COMMAND_CHARS:
        raise ValueError("command is too long")
    if any(char in command for char in SHELL_METACHARACTERS):
        raise ValueError("command must not contain shell metacharacters")
    token = _command_token(command)
    # ``mkfs.ext4`` is as destructive as ``mkfs``: compare the bare family too.
    if token in DESTRUCTIVE_COMMANDS or token.split(".", 1)[0] in DESTRUCTIVE_COMMANDS:
        raise ValueError("command is destructive and is not permitted")
    return command


async def sliver_exec_handler(arguments: dict, context: RunContext) -> ToolResult:
    validate(arguments, sliver_exec_definition().input_schema)
    session_id = arguments["session_id"]
    if not isinstance(session_id, str) or not re.fullmatch(SESSION_ID_PATTERN, session_id):
        raise ValueError("invalid session id")
    command = validated_command(arguments["command"])
    kind = str(arguments.get("kind") or "session").lower()
    if kind not in KINDS:
        raise ValueError("kind must be one of session, beacon")
    timeout = arguments.get("timeout_seconds")
    if timeout is not None and (type(timeout) is not int or not 5 <= timeout <= 300):
        raise ValueError("timeout_seconds must be between 5 and 300")
    try:
        validate_session_scope(context)
    except PermissionError:
        return ToolResult(verification_method="session_scope_required")
    registry = SessionRegistry(context.store)
    denied = registry.denial(context, session_id)
    if denied is not None:
        return denied
    client, failure = build_client()
    if client is None:
        return failure or ToolResult(verification_method="sliver_unavailable")
    try:
        await client.connect()
        raw = await client.execute_command(
            session_id,
            command,
            kind=kind,
            timeout_seconds=float(timeout) if timeout else None,
        )
        parsed = parse_sliver_exec(raw, session_id, command)
        return ToolResult(
            output=client.redact(parsed.to_dict()),
            verified=parsed.status in {"ok", "timeout"},
            verification_method=f"sliver_exec_{parsed.status}",
            evidence={
                "session_id": parsed.session_id,
                "kind": kind,
                "command": command,
                "status": parsed.status,
                "stdout_bytes": len(parsed.stdout.encode("utf-8", errors="replace")),
                "stderr_bytes": len(parsed.stderr.encode("utf-8", errors="replace")),
                "duration_seconds": parsed.duration_seconds,
                "raw_sha256": parsed.raw_sha256,
            },
        )
    except SliverError as exc:
        return error_result(exc, tool_id=TOOL_ID)
    except (ValueError, TypeError):
        return ToolResult(verification_method="sliver_response_invalid")
    finally:
        await client.disconnect()
