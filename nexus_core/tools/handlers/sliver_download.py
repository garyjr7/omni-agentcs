"""``nexus.c2.sliver_download``: pull one file out of an owned session (MEDIUM).

The download is treated as evidence, not as text: the bytes are written to the
engagement's artifact store content-addressed and the tool result only carries
metadata plus the SHA256. Three consequences, all deliberate:

* the file can never be confused with model output, so a downloaded binary
  cannot smuggle instructions into the prompt;
* the report can cite the artifact (id + hash) as chain of custody;
* the size ceiling is enforced before the second chunk is kept, so a session
  pointed at ``/etc/shadow`` or a disk image fails closed instead of filling the
  workspace.

The session must belong to the current engagement (``kernel_sessions``), exactly
like ``nexus.c2.sliver_exec``: owning a session is not a scope waiver.
"""

from __future__ import annotations

import hashlib
import re

from nexus_core.integrations.sliver.client import SliverClient, SliverError
from nexus_core.kernel.artifacts import ArtifactReference, configured_artifact_store
from nexus_core.kernel.models import RiskLevel, RunContext, ToolDefinition, ToolResult
from nexus_core.kernel.schema_validation import validate
from nexus_core.kernel.sessions import SessionRegistry, validate_session_scope
from nexus_core.tools.handlers.report_generate import default_artifact_root
from nexus_core.tools.handlers.sliver_common import build_client, error_result

TOOL_ID = "nexus.c2.sliver_download"
SESSION_ID_PATTERN = r"[A-Za-z0-9_-]{1,64}"
MAX_REMOTE_PATH_CHARS = 4096
#: Default ceiling of one pull; the handler's maximum is the client's own.
DEFAULT_MAX_BYTES = 8 * 1024 * 1024
KINDS = ("session", "beacon")
#: Shell-expanded wildcards would turn "one file" into an unbounded pull.
_WILDCARDS = ("*", "?")


def sliver_download_definition(tenant_id: str = "system") -> ToolDefinition:
    return ToolDefinition(
        tool_id=TOOL_ID,
        name="Download a file from a Sliver session",
        tenant_id=tenant_id,
        description=(
            "Descarga UN fichero de una session/beacon Sliver del engagement y lo "
            "guarda como artefacto con su SHA256. El resultado solo lleva metadatos "
            "y la referencia del artefacto, nunca el contenido."
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
                "remote_path": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": MAX_REMOTE_PATH_CHARS,
                },
                "kind": {"type": "string", "enum": list(KINDS), "default": "session"},
                "max_bytes": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": SliverClient.MAX_DOWNLOAD_BYTES,
                    "default": DEFAULT_MAX_BYTES,
                },
                "timeout_seconds": {"type": "integer", "minimum": 5, "maximum": 600},
            },
            "required": ["session_id", "remote_path"],
            "additionalProperties": False,
        },
        risk=RiskLevel.MEDIUM,
        effect="post_exploitation",
        required_permissions=[f"execute:tool:{TOOL_ID}"],
        timeout_seconds=660,
        max_output_bytes=1_000_000,
        scope_target_field=None,
        scope_required=True,
    )


def validated_remote_path(value: object) -> str:
    """One concrete path: no NULs, no wildcards, bounded length."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError("remote_path must be a non-empty string")
    text = value.strip()
    if len(text) > MAX_REMOTE_PATH_CHARS:
        raise ValueError("remote_path is too long")
    if "\x00" in text or "\n" in text or "\r" in text:
        raise ValueError("remote_path must be a single line")
    if any(char in text for char in _WILDCARDS):
        raise ValueError("remote_path must name one file, not a pattern")
    return text


async def sliver_download_handler(arguments: dict, context: RunContext) -> ToolResult:
    validate(arguments, sliver_download_definition().input_schema)
    session_id = arguments["session_id"]
    if not isinstance(session_id, str) or not re.fullmatch(SESSION_ID_PATTERN, session_id):
        raise ValueError("invalid session id")
    remote_path = validated_remote_path(arguments["remote_path"])
    kind = str(arguments.get("kind") or "session").lower()
    if kind not in KINDS:
        raise ValueError("kind must be one of session, beacon")
    max_bytes = arguments.get("max_bytes")
    if max_bytes is not None and (
        type(max_bytes) is not int or not 1 <= max_bytes <= SliverClient.MAX_DOWNLOAD_BYTES
    ):
        raise ValueError("max_bytes is out of range")
    timeout = arguments.get("timeout_seconds")
    if timeout is not None and (type(timeout) is not int or not 5 <= timeout <= 600):
        raise ValueError("timeout_seconds must be between 5 and 600")
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
        raw = await client.download_file(
            session_id,
            remote_path,
            kind=kind,
            max_bytes=int(max_bytes or DEFAULT_MAX_BYTES),
            timeout_seconds=float(timeout) if timeout else None,
        )
        data = raw.get("data") or b""
        if not data:
            return ToolResult(
                output=client.redact(
                    {
                        "session_id": session_id,
                        "path": remote_path,
                        "size": 0,
                        "empty": True,
                    }
                ),
                verification_method="sliver_download_empty",
            )
        stored = ArtifactReference.parse(
            configured_artifact_store(context.store, default_artifact_root()).put(
                context.tenant_id,
                data,
                "application/octet-stream",
                run_id=getattr(context, "run_id", None),
                metadata={
                    "tool_id": TOOL_ID,
                    "session_id": session_id,
                    "remote_path": remote_path,
                    "sha256": raw["sha256"],
                },
            )
        )
        if stored.sha256 != raw["sha256"] or stored.size_bytes != len(data):
            # The store is content-addressed; a mismatch means the bytes that
            # would be cited as evidence are not the bytes that arrived.
            return ToolResult(verification_method="sliver_download_artifact_mismatch")
        return ToolResult(
            output=client.redact(
                {
                    "session_id": session_id,
                    "kind": kind,
                    "path": remote_path,
                    "size": stored.size_bytes,
                    "sha256": stored.sha256,
                    "encoder": raw.get("encoder") or "",
                    "is_dir": bool(raw.get("is_dir")),
                    "artifact": stored.as_dict(),
                }
            ),
            verified=True,
            verification_method="sliver_download_stored",
            evidence={
                "session_id": session_id,
                "kind": kind,
                "path": remote_path,
                "size": stored.size_bytes,
                "sha256": stored.sha256,
                "artifact_id": stored.id,
                "raw_sha256": hashlib.sha256(data).hexdigest(),
            },
        )
    except SliverError as exc:
        return error_result(exc, tool_id=TOOL_ID)
    except ValueError as exc:
        # The size ceiling is a refusal, not a transient failure: say which.
        return ToolResult(
            output={"status": "refused", "reason": str(exc)[:500]},
            verification_method="sliver_download_refused",
        )
    except (TypeError, KeyError):
        return ToolResult(verification_method="sliver_response_invalid")
    finally:
        await client.disconnect()
