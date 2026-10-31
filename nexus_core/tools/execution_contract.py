"""Invocation-local capture evidence for builtin handlers; no global mutable log."""

from __future__ import annotations

import re
from contextvars import ContextVar
from dataclasses import asdict, replace
from functools import wraps
from typing import Any

from nexus_core.kernel.models import RunContext, ToolDefinition, ToolResult
from nexus_core.kernel.sandbox import SandboxResult
from nexus_core.tools.registration import Handler

_captures: ContextVar[list[dict[str, Any]] | None] = ContextVar("tool_captures", default=None)


def record_capture(result: SandboxResult, *, source: str = "process") -> None:
    """Record metadata only, never argv, output text or credentials."""
    captures = _captures.get()
    if captures is None:
        return
    streams = {}
    for name in ("stdout", "stderr"):
        manifest = getattr(result, f"{name}_manifest", None)
        streams[name] = asdict(manifest) if manifest is not None else None
    captures.append(
        {
            "source": source,
            "exit_code": result.exit_code,
            "timed_out": result.timed_out,
            "cancelled": result.cancelled,
            **streams,
        }
    )


#: A value that is an absolute URL, not an argv token. A raw space is a
#: modelling slip there, never a second token: every HTTP client encodes it.
_URL_PREFIX = re.compile(r"^https?://", re.IGNORECASE)


def validate_target(value: object) -> str:
    """Reject argv-option and control-character injection without resolving DNS.

    A URL is the one accepted target shape where whitespace is unambiguous: it
    is percent-encoded (``%20``) instead of rejected, because that is exactly
    what the server would receive from a browser. Measured in
    ``run_3d90f7f388144557ae97466b0a19ce55`` (2026-10-20): the model built a
    working ``extractvalue(... substr(password,33,32) ...)`` payload, got
    "target must be a single token" for the space, and burned two turns per
    block of the hash it was already able to read.
    """
    if not isinstance(value, str) or not value.strip():
        raise ValueError("target must be a nonempty string")
    target = value.strip()
    if target.startswith("-") or any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ValueError("target contains an option or control character")
    if any(char.isspace() for char in target):
        if _URL_PREFIX.match(target):
            return target.replace(" ", "%20")
        # Anything else is an argv token: a raw space is rejected, not split.
        raise ValueError(
            "target must be a single token (URL-encode spaces as %20; "
            "use nexus.web.sqlmap/--data for a payload with spaces)"
        )
    return target


def with_execution_contract(definition: ToolDefinition, handler: Handler) -> Handler:
    """Keep the historical envelope, adding per-execution raw manifests.

    The gateway owns schema validation, authorization and scope. This layer
    additionally rejects target transport ambiguity before dispatch.
    Context tokens are reset on failures/cancellation and isolate concurrent calls.
    """

    @wraps(handler)
    async def invoke(arguments: dict[str, Any], context: RunContext) -> ToolResult:
        field = definition.scope_target_field
        if field and field in arguments:
            value = arguments[field]
            # Normalised in place: the handler, the journal and the evidence must
            # all see the target that actually ran (a URL with ``%20`` and not
            # the raw space that motivated the normalisation).
            if isinstance(value, list):
                arguments[field] = [validate_target(item) for item in value]
            else:
                arguments[field] = validate_target(value)
        captures: list[dict[str, Any]] = []
        token = _captures.set(captures)
        try:
            result = await handler(arguments, context)
        except OSError as exc:
            # A local I/O failure is *not* a verdict about the target, so it stays
            # ``unavailable`` -but it used to carry only the exception type.
            # Measured in Bounty Hacker v2 (2026-10-31): ``nexus.report.generate``
            # answered ``outcome=unavailable`` with ``{"error_type":
            # "FileNotFoundError"}`` and no path, so a missing packaged dataset was
            # indistinguishable from a dead service. The failing *path* now
            # travels with the result; the exception message does not, because an
            # ``OSError`` text is arbitrary and has leaked user paths before (the
            # contract in ``test_missing_binary_returns_explicit_tool_result``).
            filename = str(getattr(exc, "filename", "") or "")[:1000]
            result = ToolResult(
                output={
                    "status": "execution_unavailable",
                    "error_type": type(exc).__name__,
                    "filename": filename,
                },
                verification_method="tool_execution_unavailable",
                evidence={"error_type": type(exc).__name__, "filename": filename},
                outcome="unavailable",
            )
        finally:
            _captures.reset(token)
        if captures:
            incomplete = any(
                item["timed_out"]
                or item["cancelled"]
                or any(
                    stream is not None
                    and (stream["truncated"] or not stream["complete"] or stream["error"])
                    for stream in (item["stdout"], item["stderr"])
                )
                for item in captures
            )
            evidence = {
                **result.evidence,
                "execution_capture": {
                    "schema_version": 1,
                    "executions": captures,
                    "incomplete": incomplete,
                },
            }
            result = replace(
                result,
                evidence=evidence,
                verified=result.verified and not incomplete,
                outcome="" if incomplete else result.outcome,
            )
        result.to_dto()
        return result

    return invoke
