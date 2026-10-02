"""Unwrap the ``execute_tool`` result shape for the CLI.

``execute_tool`` (and therefore ``OmniSession.invoke_tool``) returns
``{"tool_id": ..., "output": <ToolResult dict>}`` and the ``ToolResult`` dict is
``{"success", "verified", "verification_method", "evidence", "output"}`` where
the last ``output`` is the handler payload. Reading ``success`` or the payload
from the *outer* mapping silently yields ``None``, so every CLI call site goes
through these helpers instead of guessing the nesting.
"""

from __future__ import annotations

from typing import Any


def tool_result(result: Any) -> dict[str, Any]:
    """Return the ``ToolResult`` mapping of an ``execute_tool`` result."""
    if not isinstance(result, dict):
        return {}
    wrapper = result.get("output")
    return wrapper if isinstance(wrapper, dict) else {}


def tool_success(result: Any) -> bool:
    """Whether the tool verified its post-condition."""
    return bool(tool_result(result).get("success"))


def tool_method(result: Any) -> str | None:
    """The ``verification_method`` of the tool result (``None`` when absent)."""
    method = tool_result(result).get("verification_method")
    return str(method) if method else None


def tool_payload(result: Any) -> dict[str, Any]:
    """The handler payload (``ToolResult.output``) when it is a mapping."""
    payload = tool_result(result).get("output")
    return payload if isinstance(payload, dict) else {}


__all__ = ["tool_method", "tool_payload", "tool_result", "tool_success"]
