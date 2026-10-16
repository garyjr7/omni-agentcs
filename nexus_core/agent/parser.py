"""Tolerant transport extraction with strict Pydantic action validation.

The model is instructed to answer with a single JSON object, but real
providers add markdown fences, prose or a second stacked action. This module
accepts all of those, keeps the raw text for audit and reports what it had to
tolerate as ``warnings``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from pydantic import ValidationError
from nexus_core.kernel.domain_dto import (
    ACTION_ADAPTER,
    Action,
    ToolCall as ToolCall,
    TaskComplete as TaskComplete,
    RequestClarification as RequestClarification,
)
from nexus_core.kernel.serialization import decode_json

ACTION_TOOL_CALL = "tool_call"
ACTION_TASK_COMPLETE = "task_complete"
ACTION_REQUEST_CLARIFICATION = "request_clarification"

KNOWN_ACTIONS = (ACTION_TOOL_CALL, ACTION_TASK_COMPLETE, ACTION_REQUEST_CLARIFICATION)


class ReActParseError(ValueError):
    """Raised when a model response cannot be understood as a ReAct action."""

    def __init__(self, message: str, raw_response: str = "") -> None:
        super().__init__(message)
        self.raw_response = raw_response


@dataclass(frozen=True)
class ReActAction:
    """Legacy action adapter for callers and historical session shapes.

    ``raw_response`` is retained verbatim so every step can be audited even
    when the parser had to repair the model output. ``warnings`` records the
    tolerated deviations (markdown fences, multiple stacked actions, ...).
    """

    thought: str
    action: str
    tool_id: str | None = None
    arguments: dict[str, Any] | None = None
    expected_outcome: str | None = None
    summary: str | None = None
    findings: list[dict[str, Any]] = field(default_factory=list)
    question: str | None = None
    raw_response: str = ""
    warnings: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        """Serialize for persistence and audit payloads."""
        return {
            "thought": self.thought,
            "action": self.action,
            "tool_id": self.tool_id,
            "arguments": self.arguments,
            "expected_outcome": self.expected_outcome,
            "summary": self.summary,
            "findings": self.findings,
            "question": self.question,
            "warnings": list(self.warnings),
            # raw_response is intentionally excluded; audit stores it separately.
        }


def _fenced_blocks(text: str) -> list[str]:
    """Return the bodies of ```json ... ``` (or bare ```) fences."""
    blocks: list[str] = []
    marker = "```"
    position = 0
    while True:
        start = text.find(marker, position)
        if start == -1:
            return blocks
        body_start = text.find("\n", start)
        if body_start == -1:
            return blocks
        end = text.find(marker, body_start)
        if end == -1:
            return blocks
        blocks.append(text[body_start + 1 : end].strip())
        position = end + len(marker)


def _balanced_json_objects(text: str) -> list[str]:
    """Return every top-level ``{...}`` slice, string- and escape-aware."""
    objects: list[str] = []
    depth = 0
    start: int | None = None
    in_string = False
    escaped = False
    for index, char in enumerate(text):
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
        elif char == "{":
            if depth == 0:
                start = index
            depth += 1
        elif char == "}":
            if depth > 0:
                depth -= 1
                if depth == 0 and start is not None:
                    objects.append(text[start : index + 1])
                    start = None
    return objects


def _extract_json_value(text: str, warnings: list[str]) -> Any:
    """Extract the first decodable JSON value from a noisy model response."""
    stripped = text.strip()
    if stripped:
        try:
            return decode_json(stripped)
        except ValueError:
            pass

    for block in _fenced_blocks(text):
        try:
            value = decode_json(block)
        except ValueError:
            continue
        warnings.append("json was extracted from a markdown fence")
        return value

    candidates = _balanced_json_objects(text)
    for index, candidate in enumerate(candidates):
        try:
            value = decode_json(candidate)
        except ValueError:
            continue
        if index > 0 or not stripped.startswith(candidate):
            warnings.append("json object was surrounded by unparsable text")
        return value

    raise ReActParseError("response does not contain a parsable JSON object", text)


def _normalize(payload: Any, raw_response: str, warnings: list[str]) -> Action:
    """Tolerate transport wrappers; never coerce the domain action."""
    warnings = list(dict.fromkeys(warnings))
    if isinstance(payload, list):
        if not payload:
            raise ReActParseError("response is an empty JSON array", raw_response)
        if len(payload) > 1 and not any("multiple actions" in item for item in warnings):
            warnings.append("response contained multiple actions; using the first one")
        payload = payload[0]
    if not isinstance(payload, dict):
        raise ReActParseError("response is not a JSON object", raw_response)
    if payload.get("action") not in KNOWN_ACTIONS:
        raise ReActParseError("unknown or missing action", raw_response)
    if "raw_response" in payload or "warnings" in payload:
        raise ReActParseError("transport metadata is not an action field", raw_response)
    if payload.get("action") == ACTION_TOOL_CALL and "arguments" in payload:
        if not isinstance(payload["arguments"], dict):
            raise ReActParseError("tool_call arguments must be a JSON object", raw_response)
    try:
        return ACTION_ADAPTER.validate_python(
            {**payload, "raw_response": raw_response, "warnings": tuple(warnings)}
        )
    except ValidationError as exc:
        # Never reflect submitted credentials in a correction or exception.
        fields = ", ".join(".".join(map(str, error["loc"])) for error in exc.errors())
        raise ReActParseError(f"invalid action fields: {fields}", raw_response) from None


def parse_react_response(text: str) -> Action:
    """Parse a model response into the discriminated Pydantic ``Action`` union.

    Strategy: pure JSON first, then a ```` ```json ```` block, then the first
    balanced ``{...}`` slice. Stacked actions are reduced to the first one and
    reported as a warning. Raises :class:`ReActParseError` with the raw text.
    """
    if not isinstance(text, str) or not text.strip():
        raise ReActParseError("empty model response", str(text or ""))

    warnings: list[str] = []
    actionable = [
        candidate for candidate in _balanced_json_objects(text) if '"action"' in candidate
    ]
    if len(actionable) > 1:
        warnings.append("response contained multiple actions; using the first one")

    payload = _extract_json_value(text, warnings)
    return _normalize(payload, text, warnings)
