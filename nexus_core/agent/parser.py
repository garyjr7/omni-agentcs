"""Tolerant parser for the JSON contract returned by the ReAct LLM.

The model is instructed to answer with a single JSON object, but real
providers add markdown fences, prose or a second stacked action. This module
accepts all of those, keeps the raw text for audit and reports what it had to
tolerate as ``warnings``.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

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
    """One decoded decision of the loop.

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
            return json.loads(stripped)
        except ValueError:
            pass

    for block in _fenced_blocks(text):
        try:
            value = json.loads(block)
        except ValueError:
            continue
        warnings.append("json was extracted from a markdown fence")
        return value

    candidates = _balanced_json_objects(text)
    for index, candidate in enumerate(candidates):
        try:
            value = json.loads(candidate)
        except ValueError:
            continue
        if index > 0 or not stripped.startswith(candidate):
            warnings.append("json object was surrounded by unparsable text")
        return value

    raise ReActParseError("response does not contain a parsable JSON object", text)


def _normalize_findings(raw_value: Any, warnings: list[str]) -> list[dict[str, Any]]:
    """Coerce the findings list, dropping entries that are not objects."""
    if raw_value is None:
        return []
    if not isinstance(raw_value, list):
        raise ReActParseError("findings must be a JSON array", "")
    findings: list[dict[str, Any]] = []
    dropped = 0
    for item in raw_value:
        if isinstance(item, dict):
            findings.append(item)
        else:
            dropped += 1
    if dropped:
        warnings.append(f"dropped {dropped} finding(s) that were not JSON objects")
    return findings


def _normalize(payload: Any, raw_response: str, warnings: list[str]) -> ReActAction:
    """Validate an extracted JSON payload against the response contract."""
    warnings = list(dict.fromkeys(warnings))
    if isinstance(payload, list):
        if not payload:
            raise ReActParseError("response is an empty JSON array", raw_response)
        if len(payload) > 1 and not any("multiple actions" in item for item in warnings):
            warnings.append("response contained multiple actions; using the first one")
        payload = payload[0]
    if not isinstance(payload, dict):
        raise ReActParseError("response is not a JSON object", raw_response)

    action = str(payload.get("action") or "").strip()
    if action not in KNOWN_ACTIONS:
        raise ReActParseError(
            f"unknown or missing action: {action!r} (expected one of {', '.join(KNOWN_ACTIONS)})",
            raw_response,
        )

    thought = str(payload.get("thought") or "").strip()

    if action == ACTION_TOOL_CALL:
        tool_id = payload.get("tool_id")
        if not isinstance(tool_id, str) or not tool_id.strip():
            raise ReActParseError("tool_call requires a non-empty tool_id", raw_response)
        if "arguments" not in payload or payload.get("arguments") is None:
            raise ReActParseError("tool_call requires arguments", raw_response)
        arguments = payload["arguments"]
        if not isinstance(arguments, dict):
            raise ReActParseError("tool_call arguments must be a JSON object", raw_response)
        expected = payload.get("expected_outcome")
        return ReActAction(
            thought=thought,
            action=action,
            tool_id=tool_id.strip(),
            arguments=arguments,
            expected_outcome=str(expected) if expected is not None else None,
            raw_response=raw_response,
            warnings=tuple(warnings),
        )

    if action == ACTION_TASK_COMPLETE:
        summary = payload.get("summary")
        if not isinstance(summary, str) or not summary.strip():
            raise ReActParseError("task_complete requires a non-empty summary", raw_response)
        findings = _normalize_findings(payload.get("findings"), warnings)
        return ReActAction(
            thought=thought,
            action=action,
            summary=summary.strip(),
            findings=findings,
            raw_response=raw_response,
            warnings=tuple(warnings),
        )

    question = payload.get("question")
    if not isinstance(question, str) or not question.strip():
        raise ReActParseError(
            "request_clarification requires a non-empty question", raw_response
        )
    return ReActAction(
        thought=thought,
        action=action,
        question=question.strip(),
        raw_response=raw_response,
        warnings=tuple(warnings),
    )


def parse_react_response(text: str) -> ReActAction:
    """Parse a model response into a :class:`ReActAction`.

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
