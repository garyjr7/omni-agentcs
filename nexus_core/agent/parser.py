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
    MAX_PARALLEL_TOOL_CALLS,
    Action,
    ToolCall as ToolCall,
    TaskComplete as TaskComplete,
    RequestClarification as RequestClarification,
)
from nexus_core.kernel.serialization import decode_json

ACTION_TOOL_CALL = "tool_call"
ACTION_TOOL_CALLS = "tool_calls"
ACTION_SPAWN_SUBAGENT = "spawn_subagent"
ACTION_TASK_COMPLETE = "task_complete"
ACTION_REQUEST_CLARIFICATION = "request_clarification"

KNOWN_ACTIONS = (
    ACTION_TOOL_CALL,
    ACTION_TOOL_CALLS,
    ACTION_SPAWN_SUBAGENT,
    ACTION_TASK_COMPLETE,
    ACTION_REQUEST_CLARIFICATION,
)

#: Labels a model invents to mean "pause until the background job ends". They are
#: not part of the contract and never will be: the loop yields to the job itself
#: (``task_complete`` waits, the idle turn waits, the result is delivered as an
#: observation), so a wait action would only add surface without a capability.
WAIT_ACTIONS = frozenset(
    {
        "wait",
        "wait_for_result",
        "wait_for_task",
        "wait_background",
        "wait_for_background",
        "poll",
        "sleep",
    }
)


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


def _call_specs(items: Any) -> list[dict[str, Any]] | None:
    """Normalise a list of tool calls, or ``None`` when it is not one.

    Accepts both the compact shape (``tool_id``/``arguments``) and the historical
    action object (``action: "tool_call"``) so a model that stacks three answers
    in one array is understood as the parallel turn it meant, instead of silently
    running only the first one.
    """
    if not isinstance(items, list) or not items:
        return None
    specs: list[dict[str, Any]] = []
    for item in items:
        if not isinstance(item, dict):
            return None
        if item.get("action") not in (None, ACTION_TOOL_CALL):
            return None
        tool_id = item.get("tool_id")
        arguments = item.get("arguments", {})
        if not isinstance(tool_id, str) or not tool_id.strip():
            return None
        if not isinstance(arguments, dict):
            return None
        spec = {"tool_id": tool_id, "arguments": arguments}
        if isinstance(item.get("expected_outcome"), str):
            spec["expected_outcome"] = item["expected_outcome"]
        specs.append(spec)
    return specs


def _bounded(specs: list[dict[str, Any]], warnings: list[str]) -> list[dict[str, Any]]:
    """Cut an oversized batch to ``MAX_PARALLEL_TOOL_CALLS`` instead of failing.

    Measured in hijack_v7 (2026-10-30, iteration 2): after the first ``nmap`` the
    model answered with **nine** ``record_fact`` calls -one per service, all of
    them already verified by the verifier-. ``ToolCallBatch`` caps at four, the
    DTO rejected the whole turn (``invalid action fields: tool_calls.calls``) and
    the model spent the next nine turns re-recording them one at a time until the
    loop declared a dead end. A batch that is too big is a scheduling detail: run
    the first four and say so, so the rest can come next turn.
    """
    if len(specs) <= MAX_PARALLEL_TOOL_CALLS:
        return specs
    dropped = len(specs) - MAX_PARALLEL_TOOL_CALLS
    warnings.append(
        f"the batch had {len(specs)} calls; only the first {MAX_PARALLEL_TOOL_CALLS} "
        f"run and the remaining {dropped} were not executed"
    )
    return specs[:MAX_PARALLEL_TOOL_CALLS]


def _batch(specs: list[dict[str, Any]]) -> dict[str, Any]:
    """A batch payload for >= 2 calls; anything shorter stays a single call."""
    if len(specs) == 1:
        return {"action": ACTION_TOOL_CALL, **specs[0]}
    return {"action": ACTION_TOOL_CALLS, "calls": specs}


def _normalize(payload: Any, raw_response: str, warnings: list[str]) -> Action:
    """Tolerate transport wrappers; never coerce the domain action."""
    warnings = list(dict.fromkeys(warnings))
    if isinstance(payload, list):
        if not payload:
            raise ReActParseError("response is an empty JSON array", raw_response)
        specs = _call_specs(payload)
        if specs is not None:
            warnings.append(
                "response contained multiple tool calls; running them in parallel"
            )
            specs = _bounded(specs, warnings)
            thought = next(
                (
                    str(item.get("thought") or "")
                    for item in payload
                    if isinstance(item, dict) and item.get("thought")
                ),
                "",
            )
            payload = {**_batch(specs), "thought": thought}
        else:
            if len(payload) > 1 and not any("multiple actions" in item for item in warnings):
                warnings.append("response contained multiple actions; using the first one")
            payload = payload[0]
    if not isinstance(payload, dict):
        raise ReActParseError("response is not a JSON object", raw_response)
    if "action" not in payload and "tool_calls" in payload:
        # ``{"thought": ..., "tool_calls": [...]}`` without an action label: the
        # only thing it can mean is a parallel turn, so no correction is wasted.
        specs = _call_specs(payload.get("tool_calls"))
        if specs is not None:
            warnings.append("tool_calls was read without an explicit action label")
            specs = _bounded(specs, warnings)
            payload = {**_batch(specs), "thought": str(payload.get("thought") or "")}
    if payload.get("action") == ACTION_TOOL_CALLS:
        specs = _call_specs(payload.get("calls"))
        if specs is None:
            raise ReActParseError("tool_calls needs a list of tool calls", raw_response)
        specs = _bounded(specs, warnings)
        payload = {**_batch(specs), "thought": str(payload.get("thought") or "")}
    action_label = payload.get("action")
    if isinstance(action_label, str) and action_label.strip().lower() in WAIT_ACTIONS:
        # A measured run (``bg-1``) answered ``{"action": "wait", "task_id": "bg-1"}``:
        # the generic "unknown action" correction did not teach the rule, so the
        # next turn asked the human instead of waiting. The refusal carries the
        # right model of the loop: nobody waits by hand, the result is delivered.
        raise ReActParseError(
            "no existe la acción 'wait': el bucle espera el job en segundo plano por "
            "ti y te entrega su resultado como observación `background: true`. No "
            "esperes manualmente: continúa con otra acción o responde `task_complete` "
            "para ceder el turno (el cierre espera al job).",
            raw_response,
        )
    if action_label not in KNOWN_ACTIONS:
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


def _is_parallel_payload(payload: Any) -> bool:
    """Whether the decoded response is several tool calls, not stacked actions."""
    if isinstance(payload, list):
        return _call_specs(payload) is not None
    if isinstance(payload, dict):
        if payload.get("action") == ACTION_TOOL_CALLS:
            return True
        return "action" not in payload and _call_specs(payload.get("tool_calls")) is not None
    return False


def parse_react_response(text: str) -> Action:
    """Parse a model response into the discriminated Pydantic ``Action`` union.

    Strategy: pure JSON first, then a ```` ```json ```` block, then the first
    balanced ``{...}`` slice. Several tool calls in one answer become a
    :class:`ToolCallBatch`; any other stack of actions is reduced to the first
    one and reported as a warning. Raises :class:`ReActParseError` with the raw
    text.
    """
    if not isinstance(text, str) or not text.strip():
        raise ReActParseError("empty model response", str(text or ""))

    warnings: list[str] = []
    payload = _extract_json_value(text, warnings)
    actionable = [
        candidate for candidate in _balanced_json_objects(text) if '"action"' in candidate
    ]
    if len(actionable) > 1 and not _is_parallel_payload(payload):
        warnings.append("response contained multiple actions; using the first one")
    return _normalize(payload, text, warnings)
