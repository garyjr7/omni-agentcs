"""Strict domain boundaries and independently injectable ReAct services."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, Mock

import pytest
from pydantic import ValidationError

from nexus_core.agent.parser import ReActAction, ReActParseError, parse_react_response
from nexus_core.agent.react import ReActConfig
from nexus_core.agent.react_services import ActionDecoder, CompletionVerifier, ToolExecutionService
from nexus_core.agent.planner import build_plan
from nexus_core.kernel.control_store import ControlStore
from nexus_core.kernel.domain_dto import (
    ACTION_ADAPTER,
    ApprovalDecisionDTO,
    DomainEvent,
    PolicyDecisionDTO,
    ToolCall,
    TaskComplete,
    RequestClarification,
    ToolResultDTO,
)
from nexus_core.kernel.models import ToolResult
from nexus_core.report.extractor_registry import Extraction, ExtractorRegistry
from nexus_core.report.extraction_support import Observation


@pytest.mark.parametrize(
    "payload",
    [
        {"action": "tool_call", "tool_id": "tool", "arguments": {}, "unknown": 1},
        {"action": "tool_call", "tool_id": "tool", "arguments": {}, "thought": 12},
        {"action": "tool_call", "tool_id": "tool", "arguments": {}, "summary": "mixed variant"},
        {"action": "tool_call", "tool_id": "tool", "arguments": {}, "raw_response": "forged"},
        {"action": "task_complete", "summary": "done", "findings": ["discard me"]},
        {"action": "task_complete", "summary": 12},
        {"action": "request_clarification", "question": True},
        {"action": "tool_call", "tool_id": "tool", "arguments": {"value": float("nan")}},
    ],
)
def test_decoder_rejects_invalid_domain_actions(payload: dict[str, Any]) -> None:
    with pytest.raises(ReActParseError):
        ActionDecoder().decode(json.dumps(payload))


def test_decoder_never_echoes_sensitive_invalid_values() -> None:
    with pytest.raises(ReActParseError) as error:
        ActionDecoder().decode(
            '{"action":"tool_call","tool_id":"tool","arguments":{},"secret":"private-value"}'
        )
    assert "private-value" not in str(error.value)


def test_duplicate_json_fields_are_rejected() -> None:
    with pytest.raises(ReActParseError):
        parse_react_response('{"action":"task_complete","summary":"one","summary":"two"}')


@pytest.mark.parametrize(
    "dto",
    [
        ToolCall(tool_id="tool", arguments={}),
        TaskComplete(summary="done"),
        RequestClarification(question="question"),
        ApprovalDecisionDTO(approved=True),
        PolicyDecisionDTO(allowed=True, reason="ok", policy_id="policy"),
        DomainEvent(tenant_id="tenant", run_id="run", event_type="plugin.event"),
    ],
)
def test_domain_models_forbid_extras_and_are_frozen(dto: Any) -> None:
    with pytest.raises(ValidationError):
        type(dto).model_validate({**dto.model_dump(), "unexpected": True})
    field = next(iter(type(dto).model_fields))
    with pytest.raises(ValidationError):
        setattr(dto, field, getattr(dto, field))


def test_discriminated_schema_and_legacy_action_serialization() -> None:
    schema = ACTION_ADAPTER.json_schema()
    assert schema["discriminator"]["propertyName"] == "action"
    parsed = parse_react_response(
        '```json\n{"action":"tool_call","thought":"test","tool_id":"tool","arguments":{"value":"a|b"}}\n```'
    )
    assert isinstance(parsed, ToolCall)
    legacy = ReActAction(
        thought="test",
        action="tool_call",
        tool_id="tool",
        arguments={"value": "a|b"},
        warnings=parsed.warnings,
    )
    assert parsed.to_dict() == legacy.to_dict()
    assert "raw_response" not in parsed.to_dict()


def test_tool_result_preserves_legacy_wire_keys_and_rejects_coercion() -> None:
    value = ToolResult(
        output={"target": "host"}, verified=True, verification_method="parser"
    ).to_dict()
    assert set(value) == {
        "success",
        "outcome",
        "output",
        "verified",
        "verification_method",
        "evidence",
        "exit_code",
        "accepted_exit_codes",
        "stdout",
        "stderr",
        "timed_out",
    }
    assert ToolResultDTO.model_validate(value).to_dict() == value
    with pytest.raises(ValidationError):
        ToolResultDTO.model_validate({**value, "success": "true"})
    with pytest.raises(ValidationError):
        ToolResultDTO.model_validate({**value, "evidence": []})
    with pytest.raises(ValidationError):
        ToolResultDTO.model_validate({**value, "extra": True})


def test_event_boundary_preserves_persistence_shape(tmp_path: Path) -> None:
    store = ControlStore(tmp_path / "events.db")
    store.initialize()
    run_id = store.create_run("system", {})["id"]
    event = store.append_run_event(
        "system", run_id, "plugin.custom", {"password": "secret", "count": 2}
    )
    assert set(event) == {"event_id", "tenant_id", "run_id", "event_type", "payload", "created_at"}
    assert event["payload"] == {"password": "[REDACTED]", "count": 2}
    with pytest.raises((ValidationError, ValueError)):
        store.append_run_event("system", run_id, "plugin.custom", {"bad": object()})
    assert len(store.list_run_events("system", run_id)) == 1


@pytest.mark.asyncio
async def test_execution_service_timeout_and_external_cancel_drain_child() -> None:
    service = ToolExecutionService()
    stopped = asyncio.Event()

    async def work() -> dict[str, Any]:
        try:
            await asyncio.sleep(30)
            return {}
        finally:
            stopped.set()

    with pytest.raises(TimeoutError):
        await service.await_tool(work(), timeout=0.01, cancel_event=asyncio.Event())
    assert stopped.is_set()
    stopped.clear()
    task = asyncio.create_task(service.await_tool(work(), timeout=30, cancel_event=asyncio.Event()))
    await asyncio.sleep(0.01)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert stopped.is_set()


@pytest.mark.asyncio
async def test_completion_service_preserves_hook_objections(tmp_path: Path) -> None:
    store = ControlStore(tmp_path / "completion.db")
    store.initialize()
    hooks = Mock()
    hooks.verify_stop = AsyncMock(return_value=["operator evidence gate"])
    result = await CompletionVerifier().verify(
        findings=[],
        observations=[],
        run_id="run",
        plan=build_plan(engagement_id=None),
        config=ReActConfig(enforce_completion_gates=False),
        engagement_id=None,
        store=store,
        tenant_id="system",
        hooks=hooks,
        objective="objective",
    )
    assert result.objections == ["operator evidence gate"]
    hooks.verify_stop.assert_awaited_once()


def test_registry_extension_is_independent_of_storage() -> None:
    registry = ExtractorRegistry()
    observed: list[str] = []

    def extractor(observation: Observation, context: Any) -> Extraction:
        observed.append(observation.tool_id)
        return Extraction()

    registry.register("custom.tool", extractor)
    with pytest.raises(ValueError):
        registry.register("custom.tool", extractor)
    observation = Observation("run", "custom.tool", {}, True, "parser", {}, {}, "now", "message")
    registry.extract(observation, Mock())
    assert observed == ["custom.tool"]


def test_legacy_tuple_containers_are_arrays_without_scalar_coercion() -> None:
    legacy = ToolResult(output={"command": ("tool", "--version")}, verified=True)
    assert legacy.to_dict()["output"]["command"] == ["tool", "--version"]
    with pytest.raises(ValidationError):
        ToolResult(verified="yes").to_dict()  # type: ignore[arg-type]
