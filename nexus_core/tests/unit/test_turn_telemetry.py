"""Per-turn operational telemetry: the record, its sinks and the loop wiring.

One ReAct iteration is the unit the operator pays for, so the four signals that
make a run diagnosable have to travel together per turn: token consumption,
reasoning duration, friction flags and the blackboard delta. These tests pin the
record, the durability of the sink and the end-to-end wiring inside the loop.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any
from nexus_core.llm.abstraction import LLMMessage


import asyncio
import json
from datetime import datetime, timedelta, timezone
from unittest import mock

import pytest

from nexus_core.agent.react import ReActConfig, run_react_loop
from nexus_core.agent.turn_telemetry import (
    METRIC_TURNS,
    TURN_EVENT_TYPE,
    TURN_TELEMETRY_SIGNALS,
    FrictionFlag,
    TurnTelemetryRecorder,
    blackboard_delta,
    flag_for_error,
)
from nexus_core.kernel import runtime as runtime_module
from nexus_core.kernel.blackboard import Blackboard
from nexus_core.kernel.control_store import ControlStore
from nexus_core.kernel.runtime import ExecutionContext
from nexus_core.llm.abstraction import LLMProvider, LLMResponse
from nexus_core.scope import EngagementScope, EngagementStore

ENGAGEMENT = "eng-1"
TARGET = "10.0.0.5"

# The unsigned scope fixtures below exercise loop mechanics; governed scope
# authentication is covered by test_scope_governed_mode.
pytestmark = pytest.mark.usefixtures("lab_scope")


def _iso(delta: timedelta) -> str:
    return (datetime.now(timezone.utc) + delta).isoformat()


def create_scope(store: ControlStore) -> None:
    EngagementStore(store).create(
        EngagementScope(
            engagement_id=ENGAGEMENT,
            tenant_id="system",
            name="telemetry",
            client="acme",
            owner_id="owner-1",
            valid_from=_iso(-timedelta(days=1)),
            valid_until=_iso(timedelta(days=1)),
            cidrs=("10.0.0.0/24",),
            domains=(),
            urls=(),
            exclusions=(),
            created_at=_iso(timedelta(0)),
        )
    )


TOOL_SUCCESS = {
    "tool_id": "nexus.recon.nmap",
    "output": {
        "success": True,
        "verified": True,
        "verification_method": "nmap_xml_parsed",
        "evidence": {"hosts_up": 1},
        "output": {"target": TARGET, "scan": {"hosts": []}},
    },
}


class ScriptedLLM:
    """Replays scripted responses; repeats the last one when exhausted."""

    def __init__(self, responses: list[str]) -> None:
        self.responses = list(responses)
        self.calls = 0

    async def complete(self, messages: list[LLMMessage], **kwargs: Any) -> LLMResponse:
        self.calls += 1
        index = min(self.calls - 1, max(0, len(self.responses) - 1))
        return LLMResponse(
            content=self.responses[index] if self.responses else "",
            model="scripted-test",
            provider=LLMProvider.FAKE,
            tokens_input=100,
            tokens_output=25,
        )


def tool_call(tool_id: str = "nexus.recon.nmap", **arguments: Any) -> str:
    return json.dumps(
        {
            "thought": "Escaneo el objetivo autorizado.",
            "action": "tool_call",
            "tool_id": tool_id,
            "arguments": arguments or {"target": TARGET},
            "expected_outcome": "puertos abiertos",
        }
    )


def task_complete() -> str:
    return json.dumps(
        {
            "thought": "Listo.",
            "action": "task_complete",
            "summary": "recon completado",
            "findings": [{"severity": "high", "title": "SSH", "evidence": "22/tcp open"}],
        }
    )


def _harness(tmp_path: Path) -> tuple[ControlStore, ExecutionContext]:
    store = ControlStore(tmp_path / "react.db")
    store.initialize()
    create_scope(store)
    run = store.create_run("system", {})
    task = {
        "id": "task-1",
        "tenant_id": "system",
        "run_id": run["id"],
        "task_type": "react.run",
        "payload": {
            "objective": "Escanea 10.0.0.5",
            "engagement_id": ENGAGEMENT,
            "identity": {"subject_id": "operator-1", "roles": ["operator"]},
            "permissions": ["execute:tool:nexus.recon.nmap"],
        },
    }
    return store, ExecutionContext(store, task, "worker-test")


def _loop_config(**kwargs: Any) -> ReActConfig:
    kwargs.setdefault("enforce_completion_gates", False)
    return ReActConfig(**kwargs)


# ------------------------------------------------------------------ the record
def test_record_joins_tokens_durations_friction_and_blackboard() -> None:
    recorder = TurnTelemetryRecorder(emit=False)
    recorder.begin_turn(
        iteration=3, phase="recon", subagent_id="recon", facts_total=0, counts={}
    )
    recorder.note_action(
        action="tool_call", tool_id="nexus.recon.nmap", arguments={"target": TARGET}
    )

    class Response:
        tokens_input = 900
        tokens_output = 120

    recorder.note_reasoning(Response(), estimated=850, duration_ms=2100)
    recorder.note_tool(duration_ms=410, success=True)
    recorder.note_blackboard(facts_total=2, counts={"service": 2})
    record = recorder.finish(outcome="completed_turn", turn_ms=2700)

    assert record is not None
    assert record.iteration == 3
    assert record.phase == "recon"
    assert record.subagent_id == "recon"
    assert record.tool_id == "nexus.recon.nmap"
    assert record.outcome == "completed_turn"
    assert (record.reasoning_ms, record.tool_ms, record.turn_ms) == (2100, 410, 2700)
    assert record.request_tokens_estimated == 850
    assert record.prompt_tokens == 900
    assert record.completion_tokens == 120
    assert record.total_tokens == 1020
    assert record.friction == ()
    assert record.blackboard_facts == 2
    assert record.blackboard_delta == 2
    assert record.blackboard_added == ("service",)
    assert record.to_dict()["friction"] == []


def test_blackboard_delta_names_only_the_fact_types_that_grew() -> None:
    assert blackboard_delta({"service": 1, "host": 2}, {"service": 3, "host": 2}) == (
        2,
        ("service",),
    )
    assert blackboard_delta({}, {}) == (0, ())
    # A shrinking board never reports a negative delta.
    assert blackboard_delta({"service": 3}, {"service": 1})[0] == 0


def test_friction_flags_are_deduplicated_and_keep_their_order() -> None:
    recorder = TurnTelemetryRecorder(emit=False)
    recorder.begin_turn(iteration=1, phase="recon", subagent_id="recon")
    recorder.flag(FrictionFlag.TOOL_FAILURE)
    recorder.flag(FrictionFlag.TOOL_FAILURE)
    recorder.flag("custom_flag")
    record = recorder.finish(outcome="failed")
    assert record is not None
    assert record.friction == ("tool_failure", "custom_flag")


def test_repeated_action_is_flagged_as_friction() -> None:
    recorder = TurnTelemetryRecorder(emit=False)
    for iteration in (1, 2):
        recorder.begin_turn(iteration=iteration, phase="recon", subagent_id="recon")
        recorder.note_action(
            action="tool_call", tool_id="nexus.recon.nmap", arguments={"target": TARGET}
        )
        assert recorder.finish(outcome="completed_turn") is not None
    assert FrictionFlag.REPEATED_ACTION.value in recorder.turns[1].friction
    assert FrictionFlag.REPEATED_ACTION.value not in recorder.turns[0].friction


def test_error_classification_maps_onto_a_flag() -> None:
    assert flag_for_error("PermissionError") is FrictionFlag.GOVERNANCE_DENIAL
    assert flag_for_error("SchemaValidationError") is FrictionFlag.INPUT_REJECTED
    assert flag_for_error("TimeoutError") is FrictionFlag.TIMEOUT
    assert flag_for_error("RuntimeError") is FrictionFlag.TOOL_FAILURE


def test_open_turn_is_never_lost() -> None:
    recorder = TurnTelemetryRecorder(emit=False)
    recorder.begin_turn(iteration=1, phase="recon", subagent_id="recon")
    recorder.begin_turn(iteration=2, phase="recon", subagent_id="recon")
    assert [turn.iteration for turn in recorder.turns] == [1]
    assert recorder.has_open_turn is True
    assert recorder.finish(outcome="done") is not None
    assert [turn.iteration for turn in recorder.turns] == [1, 2]


# ------------------------------------------------------------------ the sinks
def test_finish_publishes_a_durable_run_event(tmp_path: Path) -> None:
    store, context = _harness(tmp_path)
    recorder = TurnTelemetryRecorder(
        store=store, tenant_id=context.tenant_id, run_id=context.run_id
    )
    recorder.begin_turn(iteration=1, phase="recon", subagent_id="recon")
    recorder.note_action(action="tool_call", tool_id="nexus.recon.nmap")
    recorder.note_tool(duration_ms=10, success=False, error_type="RuntimeError")
    recorder.finish(outcome="failed", turn_ms=20)
    assert asyncio.run(recorder.flush(timeout=2))

    events = [
        event
        for event in store.list_run_events(context.tenant_id, context.run_id)
        if event["event_type"] == TURN_EVENT_TYPE
    ]
    assert len(events) == 1
    payload = events[0]["payload"]
    assert payload["iteration"] == 1
    assert payload["phase"] == "recon"
    assert payload["tool_id"] == "nexus.recon.nmap"
    assert payload["friction"] == ["tool_failure"]


def test_finish_updates_the_in_process_metrics() -> None:
    from nexus_core.kernel.telemetry import metrics

    before = len(metrics.snapshot())
    recorder = TurnTelemetryRecorder(emit=True)
    recorder.begin_turn(iteration=1, phase="recon", subagent_id="recon")
    recorder.finish(outcome="completed_turn", turn_ms=5)
    assert asyncio.run(recorder.flush(timeout=2))
    snapshot = metrics.snapshot()
    assert any(item["name"] == METRIC_TURNS for item in snapshot)
    assert len(snapshot) >= before


def test_a_broken_sink_never_aborts_the_loop() -> None:
    class ExplodingStore:
        def append_run_event(self, *args: Any, **kwargs: Any) -> None:
            raise RuntimeError("store down")

    recorder = TurnTelemetryRecorder(
        store=ExplodingStore(), tenant_id="system", run_id="run-1"
    )
    recorder.begin_turn(iteration=1, phase="recon", subagent_id="recon")
    assert recorder.finish(outcome="completed_turn") is not None


def test_every_declared_signal_names_a_recorded_field() -> None:
    record = TurnTelemetryRecorder(emit=False)
    record.begin_turn(iteration=1, phase="recon", subagent_id="recon")
    finished = record.finish(outcome="completed_turn")
    assert finished is not None
    payload = finished.to_dict()
    for field_name in TURN_TELEMETRY_SIGNALS.values():
        assert field_name in payload, field_name


# ------------------------------------------------------------------- the loop
async def test_loop_emits_one_telemetry_record_per_iteration(tmp_path: Path) -> None:
    store, context = _harness(tmp_path)
    llm = ScriptedLLM([tool_call(), task_complete()])

    async def fake_tool(payload: dict[str, Any], run_context: ExecutionContext) -> dict[str, Any]:
        return dict(TOOL_SUCCESS)

    with mock.patch.object(runtime_module, "execute_tool", fake_tool):
        result = await run_react_loop(
            context=context,
            objective="Escanea 10.0.0.5",
            engagement_id=ENGAGEMENT,
            llm_client=llm,
            config=_loop_config(),
        )

    assert result.iterations == 2
    assert [turn["iteration"] for turn in result.turns] == [1, 2]
    first, second = result.turns
    assert first["phase"] == "recon"
    assert first["subagent_id"] == "recon"
    assert first["tool_id"] == "nexus.recon.nmap"
    assert first["total_tokens"] == 125
    assert first["reasoning_ms"] >= 0
    assert first["tool_ms"] >= 0
    assert first["turn_ms"] >= 0
    assert second["action"] == "task_complete"
    events = [
        event
        for event in store.list_run_events(context.tenant_id, context.run_id)
        if event["event_type"] == TURN_EVENT_TYPE
    ]
    assert [event["payload"]["iteration"] for event in events] == [1, 2]
    assert events[0]["payload"]["total_tokens"] == 125


async def test_loop_records_the_blackboard_delta_of_the_turn(tmp_path: Path) -> None:
    store, context = _harness(tmp_path)
    llm = ScriptedLLM([tool_call(), task_complete()])
    board = Blackboard(store)

    async def fake_tool(payload: dict[str, Any], run_context: ExecutionContext) -> dict[str, Any]:
        board.record(
            tenant_id="system",
            engagement_id=ENGAGEMENT,
            fact_type="service",
            key=f"{TARGET}:22/tcp",
            value={"port": 22},
            source="nexus.recon.nmap",
            created_by="deterministic-verifier",
            verified=True,
            asserted_by="verifier",
            verification_method="nmap_xml_parsed",
            invocation_id="inv-1",
        )
        return dict(TOOL_SUCCESS)

    with mock.patch.object(runtime_module, "execute_tool", fake_tool):
        result = await run_react_loop(
            context=context,
            objective="Escanea 10.0.0.5",
            engagement_id=ENGAGEMENT,
            llm_client=llm,
            config=_loop_config(),
        )

    first = result.turns[0]
    assert first["blackboard_delta"] == 1
    assert first["blackboard_added"] == ["service"]
    assert first["blackboard_facts"] == 1


async def test_loop_flags_a_parse_error_as_friction(tmp_path: Path) -> None:
    _, context = _harness(tmp_path)
    llm = ScriptedLLM(["no soy json", tool_call(), task_complete()])

    async def fake_tool(payload: dict[str, Any], run_context: ExecutionContext) -> dict[str, Any]:
        return dict(TOOL_SUCCESS)

    with mock.patch.object(runtime_module, "execute_tool", fake_tool):
        result = await run_react_loop(
            context=context,
            objective="Escanea 10.0.0.5",
            engagement_id=ENGAGEMENT,
            llm_client=llm,
            config=_loop_config(),
        )

    assert FrictionFlag.PARSE_ERROR.value in result.turns[0]["friction"]
    assert result.turns[0]["action"] == "parse_error"
    assert FrictionFlag.PARSE_ERROR.value not in result.turns[1]["friction"]


async def test_loop_flags_a_failing_tool_and_its_retirement(tmp_path: Path) -> None:
    _, context = _harness(tmp_path)
    llm = ScriptedLLM([tool_call()])

    async def broken_tool(payload: dict[str, Any], run_context: ExecutionContext) -> None:
        raise RuntimeError("tool post-condition was not verified")

    with mock.patch.object(runtime_module, "execute_tool", broken_tool):
        result = await run_react_loop(
            context=context,
            objective="Escanea 10.0.0.5",
            engagement_id=ENGAGEMENT,
            llm_client=llm,
            config=_loop_config(max_iterations=3),
        )

    friction = [flag for turn in result.turns for flag in turn["friction"]]
    assert FrictionFlag.TOOL_FAILURE.value in friction
    assert FrictionFlag.TOOL_RETIRED.value in friction
    assert all(turn["tool_ms"] >= 0 for turn in result.turns)


async def test_loop_records_unknown_tool_as_input_friction(tmp_path: Path) -> None:
    _, context = _harness(tmp_path)
    llm = ScriptedLLM([tool_call("nexus.does.not_exist"), task_complete()])

    result = await run_react_loop(
        context=context,
        objective="Escanea 10.0.0.5",
        engagement_id=ENGAGEMENT,
        llm_client=llm,
        config=_loop_config(),
    )

    assert FrictionFlag.INPUT_REJECTED.value in result.turns[0]["friction"]
    assert result.turns[0]["tool_id"] == "nexus.does.not_exist"
