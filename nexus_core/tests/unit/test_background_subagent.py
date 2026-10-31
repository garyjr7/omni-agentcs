"""``spawn_subagent``: background work that never bypasses governance.

The contract pinned here is the one the loop promises the model: a long tool is
accepted through the same checks as a foreground call, the turn returns
immediately, the finished task is delivered exactly once as an observation, and
the run cancels whatever it spawned when it ends.
"""

from __future__ import annotations

import asyncio
import inspect
import json
import time

import pytest

from nexus_core.agent import memory
from nexus_core.agent.parser import parse_react_response
from nexus_core.kernel.domain_dto import SpawnSubAgent
from nexus_core.tests.unit.test_parallel_tools import (
    FakeApproval,
    FakeService,
    ScriptedLLM,
    _coordinator,
    _loop_context,
    _observations,
)

pytestmark = pytest.mark.unit


async def _settle(record, timeout: float = 3.0) -> None:
    """Wait for a task to finish **without** consuming its delivery.

    ``TaskManager.wait_for_result`` is the delivery (it drains the queue), so a
    test that wants the coordinator to deliver must poll the record instead.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline and not record.terminal:
        await asyncio.sleep(0.01)
    assert record.terminal, f"task {record.task_id} never finished: {record.status}"


def _spawn(tool_id: str = "local.one", *, label: str = "nmap completo", **arguments) -> str:
    return json.dumps(
        {
            "thought": "escaneo largo en background",
            "action": "spawn_subagent",
            "tool_id": tool_id,
            "arguments": arguments or {"target": "10.0.0.5"},
            "label": label,
        }
    )


_CLARIFY = json.dumps(
    {"thought": "sigo con el resto", "action": "request_clarification", "question": "¿Continúo?"}
)


def test_the_action_parses_with_its_label():
    action = parse_react_response(_spawn("nexus.recon.nmap", label="nmap -p-"))

    assert isinstance(action, SpawnSubAgent)
    assert action.tool_id == "nexus.recon.nmap"
    assert action.label == "nmap -p-"
    assert action.arguments == {"target": "10.0.0.5"}


def test_a_spawn_without_a_tool_is_rejected():
    with pytest.raises(Exception):
        parse_react_response(json.dumps({"action": "spawn_subagent", "arguments": {}}))


async def test_spawn_returns_the_turn_without_waiting_for_the_tool(tmp_path, monkeypatch):
    exec_ctx = _loop_context(tmp_path, monkeypatch)
    service = FakeService(delay=5)  # longer than the whole test
    llm = ScriptedLLM(_spawn(), _CLARIFY)
    coordinator = _coordinator(exec_ctx, llm, ("local.one",), service)

    started = time.monotonic()
    result = await coordinator.run()
    elapsed = time.monotonic() - started

    assert result.status == "clarification"
    # The spawn was answered in this turn, not after five seconds of scan.
    assert elapsed < 3
    assert service.calls == ["local.one"]
    spawn_observation = next(
        observation
        for observation in _observations(exec_ctx, coordinator)
        if observation.get("outcome") == "background_task_started"
    )
    assert spawn_observation["background"] is True
    assert spawn_observation["task_id"].startswith("bg-")
    assert "guidance" in spawn_observation
    # What is still running is visible without a status tool.
    assert [item["task_id"] for item in spawn_observation["running_tasks"]] == [
        spawn_observation["task_id"]
    ]
    assert result.actions[0]["action"] == "spawn_subagent"


async def test_the_run_cancels_what_it_spawned(tmp_path, monkeypatch):
    exec_ctx = _loop_context(tmp_path, monkeypatch)
    service = FakeService(delay=5)
    llm = ScriptedLLM(_spawn(), _CLARIFY)
    coordinator = _coordinator(exec_ctx, llm, ("local.one",), service)

    await coordinator.run()

    statuses = [record["status"] for record in coordinator.task_manager.list_tasks()]
    assert statuses == ["cancelled"]
    # No scan is left writing after the loop returned.
    assert service.in_flight == 0


async def test_an_unknown_tool_is_refused_before_the_spawn(tmp_path, monkeypatch):
    exec_ctx = _loop_context(tmp_path, monkeypatch)
    service = FakeService()
    llm = ScriptedLLM(_spawn("nexus.does.not.exist"), _CLARIFY)
    coordinator = _coordinator(exec_ctx, llm, ("local.one",), service)

    await coordinator.run()

    assert service.calls == []
    assert coordinator.task_manager.count() == 0
    refusal = next(
        observation
        for observation in _observations(exec_ctx, coordinator)
        if observation.get("error", "").startswith("tool '")
    )
    assert "does not exist" in refusal["error"]


async def test_an_operator_denial_prevents_the_spawn(tmp_path, monkeypatch):
    exec_ctx = _loop_context(tmp_path, monkeypatch)
    service = FakeService()
    llm = ScriptedLLM(_spawn(), _CLARIFY)
    approval = FakeApproval(deny="local.one")
    coordinator = _coordinator(
        exec_ctx,
        llm,
        ("local.one",),
        service,
        approval=approval,
        # The handshake only runs when the caller can ask someone.
        on_approval_needed=lambda *args: None,
    )

    await coordinator.run()

    assert approval.reviews == ["local.one"]
    assert service.calls == []
    assert coordinator.task_manager.count() == 0
    denial = next(
        observation
        for observation in _observations(exec_ctx, coordinator)
        if observation.get("status") == "denied_by_operator"
    )
    assert "no autorizo" in denial["reason"]


async def test_a_finished_task_is_delivered_once_and_written_to_the_board(tmp_path, monkeypatch):
    from nexus_core.kernel.blackboard import Blackboard

    exec_ctx = _loop_context(tmp_path, monkeypatch)
    service = FakeService(delay=0)
    coordinator = _coordinator(exec_ctx, ScriptedLLM(_CLARIFY), ("local.one",), service)
    await coordinator._initialize()
    coordinator.engagement_id = "eng-bg"

    record = await coordinator.task_manager.spawn_task(
        tool_id="local.one",
        arguments={"target": "10.0.0.5"},
        payload={"tool_id": "local.one", "arguments": {"target": "10.0.0.5"}},
        label="nmap completo",
    )
    await _settle(record)

    coordinator._deliver_background_results()
    coordinator._deliver_background_results()  # second drain must be a no-op

    delivered = [
        observation
        for observation in _observations(exec_ctx, coordinator)
        if observation.get("background") is True
        and observation.get("task_id") == record.task_id
    ]
    assert len(delivered) == 1
    assert delivered[0]["success"] is True
    assert delivered[0]["tool_id"] == "local.one"

    facts = Blackboard(exec_ctx.store).list_facts("system", "eng-bg", fact_type="task")
    assert [fact["key"] for fact in facts] == [f"local.one:{record.task_id}"]
    assert facts[0]["value"]["status"] == "succeeded"
    # Agent-asserted: a background scan is evidence to parse, never a verified fact.
    assert facts[0]["asserted_by"] == "agent"
    assert facts[0]["verified"] is False
    await coordinator.task_manager.cancel_all()


async def test_a_saturated_manager_refuses_the_second_spawn(tmp_path, monkeypatch):
    """The cap is a real refusal with guidance, not a silent queue."""
    monkeypatch.setenv("NEXUS_BACKGROUND_TASKS", "1")
    exec_ctx = _loop_context(tmp_path, monkeypatch)
    service = FakeService(delay=5)
    llm = ScriptedLLM(_spawn(), _spawn(), _CLARIFY)
    coordinator = _coordinator(exec_ctx, llm, ("local.one",), service)

    await coordinator.run()

    refusals = [
        observation
        for observation in _observations(exec_ctx, coordinator)
        if observation.get("outcome") == "background_refused"
    ]
    assert len(refusals) == 1
    assert refusals[0]["success"] is False
    assert refusals[0]["running_tasks"]
    assert "background" in refusals[0]["error"] or "saturated" in refusals[0]["error"]
    assert service.calls == ["local.one"]  # only the accepted spawn ran


def test_a_background_observation_keeps_the_foreground_contract(tmp_path):
    from nexus_core.agent.task_manager import RUNNING, TaskRecord

    record = TaskRecord(task_id="bg-1", label="scan", tool_id="local.one")
    record.status = RUNNING
    observation = record.observation()

    for key in ("success", "outcome", "verification_method", "evidence", "assertions", "output"):
        assert key in observation
    assert observation["background"] is True
    assert observation["task_id"] == "bg-1"


async def test_delivery_keeps_history_metadata_for_the_tui(tmp_path, monkeypatch):
    exec_ctx = _loop_context(tmp_path, monkeypatch)
    service = FakeService(delay=0)
    coordinator = _coordinator(exec_ctx, ScriptedLLM(_CLARIFY), ("local.one",), service)
    await coordinator._initialize()

    record = await coordinator.task_manager.spawn_task(
        tool_id="local.one", arguments={}, payload={"tool_id": "local.one"}
    )
    await _settle(record)
    coordinator._deliver_background_results()

    messages = memory.load_history(
        exec_ctx.store, "system", coordinator.conversation_id, limit=200
    )
    entry = next(
        message
        for message in messages
        if (message.get("metadata") or {}).get("kind") == "react.observation"
        and json.loads(str(message["content"])).get("task_id") == record.task_id
    )
    assert entry["metadata"]["tool_id"] == "local.one"
    assert inspect.iscoroutinefunction(coordinator._background_runner)
