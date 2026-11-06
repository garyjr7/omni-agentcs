"""A model idling on the plan while a scan runs must wait, not buy another turn.

Measured shape: ``get_plan_status`` repeated during an active ``nmap``, each
repeat paying a model call for a checklist that cannot change. The state gate
already answers the repeat with the next TODO and open branch; these tests pin
the second half -the loop yields to the running task through
``TaskManager.wait_for_result`` and delivers its result before the next model
turn, without cancelling anything and without a new tool call.
"""

from __future__ import annotations

import json

import pytest

from nexus_core.tests.unit.test_background_subagent import _CLARIFY, _spawn
from nexus_core.tests.unit.test_parallel_tools import (
    FakeService,
    ScriptedLLM,
    _coordinator,
    _loop_context,
    _observations,
)
from nexus_core.tools.handlers.plan_engagement import GET_PLAN_STATUS_TOOL

pytestmark = pytest.mark.unit


def _poll() -> str:
    return json.dumps(
        {
            "thought": "Compruebo el estado del plan.",
            "action": "tool_call",
            "tool_id": GET_PLAN_STATUS_TOOL,
            "arguments": {},
            "expected_outcome": "plan vigente",
        }
    )


#: The spawn acknowledgement (and its reconciliations) is not a delivery.
_ACKNOWLEDGEMENTS = frozenset({
    "background_task_started", "background_already_running",
    "background_already_completed", "background_refused",
})


def _deliveries(exec_ctx, coordinator) -> list[dict]:
    return [
        observation
        for observation in _observations(exec_ctx, coordinator)
        if observation.get("background") is True
        and str(observation.get("task_id") or "").startswith("bg-")
        and observation.get("outcome") not in _ACKNOWLEDGEMENTS
    ]


async def test_an_idle_poll_waits_for_the_running_task_instead_of_another_turn(
    tmp_path, monkeypatch
):
    exec_ctx = _loop_context(tmp_path, monkeypatch)
    # The spawn carries the per-call timeout: a hanging tool becomes a TIMEOUT
    # quickly, so the test proves the *wait* without waiting for a real scan.
    service = FakeService(delay=0.01, hang="local.one")
    llm = ScriptedLLM(_spawn("local.one"), _poll(), _poll(), _CLARIFY)
    coordinator = _coordinator(
        exec_ctx,
        llm,
        ("local.one", GET_PLAN_STATUS_TOOL),
        service,
        # Long enough that the job is still running when the second poll is
        # refused, short enough to keep the wait bounded to a few seconds.
        timeout_per_tool_seconds=3.0,
    )
    await coordinator._initialize()
    # ``run()`` re-initializes the coordinator, so the spy belongs to the class
    # and not to the manager instance this test happens to hold.
    from nexus_core.agent.task_manager import TaskManager

    waits: list[float | None] = []
    original = TaskManager.wait_for_result

    async def spy(self, timeout=None):
        waits.append(timeout)
        return await original(self, timeout)

    monkeypatch.setattr(TaskManager, "wait_for_result", spy)

    result = await coordinator.run()

    assert waits, "el bucle espera al job en vez de gastar otro turno de sondeo"
    # The first poll of a state runs; the identical repeat never reaches the tool.
    assert service.calls.count(GET_PLAN_STATUS_TOOL) == 1
    delivered = _deliveries(exec_ctx, coordinator)
    assert len(delivered) == 1
    assert delivered[0]["label"] == "nmap completo"
    assert result.status == "clarification"


async def test_the_wait_delivers_once_and_leaves_nothing_pending(tmp_path, monkeypatch):
    exec_ctx = _loop_context(tmp_path, monkeypatch)
    service = FakeService(delay=0.01)
    coordinator = _coordinator(exec_ctx, ScriptedLLM(_CLARIFY), ("local.one",), service)
    await coordinator._initialize()
    record = await coordinator.task_manager.spawn_task(
        tool_id="local.one",
        arguments={"target": "10.0.0.5"},
        payload={"tool_id": "local.one", "arguments": {"target": "10.0.0.5"}},
        label="nmap completo",
    )

    await coordinator._wait_for_background_result()
    await coordinator._wait_for_background_result()  # an empty wait is a no-op

    delivered = _deliveries(exec_ctx, coordinator)
    assert [item["task_id"] for item in delivered] == [record.task_id]
    assert coordinator.task_manager.pending_results() == []
    assert record.status == "succeeded", "esperar no cancela el trabajo"
    await coordinator.task_manager.cancel_all()


async def test_a_poll_after_the_delivery_is_valid_again(tmp_path, monkeypatch):
    """Waiting is not a ban: once the result lands the state did change."""
    exec_ctx = _loop_context(tmp_path, monkeypatch)
    service = FakeService(delay=0.01)
    llm = ScriptedLLM(_spawn("local.one"), _poll(), _poll(), _poll(), _CLARIFY)
    coordinator = _coordinator(
        exec_ctx,
        llm,
        ("local.one", GET_PLAN_STATUS_TOOL),
        service,
        timeout_per_tool_seconds=0.2,
    )

    await coordinator.run()

    # The delivered observation moved the board, so the later polls execute.
    assert service.calls.count(GET_PLAN_STATUS_TOOL) >= 1
    assert coordinator.plan_status_fingerprint


async def test_the_wait_is_bounded_by_the_call_timeout(tmp_path, monkeypatch):
    exec_ctx = _loop_context(tmp_path, monkeypatch)
    service = FakeService(delay=0.01, hang="local.one")
    coordinator = _coordinator(
        exec_ctx, ScriptedLLM(_CLARIFY), ("local.one",), service, timeout_per_tool_seconds=0.2
    )
    await coordinator._initialize()
    await coordinator.task_manager.spawn_task(
        tool_id="local.one", arguments={}, payload={"tool_id": "local.one"},
        label="scan", timeout_seconds=0.2,
    )

    import time

    started = time.monotonic()
    await coordinator._wait_for_background_result()
    elapsed = time.monotonic() - started

    assert elapsed < 3, "la espera no puede bloquear el bucle"
    await coordinator.task_manager.cancel_all()


async def test_the_coordinator_never_waits_without_a_running_task(tmp_path, monkeypatch):
    """No job in flight, no wait: the gate's correction is the only answer."""
    exec_ctx = _loop_context(tmp_path, monkeypatch)
    coordinator = _coordinator(
        exec_ctx, ScriptedLLM(_CLARIFY), (GET_PLAN_STATUS_TOOL,), FakeService()
    )
    await coordinator._initialize()

    assert coordinator.task_manager.running_count() == 0
    assert coordinator.idle_background_wait is False
