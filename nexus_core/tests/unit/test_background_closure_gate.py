"""Tarea 1/3: cerrar con un job en vuelo y tolerar errores de entrada.

Measured failure: the agent spawned ``nmap`` as ``bg-1``, had no result in that
turn and called ``task_complete``. The loop returned, the process exited and
``cancel_all()`` killed the scan, so the user lost the output they had asked for.
These tests pin the three halves of the fix: the gate refuses the close while a
task is ``running`` (even for a micro-task), the loop waits and delivers the
result instead of killing it, and ``create_plan``/``discover_tools`` answer an
invalid input with the closed list of what *is* accepted.
"""

from __future__ import annotations

import json

import pytest

from nexus_core.agent.react_support import (
    _completion_objections,
    running_background_objection,
)
from nexus_core.tests.unit.test_background_subagent import _spawn
from nexus_core.tests.unit.test_parallel_tools import (
    FakeService,
    ScriptedLLM,
    _coordinator,
    _loop_context,
    _observations,
)
from nexus_core.tools.handlers.discover_tools import discover_tools_handler
from nexus_core.tools.handlers.plan_engagement import create_plan_handler
from nexus_core.tools.profiles import search_tools
from nexus_core.tools.registry import durable_tool_definitions

pytestmark = pytest.mark.unit

_RUNNING = [
    {
        "task_id": "bg-1",
        "label": "nmap completo",
        "tool_id": "nexus.recon.nmap",
        "status": "running",
    }
]

_COMPLETE = json.dumps(
    {"thought": "el escaneo ya está", "action": "task_complete", "summary": "hecho"}
)


def test_a_running_job_is_an_objection_that_names_the_delivery() -> None:
    line = running_background_objection(_RUNNING)

    assert line and "bg-1" in line and "nmap completo" in line
    # The way out: the loop delivers it, the model does not poll or rescan.
    assert "background: true" in line and "No cierres el run" in line


def test_a_finished_job_is_not_an_objection() -> None:
    assert running_background_objection([{**_RUNNING[0], "status": "succeeded"}]) is None
    assert running_background_objection(None) is None


def test_the_gate_refuses_the_close_even_for_a_micro_task() -> None:
    """The user asked for *one action*; that action is still running."""

    objections = _completion_objections(
        None,
        enforce_completion_gates=True,
        micro_task=True,
        background_tasks=_RUNNING,
    )

    assert len(objections) == 1 and "bg-1" in objections[0]


def test_the_gate_ignores_background_tasks_when_gates_are_off() -> None:
    assert (
        _completion_objections(
            None, enforce_completion_gates=False, background_tasks=_RUNNING
        )
        == []
    )


async def test_task_complete_waits_for_the_scan_instead_of_killing_it(
    tmp_path, monkeypatch
) -> None:
    exec_ctx = _loop_context(tmp_path, monkeypatch)
    service = FakeService(delay=0.05)
    coordinator = _coordinator(
        exec_ctx,
        ScriptedLLM(_spawn("local.one"), _COMPLETE),
        ("local.one",),
        service,
    )

    result = await coordinator.run()

    assert result.status == "completed"
    # The scan got to finish: closing the run no longer cancels it mid-flight.
    assert [record["status"] for record in coordinator.task_manager.list_tasks()] == [
        "succeeded"
    ]
    observations = _observations(exec_ctx, coordinator)
    delivered = [
        observation
        for observation in observations
        if observation.get("background") is True
        and observation.get("outcome") != "background_task_started"
    ]
    assert delivered, "el resultado del job llega al modelo antes de cerrar"
    started = [
        observation
        for observation in observations
        if observation.get("outcome") == "background_task_started"
    ]
    # The ack itself must rule out the invented pause, or the model spends a turn
    # on it and ends up asking the human (the measured trace).
    assert started and "`wait`" in started[0]["guidance"]


def test_discover_tools_matches_a_phrase_instead_of_failing() -> None:
    catalog = durable_tool_definitions("system")

    assert "nexus.recon.nmap" in search_tools(catalog, "nmap full_tcp scan")


def test_discover_tools_tolerates_a_typo() -> None:
    catalog = durable_tool_definitions("system")

    assert "nexus.recon.nmap" in search_tools(catalog, "reconn")


async def test_a_near_miss_group_still_activates_its_tools(tmp_path, monkeypatch) -> None:
    exec_ctx = _loop_context(tmp_path, monkeypatch)

    result = await discover_tools_handler({"group": "reconn"}, exec_ctx)

    assert result.success
    assert "nexus.recon.nmap" in result.output["tools"]


async def test_an_invalid_fact_type_lists_the_allowed_ones(tmp_path, monkeypatch) -> None:
    exec_ctx = _loop_context(tmp_path, monkeypatch)

    result = await create_plan_handler(
        {
            "todos": [
                {
                    "id": "t1",
                    "description": "cerrar sesión con la credencial",
                    "fact_types": ["sesion", "loot"],
                }
            ]
        },
        exec_ctx,
    )

    assert not result.success
    assert result.output["invalid"] == [{"todo": "t1", "unknown": ["sesion"]}]
    assert "session" in result.output["allowed_fact_types"]
    assert "loot" in result.output["allowed_fact_types"]
    assert "sesion" in result.output["error"]
