"""The plan poll: valid when the state moved, refused when it cannot answer.

Measured shape this file pins: consecutive ``nexus.orchestrator.get_plan_status``
calls while the plan, the verified board and the surface ledger are identical.
The plan block already travels in every system prompt, so each of those turns
paid a model call to re-read the same checklist, and the run reached
``max_iterations`` with every TODO still pending.

The gate is state-based: the first poll of a state runs normally, an identical
repeat is answered with the next pending TODO and the next open branch, and a
poll after real progress is valid again. Nothing is ever closed by the gate and
``task_complete`` keeps all of its existing validation.
"""

from __future__ import annotations

import json
from dataclasses import replace
from unittest import mock

import pytest

from nexus_core.agent.engagement_plan import (
    TODO_DONE,
    TODO_PENDING,
    Todo,
    load_plan_for,
    new_plan,
    now_stamp,
    save_plan,
)
from nexus_core.agent.react import (
    STATUS_MAX_ITERATIONS,
    STATUS_PREMATURE_COMPLETION,
    run_react_loop,
)
from nexus_core.agent.react_types import (
    MAX_PREMATURE_COMPLETIONS,
    PLAN_STATUS_REPEATED_EVENT_TYPE,
)
from nexus_core.kernel import runtime as runtime_module
from nexus_core.kernel.control_store import ControlStore
from nexus_core.kernel.runtime import ExecutionContext
from nexus_core.scope import EngagementStore
from nexus_core.tests.unit.test_engagement_plan import (
    ScriptedLLM_loop,
    _complete,
    _config,
    _context,
    _tool_call,
)
from nexus_core.tools.handlers.plan_engagement import GET_PLAN_STATUS_TOOL

pytestmark = [pytest.mark.unit, pytest.mark.usefixtures("lab_scope")]

TENANT = "system"
ENGAGEMENT = "eng-poll"
TARGET = "203.0.113.77"
OBJECTIVE = (
    "Realiza una prueba de penetración. Compromete el sistema, escala a root y "
    "captura las flags como prueba del compromiso."
)


@pytest.fixture()
def harness(tmp_path, monkeypatch):
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(tmp_path))
    store = ControlStore(tmp_path / "poll.db")
    store.initialize()
    EngagementStore(store).create(_context(engagement_id=ENGAGEMENT).scope)
    run = store.create_run(TENANT, {})
    task = {
        "id": f"task-{run['id']}",
        "tenant_id": TENANT,
        "run_id": run["id"],
        "task_type": "react.run",
        "payload": {
            "objective": OBJECTIVE,
            "engagement_id": ENGAGEMENT,
            "identity": {"subject_id": "operator-1", "roles": ["operator"]},
            "permissions": [],
        },
    }
    return store, ExecutionContext(store, task, "worker-test"), tmp_path


def _poll() -> str:
    """``get_plan_status`` takes no arguments (its schema forbids any)."""
    return json.dumps(
        {
            "thought": "Compruebo el estado del plan.",
            "action": "tool_call",
            "tool_id": GET_PLAN_STATUS_TOOL,
            "arguments": {},
            "expected_outcome": "plan vigente",
        }
    )


def _save_open_plan(workspace) -> None:
    save_plan(
        new_plan(
            OBJECTIVE,
            ENGAGEMENT,
            [
                Todo("recon", "Descubrir puertos", fact_types=("service",)),
                Todo("flag_root", "Capturar root.txt", fact_types=("flag",)),
            ],
        ),
        str(workspace),
    )


class ToolSpy:
    """Records the calls that reached the executor.

    ``nmap`` also ticks the ``recon`` TODO, which is what the real verifier does
    when the scan proves a service: the plan the tool answers with has changed.
    """

    def __init__(self, workspace, store=None, tenant_id: str = "system") -> None:
        self.workspace = workspace
        self.store = store
        self.tenant_id = tenant_id
        self.payloads: list[dict] = []

    async def __call__(self, payload, context):
        self.payloads.append(payload)
        tool_id = payload["tool_id"]
        if tool_id == "nexus.recon.nmap":
            plan = load_plan_for(
                ENGAGEMENT,
                str(self.workspace),
                store=self.store,
                tenant_id=self.tenant_id,
            )
            if plan is not None:
                save_plan(
                    replace(
                        plan,
                        todos=tuple(
                            replace(todo, status=TODO_DONE, verified_by="service:22/tcp")
                            if todo.id == "recon"
                            else todo
                            for todo in plan.todos
                        ),
                        updated_at=now_stamp(),
                    ),
                    str(self.workspace),
                    store=self.store,
                    tenant_id=self.tenant_id,
                )
        return {
            "tool_id": tool_id,
            "output": {"success": True, "verified": True, "output": {}},
        }


def _results(result) -> list[dict]:
    return [
        action.get("tool_result") or {}
        for action in result.actions
        if action.get("tool_result")
    ]


async def test_an_unchanged_plan_poll_is_answered_once_and_corrected(harness):
    """Two identical polls never reach the executor; the pending TODO stays open."""
    store, context, workspace = harness
    _save_open_plan(workspace)
    llm = ScriptedLLM_loop([_poll()])
    spy = ToolSpy(workspace)

    with mock.patch.object(runtime_module, "execute_tool", spy):
        result = await run_react_loop(
            context=context,
            objective=OBJECTIVE,
            engagement_id=ENGAGEMENT,
            llm_client=llm,
            config=_config(max_iterations=3),
        )

    polls = [payload for payload in spy.payloads if payload["tool_id"] == GET_PLAN_STATUS_TOOL]
    assert len(polls) == 1, "solo la primera consulta de un estado se ejecuta"
    refusals = [
        observation
        for observation in _results(result)
        if observation.get("outcome") == "plan_status_unchanged"
    ]
    assert len(refusals) == 2
    guidance = refusals[0]["guidance"]
    assert "'recon'" in guidance, "la corrección nombra el TODO pendiente"
    assert "no repitas la consulta" in guidance
    # The gate closes nothing: both TODOs are still pending.
    assert [todo["status"] for todo in result.engagement_plan["todos"]] == [
        TODO_PENDING,
        TODO_PENDING,
    ]
    assert TODO_DONE not in [todo["status"] for todo in result.engagement_plan["todos"]]
    events = [
        event
        for event in store.list_run_events(TENANT, context.run_id)
        if event["event_type"] == PLAN_STATUS_REPEATED_EVENT_TYPE
    ]
    assert len(events) == 2
    assert events[0]["payload"]["pending"] == ["recon", "flag_root"]


async def test_a_poll_after_real_progress_runs_again(harness):
    """A new verified fact makes the same call valid: the answer would differ."""
    store, context, workspace = harness
    _save_open_plan(workspace)
    llm = ScriptedLLM_loop([_poll(), _tool_call("nexus.recon.nmap", target=TARGET), _poll()])
    spy = ToolSpy(workspace, store, context.tenant_id)

    with mock.patch.object(runtime_module, "execute_tool", spy):
        result = await run_react_loop(
            context=context,
            objective=OBJECTIVE,
            engagement_id=ENGAGEMENT,
            llm_client=llm,
            config=_config(max_iterations=3),
        )

    assert [payload["tool_id"] for payload in spy.payloads] == [
        GET_PLAN_STATUS_TOOL,
        "nexus.recon.nmap",
        GET_PLAN_STATUS_TOOL,
    ]
    assert not [
        observation
        for observation in _results(result)
        if observation.get("outcome") == "plan_status_unchanged"
    ]


async def test_an_incomplete_plan_still_refuses_the_closure(harness):
    """The gate adds no second closure path: the existing validation decides."""
    _, context, workspace = harness
    _save_open_plan(workspace)
    llm = ScriptedLLM_loop([_complete()])

    with mock.patch.object(runtime_module, "execute_tool", ToolSpy(workspace)):
        result = await run_react_loop(
            context=context,
            objective=OBJECTIVE,
            engagement_id=ENGAGEMENT,
            llm_client=llm,
            config=_config(max_iterations=MAX_PREMATURE_COMPLETIONS + 1),
        )

    assert result.status == STATUS_PREMATURE_COMPLETION
    assert any("TODO" in objection for objection in result.completion_objections)
    assert [todo["status"] for todo in result.engagement_plan["todos"]] == [
        TODO_PENDING,
        TODO_PENDING,
    ]


async def test_the_iteration_limit_reads_as_reached_not_as_success(harness):
    """``max_iterations`` is an incomplete run and the summary says so."""
    store, context, workspace = harness
    _save_open_plan(workspace)
    llm = ScriptedLLM_loop([_poll()])
    spy = ToolSpy(workspace)

    with mock.patch.object(runtime_module, "execute_tool", spy):
        result = await run_react_loop(
            context=context,
            objective=OBJECTIVE,
            engagement_id=ENGAGEMENT,
            llm_client=llm,
            config=_config(max_iterations=3),
        )

    assert result.status == STATUS_MAX_ITERATIONS
    summary = str(result.final_summary)
    assert "límite de iteraciones alcanzado; trabajo incompleto" in summary
    assert "termination_reason=max_iterations" in summary
    assert "findings=0" in summary
    assert [todo["status"] for todo in result.engagement_plan["todos"]] == [
        TODO_PENDING,
        TODO_PENDING,
    ]
