"""Fase 2: durable plan and run state.

Pinned here:

* ``kernel_plan_todos`` is the source of truth; ``ENGAGEMENT_PLAN.md`` is a
  projection written from it, and deleting the file does not lose a tick.
* Every write is optimistic: a plan that read version N cannot overwrite N+1.
* A pre-F2 engagement (file only) is imported once; after that the file is no
  longer read.
* ``kernel_run_state`` survives a process restart: retired tools, locked
  vectors and phase turns come back with ``--resume`` (same run id).
* Wake-on-change: a background task that finishes during the model call cancels
  that stale call and lands its result before the next prompt.
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import replace
from types import SimpleNamespace

import pytest

from nexus_core.agent.engagement_plan import (
    EngagementPlan,
    Todo,
    load_plan_for,
    new_plan,
    now_stamp,
    save_plan,
)
from nexus_core.kernel.control_store import ControlStore
from nexus_core.kernel.errors import PlanConflict
from nexus_core.tests.unit.test_background_subagent import _spawn
from nexus_core.tests.unit.test_parallel_tools import (
    FakeService,
    ScriptedLLM,
    _coordinator,
    _loop_context,
    _observations,
)
from nexus_core.tools.handlers.plan_engagement import GET_PLAN_STATUS_TOOL

pytestmark = pytest.mark.unit

ENGAGEMENT = "eng-durable"
TENANT = "system"


def _store(tmp_path) -> ControlStore:
    store = ControlStore(tmp_path / "nexus.db")
    store.initialize()
    return store


def _todos() -> list[Todo]:
    return [
        Todo("recon", "Descubrir puertos", fact_types=("service",)),
        Todo("flag_root", "Capturar root.txt", fact_types=("flag",)),
    ]


def _plan(root=None, *, engagement: str = ENGAGEMENT) -> EngagementPlan:
    return new_plan("comprometer el host", engagement, _todos(), source="model")


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


# ------------------------------------------------------------------ plan table
def test_the_database_round_trips_the_plan_in_order(tmp_path):
    store = _store(tmp_path)
    plan = _plan()
    save_plan(plan, str(tmp_path), store=store, tenant_id=TENANT)

    assert plan.version == 1
    snapshot = store.load_engagement_plan(TENANT, ENGAGEMENT)
    assert snapshot is not None
    assert snapshot["version"] == 1
    assert [todo["id"] for todo in snapshot["todos"]] == ["recon", "flag_root"]

    loaded = load_plan_for(ENGAGEMENT, str(tmp_path), store=store, tenant_id=TENANT)
    assert loaded is not None
    assert loaded.version == 1
    assert [todo.description for todo in loaded.todos] == [
        "Descubrir puertos",
        "Capturar root.txt",
    ]


def test_a_second_create_and_a_stale_update_are_both_refused(tmp_path):
    store = _store(tmp_path)
    first = _plan()
    save_plan(first, str(tmp_path), store=store, tenant_id=TENANT)

    with pytest.raises(PlanConflict):
        save_plan(_plan(), str(tmp_path), store=store, tenant_id=TENANT)

    # ``first`` already advanced to version 1; a copy that still says 1 while the
    # database is at 2 is exactly the lost race optimistic versioning must catch.
    newer = replace(first, updated_at=now_stamp())
    newer_todos = tuple(
        replace(todo, status="done", verified_by="service:22/tcp")
        if todo.id == "recon"
        else todo
        for todo in first.todos
    )
    newer = replace(newer, todos=newer_todos)
    save_plan(newer, str(tmp_path), store=store, tenant_id=TENANT)
    assert newer.version == 2

    with pytest.raises(PlanConflict):
        save_plan(replace(first, todos=newer_todos), str(tmp_path), store=store, tenant_id=TENANT)

    assert store.load_engagement_plan(TENANT, ENGAGEMENT)["version"] == 2


def test_the_markdown_is_only_a_projection_of_the_database(tmp_path):
    store = _store(tmp_path)
    plan = _plan()
    save_plan(plan, str(tmp_path), store=store, tenant_id=TENANT)

    # A tick committed by the loop lands in the database and the file follows.
    ticked = replace(
        plan,
        todos=(
            replace(plan.todos[0], status="done", verified_by="service:22/tcp"),
            plan.todos[1],
        ),
        updated_at=now_stamp(),
    )
    save_plan(ticked, str(tmp_path), store=store, tenant_id=TENANT)
    projection = (tmp_path / "loot" / "ENGAGEMENT_PLAN.md").read_text(encoding="utf-8")
    assert "`recon`" in projection and "verificado: service:22/tcp" in projection

    # Editing the file is not a write: the database still leads.
    (tmp_path / "loot" / "ENGAGEMENT_PLAN.md").write_text("# notas\n", encoding="utf-8")
    loaded = load_plan_for(ENGAGEMENT, str(tmp_path), store=store, tenant_id=TENANT)
    assert loaded is not None
    assert [todo.status for todo in loaded.todos] == ["done", "pending"]

    # Deleting it loses nothing: --resume reads the TODOs from the database.
    (tmp_path / "loot" / "ENGAGEMENT_PLAN.md").unlink()
    resumed = load_plan_for(ENGAGEMENT, str(tmp_path), store=store, tenant_id=TENANT)
    assert resumed is not None
    assert [todo.id for todo in resumed.todos] == ["recon", "flag_root"]
    assert resumed.todos[0].verified_by == "service:22/tcp"


def test_a_pre_f2_file_is_imported_once_and_then_the_database_leads(tmp_path):
    file_only = _plan()
    save_plan(file_only, str(tmp_path))
    assert file_only.version == 0

    store = _store(tmp_path)
    imported = load_plan_for(ENGAGEMENT, str(tmp_path), store=store, tenant_id=TENANT)
    assert imported is not None
    assert imported.version == 1
    assert store.load_engagement_plan(TENANT, ENGAGEMENT) is not None

    # The import is the last read: a later file edit is ignored.
    (tmp_path / "loot" / "ENGAGEMENT_PLAN.md").write_text("# notas\n", encoding="utf-8")
    again = load_plan_for(ENGAGEMENT, str(tmp_path), store=store, tenant_id=TENANT)
    assert again is not None
    assert len(again.todos) == 2


# ------------------------------------------------------------------ run state
async def test_retired_tools_vectors_and_phase_turns_survive_a_resume(
    tmp_path, monkeypatch
):
    exec_ctx = _loop_context(tmp_path, monkeypatch)
    coordinator = _coordinator(
        exec_ctx, ScriptedLLM(_spawn("local.one")), ("local.one",), FakeService()
    )
    await coordinator._initialize()
    coordinator.observation = {}

    # Two failures leave the tool alive; the third retires it (B3).
    coordinator._note_tool_failure("nmap")
    coordinator._note_tool_failure("nmap")
    assert "nmap" not in coordinator.unavailable_tools
    coordinator._note_tool_failure("nmap")
    assert "nmap" in coordinator.unavailable_tools

    key = ("nexus.recon.nmap", "", "10.0.0.5")
    coordinator.vector_locked.add(key)
    coordinator.vector_failures[key] = 4
    coordinator.vector_last_failure[key] = 7
    coordinator.plan = SimpleNamespace(current="recon")
    coordinator._note_completed_turn()
    coordinator._persist_run_state()

    # A new process of the same run: same run id, same store.
    resumed = _coordinator(
        exec_ctx, ScriptedLLM(_spawn("local.one")), ("local.one",), FakeService()
    )
    await resumed._initialize()

    assert "nmap" in resumed.unavailable_tools
    assert resumed.tool_failures["nmap"] == 3
    assert key in resumed.vector_locked
    assert resumed.vector_failures[key] == 4
    assert resumed.vector_last_failure[key] == 7
    assert resumed.phase_turns == {"recon": 1}
    await coordinator.task_manager.cancel_all()
    await resumed.task_manager.cancel_all()


async def test_a_retired_tool_stays_retired_on_the_next_process(tmp_path, monkeypatch):
    """The measured case: nmap failed three times, the run died, --resume."""
    exec_ctx = _loop_context(tmp_path, monkeypatch)
    coordinator = _coordinator(
        exec_ctx, ScriptedLLM(_spawn("local.one")), ("local.one",), FakeService()
    )
    await coordinator._initialize()
    coordinator.observation = {}
    for _ in range(3):
        coordinator._note_tool_failure("nexus.recon.nmap")

    persisted = exec_ctx.store.load_run_state(TENANT, exec_ctx.task["run_id"])
    assert "nexus.recon.nmap" in persisted["unavailable_tools"]
    assert persisted["tool_failures"]["nexus.recon.nmap"] == 3

    resumed = _coordinator(
        exec_ctx, ScriptedLLM(_spawn("local.one")), ("local.one",), FakeService()
    )
    await resumed._initialize()
    assert "nexus.recon.nmap" in resumed.unavailable_tools
    await coordinator.task_manager.cancel_all()
    await resumed.task_manager.cancel_all()


# --------------------------------------------------------------- wake-on-change
class SlowLLM:
    """Answers after ``delay`` seconds: a model still thinking when a scan ends."""

    supports_streaming = False

    def __init__(self, *answers: str, delay: float = 0.3) -> None:
        self.answers = list(answers)
        self.delay = delay
        self.calls = 0

    async def complete(self, messages, **kwargs):
        self.calls += 1
        await asyncio.sleep(self.delay)
        answer = self.answers[min(self.calls - 1, len(self.answers) - 1)]
        from nexus_core.llm.abstraction import LLMProvider, LLMResponse

        return LLMResponse(content=answer, model="scripted", provider=LLMProvider.FAKE)


async def test_a_finished_task_cancels_the_stale_model_turn(tmp_path, monkeypatch):
    """The model's poll is discarded, the result lands, the next turn sees it."""
    exec_ctx = _loop_context(tmp_path, monkeypatch)
    fast = FakeService(delay=0.02)
    llm = SlowLLM(_spawn("local.one"), _poll(), _poll(), _poll(), delay=0.3)
    coordinator = _coordinator(
        exec_ctx,
        llm,
        ("local.one", GET_PLAN_STATUS_TOOL),
        fast,
        timeout_per_tool_seconds=3.0,
    )

    result = await coordinator.run()

    # Without the wake the first poll would have run against a board that the
    # finished scan had already changed, and the identical next poll would have
    # been refused: the task result cost a full turn of discovery.
    assert fast.calls.count(GET_PLAN_STATUS_TOOL) == 1
    delivered = [
        observation
        for observation in _observations(exec_ctx, coordinator)
        if observation.get("background") is True
        and str(observation.get("task_id") or "").startswith("bg-")
        and observation.get("outcome") != "background_task_started"
    ]
    assert len(delivered) == 1
    assert result.engagement_plan is None
    assert result.status in {"max_iterations", "clarification", "premature_completion"}
