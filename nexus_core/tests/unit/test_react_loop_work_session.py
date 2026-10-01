"""The ReAct loop can run inside a caller-provided durable conversation."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from unittest import mock

import pytest

from nexus_core.agent import memory
from nexus_core.agent.react import STATUS_COMPLETED, run_react_loop
from nexus_core.kernel import runtime as runtime_module
from nexus_core.kernel.control_store import ControlStore
from nexus_core.kernel.runtime import ExecutionContext
from nexus_core.llm.abstraction import LLMProvider, LLMResponse
from nexus_core.scope import EngagementScope, EngagementStore

pytestmark = pytest.mark.unit


def _iso(delta: timedelta) -> str:
    return (datetime.now(timezone.utc) + delta).isoformat()


def _scope() -> EngagementScope:
    return EngagementScope(
        engagement_id="eng-work",
        tenant_id="system",
        name="work",
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


class _LLM:
    def __init__(self) -> None:
        self.calls: list[str] = []

    async def complete(self, messages, **kwargs):
        self.calls.append("\n".join(m.content for m in messages))
        return LLMResponse(
            content=json.dumps(
                {"thought": "fin", "action": "task_complete", "summary": "hecho", "findings": []}
            ),
            model="test",
            provider=LLMProvider.FAKE,
        )


def _context(store: ControlStore) -> ExecutionContext:
    """A fresh run/context, the way the CLI creates one per objective."""
    run = store.create_run("system", {})
    task = {
        "id": f"task-{run['id']}",
        "tenant_id": "system",
        "run_id": run["id"],
        "task_type": "react.run",
        "payload": {"objective": "objetivo", "engagement_id": "eng-work"},
    }
    return ExecutionContext(store, task, "worker")


@pytest.fixture()
def harness(tmp_path):
    store = ControlStore(tmp_path / "work.db")
    store.initialize()
    EngagementStore(store).create(_scope())
    return store, _context(store)


async def test_run_react_loop_uses_provided_conversation(harness):
    store, context = harness
    conversation_id = memory.ensure_work_conversation(store, "system", "omni", "eng-work")
    with mock.patch.object(runtime_module, "execute_tool", mock.AsyncMock()):
        result = await run_react_loop(
            context=context,
            objective="objetivo",
            engagement_id="eng-work",
            llm_client=_LLM(),
            conversation_id=conversation_id,
        )
    assert result.conversation_id == conversation_id
    assert store.list_messages("system", conversation_id)


async def test_run_react_loop_falls_back_to_new_conversation(harness):
    store, context = harness
    with mock.patch.object(runtime_module, "execute_tool", mock.AsyncMock()):
        result = await run_react_loop(
            context=context,
            objective="objetivo",
            engagement_id="eng-work",
            llm_client=_LLM(),
        )
    assert result.conversation_id.startswith("conversation_")
    assert result.status == STATUS_COMPLETED
    # The per-run conversation still carries the deterministic react: title.
    conversation = store.get_conversation("system", result.conversation_id)
    assert conversation["title"].startswith("react:")


async def test_shared_conversation_exposes_previous_objective(harness):
    store, context = harness
    conversation_id = memory.ensure_work_conversation(store, "system", "omni", "eng-work")
    first = _LLM()
    with mock.patch.object(runtime_module, "execute_tool", mock.AsyncMock()):
        await run_react_loop(
            context=context,
            objective="Escanea el host A",
            engagement_id="eng-work",
            llm_client=first,
            conversation_id=conversation_id,
        )
    # A new objective is a new run, but it reuses the engagement work session.
    second = _LLM()
    with mock.patch.object(runtime_module, "execute_tool", mock.AsyncMock()):
        await run_react_loop(
            context=_context(store),
            objective="Ahora el host B",
            engagement_id="eng-work",
            llm_client=second,
            conversation_id=conversation_id,
        )
    # The second run's model call sees the first objective in the same session.
    assert "Escanea el host A" in second.calls[0]
    assert "Ahora el host B" in second.calls[0]
