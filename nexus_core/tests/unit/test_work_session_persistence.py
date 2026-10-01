"""The engagement work session is one durable conversation shared by every run.

These tests exercise the contract introduced to close audit finding #7: a run
per objective keeps traceability, but all of them (and ``/ask``) read/write the
same conversation so the model always sees the engagement's prior context.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from unittest import mock

import pytest

from nexus_core.agent import memory
from nexus_core.agent.react import run_react_loop
from nexus_core.cli import commands
from nexus_core.cli.session import OmniSession
from nexus_core.kernel import runtime as runtime_module
from nexus_core.kernel.control_store import ControlStore
from nexus_core.kernel.runtime import ExecutionContext
from nexus_core.llm.abstraction import LLMProvider, LLMResponse
from nexus_core.scope import EngagementScope, EngagementStore

pytestmark = pytest.mark.unit

TENANT = "system"


def _iso(delta: timedelta) -> str:
    return (datetime.now(timezone.utc) + delta).isoformat()


def _scope() -> EngagementScope:
    return EngagementScope(
        engagement_id="eng-work",
        tenant_id=TENANT,
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


class _Answer:
    def __init__(self, content: str) -> None:
        self.content = content


class _FakeLLM:
    def __init__(self, content: str | None = None) -> None:
        self.content = content or json.dumps(
            {
                "thought": "fin",
                "action": "task_complete",
                "summary": "hecho",
                "findings": [],
            }
        )
        self.calls: list[str] = []

    async def complete(self, messages, **kwargs):
        self.calls.append("\n".join(str(getattr(m, "content", "")) for m in messages))
        return LLMResponse(content=self.content, model="fake", provider=LLMProvider.FAKE)


@pytest.fixture()
def session(tmp_path) -> OmniSession:
    store = ControlStore(tmp_path / "work.db")
    store.initialize()
    scope = EngagementStore(store).create(_scope())
    return OmniSession(
        store=store,
        tenant_id=TENANT,
        engagement=scope,
        llm_client=_FakeLLM(),
        operator_id="operator:tester",
    )


def _context(store: ControlStore) -> ExecutionContext:
    run = store.create_run(TENANT, {"source": "test"})
    task = {
        "id": f"task-{run['id']}",
        "tenant_id": TENANT,
        "run_id": run["id"],
        "task_type": "react.run",
        "payload": {"objective": "objetivo", "engagement_id": "eng-work"},
    }
    return ExecutionContext(store, task, "worker")


def _run_objective(store: ControlStore, objective: str, conversation_id: str) -> _FakeLLM:
    llm = _FakeLLM()
    with mock.patch.object(runtime_module, "execute_tool", mock.AsyncMock()):
        import asyncio

        asyncio.run(
            run_react_loop(
                context=_context(store),
                objective=objective,
                engagement_id="eng-work",
                llm_client=llm,
                conversation_id=conversation_id,
            )
        )
    return llm


# ------------------------------------------------------------------ persistence


def test_work_session_created_once_per_engagement(session):
    first = session._ensure_work_session()
    second = session._ensure_work_session()
    assert first == second
    assert first
    work = commands._work_conversations(session)
    assert len(work) == 1
    assert work[0]["title"] == memory.work_session_title("eng-work")


def test_multiple_objectives_share_conversation(session):
    conversation_id = session._ensure_work_session()
    _run_objective(session.store, "Escanea el host A", conversation_id)
    _run_objective(session.store, "Escanea el host B", conversation_id)
    work = commands._work_conversations(session)
    assert len(work) == 1
    messages = session.store.list_messages(TENANT, work[0]["id"])
    objectives = [
        message["metadata"].get("objective")
        for message in messages
        if message["metadata"].get("kind") == memory.SYSTEM_MESSAGE_KIND
    ]
    assert objectives == ["Escanea el host A", "Escanea el host B"]


def test_ask_shares_conversation_with_objectives(session):
    conversation_id = session._ensure_work_session()
    _run_objective(session.store, "Escanea el host A", conversation_id)
    commands.cmd_ask(session, ["qué", "viste"])
    work = commands._work_conversations(session)
    assert len(work) == 1
    messages = session.store.list_messages(TENANT, work[0]["id"])
    sources = [message["metadata"].get("source") for message in messages]
    assert "ask" in sources
    # The objective and the /ask exchange live in the same conversation.
    assert any(
        message["metadata"].get("objective") == "Escanea el host A"
        for message in messages
    )
    assert sum(1 for source in sources if source == "ask") == 2


def test_clear_rotates_conversation(session, capsys):
    session.history.extend(["[completed] hecho"])
    previous = session._ensure_work_session()
    commands.cmd_clear(session, [])
    capsys.readouterr()
    rotated = session._ensure_work_session()
    assert rotated != previous
    work = commands._work_conversations(session)
    # The new session is the active one (first by updated_at); the old one is
    # still in the store, just no longer current (archived).
    assert work[0]["id"] == rotated
    assert previous in [item["id"] for item in work]
    assert session.store.get_conversation(TENANT, previous) is not None


def test_history_after_clear_shows_archived(session, capsys):
    previous = session._ensure_work_session()
    session.store.append_message(
        TENANT, previous, "user", "objetivo archivado", metadata={"kind": "ask"}
    )
    commands.cmd_clear(session, [])
    capsys.readouterr()
    commands.cmd_history(session, ["--archive"])
    out = capsys.readouterr().out
    assert previous in out
    assert "mensajes=1" in out


def test_work_session_survives_new_session_object(session):
    first = session._ensure_work_session()
    reborn = OmniSession(
        store=session.store,
        tenant_id=TENANT,
        engagement=session.engagement,
        llm_client=_FakeLLM(),
        operator_id="operator:tester",
    )
    assert reborn._ensure_work_session() == first


def test_react_loop_receives_prior_context(session):
    conversation_id = session._ensure_work_session()
    _run_objective(session.store, "Escanea el host A", conversation_id)
    second = _run_objective(session.store, "Ahora el host B", conversation_id)
    assert "Escanea el host A" in second.calls[0]
    assert "Ahora el host B" in second.calls[0]
