"""E2E: consecutive objectives share the engagement work session.

Deterministic (no real LLM, no network): a ``FakeLLM`` records the messages it
receives through the real CLI ``run_objective`` path, proving that the second
objective sees the context of the first one in the same durable conversation.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from unittest import mock

import pytest

from nexus_core.agent import memory
from nexus_core.cli import commands
from nexus_core.cli.session import OmniSession
from nexus_core.kernel import runtime as runtime_module
from nexus_core.kernel.control_store import ControlStore
from nexus_core.llm.abstraction import LLMProvider, LLMResponse
from nexus_core.scope import EngagementScope, EngagementStore

pytestmark = pytest.mark.integration

TENANT = "system"


def _iso(delta: timedelta) -> str:
    return (datetime.now(timezone.utc) + delta).isoformat()


def _scope() -> EngagementScope:
    return EngagementScope(
        engagement_id="eng-e2e",
        tenant_id=TENANT,
        name="e2e",
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


class _RecordingLLM:
    """Returns a valid ``task_complete`` and records each prompt it receives."""

    def __init__(self) -> None:
        self.prompts: list[str] = []

    async def complete(self, messages, **kwargs):
        self.prompts.append("\n".join(str(m.content) for m in messages))
        return LLMResponse(
            content=json.dumps(
                {
                    "thought": "fin",
                    "action": "task_complete",
                    "summary": "hecho",
                    "findings": [],
                }
            ),
            model="fake",
            provider=LLMProvider.FAKE,
        )


@pytest.fixture()
def session(tmp_path) -> OmniSession:
    store = ControlStore(tmp_path / "e2e.db")
    store.initialize()
    scope = EngagementStore(store).create(_scope())
    return OmniSession(
        store=store,
        tenant_id=TENANT,
        engagement=scope,
        llm_client=_RecordingLLM(),
        operator_id="operator:tester",
        use_tui=False,
    )


def test_consecutive_objectives_share_work_session(session):
    llm = session.llm_client
    with mock.patch.object(runtime_module, "execute_tool", mock.AsyncMock()):
        session.run_objective("Escanea el host 10.0.0.5")
        session.run_objective("Ahora enumera SMB en ese host")

    # One run per objective (traceability) but a single durable conversation.
    runs = session.store.list_runs(TENANT) if hasattr(session.store, "list_runs") else []
    if runs:
        assert len(runs) == 2
    work = commands._work_conversations(session)
    assert len(work) == 1
    objectives = [
        message["metadata"].get("objective")
        for message in session.store.list_messages(TENANT, work[0]["id"])
        if message["metadata"].get("kind") == memory.SYSTEM_MESSAGE_KIND
    ]
    assert objectives == ["Escanea el host 10.0.0.5", "Ahora enumera SMB en ese host"]

    # The second objective's model call saw the first objective's context. It
    # arrives as *summarised session context* (B8.2.1): the first run's raw
    # transcript is never replayed into another run, so the earlier objective is
    # cited in the session block while its tool turns stay behind.
    assert "Escanea el host 10.0.0.5" in llm.prompts[-1]
    assert "Ahora enumera SMB en ese host" in llm.prompts[-1]
    assert "Objetivos previos de esta sesión de trabajo" in llm.prompts[-1]


def test_ask_reuses_work_session_created_by_objectives(session):
    with mock.patch.object(runtime_module, "execute_tool", mock.AsyncMock()):
        session.run_objective("Escanea el host 10.0.0.5")
    conversation = commands._work_conversations(session)[0]["id"]
    commands.cmd_ask(session, ["qué", "encontraste"])
    messages = session.store.list_messages(TENANT, conversation)
    assert sum(1 for m in messages if m["metadata"].get("source") == "ask") == 2
    # No extra work session was opened by /ask.
    assert len(commands._work_conversations(session)) == 1
