"""``/ask`` and ``/chat``: conversational LLM help that executes nothing."""

from __future__ import annotations

from unittest import mock

import pytest

from nexus_core.cli import banner as banner_module
from nexus_core.cli import commands as commands_module
from nexus_core.cli import render, session as session_module
from nexus_core.cli.session import OmniSession
from nexus_core.kernel.audit import AuditWriter
from nexus_core.kernel.control_store import ControlStore
from nexus_core.scope import EngagementScope, EngagementStore

TENANT = "system"


class _Answer:
    """Minimal stand-in for an ``LLMResponse``."""

    def __init__(self, content: str = "usa /scope para ver el alcance") -> None:
        self.content = content


class _FakeLLM:
    def __init__(self, content: str = "usa /scope para ver el alcance") -> None:
        self.content = content
        self.calls: list[list] = []

    async def complete(self, messages, **kwargs):
        self.calls.append(list(messages))
        return _Answer(self.content)

    async def ask(self, system_prompt, user_message):
        return self.content


def _iso() -> str:
    from datetime import datetime, timedelta, timezone

    return (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()


@pytest.fixture()
def session(tmp_path) -> OmniSession:
    store = ControlStore(tmp_path / "ask.db")
    store.initialize()
    scope = EngagementStore(store).create(
        store_scope := EngagementScope(
            engagement_id="eng-ask",
            tenant_id=TENANT,
            name="lab",
            client="acme",
            owner_id="owner-1",
            valid_from=_iso(),
            valid_until=_iso(),
            cidrs=("10.0.0.0/24",),
            domains=(),
            urls=(),
            exclusions=(),
            created_at=_iso(),
        )
    )
    assert store_scope is not None
    value = OmniSession(
        store=store,
        tenant_id=TENANT,
        engagement=scope,
        llm_client=_FakeLLM(),
        operator_id="operator:tester",
    )
    return value


def test_cmd_ask_without_args_shows_usage(session, capsys):
    commands_module.cmd_ask(session, [])
    out = capsys.readouterr().out
    assert "uso: /ask <pregunta>" in out
    assert session.ask_history == []


def test_cmd_ask_calls_llm_with_system_prompt(session, capsys):
    commands_module.cmd_ask(session, ["qué", "puedo", "hacer"])
    messages = session.llm_client.calls[0]
    assert messages[0].role == "system"
    # Contextual prompt: the base persona plus the real CLI catalog.
    assert messages[0].content.startswith(commands_module.ASK_SYSTEM_PROMPT)
    assert "nexus.recon.nmap" in messages[0].content
    assert messages[1].role == "user"
    assert messages[1].content == "qué puedo hacer"
    assert "usa /scope para ver el alcance" in capsys.readouterr().out


def test_cmd_ask_does_not_invoke_tools(session):
    with mock.patch.object(OmniSession, "invoke_tool") as invoke_tool:
        commands_module.cmd_ask(session, ["explica", "qué", "es", "nmap"])
    invoke_tool.assert_not_called()


def test_cmd_ask_does_not_persist_to_engagement(session):
    """No durable conversation, no run, no messages: purely local."""
    commands_module.cmd_ask(session, ["hola"])
    assert session.run_id is None
    assert session.conversation_id is None
    assert session.store.list_conversations(TENANT, session.agent_subject_id) == []
    # ``ensure_run`` would have set ``run_id``; the durable run table stays empty.
    with session.store.connect() as conn:
        runs = conn.execute(
            "SELECT COUNT(*) FROM kernel_runs WHERE tenant_id=?", (TENANT,)
        ).fetchone()[0]
    assert runs == 0


def test_cmd_ask_does_not_audit_as_tool_call(session):
    commands_module.cmd_ask(session, ["hola"])
    events = AuditWriter(session.store).export(TENANT)
    assert events == []


def test_cmd_ask_with_llm_none_shows_error(tmp_path, capsys):
    store = ControlStore(tmp_path / "ask-none.db")
    store.initialize()
    session = OmniSession(store=store, tenant_id=TENANT, engagement=None)
    session.llm_client = None
    with mock.patch.object(
        session_module, "build_llm_client", return_value=None
    ):
        commands_module.cmd_ask(session, ["hola"])
    assert "LLM no configurado" in capsys.readouterr().out


def test_cmd_ask_reports_broken_llm_construction(tmp_path, capsys):
    store = ControlStore(tmp_path / "ask-broken.db")
    store.initialize()
    session = OmniSession(store=store, tenant_id=TENANT, engagement=None)
    session.llm_client = None
    with mock.patch.object(
        session_module, "build_llm_client", side_effect=RuntimeError("no provider")
    ):
        commands_module.cmd_ask(session, ["hola"])
    assert "no se pudo construir el cliente LLM" in capsys.readouterr().out


def test_cmd_ask_spinner_shown_during_llm_call(session):
    seen: list[dict] = []

    class _FakeSpinner:
        def __init__(self, message, **kwargs):
            seen.append({"message": message, **kwargs})

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    with (
        mock.patch("nexus_core.cli.spinner.spinner_enabled", return_value=True),
        mock.patch("nexus_core.cli.spinner.Spinner", _FakeSpinner),
    ):
        commands_module.cmd_ask(session, ["hola"])
    assert seen and seen[0]["message"] == "Consultando al modelo"
    assert seen[0]["enabled"] is True


def test_cmd_ask_failure_does_not_break_the_repl(session, capsys):
    async def _boom(messages, **kwargs):
        raise RuntimeError("rate limited")

    session.llm_client.complete = _boom
    commands_module.cmd_ask(session, ["hola"])
    assert "la consulta falló" in capsys.readouterr().out
    # A failed exchange leaves no trace in the local history either.
    assert session.ask_history == []


def test_cmd_ask_keeps_local_history_for_follow_ups(session):
    commands_module.cmd_ask(session, ["primera"])
    commands_module.cmd_ask(session, ["segunda"])
    assert [role for role, _ in session.ask_history] == [
        "user",
        "assistant",
        "user",
        "assistant",
    ]
    second = session.llm_client.calls[1]
    # system + (user, assistant) + the new question
    assert len(second) == 4
    assert second[2].content == "usa /scope para ver el alcance"
    assert second[3].content == "segunda"


def test_cmd_chat_alias_of_ask(session):
    with mock.patch.object(commands_module, "cmd_ask") as ask:
        commands_module.cmd_chat(session, ["hola"])
    ask.assert_called_once_with(session, ["hola"])
    assert commands_module.COMMANDS["/chat"] is commands_module.cmd_chat


def test_help_lists_ask_command(capsys):
    session = OmniSession(store=None, engagement=None)
    commands_module.cmd_help(session, [])
    out = capsys.readouterr().out
    assert "/ask" in out
    assert "/chat" in out


def test_tip_includes_ask_command():
    assert any("/ask" in tip for tip in banner_module.TIPS)


def test_ask_history_is_capped():
    assert commands_module.ASK_HISTORY_LIMIT > 0
    assert commands_module.ASK_HISTORY_LIMIT <= 100


def test_render_answer_prints_body(capsys):
    render.render_answer("primera línea\n\nsegunda línea")
    out = capsys.readouterr().out
    assert "OmniAgent" in out
    assert "primera línea" in out
    assert "segunda línea" in out