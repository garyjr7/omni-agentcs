"""Unit tests for the omni meta commands (the REPL itself is never started)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from nexus_core.agent import memory
from nexus_core.cli import commands
from nexus_core.cli.session import OmniSession
from nexus_core.kernel.control_store import ControlStore
from nexus_core.scope import EngagementScope, EngagementStore

def _iso(delta: timedelta) -> str:
    return (datetime.now(timezone.utc) + delta).isoformat()


def _scope() -> EngagementScope:
    return EngagementScope(
        engagement_id="eng-scanme",
        tenant_id="system",
        name="scanme-test",
        client="acme",
        owner_id="owner-1",
        valid_from=_iso(-timedelta(days=1)),
        valid_until=_iso(timedelta(days=1)),
        cidrs=("45.33.32.156/32",),
        domains=("scanme.nmap.org",),
        urls=(),
        exclusions=(),
        created_at=_iso(timedelta(0)),
    )


@pytest.fixture()
def session(tmp_path) -> OmniSession:
    store = ControlStore(tmp_path / "cli.db")
    store.initialize()
    scope = EngagementStore(store).create(_scope())
    run = store.create_run("system", {"source": "test"})
    value = OmniSession(
        store=store,
        tenant_id="system",
        engagement=scope,
        llm_client=None,
        max_iterations=5,
        operator_id="operator:tester",
        export_dir=tmp_path,
    )
    value.run_id = str(run["id"])
    value.conversation_id = memory.ensure_conversation(
        store, "system", value.run_id, value.agent_id
    )
    store.append_message(
        "system",
        value.conversation_id,
        "system",
        "Escanea 10.0.0.5",
        run_id=value.run_id,
        metadata={"kind": memory.SYSTEM_MESSAGE_KIND},
    )
    store.append_message(
        "system",
        value.conversation_id,
        "assistant",
        '{"thought": "lanzo el scan", "action": "tool_call"}',
        run_id=value.run_id,
        metadata={"kind": "react.action", "iteration": 1, "action": "tool_call"},
    )
    return value


def test_cmd_scope_renders_engagement(session, capsys):
    commands.cmd_scope(session, [])
    out = capsys.readouterr().out
    assert "eng-scanme" in out
    assert "scanme-test" in out
    assert "45.33.32.156/32" in out
    assert "scanme.nmap.org" in out


def test_cmd_tools_lists_durable_tools(session, capsys):
    commands.cmd_tools(session, [])
    out = capsys.readouterr().out
    assert "nexus.recon.nmap" in out
    assert "nexus.system.status" in out
    assert "nexus.workspace.search" in out
    assert "riesgo=" in out
    assert "scope=" in out


def test_cmd_history_returns_messages(session, capsys):
    commands.cmd_history(session, ["5"])
    out = capsys.readouterr().out
    assert "Escanea 10.0.0.5" in out
    assert "react.action" in out


def test_cmd_clear_rotates_work_session_not_engagement(session, capsys):
    engagement = session.engagement
    durable_conversation = session.conversation_id
    session.history.extend(["[completed] hecho", "└─$ escanea"])

    commands.cmd_clear(session, [])

    out = capsys.readouterr().out
    assert "Contexto local limpiado" in out
    assert "Nueva sesión de trabajo" in out
    assert session.history == []
    assert session.engagement is engagement
    assert session.engagement_id == "eng-scanme"
    assert session.run_id is None and session.conversation_id is None
    # The previous durable record is untouched and a new work session exists.
    assert session.store.list_messages("system", durable_conversation)
    assert len(session.store.list_conversations("system", "omni")) == 2
    assert len(commands._work_conversations(session)) == 1
    assert commands._work_conversations(session)[0]["id"] != durable_conversation


def test_cmd_export_writes_markdown(session, capsys, tmp_path):
    commands.cmd_export(session, [])
    out = capsys.readouterr().out
    assert "Sesión exportada a" in out
    exported = list(tmp_path.glob("omni-session-*.md"))
    assert len(exported) == 1
    content = exported[0].read_text(encoding="utf-8")
    assert content.startswith("# Sesión omni")
    assert "eng-scanme" in content
    assert "Escanea 10.0.0.5" in content


def test_cmd_approvals_empty_when_none_pending(session, capsys):
    commands.cmd_approvals(session, [])
    out = capsys.readouterr().out
    assert "(no hay aprobaciones pendientes)" in out


def test_cmd_help_lists_all_commands(session, capsys):
    commands.cmd_help(session, [])
    out = capsys.readouterr().out
    for name in commands.command_names():
        assert name in out
    assert "/scope" in out and "/tools" in out and "/exit" in out


def test_cmd_exit_signals_loop_to_stop(session, capsys):
    assert session.should_exit is False
    commands.cmd_exit(session, [])
    assert session.should_exit is True
    assert "Cerrando sesión omni" in capsys.readouterr().out


def test_unknown_command_shows_error_not_crash(session, capsys):
    handled = commands.run_command(session, "/definitely-not-a-command")
    out = capsys.readouterr().out
    assert handled is False
    assert "comando desconocido" in out
    assert session.should_exit is False


def test_cmd_with_invalid_args_does_not_crash(session, capsys, tmp_path):
    blocker = tmp_path / "blocker.txt"
    blocker.write_text("not a directory", encoding="utf-8")
    attempts = [
        "/scope --bogus 1 2",
        "/tools extra args",
        "/history not-a-number",
        f"/export {blocker / 'out.md'}",
        "/approvals unexpected",
        "/help whatever",
    ]
    for line in attempts:
        assert commands.run_command(session, line) is True, line
    out = capsys.readouterr().out
    assert "límite inválido" in out
    assert "no se pudo escribir" in out
    assert session.should_exit is False
    assert Path(blocker).exists()
