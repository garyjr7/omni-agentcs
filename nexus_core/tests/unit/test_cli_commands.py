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


def test_cmd_plan_renders_phases(session, capsys):
    commands.cmd_plan(session, [])
    out = capsys.readouterr().out
    assert "PLAN DE ENGAGEMENT" in out
    assert "Reconocimiento" in out
    assert "fase actual" in out


def test_cmd_panel_toggles_panel(session, capsys):
    commands.cmd_panel(session, ["on"])
    assert "panel de plan: ON" in capsys.readouterr().out
    commands.cmd_panel(session, ["off"])
    assert "panel de plan: OFF" in capsys.readouterr().out


def test_cmd_panel_rejects_bad_argument(session, capsys):
    commands.cmd_panel(session, ["maybe"])
    assert "uso: /panel" in capsys.readouterr().out


def test_cmd_expand_toggles_tool_cards(session, capsys):
    commands.cmd_expand(session, ["on"])
    assert "tarjetas de tool: expandidas" in capsys.readouterr().out
    assert session._tui.expand_cards is True
    commands.cmd_expand(session, ["off"])
    assert "tarjetas de tool: plegadas" in capsys.readouterr().out
    assert session._tui.expand_cards is False


def test_cmd_expand_rejects_bad_argument(session, capsys):
    commands.cmd_expand(session, ["maybe"])
    assert "uso: /expand" in capsys.readouterr().out


def test_cmd_playbook_lists_applicable(session, capsys):
    from nexus_core.kernel.blackboard import Blackboard

    Blackboard(session.store).record(
        tenant_id="system", engagement_id=session.engagement_id, fact_type="service",
        key="10.0.0.5:21/tcp", value={"port": 21, "product": "vsftpd"},
        source="test", created_by="tester",
    )
    commands.cmd_playbook(session, [])
    out = capsys.readouterr().out
    assert "ftp_anon_to_cred" in out and "siguiente" in out


def test_cmd_playbook_show_prints_steps(session, capsys):
    commands.cmd_playbook(session, ["show", "linux_privesc"])
    out = capsys.readouterr().out
    assert "linux_privesc" in out and "enum_system" in out


def test_cmd_playbook_show_unknown(session, capsys):
    commands.cmd_playbook(session, ["show", "nope"])
    assert "playbook desconocido" in capsys.readouterr().out


def test_cmd_loot_fail_closed_without_sliver(session, capsys, monkeypatch):
    monkeypatch.delenv("SLIVER_OPERATOR_CONFIG", raising=False)
    commands.cmd_loot(session, [])
    out = capsys.readouterr().out
    assert "sliver_loot" in out and "sliver_auth_missing" in out


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


def test_cmd_facts_lists_recorded_facts(session, capsys):
    from nexus_core.kernel.blackboard import Blackboard

    Blackboard(session.store).record(
        tenant_id="system",
        engagement_id=session.engagement_id,
        fact_type="service",
        key="10.0.0.5:21/tcp",
        value={"port": 21},
        source="nexus.recon.nmap",
        created_by="operator:tester",
    )
    commands.cmd_facts(session, [])
    out = capsys.readouterr().out
    assert "[service]" in out
    assert "10.0.0.5:21/tcp" in out
    assert "Resumen:" in out


def test_cmd_facts_empty_engagement(session, capsys):
    commands.cmd_facts(session, [])
    assert "sin hechos registrados" in capsys.readouterr().out


def test_cmd_facts_rejects_unknown_type(session, capsys):
    commands.cmd_facts(session, ["bogus"])
    assert "tipo desconocido" in capsys.readouterr().out


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


# This module's unsigned scopes exercise targeting/session behavior. Authentication
# is covered separately in test_scope_governed_mode with the governed default.
pytestmark = globals().get("pytestmark", [])
if not isinstance(pytestmark, list):
    pytestmark = [pytestmark]
pytestmark.append(pytest.mark.usefixtures("lab_scope"))


def test_razonamiento_exports_only_this_run(tmp_path, monkeypatch, capsys):
    """/razonamiento writes the current run's durable thoughts, in order."""
    from types import SimpleNamespace

    from nexus_core.cli import commands

    messages = [
        {"run_id": "run-1", "created_at": "2026-11-03T10:00:00Z",
         "metadata": {"kind": "react.action", "thought": "primero enumero el 445"}},
        {"run_id": "run-1", "created_at": "2026-11-03T10:01:00Z",
         "metadata": {"kind": "react.action", "thought": "luego ataco la web"}},
        {"run_id": "run-2", "created_at": "2026-11-03T10:02:00Z",
         "metadata": {"kind": "react.action", "thought": "otro run"}},
        {"run_id": "run-1", "metadata": {"kind": "react.observation"}},
    ]
    session = SimpleNamespace(
        store=SimpleNamespace(list_messages=lambda *a, **k: messages),
        tenant_id="system", conversation_id="conversation", run_id="run-1",
        use_tui=False, no_color=True,
    )
    monkeypatch.chdir(tmp_path)
    commands.cmd_razonamiento(session, [])
    text = (tmp_path / "reports" / "run-1" / "reasoning.md").read_text(encoding="utf-8")
    assert "primero enumero el 445" in text and "luego ataco la web" in text
    assert text.index("primero enumero") < text.index("luego ataco")
    assert "otro run" not in text
    assert "razonamiento exportado" in capsys.readouterr().out


def test_razonamiento_reports_a_run_without_reasoning(tmp_path, monkeypatch, capsys):
    from types import SimpleNamespace

    from nexus_core.cli import commands

    session = SimpleNamespace(
        store=SimpleNamespace(list_messages=lambda *a, **k: []),
        tenant_id="system", conversation_id="conversation", run_id="run-1",
        use_tui=False, no_color=True,
    )
    monkeypatch.chdir(tmp_path)
    commands.cmd_razonamiento(session, [])
    assert "no tiene razonamiento" in capsys.readouterr().out
    assert not (tmp_path / "reports").exists()
