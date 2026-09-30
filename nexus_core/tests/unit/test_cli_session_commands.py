"""Session meta commands: /sessions, /session, /detach and /kill-session."""

from __future__ import annotations

from unittest import mock

import pytest

from nexus_core.cli import commands as commands_module
from nexus_core.cli import session as session_module
from nexus_core.cli.session import OmniSession
from nexus_core.kernel.control_store import ControlStore

TENANT = "system"
UUID = "sess-1"
OTHER = "sess-2"
SESSIONS = {
    3: {
        "uuid": UUID,
        "type": "meterpreter",
        "tunnel_peer": "10.0.0.5:51234",
        "session_host": "10.0.0.5",
        "via_exploit": "exploit/windows/smb/ms17_010_eternalblue",
        "username": "NT AUTHORITY\\SYSTEM",
    },
    4: {
        "uuid": OTHER,
        "type": "shell",
        "tunnel_peer": "10.0.0.7:49123",
        "session_host": "10.0.0.7",
        "via_exploit": "exploit/multi/handler",
        "username": "root",
    },
}


class Feed:
    def __init__(self, answers: list[str]) -> None:
        self.answers = list(answers)
        self.prompts: list[str] = []

    def __call__(self, prompt: str = "") -> str:
        self.prompts.append(prompt)
        return self.answers.pop(0) if self.answers else ""


@pytest.fixture()
def session(tmp_path) -> OmniSession:
    store = ControlStore(tmp_path / "commands.db")
    store.initialize()
    value = OmniSession(store=store, tenant_id=TENANT, operator_id="operator:tester")
    value.run_id = str(store.create_run(TENANT, {})["id"])
    return value


@pytest.fixture()
def daemon(monkeypatch):
    state = {"sessions": SESSIONS}
    monkeypatch.setattr(session_module, "fetch_sessions", lambda: state["sessions"])
    return state


def _kill_ok(*_args, **_kwargs):
    return {"output": {"success": True, "verification_method": "msf_session_kill_rpc"}}


def test_cmd_sessions_renders_table(session, daemon, capsys):
    commands_module.cmd_sessions(session, [])
    out = capsys.readouterr().out
    assert "Active Metasploit sessions:" in out
    for header in ("UUID", "Type", "Peer", "Via", "User"):
        assert header in out
    assert "sess-1" in out and "meterpreter" in out
    assert "10.0.0.5:51234" in out and "ms17_010_eternalblue" in out
    assert "sess-2" in out and "root" in out


def test_cmd_sessions_reports_unreachable_daemon(session, monkeypatch, capsys):
    monkeypatch.setattr(session_module, "fetch_sessions", lambda: None)
    commands_module.cmd_sessions(session, [])
    assert "no se pudo consultar msfrpcd" in capsys.readouterr().out


def test_cmd_session_attach(session, daemon, capsys):
    commands_module.cmd_session(session, ["attach", UUID])
    out = capsys.readouterr().out
    assert session.active_session_uuid == UUID
    assert "Attached to session sess-1 (meterpreter)" in out
    assert "NT AUTHORITY\\SYSTEM" in out


def test_cmd_session_attach_requires_uuid(session, daemon, capsys):
    commands_module.cmd_session(session, ["attach"])
    assert session.active_session_uuid is None
    assert "uso: /session attach <uuid>" in capsys.readouterr().out


def test_cmd_session_info_without_args(session, daemon, capsys):
    commands_module.cmd_session(session, [])
    assert "sin sesión activa" in capsys.readouterr().out
    session.attach_session(UUID)
    capsys.readouterr()
    commands_module.cmd_session(session, ["info"])
    assert "Attached to session sess-1" in capsys.readouterr().out


def test_cmd_session_unknown_subcommand(session, daemon, capsys):
    commands_module.cmd_session(session, ["frobnicate"])
    assert "subcomando desconocido" in capsys.readouterr().out


def test_cmd_kill_session_with_uuid(session, daemon, capsys):
    session.input_reader = Feed(["y"])
    with mock.patch.object(OmniSession, "invoke_tool", side_effect=_kill_ok) as invoke:
        commands_module.cmd_kill_session(session, [UUID])
    out = capsys.readouterr().out
    assert "Kill session sess-1" in out
    assert "Sesión sess-1 terminada." in out
    invoke.assert_called_once_with("nexus.session.kill", {"session_uuid": UUID})


def test_cmd_kill_session_without_uuid_prompts(session, daemon, capsys):
    session.attach_session(UUID)
    session.input_reader = Feed(["e"])
    capsys.readouterr()
    with mock.patch.object(OmniSession, "invoke_tool", side_effect=_kill_ok) as invoke:
        commands_module.cmd_kill_session(session, [])
    out = capsys.readouterr().out
    assert "[Y] Yes  [N] No  [E] Kill all sessions" in out
    assert invoke.call_count == 2  # "e" kills every known session
    assert session.active_session_uuid is None


def test_cmd_kill_session_cancelled(session, daemon, capsys):
    session.input_reader = Feed(["n"])
    with mock.patch.object(OmniSession, "invoke_tool") as invoke:
        commands_module.cmd_kill_session(session, [UUID])
    invoke.assert_not_called()
    assert "cancelado" in capsys.readouterr().out


def test_cmd_kill_session_without_target_lists_sessions(session, daemon, capsys):
    commands_module.cmd_kill_session(session, [])
    out = capsys.readouterr().out
    assert "no hay sesión activa; indica un uuid" in out
    assert "sess-1" in out


def test_cmd_kill_session_reports_failure(session, daemon, capsys):
    session.input_reader = Feed(["y"])
    with mock.patch.object(
        OmniSession,
        "invoke_tool",
        return_value={"output": {"success": False, "verification_method": "msf_rpc_failed"}},
    ):
        commands_module.cmd_kill_session(session, [UUID])
    assert "no se pudo terminar sess-1" in capsys.readouterr().out


def test_cmd_detach_idempotent(session, daemon, capsys):
    session.attach_session(UUID)
    capsys.readouterr()
    commands_module.cmd_detach(session, [])
    assert "Detached from session sess-1" in capsys.readouterr().out
    assert session.active_session_uuid is None
    commands_module.cmd_detach(session, [])
    assert "(no había sesión activa)" in capsys.readouterr().out
    assert session.active_session_uuid is None


def test_detach_survives_unreachable_daemon(session, monkeypatch, capsys):
    """Detaching is local state; an unreachable daemon must not block it."""
    session.active_session_uuid = UUID
    monkeypatch.setattr(session_module, "fetch_sessions", lambda: None)
    commands_module.cmd_detach(session, [])
    assert session.active_session_uuid is None


def test_sessions_command_registered():
    for name in ("/sessions", "/session", "/detach", "/kill-session"):
        assert name in commands_module.COMMANDS
