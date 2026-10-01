"""Stateful REPL: attach/detach, prompt, routing and dead-session detection.

The daemon is never contacted: ``nexus_core.cli.session.fetch_sessions`` is
patched with a deterministic session listing.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest import mock

import pytest

from nexus_core.cli import commands as commands_module
from nexus_core.cli import session as session_module
from nexus_core.cli.session import OmniSession
from nexus_core.kernel.control_store import ControlStore
from nexus_core.scope import EngagementScope, EngagementStore

TENANT = "system"
UUID = "sess-1"
SESSIONS = {
    3: {
        "uuid": UUID,
        "type": "meterpreter",
        "tunnel_peer": "10.0.0.5:51234",
        "session_host": "10.0.0.5",
        "via_exploit": "exploit/windows/smb/ms17_010_eternalblue",
        "username": "NT AUTHORITY\\SYSTEM",
    }
}


class Feed:
    """Deterministic ``input()`` that replays a script and records prompts."""

    def __init__(self, answers: list[str]) -> None:
        self.answers = list(answers)
        self.prompts: list[str] = []

    def __call__(self, prompt: str = "") -> str:
        self.prompts.append(prompt)
        if not self.answers:
            raise EOFError
        return self.answers.pop(0)


def _iso(delta: timedelta) -> str:
    return (datetime.now(timezone.utc) + delta).isoformat()


@pytest.fixture()
def session(tmp_path) -> OmniSession:
    store = ControlStore(tmp_path / "stateful.db")
    store.initialize()
    scope = EngagementStore(store).create(
        EngagementScope(
            engagement_id="eng-1",
            tenant_id=TENANT,
            name="lab",
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
    )
    run = store.create_run(TENANT, {})
    value = OmniSession(
        store=store,
        tenant_id=TENANT,
        engagement=scope,
        llm_client=None,
        max_iterations=2,
        operator_id="operator:tester",
    )
    value.run_id = str(run["id"])
    from nexus_core.kernel.sessions import SessionRegistry
    for record in SESSIONS.values():
        SessionRegistry(store).register(session_uuid=record['uuid'], tenant_id=TENANT,
            engagement_id=value.engagement.engagement_id, run_id=value.run_id,
            session_type=record['type'], target_host=record['session_host'], opened_by_tool='fixture')
    return value


@pytest.fixture()
def daemon(monkeypatch):
    """Patch the session listing; the returned dict can be mutated per test."""
    state = {"sessions": SESSIONS}
    monkeypatch.setattr(
        session_module, "fetch_sessions", lambda: state["sessions"]
    )
    return state


def test_attach_sets_active_uuid_and_prompt(session, daemon, capsys):
    assert session.attach_session(UUID) is True
    out = capsys.readouterr().out
    assert session.active_session_uuid == UUID
    assert session.active_session_info["type"] == "meterpreter"
    assert session.session_started_at is not None
    assert "Attached to session sess-1" in out
    assert "[session sess-1/meterpreter]" in session.prompt


def test_detach_clears_active_uuid(session, daemon, capsys):
    session.attach_session(UUID)
    capsys.readouterr()
    assert session.detach_session() == UUID
    assert session.active_session_uuid is None
    assert session.active_session_info is None
    assert session.session_started_at is None
    assert "[session" not in session.prompt
    assert "Detached from session sess-1" in capsys.readouterr().out


def test_attach_unknown_uuid_shows_error(session, daemon, capsys):
    assert session.attach_session("nope") is False
    assert session.active_session_uuid is None
    assert "sesión no encontrada: nope" in capsys.readouterr().out


def test_attach_without_daemon_shows_error(session, monkeypatch, capsys):
    monkeypatch.setattr(session_module, "fetch_sessions", lambda: None)
    assert session.attach_session(UUID) is False
    assert "no se pudo consultar msfrpcd" in capsys.readouterr().out


def test_commands_route_to_session_when_attached(session, daemon, monkeypatch):
    session.attach_session(UUID)
    feed = Feed(["id", "/exit"])
    session.input_reader = feed
    with (
        mock.patch.object(OmniSession, "run_session_command", return_value=True) as routed,
        mock.patch.object(OmniSession, "run_objective") as objective,
    ):
        session.run_repl()
    routed.assert_called_once_with("id")
    objective.assert_not_called()


def test_meta_commands_still_work_when_attached(session, daemon, monkeypatch):
    session.attach_session(UUID)
    session.input_reader = Feed(["/scope", "/exit"])
    with (
        mock.patch.object(commands_module, "run_command") as run_command,
        mock.patch.object(OmniSession, "run_session_command") as routed,
    ):
        session.run_repl()
    # Both meta lines were handled as Omni commands, never sent to the session.
    assert [call.args[1] for call in run_command.call_args_list] == ["/scope", "/exit"]
    routed.assert_not_called()


def test_objectives_route_to_react_when_not_attached(session, daemon, monkeypatch):
    session.input_reader = Feed(["escanea el host", "/exit"])
    with (
        mock.patch.object(OmniSession, "run_objective") as objective,
        mock.patch.object(OmniSession, "run_session_command") as routed,
    ):
        session.run_repl()
    objective.assert_called_once_with("escanea el host")
    routed.assert_not_called()


def test_detach_when_not_attached_noop(session, daemon, capsys):
    assert session.detach_session() is None
    commands_module.cmd_detach(session, [])
    assert "(no había sesión activa)" in capsys.readouterr().out


def test_kill_session_clears_active_if_same(session, daemon, monkeypatch, capsys):
    session.attach_session(UUID)
    session.input_reader = Feed(["y"])
    capsys.readouterr()
    with mock.patch.object(
        OmniSession, "invoke_tool", return_value={"output": {"success": True}}
    ) as invoke:
        commands_module.cmd_kill_session(session, [])
    invoke.assert_called_once_with("nexus.session.kill", {"session_uuid": UUID})
    assert session.active_session_uuid is None
    assert "Sesión sess-1 terminada." in capsys.readouterr().out


def test_kill_session_when_not_attached_lists_sessions(session, daemon, capsys):
    commands_module.cmd_kill_session(session, [])
    out = capsys.readouterr().out
    assert "no hay sesión activa" in out
    assert "sess-1" in out


def test_session_list_empty_output(session, daemon, capsys):
    daemon["sessions"] = {}
    commands_module.cmd_sessions(session, [])
    assert "(no hay sesiones activas)" in capsys.readouterr().out


def test_session_death_detected_on_prompt_return(session, daemon, capsys):
    session.attach_session(UUID)
    capsys.readouterr()
    daemon["sessions"] = {}
    assert session.check_active_session() is False
    assert session.active_session_uuid is None
    out = capsys.readouterr().out
    assert "ya no está activa" in out
    assert "[session" not in session.prompt


def test_prompt_includes_session_uuid_and_type(session, daemon):
    session.attach_session(UUID)
    prompt = session.prompt
    assert "[session sess-1/meterpreter]" in prompt
    assert prompt.endswith("└─$ ")


def test_trust_mode_flag_still_shown_in_session_mode(session, daemon):
    session.attach_session(UUID)
    session.trust_mode = True
    prompt = session.prompt
    assert "[TRUST MODE]" in prompt and "[session sess-1/meterpreter]" in prompt


def test_session_command_audits_engagement_and_outcome(session, daemon):
    session.attach_session(UUID)
    with mock.patch.object(
        OmniSession,
        "invoke_tool",
        return_value={
            "output": {"success": True, "status": "ok", "output": "uid=0(root)\n"}
        },
    ):
        assert session.run_session_command("id") is True
    assert session.session_commands_sent == 1
    from nexus_core.kernel.audit import AuditWriter

    events = [
        event
        for event in AuditWriter(session.store).export(TENANT)
        if event["action"] == "session.command"
    ]
    assert len(events) == 1
    payload = events[0]["payload"]
    assert payload["engagement_id"] == "eng-1"
    assert payload["session_uuid"] == UUID
    assert payload["command"] == "id"
    assert payload["outcome"] == "ok"
    assert events[0]["resource_type"] == "session"


def test_session_command_denied_is_audited_as_deny(session, daemon):
    session.attach_session(UUID)
    with mock.patch.object(OmniSession, "invoke_tool", return_value=None):
        assert session.run_session_command("hashdump") is True
    from nexus_core.kernel.audit import AuditWriter

    events = [
        event
        for event in AuditWriter(session.store).export(TENANT)
        if event["action"] == "session.command"
    ]
    assert events[0]["decision"] == "deny"
    assert events[0]["payload"]["outcome"] == "denied"
    assert session.session_commands_sent == 0


def test_session_command_reports_dead_session_and_detaches(session, daemon, capsys):
    session.attach_session(UUID)
    capsys.readouterr()
    with mock.patch.object(
        OmniSession,
        "invoke_tool",
        return_value={"output": {"success": False, "status": "session_dead"}},
    ):
        session.run_session_command("id")
    assert session.active_session_uuid is None
    assert "ya no está activa" in capsys.readouterr().out


def test_invoke_tool_denies_when_operator_refuses(session, daemon, capsys):
    """The governed path asks the operator before running a HIGH-risk tool."""
    session.attach_session(UUID)
    capsys.readouterr()
    with mock.patch.object(
        session_module,
        "_operator_approval_gate",
        return_value={"status": "denied_by_operator", "reason": "user denied"},
    ):
        assert session.invoke_tool("nexus.session.interact", {"command": "id"}) is None
    assert "denegado por el operador" in capsys.readouterr().out
