"""REPL session mode for Sliver: prompt prefix, routing and meta commands.

No team server is contacted: ``fetch_sliver_sessions`` / ``invoke_tool`` are
patched with deterministic stand-ins.
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
SLIVER_ID = "slv-1"

SLIVER_RECORD = {
    "session_id": SLIVER_ID,
    "kind": "session",
    "uuid": SLIVER_ID,
    "type": "session",
    "hostname": "victim",
    "remote_address": "10.0.0.5:5555",
    "username": "root",
    "target_host": "10.0.0.5:5555",
}


def _iso(delta: timedelta) -> str:
    return (datetime.now(timezone.utc) + delta).isoformat()


@pytest.fixture()
def session(tmp_path) -> OmniSession:
    store = ControlStore(tmp_path / "cli-sliver.db")
    store.initialize()
    scope = EngagementStore(store).create(
        EngagementScope(
            engagement_id="eng-sliver",
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
    value = OmniSession(
        store=store,
        tenant_id=TENANT,
        engagement=scope,
        llm_client=None,
        max_iterations=1,
        operator_id="operator:tester",
    )
    value.run_id = str(store.create_run(TENANT, {})["id"])
    return value


def _attach(session: OmniSession) -> None:
    session.active_session_uuid = SLIVER_ID
    session.active_session_info = dict(SLIVER_RECORD)
    session.active_session_backend = session_module.SESSION_BACKEND_SLIVER


def test_prompt_shows_sliver_prefix(session):
    _attach(session)
    assert f"[sliver:{SLIVER_ID}/session]" in session.prompt
    assert "[session slv-1" not in session.prompt


def test_default_prompt_still_msf(session):
    session.active_session_uuid = "sess-1"
    session.active_session_info = {"uuid": "sess-1", "type": "meterpreter"}
    assert "[session sess-1/meterpreter]" in session.prompt


def test_attach_sliver_sets_backend(session):
    with mock.patch.object(
        OmniSession, "fetch_sliver_sessions", return_value={SLIVER_ID: dict(SLIVER_RECORD)}
    ):
        assert session.attach_sliver_session(SLIVER_ID) is True
    assert session.active_session_backend == session_module.SESSION_BACKEND_SLIVER
    assert session.active_session_uuid == SLIVER_ID
    assert f"[sliver:{SLIVER_ID}/session]" in session.prompt


def test_attach_sliver_unknown_session(session):
    with mock.patch.object(OmniSession, "fetch_sliver_sessions", return_value={}):
        assert session.attach_sliver_session("nope") is False
    assert session.active_session_backend == session_module.SESSION_BACKEND_MSF


def test_detach_resets_backend(session):
    _attach(session)
    session.detach_session(notify=False)
    assert session.active_session_backend == session_module.SESSION_BACKEND_MSF
    assert session.active_session_uuid is None


def test_run_session_command_routes_to_sliver_exec(session):
    _attach(session)
    # Real ``invoke_tool`` shape: the handler payload nests under output.output.
    payload = {
        "tool_id": "nexus.c2.sliver_exec",
        "output": {
            "success": True,
            "verification_method": "sliver_exec_ok",
            "output": {"status": "ok", "stdout": "uid=0\n"},
        },
    }
    with mock.patch.object(OmniSession, "invoke_tool", return_value=payload) as invoke:
        assert session.run_session_command("id") is True
    invoke.assert_called_once_with(
        "nexus.c2.sliver_exec",
        {"session_id": SLIVER_ID, "command": "id", "kind": "session"},
    )


def test_check_active_session_detaches_dead_sliver(session):
    _attach(session)
    with mock.patch.object(OmniSession, "fetch_sliver_sessions", return_value={}):
        assert session.check_active_session() is False
    assert session.active_session_uuid is None
    assert session.active_session_backend == session_module.SESSION_BACKEND_MSF


def test_cmd_sessions_sliver_lists(session, capsys):
    with mock.patch.object(
        OmniSession, "fetch_sliver_sessions", return_value={SLIVER_ID: dict(SLIVER_RECORD)}
    ) as fetch:
        assert commands_module.run_command(session, "/sessions --sliver") is True
    fetch.assert_called_once()
    output = capsys.readouterr().out
    assert "Active Sliver sessions" in output
    assert SLIVER_ID in output


def test_cmd_sliver_reports_version(session, capsys):
    payload = {
        "tool_id": "nexus.c2.sliver_server",
        "output": {
            "success": True,
            "verification_method": "sliver_server_ok",
            "output": {
                "version": "1.6.2",
                "operators_count": 1,
                "jobs_count": 2,
                "operators": [{"name": "nexus", "online": True}],
            },
        },
    }
    with mock.patch.object(OmniSession, "invoke_tool", return_value=payload) as invoke:
        commands_module.run_command(session, "/sliver")
    invoke.assert_called_once_with("nexus.c2.sliver_server", {})
    output = capsys.readouterr().out
    assert "Sliver 1.6.2" in output
    assert "nexus (online)" in output


def test_cmd_sliver_reports_unavailable(session, capsys):
    payload = {
        "tool_id": "nexus.c2.sliver_server",
        "output": {
            "success": False,
            "verification_method": "sliver_unavailable",
            "output": {},
        },
    }
    with mock.patch.object(OmniSession, "invoke_tool", return_value=payload):
        commands_module.run_command(session, "/sliver")
    assert "no está disponible" in capsys.readouterr().out


def test_cmd_implants_lists_counts(session, capsys):
    payload = {
        "tool_id": "nexus.c2.sliver_implants",
        "output": {
            "success": True,
            "verification_method": "sliver_implants_ok",
            "output": {
                "builds": {"beacon-x": {"Name": "beacon-x"}},
                "profiles": [{"Name": "windows-beacon"}],
                "builds_count": 1,
                "profiles_count": 1,
            },
        },
    }
    with mock.patch.object(OmniSession, "invoke_tool", return_value=payload):
        commands_module.run_command(session, "/implants")
    output = capsys.readouterr().out
    assert "Builds: 1" in output
    assert "beacon-x" in output
    assert "windows-beacon" in output
