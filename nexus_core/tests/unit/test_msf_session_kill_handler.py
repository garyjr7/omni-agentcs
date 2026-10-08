"""``nexus.session.kill``: audited session termination by UUID."""

from __future__ import annotations

import asyncio
from unittest.mock import patch

import pytest

from nexus_core.integrations.metasploit.client import MetasploitUnavailable
from nexus_core.tests.msf_support import context, fake_client, gateway
from nexus_core.tools.handlers import msf_session_kill as module

ARGS = {"session_uuid": "sess-1"}


def execute(args=None):
    return asyncio.run(module.msf_session_kill_handler(args or ARGS, context()))


def test_session_kill_success(monkeypatch):
    client = fake_client(monkeypatch, module)
    result = execute()
    assert result.success and result.verified
    assert result.verification_method == "msf_session_kill_rpc"
    assert result.output == {"session_uuid": "sess-1", "result": "success"}
    client.stop_session.assert_awaited_once_with("sess-1")


@pytest.mark.parametrize("uuid", ["bad uuid", "x" * 65, "sess;drop", ""])
def test_session_kill_invalid_uuid(monkeypatch, uuid):
    client = fake_client(monkeypatch, module)
    with pytest.raises(ValueError):
        execute({"session_uuid": uuid})
    client.stop_session.assert_not_awaited()


def test_session_kill_daemon_unavailable(monkeypatch):
    client = fake_client(monkeypatch, module)
    client.stop_session.side_effect = MetasploitUnavailable("daemon down")
    result = execute()
    assert not result.success
    assert result.verification_method == "msf_rpc_failed"
    assert result.evidence["error_type"] == "MetasploitUnavailable"


def test_session_kill_not_verified_when_rpc_reports_error(monkeypatch):
    client = fake_client(monkeypatch, module)
    client.stop_session.return_value = {"result": "error"}
    result = execute()
    assert not result.success
    assert result.verification_method == "msf_session_kill_rpc"


def test_session_kill_never_executes_shell(monkeypatch):
    fake_client(monkeypatch, module)
    with (
        patch("subprocess.Popen", side_effect=AssertionError("no subprocess")),
        patch("asyncio.create_subprocess_exec", side_effect=AssertionError("no process")),
    ):
        assert execute().success


def test_session_kill_audit_event(tmp_path, monkeypatch):
    fake_client(monkeypatch, module)
    gw, audit = gateway(tmp_path)
    result = asyncio.run(gw.invoke("nexus.session.kill", ARGS, context()))
    assert result["success"] is True
    events = [e for e in audit.export("system") if e["resource_id"] == "nexus.session.kill"]
    actions = {event["action"] for event in events}
    assert {"tool.invoke", "tool.complete"} <= actions
    assert all(event["decision"] == "allow" for event in events)
    assert module.msf_session_kill_definition().risk.value == "medium"


@pytest.fixture(autouse=True)
def _owned_context(tmp_path, monkeypatch):
    from dataclasses import replace
    from nexus_core.kernel.control_store import ControlStore
    from nexus_core.kernel.sessions import SessionRegistry
    from nexus_core.tests.msf_support import context as base_context, scope

    store = ControlStore(tmp_path / "ownership.db")
    store.initialize()
    def owned_context(engagement=None):
        ctx = replace(base_context(engagement or scope()), store=store)
        for uuid in ("sess-1", "sess-2"):
            registry = SessionRegistry(store)
            if registry.get("system", uuid) is None:
                registry.register(session_uuid=uuid, tenant_id="system",
                    engagement_id=ctx.scope.engagement_id, run_id=ctx.run_id,
                    session_type="shell", target_host="203.0.113.10", opened_by_tool="fixture")
        return ctx
    monkeypatch.setitem(globals(), "context", owned_context)


# This module's unsigned scopes exercise targeting/session behavior. Authentication
# is covered separately in test_scope_governed_mode with the governed default.
pytestmark = globals().get("pytestmark", [])
if not isinstance(pytestmark, list):
    pytestmark = [pytestmark]
pytestmark.append(pytest.mark.usefixtures("lab_scope"))
