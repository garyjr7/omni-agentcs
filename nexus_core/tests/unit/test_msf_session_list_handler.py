"""``nexus.session.list``: read-only session inventory, no engagement needed."""

from __future__ import annotations

import asyncio

import pytest

from nexus_core.integrations.metasploit.client import MetasploitUnavailable
from nexus_core.tests.msf_support import context, fake_client, gateway
from nexus_core.tools.handlers import msf_session_list as module

METERPRETER = {
    "type": "meterpreter",
    "tunnel_local": "203.0.113.10:4444",
    "tunnel_peer": "203.0.113.10:41234",
    "via_exploit": "exploit/windows/smb/ms17_010_eternalblue",
    "via_payload": "windows/x64/meterpreter/reverse_tcp",
    "session_host": "203.0.113.10",
    "session_port": 445,
    "uuid": "sess-1",
}
SHELL = {
    "type": "shell",
    "tunnel_local": "203.0.113.11:4444",
    "tunnel_peer": "203.0.113.11:51234",
    "via_exploit": "exploit/multi/script/web_delivery",
    "via_payload": "cmd/unix/reverse",
    "session_host": "203.0.113.11",
    "session_port": 8080,
    "uuid": "sess-2",
}


def execute(args=None):
    return asyncio.run(module.msf_session_list_handler(args or {}, context()))


def test_session_list_returns_all(monkeypatch):
    client = fake_client(monkeypatch, module)
    client.list_sessions.return_value = {"sess-1": METERPRETER, "sess-2": SHELL}
    result = execute()
    assert result.success
    assert result.output["count"] == 2 and result.output["total"] == 2
    assert result.output["sessions"][0]["uuid"] == "sess-1"
    assert result.output["sessions"][1]["type"] == "shell"
    assert result.evidence["raw_sha256"] == result.output["raw_sha256"]


def test_session_list_filters_by_type(monkeypatch):
    client = fake_client(monkeypatch, module)
    client.list_sessions.return_value = {"sess-1": METERPRETER, "sess-2": SHELL}
    result = execute({"filter_type": "shell"})
    assert result.output["count"] == 1 and result.output["total"] == 2
    assert [s["uuid"] for s in result.output["sessions"]] == ["sess-2"]
    assert execute({"filter_type": "meterpreter"}).output["count"] == 1
    assert execute({"filter_type": "all"}).output["count"] == 2


def test_session_list_empty(monkeypatch):
    fake_client(monkeypatch, module)
    result = execute()
    assert result.success and result.output["count"] == 0
    assert result.output["sessions"] == []


def test_session_list_requires_engagement(tmp_path, monkeypatch):
    from dataclasses import replace
    definition = module.msf_session_list_definition()
    assert definition.scope_required is True and definition.scope_target_field is None
    client = fake_client(monkeypatch, module)
    gw, audit = gateway(tmp_path)
    with pytest.raises(PermissionError, match="scope"):
        asyncio.run(gw.invoke("nexus.session.list", {}, replace(context(), scope=None)))
    client.authenticate.assert_not_awaited()
    assert any(e["action"] == "scope.denied" for e in audit.export("system"))


def test_session_list_fail_closed_when_daemon_down(monkeypatch):
    client = fake_client(monkeypatch, module)
    client.list_sessions.side_effect = MetasploitUnavailable("down")
    result = execute()
    assert not result.success
    assert result.verification_method == "msf_rpc_failed"


def test_session_list_rejects_unknown_filter(monkeypatch):
    fake_client(monkeypatch, module)
    with pytest.raises(ValueError):
        execute({"filter_type": "rootkit"})


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
