"""``nexus.session.interact``: command hardening, outcome mapping and audit."""

from __future__ import annotations

import asyncio
from unittest.mock import patch

import pytest

from nexus_core.tests.msf_support import (
    context,
    fake_client,
    gateway,
    gateway_with_approvals,
)
from nexus_core.tools.handlers import msf_session_interact as module

UUID = "sess-1"
ARGS = {"session_uuid": UUID, "command": "id"}


def execute(args=None):
    return asyncio.run(module.msf_session_interact_handler(args or ARGS, context()))


def test_interact_requires_existing_session(monkeypatch):
    client = fake_client(monkeypatch, module)
    client.has_session.return_value = False
    result = execute()
    assert not result.success
    assert result.verification_method == "msf_session_not_found"
    assert result.evidence["session_uuid"] == UUID
    client.run_in_session.assert_not_awaited()


@pytest.mark.parametrize(
    "command",
    ["exit", "exit(0)", "quit", "quit; ", "background", "bg", "detach"],
)
def test_interact_rejects_exit_command(monkeypatch, command):
    client = fake_client(monkeypatch, module)
    with pytest.raises(ValueError) as error:
        execute({**ARGS, "command": command})
    assert "nexus.session.kill" in str(error.value)
    client.run_in_session.assert_not_awaited()


def test_interact_rejects_null_bytes(monkeypatch):
    client = fake_client(monkeypatch, module)
    with pytest.raises(ValueError):
        execute({**ARGS, "command": "id\x00whoami"})
    client.run_in_session.assert_not_awaited()


def test_interact_rejects_invalid_uuid(monkeypatch):
    client = fake_client(monkeypatch, module)
    with pytest.raises(ValueError):
        execute({**ARGS, "session_uuid": "bad uuid"})
    client.run_in_session.assert_not_awaited()


def test_interact_rejects_out_of_range_max_wait(monkeypatch):
    client = fake_client(monkeypatch, module)
    with pytest.raises(ValueError):
        execute({**ARGS, "max_wait_seconds": 400})
    client.run_in_session.assert_not_awaited()


def test_interact_ok_returns_output(monkeypatch):
    client = fake_client(monkeypatch, module)
    client.run_in_session.return_value = {
        "status": "ok",
        "output": "uid=1000(fixture)\n",
        "bytes": 17,
        "duration_seconds": 0.9,
    }
    result = execute()
    assert result.success and result.verified
    assert result.verification_method == "msf_session_interact_ok"
    assert "uid=1000" in result.output["output"]
    # output_bytes is derived from the real output, never trusted from the RPC.
    assert result.evidence == {
        "session_uuid": UUID,
        "command": "id",
        "status": "ok",
        "output_bytes": len("uid=1000(fixture)\n".encode()),
        "duration_seconds": 0.9,
        "raw_sha256": result.evidence["raw_sha256"],
    }
    assert result.evidence["raw_sha256"]


def test_interact_timeout_returns_partial(monkeypatch):
    client = fake_client(monkeypatch, module)
    client.run_in_session.return_value = {
        "status": "timeout",
        "output": "chunk1\n",
        "bytes": 7,
        "duration_seconds": 30.0,
    }
    result = execute({**ARGS, "command": "cat huge.log"})
    assert result.verified and result.success
    assert result.verification_method == "msf_session_interact_timeout"
    assert result.output["output"] == "chunk1\n"
    assert result.evidence["status"] == "timeout"


def test_interact_session_dead_returns_verified_false(monkeypatch):
    client = fake_client(monkeypatch, module)
    client.run_in_session.return_value = {
        "status": "session_dead",
        "output": "",
        "bytes": 0,
        "duration_seconds": 1.0,
    }
    result = execute()
    assert not result.verified and not result.success
    assert result.verification_method == "msf_session_interact_session_dead"


def test_interact_respects_max_wait_from_args(monkeypatch):
    client = fake_client(monkeypatch, module)
    execute({**ARGS, "max_wait_seconds": 42})
    args, kwargs = client.run_in_session.call_args
    assert args[:2] == (UUID, "id")
    assert kwargs["max_wait_seconds"] == 42.0


def _approved_gateway(tmp_path):
    """Gateway with a durable approval the operator already granted."""
    gw, audit, approvals, _ = gateway_with_approvals(tmp_path)
    run_context = context()
    approval = approvals.request(
        run_context, f"execute:tool:{module.msf_session_interact_definition().tool_id}"
    )
    approvals.decide(approval["id"], "system", "operator-test", True, "test approval")
    return gw, audit, run_context, approval["id"]


def test_interact_audits_each_command(tmp_path, monkeypatch):
    fake_client(monkeypatch, module)
    gw, audit, run_context, approval_id = _approved_gateway(tmp_path)
    result = asyncio.run(
        gw.invoke("nexus.session.interact", ARGS, run_context, approval_id=approval_id)
    )
    assert result["success"] is True
    events = [e for e in audit.export("system") if e["resource_id"] == "nexus.session.interact"]
    assert {"tool.invoke", "tool.complete"} <= {event["action"] for event in events}


def test_interact_requires_engagement(tmp_path, monkeypatch):
    from dataclasses import replace
    definition = module.msf_session_interact_definition()
    assert definition.scope_required is True and definition.scope_target_field is None
    assert definition.risk.value == "high"
    client = fake_client(monkeypatch, module)
    gw, _, run_context, approval_id = _approved_gateway(tmp_path)
    with pytest.raises(PermissionError, match="scope"):
        asyncio.run(gw.invoke("nexus.session.interact", ARGS,
                             replace(run_context, scope=None), approval_id=approval_id))
    client.authenticate.assert_not_awaited()


def test_interact_high_risk_needs_approval_in_the_gateway(tmp_path, monkeypatch):
    from nexus_core.kernel.tool_gateway import ToolGateway

    fake_client(monkeypatch, module)
    gw, _ = gateway(tmp_path)
    # No ApprovalService in this gateway: a HIGH tool must be refused outright.
    assert isinstance(gw, ToolGateway)
    with pytest.raises(PermissionError):
        asyncio.run(gw.invoke("nexus.session.interact", ARGS, context()))  # no approval_id


def test_interact_honours_optional_allowlist(monkeypatch):
    client = fake_client(monkeypatch, module)
    monkeypatch.setenv(module.ALLOWLIST_ENV, "whoami, sysinfo")
    execute({**ARGS, "command": "whoami"})
    assert client.run_in_session.await_count == 1
    with pytest.raises(ValueError):
        execute({**ARGS, "command": "rm -rf /"})
    assert module.command_allowlist() == frozenset({"whoami", "sysinfo"})


def test_interact_never_executes_shell(monkeypatch):
    fake_client(monkeypatch, module)
    with (
        patch("subprocess.Popen", side_effect=AssertionError("no subprocess")),
        patch("asyncio.create_subprocess_exec", side_effect=AssertionError("no process")),
    ):
        assert execute().success


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
