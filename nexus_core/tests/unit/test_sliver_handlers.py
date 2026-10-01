"""Sliver durable handlers: fail-closed, engagement binding and hardening."""

from __future__ import annotations

import asyncio
import inspect
from pathlib import Path
from unittest.mock import patch

import pytest

from nexus_core.integrations.sliver.client import SliverUnavailable
from nexus_core.kernel.sessions import SessionRegistry
from nexus_core.tests.sliver_support import (
    context,
    fake_client,
    gateway,
    gateway_with_approvals,
    owned_context,
    session_record,
)
from nexus_core.tools.handlers import (
    sliver_exec,
    sliver_implants,
    sliver_pivot,
    sliver_server,
    sliver_sessions,
)

SERVER_TOOL = "nexus.c2.sliver_server"
EXEC_TOOL = "nexus.c2.sliver_exec"
PIVOT_TOOL = "nexus.c2.sliver_pivot"

HANDLER_MODULES = (sliver_server, sliver_implants, sliver_sessions, sliver_exec, sliver_pivot)


# --------------------------------------------------------------- server
def test_server_fail_closed_when_unavailable(monkeypatch):
    client = fake_client(monkeypatch)
    client.connect.side_effect = SliverUnavailable("down")
    result = asyncio.run(sliver_server.sliver_server_handler({}, context()))
    assert not result.success
    assert result.verification_method == "sliver_unavailable"
    assert result.evidence["error_type"] == "SliverUnavailable"
    client.disconnect.assert_awaited_once()


def test_server_fail_closed_without_operator_config(monkeypatch):
    monkeypatch.delenv("SLIVER_OPERATOR_CONFIG", raising=False)
    result = asyncio.run(sliver_server.sliver_server_handler({}, context()))
    assert not result.success
    assert result.verification_method == "sliver_auth_missing"


def test_server_returns_version_on_success(monkeypatch):
    fake_client(monkeypatch)
    result = asyncio.run(sliver_server.sliver_server_handler({}, context()))
    assert result.success and result.verified
    assert result.verification_method == "sliver_server_ok"
    assert result.output["version"] == "1.6.2-abc123"
    assert result.output["operators_count"] == 1
    assert result.evidence["jobs_count"] == 1


# --------------------------------------------------------------- implants
def test_implants_lists_builds(monkeypatch):
    client = fake_client(monkeypatch)
    client.list_implant_builds.return_value = {"beacon-x": {"Name": "beacon-x"}}
    result = asyncio.run(
        sliver_implants.sliver_implants_handler({"kind": "builds"}, context())
    )
    assert result.success
    assert result.output["builds_count"] == 1
    assert result.output["profiles"] == []
    client.list_implant_profiles.assert_not_awaited()


def test_implants_lists_profiles(monkeypatch):
    client = fake_client(monkeypatch)
    client.list_implant_profiles.return_value = [{"Name": "windows-beacon"}]
    result = asyncio.run(
        sliver_implants.sliver_implants_handler({"kind": "profiles"}, context())
    )
    assert result.output["profiles_count"] == 1
    assert result.output["builds"] == {}
    client.list_implant_builds.assert_not_awaited()


# --------------------------------------------------------------- sessions
def test_sessions_requires_scope(monkeypatch):
    fake_client(monkeypatch)
    assert sliver_sessions.sliver_sessions_definition().scope_required is True
    result = asyncio.run(sliver_sessions.sliver_sessions_handler({}, context()))
    assert not result.success
    assert result.verification_method == "session_scope_required"


def test_sessions_filters_by_engagement(tmp_path, monkeypatch):
    client = fake_client(monkeypatch)
    run_context, _ = owned_context(
        tmp_path,
        register=[
            {"id": "mine", "target_host": "203.0.113.10"},
            {"id": "theirs", "engagement_id": "eng-other"},
        ],
    )
    client.list_sessions.return_value = [session_record("mine"), session_record("theirs")]
    result = asyncio.run(
        sliver_sessions.sliver_sessions_handler({"kind": "sessions"}, run_context)
    )
    assert result.success
    assert [item["session_id"] for item in result.output["sessions"]] == ["mine"]
    assert result.evidence["total_seen"] == 2


def test_sessions_registers_new_in_kernel_sessions(tmp_path, monkeypatch):
    client = fake_client(monkeypatch)
    run_context, store = owned_context(tmp_path)
    client.list_sessions.return_value = [
        session_record("fresh", remote_address="203.0.113.55:5555")
    ]
    result = asyncio.run(sliver_sessions.sliver_sessions_handler({}, run_context))
    assert result.success and result.evidence["registered"] == 1
    record = SessionRegistry(store).get("system", "fresh")
    assert record is not None
    assert record["engagement_id"] == run_context.scope.engagement_id
    assert record["session_type"] == "sliver:session"
    assert record["target_host"] == "203.0.113.55"
    assert record["opened_by_tool"] == "nexus.c2.sliver_sessions"


def test_sessions_hides_out_of_scope_peer(tmp_path, monkeypatch):
    client = fake_client(monkeypatch)
    run_context, _ = owned_context(tmp_path)
    client.list_sessions.return_value = [
        session_record("far", remote_address="8.8.8.8:4444")
    ]
    result = asyncio.run(sliver_sessions.sliver_sessions_handler({}, run_context))
    # Registered, but the peer is outside the scope, so it is not shown.
    assert result.output["sessions"] == []
    assert result.evidence["count"] == 0


# --------------------------------------------------------------- exec
def test_exec_requires_approval(tmp_path, monkeypatch):
    fake_client(monkeypatch)
    gw, _ = gateway(tmp_path)
    run_context, _ = owned_context(tmp_path, register=[{"id": "sess-1"}])
    with pytest.raises(PermissionError, match="approval"):
        asyncio.run(
            gw.invoke(
                EXEC_TOOL,
                {"session_id": "sess-1", "command": "id"},
                run_context,
            )
        )


def test_exec_rejects_unauthorized_session(tmp_path, monkeypatch):
    client = fake_client(monkeypatch)
    run_context, _ = owned_context(tmp_path)
    result = asyncio.run(
        sliver_exec.sliver_exec_handler(
            {"session_id": "ghost", "command": "id"}, run_context
        )
    )
    assert not result.success
    assert result.verification_method == "session_not_registered"
    client.execute_command.assert_not_awaited()


def test_exec_rejects_session_of_another_engagement(tmp_path, monkeypatch):
    client = fake_client(monkeypatch)
    run_context, _ = owned_context(
        tmp_path, register=[{"id": "sess-1", "engagement_id": "eng-other"}]
    )
    result = asyncio.run(
        sliver_exec.sliver_exec_handler(
            {"session_id": "sess-1", "command": "id"}, run_context
        )
    )
    assert result.verification_method == "session_engagement_mismatch"
    client.execute_command.assert_not_awaited()


@pytest.mark.parametrize(
    "command",
    ["shutdown -h now", "/sbin/reboot", "mkfs.ext4 /dev/sda1", "diskpart", "format C:"],
)
def test_exec_rejects_destructive_command(tmp_path, monkeypatch, command):
    client = fake_client(monkeypatch)
    run_context, _ = owned_context(tmp_path, register=[{"id": "sess-1"}])
    with pytest.raises(ValueError, match="destructive"):
        asyncio.run(
            sliver_exec.sliver_exec_handler(
                {"session_id": "sess-1", "command": command}, run_context
            )
        )
    client.execute_command.assert_not_awaited()


@pytest.mark.parametrize(
    "command",
    ["id; whoami", "id | cat", "id && cat /etc/passwd", "id > /tmp/x", "echo `id`", "echo $(id)"],
)
def test_exec_rejects_shell_metacharacters(tmp_path, monkeypatch, command):
    client = fake_client(monkeypatch)
    run_context, _ = owned_context(tmp_path, register=[{"id": "sess-1"}])
    with pytest.raises(ValueError):
        asyncio.run(
            sliver_exec.sliver_exec_handler(
                {"session_id": "sess-1", "command": command}, run_context
            )
        )
    client.execute_command.assert_not_awaited()


def test_exec_success_returns_output(tmp_path, monkeypatch):
    client = fake_client(monkeypatch)
    run_context, _ = owned_context(tmp_path, register=[{"id": "sess-1"}])
    result = asyncio.run(
        sliver_exec.sliver_exec_handler(
            {"session_id": "sess-1", "command": "id"}, run_context
        )
    )
    assert result.success and result.verified
    assert result.verification_method == "sliver_exec_ok"
    assert "uid=0" in result.output["stdout"]
    assert result.evidence["status"] == "ok"
    client.execute_command.assert_awaited_once()
    args, kwargs = client.execute_command.call_args
    assert args[:2] == ("sess-1", "id")
    assert kwargs["kind"] == "session"


def test_exec_runs_through_gateway_with_approval(tmp_path, monkeypatch):
    client = fake_client(monkeypatch)
    gw, _audit, approvals, _store = gateway_with_approvals(tmp_path)
    run_context, _ = owned_context(tmp_path, register=[{"id": "sess-1"}])
    approval = approvals.request(run_context, f"execute:tool:{EXEC_TOOL}")
    approvals.decide(approval["id"], "system", "operator-test", True, "test approval")
    result = asyncio.run(
        gw.invoke(
            EXEC_TOOL,
            {"session_id": "sess-1", "command": "id"},
            run_context,
            approval_id=approval["id"],
        )
    )
    assert result["success"] is True
    client.execute_command.assert_awaited_once()


# --------------------------------------------------------------- pivot
def test_pivot_requires_approval(tmp_path, monkeypatch):
    fake_client(monkeypatch)
    gw, _ = gateway(tmp_path)
    run_context, _ = owned_context(tmp_path, register=[{"id": "sess-1"}])
    with pytest.raises(PermissionError, match="approval"):
        asyncio.run(
            gw.invoke(
                PIVOT_TOOL,
                {"session_id": "sess-1", "action": "list"},
                run_context,
            )
        )


@pytest.mark.parametrize("bind_port", [0, 70000, -1])
def test_pivot_rejects_invalid_port(tmp_path, monkeypatch, bind_port):
    client = fake_client(monkeypatch)
    run_context, _ = owned_context(tmp_path, register=[{"id": "sess-1"}])
    with pytest.raises(ValueError):
        asyncio.run(
            sliver_pivot.sliver_pivot_handler(
                {
                    "session_id": "sess-1",
                    "action": "portfwd",
                    "bind_port": bind_port,
                    "remote_host": "10.0.0.5",
                    "remote_port": 80,
                },
                run_context,
            )
        )
    client.start_portfwd.assert_not_awaited()


def test_pivot_list_returns_pivots(tmp_path, monkeypatch):
    client = fake_client(monkeypatch)
    run_context, _ = owned_context(tmp_path, register=[{"id": "sess-1"}])
    client.list_pivots.return_value = [{"ID": 1, "Type": "TCP", "BindAddress": "0.0.0.0:1080"}]
    result = asyncio.run(
        sliver_pivot.sliver_pivot_handler(
            {"session_id": "sess-1", "action": "list"}, run_context
        )
    )
    assert result.success
    assert result.verification_method == "sliver_pivot_list"
    assert result.output["pivots"][0]["bind_port"] == 1080


# --------------------------------------------------------------- invariants
def test_never_executes_subprocess(monkeypatch):
    fake_client(monkeypatch)
    with (
        patch("subprocess.Popen", side_effect=AssertionError("no subprocess")),
        patch("asyncio.create_subprocess_exec", side_effect=AssertionError("no process")),
    ):
        assert asyncio.run(sliver_server.sliver_server_handler({}, context())).success
    for module in HANDLER_MODULES:
        source = Path(inspect.getfile(module)).read_text()
        assert "subprocess" not in source
        assert "os.system" not in source
        assert "shell=True" not in source
