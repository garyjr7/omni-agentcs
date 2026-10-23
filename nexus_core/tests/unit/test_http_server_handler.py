"""Tests for ``nexus.post.http_server`` (the server really starts and answers).

The acceptance criterion of Tanda G is behavioural: lift the server and check it
answers a local request. The serving tests are skipped when ``tmux`` is missing
(the same contract as ``test_session_pty``): the tool reuses the persistent-PTY
substrate, so without tmux there is no server to test.
"""

from __future__ import annotations

import asyncio
import shutil
import socket
import urllib.request
from unittest import mock

import pytest

from nexus_core.kernel.models import Identity, RiskLevel, RunContext
from nexus_core.kernel.pty_sessions import PtySessionManager
from nexus_core.tools.handlers import http_server as module
from nexus_core.tools.handlers.http_server import (
    attacker_ip,
    http_server_definition,
    http_server_handler,
    server_argv,
)

needs_tmux = pytest.mark.skipif(
    shutil.which("tmux") is None, reason="tmux is required for the http server pane"
)


def _context(run_id: str = "run-http-1") -> RunContext:
    return RunContext(
        "system", Identity("operator-1", "system", roles=("operator",)), run_id=run_id
    )


def _run(arguments: dict, run_id: str = "run-http-1") -> object:
    return asyncio.run(http_server_handler(arguments, _context(run_id)))


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def _fetch(url: str, timeout: float = 3.0) -> str:
    with urllib.request.urlopen(url, timeout=timeout) as response:
        return response.read().decode("utf-8", "replace")


# ------------------------------------------------------------------ definition
def test_definition_is_low_risk_post_exploitation_with_a_required_port():
    definition = http_server_definition()
    assert definition.tool_id == "nexus.post.http_server"
    assert definition.risk is RiskLevel.LOW
    assert definition.effect == "post_exploitation"
    assert definition.input_schema["required"] == ["port"]
    assert definition.scope_required is False


def test_argv_is_the_stdlib_server_over_the_chosen_directory(tmp_path):
    argv = server_argv(8080, tmp_path)
    assert argv[:4] == ["python3", "-m", "http.server", "8080"]
    assert argv[argv.index("--bind") + 1] == "0.0.0.0"
    assert argv[argv.index("--directory") + 1] == str(tmp_path)


# ------------------------------------------------------------------- refusals
def test_a_port_below_the_unprivileged_range_is_refused(tmp_path, monkeypatch):
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(tmp_path))
    with pytest.raises(ValueError, match="below 1024"):
        _run({"port": 80})


def test_a_directory_outside_the_workspace_is_refused(tmp_path, monkeypatch):
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(tmp_path))
    with pytest.raises(ValueError, match="escapes the engagement workspace"):
        _run({"port": 8080, "directory": "/etc"})


def test_a_directory_that_does_not_exist_is_refused(tmp_path, monkeypatch):
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(tmp_path))
    with pytest.raises(ValueError, match="not found in workspace"):
        _run({"port": 8080, "directory": "loot/nope"})


def test_an_oci_sandbox_is_reported_unavailable(tmp_path, monkeypatch):
    """A pane inside a container is not reachable from the target."""
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(tmp_path))

    class ContainerManager(_FakeManager):
        def sandbox(self):
            return mock.Mock(spec=module.OCISandbox)

    with mock.patch.object(
        module, "PtySessionManager", lambda root, run_id: ContainerManager("omni-x-http-8080")
    ):
        result = _run({"port": 8080})
    assert result.outcome == "unavailable"
    assert result.verification_method == "http_server_requires_persistent_sandbox"


def test_a_port_held_by_another_server_is_a_determinate_negative(tmp_path, monkeypatch):
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(tmp_path))
    with mock.patch.object(
        module, "PtySessionManager", _FakeManager.live_factory("omni-run-http-http-8080")
    ), mock.patch.object(
        module,
        "_probe_server",
        lambda port: {"ok": True, "status": 200, "server": "nginx/1.24.0", "body": ""},
    ):
        result = _run({"port": 8080})
    assert result.verified is False
    assert result.outcome == "negative"
    assert result.verification_method == "http_server_port_conflict"


# ------------------------------------------------------------ the real server
@needs_tmux
def test_the_server_starts_and_serves_a_file_to_a_local_request(tmp_path, monkeypatch):
    """Acceptance criterion: the server is up and answers with the payload."""
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(tmp_path))
    payload = tmp_path / "loot" / "exploits"
    payload.mkdir(parents=True)
    (payload / "callback.txt").write_text("OMNI-HTTP-SERVER-OK\n", encoding="utf-8")
    port = _free_port()
    run_id = f"run-http-{port}"
    manager = PtySessionManager(tmp_path, run_id)
    session = manager.session_id(f"http-{port}")
    try:
        result = _run({"port": port, "directory": "loot/exploits"}, run_id=run_id)
        assert result.verified is True, result.output
        assert result.verification_method == "http_server_serving"
        assert result.output["status"] == "serving"
        assert result.output["port"] == port
        assert result.output["directory"] == "loot/exploits"
        # The post-condition is the server's own answer: a local request gets the
        # file back, not a directory listing or a timeout.
        body = _fetch(f"http://127.0.0.1:{port}/callback.txt")
        assert body == "OMNI-HTTP-SERVER-OK\n"
        assert asyncio.run(manager.exists(f"http-{port}")) is True
    finally:
        asyncio.run(manager.kill(f"http-{port}"))
    assert session.startswith("omni-")
    assert asyncio.run(manager.exists(f"http-{port}")) is False


@needs_tmux
def test_a_second_call_reuses_the_live_session_instead_of_failing_to_bind(
    tmp_path, monkeypatch
):
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(tmp_path))
    port = _free_port()
    run_id = f"run-http-reuse-{port}"
    manager = PtySessionManager(tmp_path, run_id)
    try:
        first = _run({"port": port}, run_id=run_id)
        second = _run({"port": port}, run_id=run_id)
        assert first.verified is True and second.verified is True
        assert first.output["session_ref"] == second.output["session_ref"]
    finally:
        asyncio.run(manager.kill(f"http-{port}"))


# --------------------------------------------------------------- the address
def test_the_callback_address_prefers_the_operator_configured_msf_lhost():
    address, source = attacker_ip(environ={"MSF_LHOST": "10.10.14.7"})
    assert address == "10.10.14.7"
    assert source == "MSF_LHOST"


def test_without_msf_lhost_the_tun0_address_is_used():
    with mock.patch("nexus_core.cli.wizard.detect_tun0_ip", lambda: "192.168.144.132"):
        address, source = attacker_ip(environ={})
    assert address == "192.168.144.132"
    assert source == "tun0"


def test_the_served_output_never_points_the_target_at_localhost(tmp_path, monkeypatch):
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(tmp_path))
    with mock.patch.object(
        module, "PtySessionManager", _FakeManager.live_factory("omni-run-http-http-8080")
    ), mock.patch.object(
        module,
        "_probe_server",
        lambda port: {"ok": True, "status": 200, "server": "SimpleHTTP/0.6 Python/3.12",
                      "body": "<html>listing</html>"},
    ), mock.patch.object(module, "attacker_ip", lambda: ("10.10.14.7", "tun0")):
        result = _run({"port": 8080})
    assert result.verified is True
    assert result.output["attacker_ip"] == "10.10.14.7"
    assert result.output["targetmachine"] == "10.10.14.7"
    assert result.output["url"] == "http://10.10.14.7:8080/"
    steps = " ".join(result.output["next_steps"])
    assert "NO uses 127.0.0.1" in steps
    assert "10.10.14.7" in steps


class _FakeSession:
    def __init__(self, session_id: str, alive: bool = True, already_running: bool = False):
        self.session_id = session_id
        self.alive = alive
        self.already_running = already_running
        self.error = None


class _FakeManager:
    """Minimal ``PtySessionManager`` stand-in for the non-serving assertions."""

    def __init__(self, session_id: str, alive: bool = True, already_running: bool = False):
        self._session = _FakeSession(session_id, alive, already_running)

    @classmethod
    def live_factory(cls, session_id: str, *, alive: bool = True):
        return lambda root, run_id, **kwargs: cls(session_id, alive=alive)

    def sandbox(self):
        return mock.Mock()

    async def start(self, command: str, name: str):
        return self._session

    async def kill(self, name: str):
        return self._session

    async def capture(self, name: str, lines: int = 40):
        return mock.Mock(output=f"$ {name}")


def test_a_live_session_without_a_probe_answer_is_not_verified(tmp_path, monkeypatch):
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(tmp_path))
    with mock.patch.object(
        module, "PtySessionManager", _FakeManager.live_factory("omni-run-http-http-8080")
    ), mock.patch.object(
        module, "_probe_server", lambda port: {"ok": False, "error": "URLError: refused"}
    ):
        result = _run({"port": 8080})
    assert result.verified is False
    assert result.verification_method == "http_server_not_serving"


def test_a_session_that_died_on_start_is_not_verified(tmp_path, monkeypatch):
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(tmp_path))

    class DeadManager(_FakeManager):
        def __init__(self):
            super().__init__("omni-run-http-http-8080", alive=False)

    with mock.patch.object(module, "PtySessionManager", lambda root, run_id: DeadManager()):
        result = _run({"port": 8080})
    assert result.verified is False
    assert result.verification_method == "http_server_start_failed"
    assert "pane" in result.output
