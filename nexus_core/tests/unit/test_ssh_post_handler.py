"""Unit tests for the post-exploitation SSH handlers (sandbox mocked)."""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
from unittest import mock

import pytest

from nexus_core.kernel.models import Identity, RunContext
from nexus_core.kernel.sandbox import SandboxResult
from nexus_core.tools.handlers import ssh_post as module
from nexus_core.tools.handlers.ssh_post import (
    enum_system_definition,
    enum_system_handler,
    parse_sudo_rules,
    ssh_exec_definition,
    ssh_exec_handler,
    ssh_upload_definition,
    ssh_upload_handler,
)


@pytest.fixture(autouse=True)
def _no_connect_cooldown(monkeypatch):
    """Pacing is covered by test_ssh_connection_pacing.py; no need to sleep here."""
    monkeypatch.setattr(module, "SSH_CONNECT_COOLDOWN_SECONDS", 0.0)


class FakeSandbox:
    def __init__(self, result: SandboxResult):
        self.result = result
        self.calls: list[tuple[list[str], float]] = []

    async def run(self, argv, *, timeout_seconds: float = 30):
        self.calls.append((list(argv), timeout_seconds))
        return self.result


@contextlib.contextmanager
def _fake_sandbox(result: SandboxResult):
    sandbox = FakeSandbox(result)
    with mock.patch.object(
        module, "sandbox_for_environment", lambda *args, **kwargs: sandbox
    ):
        yield sandbox


def _context() -> RunContext:
    return RunContext("system", Identity("operator-1", "system", roles=("operator",)))


def _run(handler, arguments: dict) -> object:
    return asyncio.run(handler(arguments, _context()))


def _sandbox_for(payload: dict, exit_code: int = 0) -> SandboxResult:
    return SandboxResult(exit_code, json.dumps(payload) + "\n", "")


# ------------------------------------------------------------------ definitions
def test_ssh_exec_is_high_risk_and_scope_gated():
    definition = ssh_exec_definition()
    assert definition.risk.value == "high"
    assert definition.scope_target_field == "target"
    assert definition.scope_required is True


def test_enum_system_is_medium_risk():
    definition = enum_system_definition()
    assert definition.risk.value == "medium"
    assert definition.scope_required is True


# -------------------------------------------------------------------- sudo parse
def test_parse_sudo_rules_extracts_command():
    text = (
        "Matching Defaults entries for lin on ip-10-65-151-43:\n"
        "    env_reset, mail_badpass\n\n"
        "User lin may run the following commands on ip-10-65-151-43:\n"
        "    (root) /bin/tar\n"
    )
    assert parse_sudo_rules(text) == [{"who": "root", "command": "/bin/tar"}]


# --------------------------------------------------------------------- ssh_exec
def test_ssh_exec_runs_client_in_sandbox():
    payload = {
        "ok": True,
        "connected": True,
        "stdout": "lin\n",
        "stderr": "",
        "exit_status": 0,
    }
    with _fake_sandbox(_sandbox_for(payload)) as sandbox:
        result = _run(
            ssh_exec_handler,
            {"target": "10.65.151.43", "username": "lin", "password": "pw", "command": "whoami"},
        )
    argv = sandbox.calls[0][0]
    assert argv[0] == "python3" and argv[1] == "-c"
    assert argv[3] == "exec" and argv[4] == "10.65.151.43"
    assert result.verified is True
    assert result.output["stdout"] == "lin\n"


def test_ssh_exec_feeds_sudo_password_on_stdin():
    payload = {
        "ok": True,
        "connected": True,
        "stdout": "uid=0(root)\n",
        "stderr": "",
        "exit_status": 0,
    }
    with _fake_sandbox(_sandbox_for(payload)) as sandbox:
        result = _run(
            ssh_exec_handler,
            {
                "target": "10.65.151.43",
                "username": "lin",
                "password": "secret",
                "command": "sudo /bin/tar cf /dev/null /dev/null",
            },
        )
    remote = json.loads(sandbox.calls[0][0][-1])
    assert remote["command"].startswith("sudo -S ")
    assert remote["stdin"] == "secret\n"
    assert result.evidence["sudo_stdin"] is True


def test_ssh_exec_no_stdin_for_plain_command():
    payload = {"ok": True, "connected": True, "stdout": "x\n", "stderr": "", "exit_status": 0}
    with _fake_sandbox(_sandbox_for(payload)) as sandbox:
        _run(
            ssh_exec_handler,
            {"target": "10.65.151.43", "username": "lin", "password": "secret", "command": "id"},
        )
    remote = json.loads(sandbox.calls[0][0][-1])
    assert remote["stdin"] is None


def test_ssh_exec_rejects_destructive_command():
    with pytest.raises(ValueError):
        _run(
            ssh_exec_handler,
            {
                "target": "10.65.151.43",
                "username": "lin",
                "password": "pw",
                "command": "sudo reboot",
            },
        )


def test_ssh_exec_reports_paramiko_missing():
    payload = {"ok": False, "connected": False, "error": "ssh_unavailable", "detail": "no paramiko"}
    with _fake_sandbox(_sandbox_for(payload)):
        result = _run(
            ssh_exec_handler,
            {"target": "10.65.151.43", "username": "lin", "password": "pw", "command": "id"},
        )
    assert result.verified is False
    assert result.verification_method == "ssh_unavailable"


def test_ssh_exec_timeout_is_not_verified():
    with _fake_sandbox(SandboxResult(-1, "", "", timed_out=True)):
        result = _run(
            ssh_exec_handler,
            {"target": "10.65.151.43", "username": "lin", "password": "pw", "command": "id"},
        )
    assert result.verified is False
    assert result.verification_method == "ssh_exec_timeout"


# ------------------------------------------------------------------- enum_system
def test_enum_system_extracts_sudo_rules():
    payload = {
        "ok": True,
        "connected": True,
        "results": {
            "__SUDO__": {"stdout": "User lin may run:\n    (root) /bin/tar\n", "exit_status": 0},
            "identity": {"stdout": "uid=1001(lin)\n", "exit_status": 0},
        },
    }
    with _fake_sandbox(_sandbox_for(payload)) as sandbox:
        result = _run(
            enum_system_handler,
            {"target": "10.65.151.43", "username": "lin", "password": "pw"},
        )
    argv = sandbox.calls[0][0]
    assert argv[3] == "enum"
    assert result.verified is True
    assert result.output["sudo_rules"] == [{"who": "root", "command": "/bin/tar"}]
    assert result.evidence["sudo_rules"] == ["/bin/tar"]


def test_enum_system_reports_paramiko_missing():
    payload = {"ok": False, "connected": False, "error": "ssh_unavailable", "detail": "x"}
    with _fake_sandbox(_sandbox_for(payload)):
        result = _run(
            enum_system_handler,
            {"target": "10.65.151.43", "username": "lin", "password": "pw"},
        )
    assert result.verified is False
    assert result.verification_method == "ssh_unavailable"


# -------------------------------------------------------------------- ssh_upload
def _workspace(tmp_path, content: bytes = b"#!/bin/sh\necho pe\n") -> tuple[str, str]:
    """Write a file in a temp workspace and return (root, sha256)."""
    (tmp_path / "pe.sh").write_bytes(content)
    return str(tmp_path), hashlib.sha256(content).hexdigest()


def test_ssh_upload_is_medium_risk_and_scope_gated():
    definition = ssh_upload_definition()
    assert definition.risk.value == "medium"
    assert definition.effect == "exploit"
    assert definition.scope_target_field == "target"
    assert definition.scope_required is True


def test_ssh_upload_verifies_the_remote_sha256(tmp_path, monkeypatch):
    root, digest = _workspace(tmp_path)
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", root)
    payload = {
        "ok": True,
        "connected": True,
        "mode": "upload",
        "remote_path": "/tmp/pe.sh",
        "uploaded_bytes": 19,
        "remote_sha256": digest,
        "remote_mode": "0o755",
    }
    with _fake_sandbox(_sandbox_for(payload)) as sandbox:
        result = _run(
            ssh_upload_handler,
            {
                "target": "10.64.182.188",
                "username": "grafana-admin",
                "password": "pw",
                "local_path": "pe.sh",
                "remote_path": "/tmp/pe.sh",
                "file_mode": "755",
            },
        )
    argv = sandbox.calls[0][0]
    # python3 -c <script> upload <host> <port> <user> <password> <payload>
    assert argv[:5] == ["python3", "-c", module.SSH_CLIENT_SCRIPT, "upload", "10.64.182.188"]
    request = json.loads(argv[8])
    assert request["local_path"].endswith("pe.sh")
    assert request["remote_path"] == "/tmp/pe.sh"
    assert request["file_mode"] == "755"
    assert result.verified is True
    assert result.verification_method == "ssh_upload_verified_sha256"
    assert result.output["sha256"] == digest
    assert result.evidence["local_sha256"] == digest


def test_ssh_upload_declares_a_hash_mismatch(tmp_path, monkeypatch):
    root, _ = _workspace(tmp_path)
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", root)
    payload = {
        "ok": True,
        "connected": True,
        "remote_path": "/tmp/pe.sh",
        "uploaded_bytes": 19,
        "remote_sha256": "0" * 64,
    }
    with _fake_sandbox(_sandbox_for(payload)):
        result = _run(
            ssh_upload_handler,
            {
                "target": "10.64.182.188",
                "username": "grafana-admin",
                "password": "pw",
                "local_path": "pe.sh",
                "remote_path": "/tmp/pe.sh",
            },
        )
    assert result.verified is False
    assert result.verification_method == "ssh_upload_hash_mismatch"


def test_ssh_upload_refuses_a_path_outside_the_workspace(tmp_path, monkeypatch):
    root, _ = _workspace(tmp_path)
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", root)
    with _fake_sandbox(_sandbox_for({"ok": True, "connected": True})):
        with pytest.raises(ValueError):
            _run(
                ssh_upload_handler,
                {
                    "target": "10.64.182.188",
                    "username": "lin",
                    "password": "pw",
                    "local_path": "../../etc/passwd",
                    "remote_path": "/tmp/x",
                },
            )


def test_ssh_upload_refuses_a_traversing_remote_path(tmp_path, monkeypatch):
    root, _ = _workspace(tmp_path)
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", root)
    with _fake_sandbox(_sandbox_for({"ok": True, "connected": True})):
        with pytest.raises(ValueError):
            _run(
                ssh_upload_handler,
                {
                    "target": "10.64.182.188",
                    "username": "lin",
                    "password": "pw",
                    "local_path": "pe.sh",
                    "remote_path": "/tmp/../etc/cron.d/backdoor",
                },
            )


def test_ssh_upload_refuses_an_invalid_file_mode(tmp_path, monkeypatch):
    root, _ = _workspace(tmp_path)
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", root)
    with _fake_sandbox(_sandbox_for({"ok": True, "connected": True})):
        with pytest.raises(ValueError):
            _run(
                ssh_upload_handler,
                {
                    "target": "10.64.182.188",
                    "username": "lin",
                    "password": "pw",
                    "local_path": "pe.sh",
                    "remote_path": "/tmp/pe.sh",
                    "file_mode": "888",
                },
            )


def test_ssh_upload_reports_paramiko_missing(tmp_path, monkeypatch):
    root, _ = _workspace(tmp_path)
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", root)
    payload = {"ok": False, "connected": False, "error": "ssh_unavailable", "detail": "x"}
    with _fake_sandbox(_sandbox_for(payload)):
        result = _run(
            ssh_upload_handler,
            {
                "target": "10.64.182.188",
                "username": "lin",
                "password": "pw",
                "local_path": "pe.sh",
                "remote_path": "/tmp/pe.sh",
            },
        )
    assert result.verified is False
    assert result.verification_method == "ssh_unavailable"


def test_ssh_upload_reports_a_timeout(tmp_path, monkeypatch):
    root, _ = _workspace(tmp_path)
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", root)
    with _fake_sandbox(SandboxResult(-1, "", "", timed_out=True)):
        result = _run(
            ssh_upload_handler,
            {
                "target": "10.64.182.188",
                "username": "lin",
                "password": "pw",
                "local_path": "pe.sh",
                "remote_path": "/tmp/pe.sh",
            },
        )
    assert result.verified is False
    assert result.verification_method == "ssh_upload_timeout"
