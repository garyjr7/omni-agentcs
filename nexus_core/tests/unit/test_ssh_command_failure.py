"""Simple CTF fixes: a failed command is not a failed credential.

Measured in Simple CTF: after the SQLi, the hash crack and a working SSH login
(``user.txt`` captured), the agent ran ``sudo -n -l`` through
``nexus.post.ssh_exec``. The login was already established, but the tool answered

    {"error": "AuthenticationException: Authentication failed."}

on an ``ssh_exec_failed`` post-condition. The agent read that as "the SSH
password is wrong", repeated the same call (``repeated_action``) and died at the
20-minute timeout with the escalation still pending.

What this module pins:

* the client distinguishes "the login failed" from "the command failed", and a
  post-login exception never surfaces as an authentication failure;
* a non-zero remote exit is ``success=False``/``verified=False`` with
  ``outcome="command_failed"`` and the *real* stdout/stderr in the evidence;
* a refused login stays ``denied`` (determinate, not a broken post-condition);
* the ReAct loop tells the model the credential is fine, points at the
  ``privesc-sudo`` skill, and never re-executes the identical failing call.
"""

from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
from unittest import mock

import pytest

from nexus_core.agent.react import (
    STATUS_COMPLETED,
    TOOL_UNAVAILABLE_EVENT_TYPE,
    run_react_loop,
)
from nexus_core.kernel import runtime as runtime_module
from nexus_core.kernel.control_store import ControlStore
from nexus_core.kernel.models import Identity, RunContext
from nexus_core.kernel.runtime import ExecutionContext
from nexus_core.kernel.sandbox import SandboxResult
from nexus_core.tests.unit.test_phase3b_fixes import (
    ScriptedLLM,
    ToolSpy,
    _config,
    _create_scope,
    _observations,
)
from nexus_core.tools.handlers import ssh_post as module
from nexus_core.tools.handlers.ssh_post import SSH_CLIENT_SCRIPT, ssh_exec_handler

pytestmark = [pytest.mark.unit, pytest.mark.usefixtures("lab_scope")]


@pytest.fixture(autouse=True)
def _no_connect_cooldown(monkeypatch):
    """Pacing has its own module; a real second per call here only slows the suite."""
    monkeypatch.setattr(module, "SSH_CONNECT_COOLDOWN_SECONDS", 0.0)

TARGET = "10.0.0.5"
TENANT = "system"
ENGAGEMENT = "eng-1"


# --------------------------------------------------------------------- helpers
class _FakeSandbox:
    def __init__(self, result: SandboxResult) -> None:
        self.result = result
        self.calls: list[list[str]] = []

    async def run(self, argv, *, timeout_seconds: float = 30):
        self.calls.append(list(argv))
        return self.result


def _fake_sandbox(payload: dict):
    result = SandboxResult(0, json.dumps(payload) + "\n", "")
    sandbox = _FakeSandbox(result)
    return mock.patch.object(
        module, "sandbox_for_environment", lambda *args, **kwargs: sandbox
    )


def _context() -> RunContext:
    return RunContext(TENANT, Identity("operator-1", TENANT, roles=("operator",)))


def _exec(payload: dict):
    with _fake_sandbox(payload):
        return asyncio.run(
            ssh_exec_handler(
                {
                    "target": TARGET,
                    "username": "mitch",
                    "password": "secret",
                    "command": "sudo -n -l",
                },
                _context(),
            )
        )


# ------------------------------------------- the command failed, not the login
def test_a_nonzero_exit_is_a_command_failure_with_the_real_streams() -> None:
    """``sudo -n -l`` fails with rc 1 on a password-protected account."""
    stderr = "sudo: a password is required\n"
    result = _exec(
        {
            "ok": False,
            "connected": True,
            "outcome": "command_failed",
            "stdout": "",
            "stderr": stderr,
            "exit_status": 1,
        }
    )

    assert result.outcome == "command_failed"
    assert result.success is False
    assert result.verified is False
    # Determinate: the gateway must not turn it into ``RuntimeError``.
    assert result.completed is True
    assert result.output["exit_status"] == 1
    assert result.evidence["exit_status"] == 1
    assert result.evidence["stdout"] == ""
    assert result.evidence["stderr"] == stderr


def test_an_old_client_shape_cannot_mark_a_failed_command_as_verified() -> None:
    """The client process exiting 0 is not the remote command succeeding."""
    result = _exec(
        {"ok": True, "connected": True, "stdout": "", "stderr": "denied\n", "exit_status": 1}
    )

    assert result.outcome == "command_failed"
    assert result.verified is False
    assert result.success is False
    assert result.output["exit_status"] == 1


def test_an_authentication_exception_after_login_is_reported_as_a_command_failure() -> None:
    """The exact measured payload: connected session, auth-flavoured error."""
    result = _exec(
        {
            "ok": False,
            "connected": True,
            "error": "AuthenticationException: Authentication failed.",
            "stdout": "",
            "stderr": "sudo: a password is required\n",
            "exit_status": 1,
        }
    )

    assert result.outcome == "command_failed"
    assert result.verification_method == "ssh_exec_command_failed"
    assert "authenticationexception" not in result.verification_method.lower()
    assert result.output["error"].startswith("CommandFailed:")
    assert "AuthenticationException" not in result.output["error"]
    # The diagnostic the model needs to pivot is the command's own stderr.
    assert "sudo: a password is required" in result.evidence["stderr"]


def test_a_refused_login_is_denied_not_a_broken_post_condition() -> None:
    """A wrong credential is a determinate ``denied``, never ``RuntimeError``."""
    detail = "AuthenticationException: Authentication failed."
    result = _exec({"ok": False, "connected": False, "error": detail})

    assert result.outcome == "denied"
    assert result.completed is True
    assert result.verified is False
    assert result.output["exit_status"] is None
    assert result.output["error"] == detail
    assert result.evidence["error_detail"] == detail


def test_an_unreachable_host_is_unavailable_not_denied() -> None:
    result = _exec({"ok": False, "connected": False, "error": "NoValidConnectionsError: refused"})

    assert result.outcome == "unavailable"
    assert result.completed is True


def test_a_healthy_command_still_verifies() -> None:
    result = _exec(
        {"ok": True, "connected": True, "stdout": "uid=0(root)\n", "stderr": "", "exit_status": 0}
    )

    assert result.verified is True
    assert result.outcome_class == "success"
    assert "error" not in result.output


# ------------------------------------------------- the client translates it too
_FAKE_PARAMIKO = '''
class AuthenticationException(Exception):
    pass


class AutoAddPolicy:
    pass


class _Channel:
    def recv_exit_status(self):
        return {exit_code}

    def shutdown_write(self):
        pass


class _Stream:
    def __init__(self, data=b""):
        self._data = data
        self.channel = _Channel()

    def read(self):
        return self._data

    def write(self, data):
        pass

    def flush(self):
        pass


class SSHClient:
    def set_missing_host_key_policy(self, policy):
        pass

    def connect(self, **kwargs):
        self.connected = True

    def exec_command(self, command, timeout=None, get_pty=False):
        {body}

    def close(self):
        # The target's client must drop the transport on every exit path; the
        # marker proves the ``finally`` ran, not just that the call returned.
        open("closed.flag", "w").write("1")
'''


def _run_client(tmp_path, *, exit_code: int, body: str) -> dict:
    """Run the real client script against a fake ``paramiko`` module."""
    (tmp_path / "paramiko.py").write_text(
        _FAKE_PARAMIKO.format(exit_code=exit_code, body=body), encoding="utf-8"
    )
    proc = subprocess.run(
        [
            sys.executable,
            "-c",
            SSH_CLIENT_SCRIPT,
            "exec",
            TARGET,
            "22",
            "mitch",
            "secret",
            json.dumps({"command": "sudo -n -l", "command_timeout": 10}),
        ],
        cwd=tmp_path,
        env={**os.environ, "PYTHONPATH": str(tmp_path)},
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout.strip().splitlines()[-1])


def test_the_client_never_labels_a_post_login_failure_as_authentication(tmp_path) -> None:
    """A session that breaks after ``connect`` is the command's failure."""
    payload = _run_client(
        tmp_path,
        exit_code=1,
        body='raise AuthenticationException("Authentication failed.")',
    )

    assert payload["connected"] is True
    assert payload["outcome"] == "command_failed"
    assert payload["exit_status"] == 1
    assert payload["error"].startswith("CommandFailed:")
    assert "AuthenticationException" not in payload["error"]


@pytest.mark.parametrize(
    "body, exit_code",
    [
        ("return _Stream(), _Stream(), _Stream(b'')", 0),
        ('raise AuthenticationException("boom")', 1),
    ],
)
def test_the_client_always_closes_the_transport(tmp_path, body, exit_code) -> None:
    """No dangling session, whether the command worked or broke the session."""
    _run_client(tmp_path, exit_code=exit_code, body=body)

    assert (tmp_path / "closed.flag").exists()


def test_the_client_reports_a_nonzero_exit_as_a_command_failure(tmp_path) -> None:
    payload = _run_client(
        tmp_path,
        exit_code=1,
        body=(
            "return _Stream(), _Stream(), "
            "_Stream(b'sudo: a password is required\\n')"
        ),
    )

    assert payload["connected"] is True
    assert payload["ok"] is False
    assert payload["outcome"] == "command_failed"
    assert payload["exit_status"] == 1
    assert payload["stderr"] == "sudo: a password is required\n"


# ------------------------------------------------------------ the ReAct fallback
def _ssh_call(command: str = "sudo -n -l") -> str:
    return json.dumps(
        {
            "thought": "Escalo con sudo.",
            "action": "tool_call",
            "tool_id": "nexus.post.ssh_exec",
            "arguments": {
                "target": TARGET,
                "username": "mitch",
                "password": "secret",
                "command": command,
            },
            "expected_outcome": "reglas de sudo",
        }
    )


def _task_complete() -> str:
    return json.dumps(
        {"thought": "listo", "action": "task_complete", "summary": "ok", "findings": []}
    )


def _command_failed_payload(tool_id: str) -> dict:
    return {
        "tool_id": tool_id,
        "output": {
            "success": False,
            "outcome": "command_failed",
            "verification_method": "ssh_exec_command_failed",
            "evidence": {
                "connected": True,
                "exit_status": 1,
                "stdout": "",
                "stderr": "sudo: a password is required\n",
            },
            "output": {
                "target": TARGET,
                "command": "sudo -n -l",
                "stdout": "",
                "stderr": "sudo: a password is required\n",
                "exit_status": 1,
            },
            "assertions": [],
        },
    }


def _harness(tmp_path):
    store = ControlStore(tmp_path / "react.db")
    store.initialize()
    _create_scope(store, ENGAGEMENT)
    run = store.create_run(TENANT, {})
    task = {
        "id": "task-ssh-command-failed",
        "tenant_id": TENANT,
        "run_id": run["id"],
        "task_type": "react.run",
        "payload": {
            "objective": "Escala privilegios en 10.0.0.5",
            "engagement_id": ENGAGEMENT,
            "identity": {"subject_id": "operator-1", "roles": ["operator"]},
            "permissions": ["execute:tool:nexus.post.ssh_exec"],
        },
    }
    return store, ExecutionContext(store, task, "worker-test")


async def test_the_loop_tells_the_model_the_credential_is_fine(tmp_path) -> None:
    """One failed command must produce guidance, not a credential hunt."""
    store, context = _harness(tmp_path)
    spy = ToolSpy(_command_failed_payload("nexus.post.ssh_exec"))
    llm = ScriptedLLM([_ssh_call(), _task_complete()])

    with mock.patch.object(runtime_module, "execute_tool", spy):
        result = await run_react_loop(
            context=context,
            objective="Escala privilegios en 10.0.0.5",
            engagement_id=ENGAGEMENT,
            llm_client=llm,
            config=_config(max_iterations=6),
        )

    assert result.status == STATUS_COMPLETED
    observations = "\n".join(_observations(store, result.conversation_id))
    # Says what failed, that the credential is not the problem, and where to go.
    assert "el fallo es del comando, NO de la credencial" in observations
    assert "privesc-sudo" in observations
    assert "nexus.skill.load" in observations
    assert "sudo -S -l" in observations
    assert "No repitas la misma invocación" in observations


async def test_the_loop_does_not_retire_the_tool_for_a_failed_command(tmp_path) -> None:
    """A working SSH channel that runs failing commands is still a channel."""
    store, context = _harness(tmp_path)
    spy = ToolSpy(_command_failed_payload("nexus.post.ssh_exec"))
    llm = ScriptedLLM(
        [_ssh_call("sudo -n -l"), _ssh_call("id"), _ssh_call("uname -a"), _task_complete()]
    )

    with mock.patch.object(runtime_module, "execute_tool", spy):
        result = await run_react_loop(
            context=context,
            objective="Escala privilegios en 10.0.0.5",
            engagement_id=ENGAGEMENT,
            llm_client=llm,
            config=_config(max_iterations=8),
        )

    assert result.status == STATUS_COMPLETED, result.final_summary
    assert len(spy.payloads) == 3, "each distinct command was attempted once"
    retired = [
        event
        for event in store.list_run_events(TENANT, context.run_id)
        if event["event_type"] == TOOL_UNAVAILABLE_EVENT_TYPE
    ]
    assert retired == [], "the channel never worked badly enough to be retired"


async def test_the_identical_repeat_is_corrected_not_replayed(tmp_path) -> None:
    """The measured loop: the same ``sudo -n -l`` twice must not consume two calls."""
    store, context = _harness(tmp_path)
    spy = ToolSpy(_command_failed_payload("nexus.post.ssh_exec"))
    same = _ssh_call()
    llm = ScriptedLLM([same, same, _task_complete()])

    with mock.patch.object(runtime_module, "execute_tool", spy):
        result = await run_react_loop(
            context=context,
            objective="Escala privilegios en 10.0.0.5",
            engagement_id=ENGAGEMENT,
            llm_client=llm,
            config=_config(max_iterations=6),
        )

    assert result.status == STATUS_COMPLETED
    assert len(spy.payloads) == 1, "the identical repeat never reached the executor"
    observations = "\n".join(_observations(store, result.conversation_id))
    assert "mismos argumentos" in observations
