"""Simple CTF fix: Plan B when SSH refuses an already-validated credential.

Measured in Simple CTF runs 1 and 2: iteration 19 logged in with ``mitch`` and
read ``user.txt``; iterations 20-22 (``enum_system`` and two ``ssh_exec`` calls,
seconds apart) were answered with ``AuthenticationException: Authentication
failed`` although the password was right. The target -or a ban daemon in front
of it- was counting our own paramiko sessions.

What this module pins:

* a refused login for a credential the blackboard already proved valid is
  replayed through ``nexus.shell.exec`` with the native ``ssh`` client driven by
  ``sshpass`` -no second paramiko session;
* the password travels on stdin (``sshpass -d 0``), never in the command line
  that reaches the shell audit or the observation;
* a ``sudo -S`` command still gets its second copy of the password on stdin;
* a credential the board does *not* prove stays ``denied`` (a wrong password is
  never replayed against a rate limiter);
* a missing ``sshpass`` is reported as a determinate ``denied`` with the reason,
  never a broken post-condition.
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timedelta, timezone
from unittest import mock

import pytest

from nexus_core.cli.engage import build_scope
from nexus_core.kernel.blackboard import Blackboard
from nexus_core.kernel.control_store import ControlStore
from nexus_core.kernel.models import Identity, RunContext, ToolResult
from nexus_core.kernel.sandbox import SandboxResult
from nexus_core.scope import EngagementScope, EngagementStore
from nexus_core.tools.handlers import shell_exec_local
from nexus_core.tools.handlers import ssh_post as module
from nexus_core.tools.handlers.ssh_post import ssh_exec_handler

pytestmark = [pytest.mark.unit]

TARGET = "10.64.128.102"
TENANT = "system"
ENGAGEMENT = "eng-1"
PASSWORD = "secret"


@pytest.fixture(autouse=True)
def _no_connect_cooldown(monkeypatch):
    """Pacing has its own module; a real three seconds per call only slows us."""
    monkeypatch.setattr(module, "SSH_CONNECT_COOLDOWN_SECONDS", 0.0)


class _FakeSandbox:
    """Returns the same paramiko payload without opening a socket."""

    def __init__(self, payload: dict) -> None:
        self.payload = payload
        self.calls: list[list[str]] = []

    async def run(self, argv, *, timeout_seconds: float = 30):
        self.calls.append(list(argv))
        return SandboxResult(0, json.dumps(self.payload) + "\n", "")


def _iso(delta: timedelta) -> str:
    return (datetime.now(timezone.utc) + delta).isoformat()


def _scope() -> EngagementScope:
    return EngagementScope(
        engagement_id=ENGAGEMENT,
        tenant_id=TENANT,
        name="simple-ctf",
        client="acme",
        owner_id="owner-1",
        valid_from=_iso(-timedelta(days=1)),
        valid_until=_iso(timedelta(days=1)),
        cidrs=("10.64.0.0/16",),
        domains=(),
        urls=(),
        exclusions=(),
        created_at=_iso(timedelta(0)),
    )


def _context(tmp_path, *, verified: bool = True) -> RunContext:
    store = ControlStore(tmp_path / "fallback.db")
    store.initialize()
    if verified:
        Blackboard(store).record(
            tenant_id=TENANT,
            engagement_id=ENGAGEMENT,
            fact_type="access",
            key=TARGET,
            value={"transport": "ssh", "username": "mitch"},
            source="nexus.post.ssh_exec",
            created_by="verifier",
            verified=True,
            asserted_by="verifier",
            verification_method="ssh_exec_completed",
            invocation_id="inv-1",
        )
    return RunContext(
        TENANT,
        Identity("operator", TENANT, roles=("operator",)),
        store=store,
        scope=_scope(),
    )


_AUTH_FAILED = {
    "ok": False,
    "connected": False,
    "error": "AuthenticationException: Authentication failed.",
}


def _invoke(tmp_path, *, context: RunContext | None = None, command: str = "id"):
    context = context or _context(tmp_path)
    sandbox = _FakeSandbox(_AUTH_FAILED)
    captured: dict[str, dict] = {}

    async def fake_shell(arguments, ctx):
        captured["arguments"] = dict(arguments)
        return ToolResult(
            output={"summary": "uid=0(root)\n", "artifact_ref": "art-1"},
            verified=True,
            verification_method="shell_exit_code",
            exit_code=0,
            stdout="uid=0(root)\n",
        )

    with mock.patch.object(
        module, "sandbox_for_environment", lambda *a, **k: sandbox
    ), mock.patch.object(shell_exec_local, "shell_exec_handler", fake_shell):
        result = asyncio.run(
            ssh_exec_handler(
                {
                    "target": TARGET,
                    "username": "mitch",
                    "password": PASSWORD,
                    "command": command,
                },
                context,
            )
        )
    return result, sandbox, captured


def test_a_refused_login_replays_the_command_with_sshpass(tmp_path):
    """The credential is right: replay through the native client, not paramiko."""
    with mock.patch.object(module.shutil, "which", lambda _: "/usr/bin/sshpass"):
        result, sandbox, captured = _invoke(tmp_path)

    # One paramiko attempt (the refused login), then the subprocess fallback.
    assert len(sandbox.calls) == 1
    assert result.verified is True
    assert result.verification_method == "ssh_exec_sshpass_completed"
    command = captured["arguments"]["command"]
    assert command.startswith("sshpass -d 0 ssh ")
    assert f"mitch@{TARGET}" in command
    # The secret never reaches the command line that the shell audit records.
    assert PASSWORD not in command
    assert captured["arguments"]["stdin"] == PASSWORD + "\n"
    assert result.output["fallback"] == "sshpass"
    assert result.evidence["fallback_transport"] == "sshpass"


def test_the_sudo_password_is_still_on_stdin_after_the_sshpass_line(tmp_path):
    """``sshpass`` consumes line one; ``sudo -S`` reads line two."""
    with mock.patch.object(module.shutil, "which", lambda _: "/usr/bin/sshpass"):
        _, _, captured = _invoke(tmp_path, command="sudo -l")

    assert captured["arguments"]["stdin"] == PASSWORD + "\n" + PASSWORD + "\n"
    assert "sudo -S -l" in captured["arguments"]["command"]


def test_a_credential_the_board_does_not_prove_is_not_replayed(tmp_path):
    """A genuinely wrong password stays ``denied`` and is never retried."""
    context = _context(tmp_path, verified=False)
    with mock.patch.object(module.shutil, "which", lambda _: "/usr/bin/sshpass"):
        result, sandbox, captured = _invoke(tmp_path, context=context)

    assert len(sandbox.calls) == 1
    assert captured == {}, "Plan B must not run without a verified access fact"
    assert result.verified is False
    assert result.outcome == "denied"
    assert result.evidence["fallback"]["reason"] == "no_verified_credential"


def test_a_missing_sshpass_keeps_the_determinate_denied_result(tmp_path):
    """No binary is a reason, not a broken post-condition."""
    with mock.patch.object(module.shutil, "which", lambda _: None):
        result, _, captured = _invoke(tmp_path)

    assert captured == {}
    assert result.verified is False
    assert result.outcome == "denied"
    assert result.evidence["fallback"]["reason"] == "sshpass_not_installed"
    assert "sshpass" in result.output["guidance"]


class _RecordingShellSandbox:
    """Captures what the *real* ``nexus.shell.exec`` passes to a child."""

    def __init__(self) -> None:
        self.argv: list[str] = []
        self.input_data: bytes | None = None

    async def run(self, argv, *, timeout_seconds=30, input_data=None, **kwargs):
        self.argv = list(argv)
        self.input_data = input_data
        return SandboxResult(0, "uid=0(root) gid=0(root) groups=0(root)\n", "")


def test_the_real_shell_handler_runs_the_sshpass_replay(tmp_path, monkeypatch):
    """End to end through the real ``nexus.shell.exec`` handler.

    Only ``sshpass`` itself is faked (a binary on PATH): the replay goes through
    the genuine ``shell_exec_handler``, so this pins the shell contract -argv,
    stdin, summary, exit status- and the verification of the fallback result.
    """
    monkeypatch.setenv("NEXUS_SCOPE_SIGNING_SECRET", "test-signing-secret")
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(workspace))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    store = ControlStore(tmp_path / "real.db")
    store.initialize()
    scope = EngagementStore(store).create(
        build_scope("bench", f"{TARGET}/32", "test-signing-secret")
    )
    Blackboard(store).record(
        tenant_id=TENANT,
        engagement_id=scope.engagement_id,
        fact_type="access",
        key=TARGET,
        value={"transport": "ssh", "username": "mitch"},
        source="nexus.post.ssh_exec",
        created_by="verifier",
        verified=True,
        asserted_by="verifier",
        verification_method="ssh_exec_completed",
        invocation_id="inv-real",
    )
    context = RunContext(
        TENANT,
        Identity("operator", TENANT, roles=("operator",)),
        store=store,
        scope=scope,
        project_root=str(workspace),
        run_id="run-fallback-real",
    )
    shell_sandbox = _RecordingShellSandbox()
    with mock.patch.object(module, "sandbox_for_environment", lambda *a, **k: _FakeSandbox(_AUTH_FAILED)), \
            mock.patch.object(module.shutil, "which", lambda _: "/usr/bin/sshpass"), \
            mock.patch.object(
                shell_exec_local, "sandbox_for_environment", lambda *a, **k: shell_sandbox
            ):
        result = asyncio.run(
            ssh_exec_handler(
                {"target": TARGET, "username": "mitch", "password": PASSWORD, "command": "id"},
                context,
            )
        )

    assert result.verified is True, result.output
    assert result.verification_method == "ssh_exec_sshpass_completed"
    assert "uid=0(root) gid=0(root)" in result.output["stdout"]
    # A verified Plan B derives the same facts as the paramiko channel.
    from types import SimpleNamespace

    from nexus_core.kernel.fact_verification import derive_assertions

    assertions = derive_assertions(
        "nexus.post.ssh_exec",
        {"username": "mitch"},
        result,
        SimpleNamespace(invocation_id="inv-real", run_id="run-fallback-real"),
    )
    assert {row["fact_type"] for row in assertions} == {"access", "privilege"}
    assert shell_sandbox.input_data == (PASSWORD + "\n").encode("utf-8")
    assert shell_sandbox.argv[0] == "bash"
    assert shell_sandbox.argv[1] == "-lc"
    command = shell_sandbox.argv[2]
    assert command.startswith("sshpass -d 0 ssh ")
    assert f"mitch@{TARGET}" in command
    assert PASSWORD not in command


def test_a_failed_fallback_is_a_command_failure_not_a_broken_post_condition(tmp_path):
    """The replay ran and exited non-zero: determinate, and the run continues."""
    context = _context(tmp_path)
    sandbox = _FakeSandbox(_AUTH_FAILED)

    async def failing_shell(arguments, ctx):
        return ToolResult(
            output={"summary": "ssh: connect to host timed out\n", "artifact_ref": "art-2"},
            verified=False,
            verification_method="shell_exit_code",
            exit_code=1,
            stdout="ssh: connect to host timed out\n",
        )

    with mock.patch.object(module, "sandbox_for_environment", lambda *a, **k: sandbox), \
            mock.patch.object(module.shutil, "which", lambda _: "/usr/bin/sshpass"), \
            mock.patch.object(shell_exec_local, "shell_exec_handler", failing_shell):
        result = asyncio.run(
            ssh_exec_handler(
                {"target": TARGET, "username": "mitch", "password": PASSWORD, "command": "id"},
                context,
            )
        )

    assert result.verified is False
    assert result.completed is True
    assert result.outcome == "command_failed"
    assert result.verification_method == "ssh_exec_sshpass_failed"
    assert result.evidence["exit_status"] == 1
