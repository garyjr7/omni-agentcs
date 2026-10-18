"""WP1: the universal shell executes, times out, refuses and archives.

The acceptance list of the plan asks for four behaviours and nothing else:
``echo`` works, a timeout is a determinate result (not a crash), the deny list
refuses a prohibited command, and the full output is a content-addressed
artifact with its sha256.
"""

from __future__ import annotations

import asyncio
import hashlib
import os
import signal
import time
from contextlib import suppress
from pathlib import Path

import pytest

from nexus_core.cli.engage import build_scope
from nexus_core.kernel.artifacts import configured_artifact_store
from nexus_core.kernel.audit import AuditWriter
from nexus_core.kernel.control_store import ControlStore
from nexus_core.kernel.models import Identity, RunContext
from nexus_core.scope import EngagementStore
from nexus_core.tools.handlers.report_generate import default_artifact_root
from nexus_core.tools.handlers.shell_exec_local import (
    ShellExecRequest,
    is_background_command,
    shell_exec_definition,
    shell_exec_handler,
    workspace_root,
)

SECRET = "test-signing-secret"
TARGET = "10.10.10.5"


@pytest.fixture()
def context(tmp_path, monkeypatch):
    """A signed engagement and an isolated workspace/artifact root."""
    monkeypatch.setenv("NEXUS_SCOPE_SIGNING_SECRET", SECRET)
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
        run_id="run-shell-test",
    )


def _run(context, arguments: dict):
    return asyncio.run(shell_exec_handler(arguments, context))


def test_definition_is_high_risk_execution():
    definition = shell_exec_definition()
    assert definition.risk.value == "high"
    assert definition.effect == "execution"
    assert definition.sandbox_required is True
    assert definition.scope_required is True
    assert set(ShellExecRequest.model_json_schema()["properties"]) == {
        "command", "cwd", "timeout_seconds", "stdin",
    }


def test_shell_exec_runs_echo_hola(context):
    result = _run(context, {"command": "echo hola"})
    assert result.verified is True
    assert result.exit_code == 0
    assert "hola" in result.output["summary"]
    assert result.output["artifact_ref"].startswith("artifact_")


def test_shell_exec_timeout_is_a_result_with_partial_artifact(context):
    # 64 KiB of stdin to a child that never reads it: the feed must not stall
    # the timeout (the sandbox writes stdin concurrently with the deadline).
    result = _run(context, {
        "command": "echo antes; sleep 30",
        "timeout_seconds": 5,
        "stdin": "x" * 65536,
    })
    assert result.timed_out is True
    assert result.verified is False
    assert result.outcome == "timeout"
    # What the command produced before the deadline is not lost.
    artifact = configured_artifact_store(
        context.store, default_artifact_root()
    ).get(context.tenant_id, result.output["artifact_ref"])
    assert b"antes" in artifact


def test_shell_exec_feeds_stdin(context):
    result = _run(context, {"command": "cat", "stdin": "hola stdin"})
    assert result.verified is True
    assert "hola stdin" in result.output["summary"]


def test_shell_exec_refuses_a_prohibited_command(context):
    result = _run(context, {"command": "sudo id"})
    assert result.verified is False
    assert result.outcome == "denied"
    assert result.verification_method == "shell_command_denied"
    assert "deny list" in result.output["error"]
    events = AuditWriter(context.store).export(context.tenant_id, trace_id=context.trace_id)
    denied = [event for event in events if event["action"] == "shell.exec"]
    assert denied and denied[-1]["decision"] == "deny"


def test_shell_exec_records_the_sshpass_channel_it_was_asked_to_run(context):
    """An ``sshpass`` login is a channel, not an opaque local process (V1-49).

    The command cannot start ``sshpass`` (the assignment empties ``PATH``), so the
    call is cheap and offline: the point is that the handler *reports* which host
    the command was going to reach, never the password it carried.
    """
    result = _run(context, {
        "command": "PATH=/nonexistent sshpass -p 'cyber' ssh -p 2222 "
                   "mitch@10.10.10.5 'id'",
    })

    assert result.evidence["ssh_channels"] == [
        {"target": "10.10.10.5", "username": "mitch", "port": 2222,
         "command": "id"},
    ]
    assert "cyber" not in str(result.evidence)


def test_shell_exec_without_sshpass_reports_no_channel(context):
    result = _run(context, {"command": "echo hola"})
    assert "ssh_channels" not in result.evidence


class _FakeSandbox:
    """A sandbox that answers with a canned ``SandboxResult`` (no process)."""

    def __init__(self, result) -> None:
        self.result = result
        self.calls: list[list[str]] = []

    async def run(self, argv, *, timeout_seconds: float = 30):
        self.calls.append(list(argv))
        return self.result


def _with_sandbox(result):
    from unittest import mock

    import nexus_core.tools.handlers.shell_exec_local as shell_module

    sandbox = _FakeSandbox(result)
    return mock.patch.object(shell_module, "sandbox_for_environment", lambda *a, **k: sandbox)


def test_an_sshpass_run_feeds_the_board_and_closes_the_objective(context, tmp_path, monkeypatch):
    """The real handler output shape is what the verifier must read (V1-49).

    Until this branch existed the run captured both flags over ``sshpass`` and
    closed with ``objective_complete=false``; here the same two commands go
    through the sandbox, the verifier and the blackboard, and the objective is
    reported met.
    """
    from dataclasses import replace

    from nexus_core.agent.planner import build_plan, objective_completion
    from nexus_core.kernel.blackboard import Blackboard
    from nexus_core.kernel.fact_verification import derive_assertions, persist_assertions
    from nexus_core.kernel.sandbox import SandboxResult

    monkeypatch.setenv("NEXUS_VAULT_ROOT", str(tmp_path / "vault"))
    runs = [
        ("sshpass -p 'guessed' ssh -p 2222 mitch@10.10.10.5 'id'",
         "uid=0(root) gid=0(root) groups=0(root)\n"),
        ("sshpass -p 'guessed' ssh -p 2222 mitch@10.10.10.5 'sudo cat /root/root.txt'",
         "W3ll d0n3. You made it!\n"),
    ]
    for index, (command, stdout) in enumerate(runs):
        run_context = replace(context, invocation_id=f"inv-{index}")
        with _with_sandbox(SandboxResult(0, stdout, "")):
            result = asyncio.run(shell_exec_handler({"command": command}, run_context))
        assert result.verified is True
        # The gateway validates every result before deriving assertions.
        result.to_dto()
        persist_assertions(
            derive_assertions("nexus.shell.exec", {"command": command}, result, run_context),
            run_context, "nexus.shell.exec",
        )

    facts = Blackboard(context.store).list_facts("system", context.scope.engagement_id)
    derived = {fact["fact_type"] for fact in facts
               if fact.get("verification_method") == "shell_sshpass_completed"}
    assert {"access", "credential", "privilege", "loot"} <= derived
    assert {fact["source"] for fact in facts
            if fact.get("verification_method") == "shell_sshpass_completed"} == {
        "nexus.shell.exec"}

    assert objective_completion(facts).complete is True
    statuses = {phase.id: phase.status for phase in build_plan(facts=facts).phases}
    assert statuses["exploitation"] == "done"
    assert statuses["privilege_escalation"] == "done"


# --------------------------------------------------------------- V1-51 · background


@pytest.mark.parametrize(
    "command,expected",
    [
        ("nohup python3 worker.py > out.txt 2>&1 &", True),
        ("nohup python3 worker.py", True),
        ("sqlmap -u http://t/ --batch &", True),
        ("echo hi &", True),
        ("echo hi && echo bye", False),
        ("cmd 2>&1 | tee log", False),
        ("cmd &> out.txt", False),
        ("curl -s 'http://t/?a=1&b=2'", False),
        ("echo 'a & b'", False),
    ],
)
def test_only_a_real_ampersand_is_a_background_operator(command, expected):
    """``&&``, ``&>``, ``2>&1`` and quoted ``&`` are not background requests."""
    assert is_background_command(command) is expected


def _kill(pid: int | None) -> None:
    if not pid:
        return
    with suppress(ProcessLookupError, PermissionError):
        os.killpg(pid, signal.SIGKILL)


def test_a_background_command_returns_at_once_with_its_pid(context):
    """The measured hang: ``nohup ... &`` blocked until the 60 s timeout.

    The wrapper detaches the child with ``setsid`` and redirects its stdio, so
    the handler answers with the PID instead of waiting for a job it was told to
    leave running. The child's output is not lost: it goes to the workspace log
    the observation names.
    """
    started = time.monotonic()
    result = _run(context, {
        "command": "nohup sh -c 'sleep 1; printf hola-bg' &",
        "timeout_seconds": 60,
    })
    elapsed = time.monotonic() - started

    assert elapsed < 10, "a background launch must not wait for the job"
    assert result.verified is True and result.timed_out is False
    # The gateway validates every result before it becomes an observation.
    assert result.success is True and result.to_dto().outcome == "success"
    assert result.verification_method == "shell_background_launched"
    assert result.output["background"] is True and result.output["launched"] is True
    pid = result.output["pid"]
    assert isinstance(pid, int) and pid > 0
    assert result.evidence["pid"] == pid

    log = Path(workspace_root()) / result.output["log"]
    try:
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline and "hola-bg" not in (
            log.read_text() if log.is_file() else ""
        ):
            time.sleep(0.1)
        assert "hola-bg" in log.read_text()
    finally:
        _kill(pid)


def test_a_background_command_never_holds_the_handler_pipes(context):
    """``nohup python -c 'sleep 30' &`` returns in seconds, not in 60."""
    started = time.monotonic()
    result = _run(context, {
        "command": "nohup python3 -c 'import time; time.sleep(30)' >/dev/null 2>&1 &",
        "timeout_seconds": 60,
    })
    elapsed = time.monotonic() - started
    try:
        assert elapsed < 10
        assert result.verified is True
        assert result.output["pid"] > 0
    finally:
        _kill(result.output["pid"])


def test_a_background_command_is_audited_as_such(context):
    result = _run(context, {"command": "sleep 5 &", "timeout_seconds": 30})
    _kill(result.output["pid"])
    events = AuditWriter(context.store).export(context.tenant_id, trace_id=context.trace_id)
    audited = [event for event in events if event["action"] == "shell.exec"]
    assert audited[-1]["payload"]["reason"] == "background"


def test_a_foreground_list_is_not_detached(context):
    result = _run(context, {"command": "echo uno && echo dos"})
    assert result.verified is True
    assert "uno" in result.output["summary"] and "dos" in result.output["summary"]
    assert result.verification_method == "shell_exit_code"


def test_the_oci_sandbox_refuses_background_work_explicitly(context):
    """An ephemeral container cannot keep a detached process alive: say so."""
    from unittest import mock

    import nexus_core.tools.handlers.shell_exec_local as shell_module
    from nexus_core.kernel.sandbox import OCISandbox

    sandbox = OCISandbox(workspace_root(), allowed_images=["x"])
    with mock.patch.object(shell_module, "sandbox_for_environment", lambda *a, **k: sandbox):
        result = _run(context, {"command": "sleep 30 &"})

    assert result.verified is False
    assert result.outcome == "unavailable"
    assert result.verification_method == "shell_background_unavailable"
    assert "timeout_seconds" in result.output["guidance"]


def test_shell_exec_archives_full_stdout_and_stderr(context):
    result = _run(context, {"command": "printf 'hola\\nque tal\\n'; echo oops >&2"})
    reference = result.output["artifact_ref"]
    content = configured_artifact_store(
        context.store, default_artifact_root()
    ).get(context.tenant_id, reference)
    assert b"hola" in content
    assert b"oops" in content
    assert hashlib.sha256(content).hexdigest() == result.output["sha256"]
    events = AuditWriter(context.store).export(context.tenant_id, trace_id=context.trace_id)
    audited = [event for event in events if event["action"] == "shell.exec"]
    assert audited and audited[-1]["payload"]["exit_code"] == 0
