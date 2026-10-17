"""WP1: the universal shell executes, times out, refuses and archives.

The acceptance list of the plan asks for four behaviours and nothing else:
``echo`` works, a timeout is a determinate result (not a crash), the deny list
refuses a prohibited command, and the full output is a content-addressed
artifact with its sha256.
"""

from __future__ import annotations

import asyncio
import hashlib

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
    shell_exec_definition,
    shell_exec_handler,
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
