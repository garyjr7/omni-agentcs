"""WP1/P0: persistent PTY sessions (governed, redacted, artifact-backed).

These tests need a real ``tmux`` on the host for the lifecycle cases; they skip
cleanly when it is absent so the offline suite stays hermetic. The session socket
is per-run, so they never touch the operator's own tmux server. The guard,
lexical and redaction cases run without tmux.
"""

from __future__ import annotations

import asyncio
import shutil
from dataclasses import replace
from uuid import uuid4

import pytest
from pydantic import ValidationError

from nexus_core.cli.engage import build_scope
from nexus_core.kernel.artifacts import configured_artifact_store
from nexus_core.kernel.blackboard import Blackboard
from nexus_core.kernel.control_store import ControlStore
from nexus_core.kernel.fact_verification import derive_assertions
from nexus_core.kernel.models import Identity, RunContext, ToolResult
from nexus_core.kernel.pty_sessions import PtyResult, PtySessionManager
from nexus_core.kernel.sandbox import OCISandbox
from nexus_core.kernel.secret_store import default_secret_store
from nexus_core.scope import EngagementStore
from nexus_core.tools.handlers.report_generate import default_artifact_root
from nexus_core.tools.handlers.session_pty import (
    PTY_SUMMARY_LINES,
    PtyRequest,
    session_pty_definition,
    session_pty_handler,
)

SECRET = "test-signing-secret"
VAULT_SECRET = "Sup3rS3cret!2026"
TARGET = "10.10.10.5"

pytestmark = pytest.mark.skipif(
    shutil.which("tmux") is None, reason="tmux is required for PTY sessions"
)


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
        # Unique per test *and* per pytest session: a leaked tmux server from an
        # interrupted run can never make an unrelated test see its session.
        run_id=f"run_pty_{uuid4().hex[:8]}",
    )


def _run(context, arguments: dict):
    return asyncio.run(session_pty_handler(arguments, context))


def _fake_capture(output: str):
    async def capture(self, name: str, *, lines: int = 200) -> PtyResult:
        return PtyResult(session_id="omni-test-shell", alive=True, output=output)

    return capture


def test_definition_is_a_high_risk_session_tool():
    definition = session_pty_definition()
    assert definition.risk.value == "high"
    assert definition.effect == "execution"
    assert definition.sandbox_required is True
    # The schema itself refuses a wait longer than the plan's 60 s ceiling.
    assert PtyRequest.model_json_schema()["properties"]["timeout_seconds"]["maximum"] == 60


def test_wait_longer_than_sixty_seconds_is_rejected_by_the_contract(context):
    with pytest.raises(ValidationError):
        _run(
            context,
            {"action": "wait", "name": "shell", "pattern": "x", "timeout_seconds": 61},
        )


def test_oci_sandbox_fails_explicitly_before_tmux(context, monkeypatch, tmp_path):
    oci = OCISandbox(str(tmp_path), allowed_images=["python:3.12-alpine"])
    monkeypatch.setattr(PtySessionManager, "sandbox", lambda self: oci)
    result = _run(context, {"action": "start", "name": "shell", "cmd": "bash"})
    assert result.verified is False
    assert result.outcome == "unavailable"
    assert result.verification_method == "pty_requires_persistent_sandbox"
    assert result.output["reason"] == "pty_requires_persistent_sandbox"


@pytest.mark.parametrize(
    ("text", "method", "outcome"),
    [
        ("sleep 30", "pty_passive_wait_denied", "denied"),
        ("sudo id", "pty_command_denied", "denied"),
        ("curl http://evil.example/x", "pty_scope_denied", "scope_denied"),
    ],
)
def test_send_refuses_wait_denylist_and_out_of_scope_fetch(
    context, text, method, outcome
):
    result = _run(context, {"action": "send", "name": "shell", "text": text})
    assert result.verified is False
    assert result.outcome == outcome
    assert result.verification_method == method
    assert result.output["command"] == text


def test_start_refuses_an_out_of_scope_fetch_too(context):
    result = _run(
        context,
        {"action": "start", "name": "shell", "cmd": "curl http://evil.example/x"},
    )
    assert result.verification_method == "pty_scope_denied"
    # Nothing was started: no session exists to capture.
    captured = _run(context, {"action": "capture", "name": "shell"})
    assert captured.output["error"] == "session_not_found"


def test_capture_returns_artifact_and_a_bounded_summary(context, monkeypatch):
    lines = "\n".join(f"line-{index}" for index in range(100))
    monkeypatch.setattr(
        PtySessionManager, "capture", _fake_capture(f"{lines}\nuid=0(root) gid=0(root)\n")
    )
    result = _run(context, {"action": "capture", "name": "shell", "lines": 200})
    assert result.verified is True
    assert result.output["artifact_ref"].startswith("artifact_")
    assert result.output["sha256"]
    assert result.output["capture_lines"] == 101
    # The prompt gets the evidence line plus a bounded tail, not 100 lines.
    assert "uid=0(root)" in result.output["output"]
    assert result.output["output"].count("\n") <= PTY_SUMMARY_LINES + 4
    assert len(result.output["output"]) < 2_000
    stored = configured_artifact_store(
        context.store, default_artifact_root()
    ).get("system", result.output["artifact_ref"])
    assert b"line-99" in stored


def test_capture_redacts_a_secret_known_to_the_vault(context, monkeypatch):
    ref = default_secret_store().put(VAULT_SECRET, kind="credential", tenant_id="system")
    Blackboard(context.store).record(
        tenant_id="system",
        engagement_id=context.scope.engagement_id,
        fact_type="credential",
        key=f"cred:ssh:lin@{TARGET}",
        value={"username": "lin", "secret_ref": ref, "service": "ssh"},
        source="test",
        created_by="test",
        verified=True,
        asserted_by="verifier",
        verification_method="test_verifier",
        invocation_id="inv-1",
    )
    monkeypatch.setattr(
        PtySessionManager,
        "capture",
        _fake_capture(f"[sudo] password for lin: {VAULT_SECRET}\nuid=33(www-data)\n"),
    )
    result = _run(context, {"action": "capture", "name": "shell"})
    assert VAULT_SECRET not in result.output["output"]
    assert VAULT_SECRET not in result.stdout
    assert "[REDACTED]" in result.output["output"]
    stored = configured_artifact_store(
        context.store, default_artifact_root()
    ).get("system", result.output["artifact_ref"]).decode("utf-8")
    assert VAULT_SECRET not in stored
    assert "[REDACTED]" in stored


def test_capture_without_evidence_is_an_unverified_observation(context, monkeypatch):
    monkeypatch.setattr(PtySessionManager, "capture", _fake_capture("hello world\n"))
    result = _run(context, {"action": "capture", "name": "shell"})
    assert result.verified is True
    assert result.output["observation_status"] == "unverified_observation"


def test_capture_assertions_derive_loot_and_privilege(context):
    derive_context = replace(context, invocation_id="inv-pty-1")
    result = ToolResult(
        output={
            "session_id": "omni-test-shell",
            "output": "uid=0(root) gid=0(root)\nflag{fake_flag}\n",
        },
        verified=True,
        verification_method="pty_capture",
    )
    rows = derive_assertions(
        "nexus.session.pty", {"action": "capture"}, result, derive_context
    )
    kinds = {row["fact_type"] for row in rows}
    assert kinds == {"loot", "privilege"}
    loot = next(row for row in rows if row["fact_type"] == "loot")
    assert loot["value"]["flag"] == "flag{fake_flag}"
    assert loot["value"]["service"] == "pty"


def test_capture_without_a_flag_or_root_derives_no_fact(context):
    derive_context = replace(context, invocation_id="inv-pty-2")
    result = ToolResult(
        output={"session_id": "omni-test-shell", "output": "hello world\n"},
        verified=True,
        verification_method="pty_capture",
    )
    assert derive_assertions(
        "nexus.session.pty", {"action": "capture"}, result, derive_context
    ) == []


def test_pty_start_is_alive_and_kill_closes_the_session(context):
    started = _run(context, {"action": "start", "name": "shell", "cmd": "bash"})
    assert started.verified is True, started.output
    assert started.output["alive"] is True
    assert started.output["session_id"].startswith("omni-")

    killed = _run(context, {"action": "kill", "name": "shell"})
    assert killed.verified is True, killed.output
    assert killed.output["alive"] is False

    captured = _run(context, {"action": "capture", "name": "shell"})
    assert captured.verified is False
    assert captured.output["error"] == "session_not_found"


def test_pty_send_and_capture_returns_the_echo(context):
    started = _run(context, {"action": "start", "name": "shell", "cmd": "bash"})
    assert started.verified is True, started.output
    sent = _run(context, {"action": "send", "name": "shell", "text": "echo 123"})
    assert sent.verified is True, sent.output
    waited = _run(
        context,
        {"action": "wait", "name": "shell", "pattern": r"^123$", "timeout_seconds": 10},
    )
    assert waited.verified is True, waited.output
    assert "123" in waited.output["output"]
    assert waited.output["artifact_ref"].startswith("artifact_")
    # The session survives the call that read it: that is the whole point.
    assert waited.output["alive"] is True
    _run(context, {"action": "kill", "name": "shell"})


def test_reaper_closes_every_session_of_the_run(context):
    started = _run(context, {"action": "start", "name": "shell", "cmd": "bash"})
    assert started.verified is True, started.output
    manager = PtySessionManager(context.project_root, context.run_id)
    assert asyncio.run(manager.reap()) >= 1
    captured = _run(context, {"action": "capture", "name": "shell"})
    assert captured.output["error"] == "session_not_found"


def test_pty_capture_unknown_session_is_reported(context):
    captured = _run(context, {"action": "capture", "name": "missing"})
    assert captured.verified is False
    assert captured.output["error"] == "session_not_found"
