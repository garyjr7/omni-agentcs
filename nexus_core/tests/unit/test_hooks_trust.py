"""P2-A closure: explicit operator trust, workspace binding, session_end.

Covers the three P2-A gaps the checkpoint left open:

* A1 — repository hooks are only loaded after a human operator approves their
  exact revision (``omni hooks trust``), and any edit revokes that trust;
* A2 — the engagement workspace/engagement are passed explicitly to
  ``HookRunner`` (never read from the process cwd) on every route;
* A3 — ``run_react_loop`` emits ``session_end`` exactly once, including when the
  engine raises, and a hook can never swallow the engine error.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import sys

import pytest

from nexus_core.agent.react import ReActConfig, run_react_loop
from nexus_core.cli import hooks_cli
from nexus_core.hooks import (
    HookRunner,
    approve_project_hooks,
    project_hooks_path,
    revoke_project_hooks,
    trusted_project_hooks,
)
from nexus_core.kernel.audit import AuditWriter
from nexus_core.kernel.models import Identity
from nexus_core.kernel.runtime import ExecutionContext
from nexus_core.tests.unit.test_hooks_lifecycle import context
from nexus_core.tests.unit.test_react_loop import ScriptedLLM, create_scope, task_complete

# The engine tests build unsigned engagement scopes on purpose (they exercise
# hooks, not scope authentication), so they run in the lab scope mode.
pytestmark = pytest.mark.usefixtures("lab_scope")


def human(tenant: str = "system") -> Identity:
    return Identity("alice", tenant, kind="human", roles=("operator",))


def write_project_hooks(root, *, event="pre_tool_use", code='print("{}")'):
    path = root / ".agents" / "hooks.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"hooks": {event: [
        {"name": "probe", "command": [sys.executable, "-c", code], "timeout": 5}]}}))
    return path


def capture_hooks(tmp_path, events, outdir, *, decision_code=None):
    """Global hooks that dump the JSON payload they receive, one file per event."""
    outdir.mkdir(parents=True, exist_ok=True)
    body = decision_code or (
        "import sys,json; from pathlib import Path; "
        "d=json.loads(sys.stdin.read()); "
        f"p=Path({str(outdir)!r}); p.mkdir(parents=True,exist_ok=True); "
        "(p/(d['event']+'.json')).write_text(json.dumps(d)); print('{{}}')"
    )
    script = tmp_path / f"capture-{'-'.join(events)}.py"
    script.write_text(body)
    path = tmp_path / "config" / "omni" / "hooks.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"hooks": {
        event: [{"name": event, "command": [sys.executable, str(script)], "timeout": 10}]
        for event in events}}))
    return path


def engine_context(store, workspace, *, agent_id="omni", engagement_id="eng-1"):
    run = store.create_run("system", {})
    payload = {
        "objective": "recon",
        "engagement_id": engagement_id,
        "project_root": str(workspace),
        "agent_id": agent_id,
        "identity": {"subject_id": "op", "roles": ["operator"]},
    }
    task = {"id": "t", "tenant_id": "system", "run_id": run["id"],
            "task_type": "react.run", "payload": payload}
    return ExecutionContext(store, task, "worker-test")


# --------------------------------------------------------------------------- A1


def test_hooks_trust_requires_explicit_hash(tmp_path, monkeypatch):
    context(tmp_path, monkeypatch)
    write_project_hooks(tmp_path)
    with pytest.raises(ValueError, match="hash"):
        approve_project_hooks(tmp_path, human(), expected_hash="0" * 64)
    digest = hashlib.sha256(project_hooks_path(tmp_path).read_bytes()).hexdigest()
    record = approve_project_hooks(tmp_path, human(), expected_hash=digest)
    assert record["sha256"] == digest


def test_hooks_config_change_revokes_trust(tmp_path, monkeypatch):
    ctx = context(tmp_path, monkeypatch)
    path = write_project_hooks(tmp_path)
    approve_project_hooks(tmp_path, human())
    assert HookRunner(ctx, project_root=tmp_path).project_trusted
    path.write_text(json.dumps({"hooks": {"pre_tool_use": []}}))
    runner = HookRunner(ctx, project_root=tmp_path)
    assert not runner.project_trusted
    assert asyncio.run(runner.emit("pre_tool_use")) == []
    assert any(e["action"] == "hook.untrusted" for e in AuditWriter(ctx.store).export("system"))


def test_hooks_revoke_removes_approval(tmp_path, monkeypatch):
    context(tmp_path, monkeypatch)
    write_project_hooks(tmp_path)
    approve_project_hooks(tmp_path, human())
    assert trusted_project_hooks()
    assert revoke_project_hooks(tmp_path) is True
    assert trusted_project_hooks() == []
    assert revoke_project_hooks(tmp_path) is False


def test_project_hooks_without_trust_are_not_loaded(tmp_path, monkeypatch):
    ctx = context(tmp_path, monkeypatch)
    write_project_hooks(tmp_path, code='print(\'{"decision":"block","reason":"nope"}\')')
    runner = HookRunner(ctx, project_root=tmp_path)
    assert runner.entries == [] and not runner.project_trusted
    assert asyncio.run(runner.emit("pre_tool_use")) == []
    assert any(e["action"] == "hook.untrusted" for e in AuditWriter(ctx.store).export("system"))


def test_hooks_cli_trust_list_revoke(tmp_path, monkeypatch, capsys):
    context(tmp_path, monkeypatch)
    write_project_hooks(tmp_path)
    assert hooks_cli.run_hooks_command(
        ["trust", str(tmp_path), "--yes"], "system") == 0
    assert hooks_cli.run_hooks_command(["list"], "system") == 0
    listed = capsys.readouterr().out
    assert "sha256=" in listed and str(tmp_path) in listed
    assert trusted_project_hooks()
    assert hooks_cli.run_hooks_command(["revoke", str(tmp_path)], "system") == 0
    assert not trusted_project_hooks()
    assert hooks_cli.run_hooks_command(["revoke", str(tmp_path)], "system") == 1


def test_hooks_cli_declined_confirmation_does_not_trust(tmp_path, monkeypatch):
    context(tmp_path, monkeypatch)
    write_project_hooks(tmp_path)
    code = hooks_cli.run_hooks_command(
        ["trust", str(tmp_path)], "system", reader=lambda prompt: "n")
    assert code == 1
    assert not trusted_project_hooks()


# --------------------------------------------------------------------------- A2


def test_hooks_see_engagement_id_consistently(tmp_path, monkeypatch):
    ctx = context(tmp_path, monkeypatch)
    workspace = tmp_path / "engagement-ws"
    workspace.mkdir()
    outdir = tmp_path / "captured"
    capture_hooks(tmp_path, ["session_start", "pre_tool_use", "post_tool_use", "session_end"], outdir)
    runner = HookRunner(ctx, engagement_id="eng-9", workspace=str(workspace))
    for event in ("session_start", "pre_tool_use", "post_tool_use", "session_end"):
        asyncio.run(runner.emit(event))
    for event in ("session_start", "pre_tool_use", "post_tool_use", "session_end"):
        payload = json.loads((outdir / f"{event}.json").read_text())
        assert payload["engagement_id"] == "eng-9"
        assert payload["workspace"] == str(workspace)


def test_session_start_receives_workspace_in_repl_headless_worker(tmp_path, monkeypatch):
    ctx = context(tmp_path, monkeypatch)
    workspace = tmp_path / "engagement-ws"
    workspace.mkdir()
    outdir = tmp_path / "captured"
    capture_hooks(tmp_path, ["session_start"], outdir)
    create_scope(ctx.store, "eng-1")
    wrong_cwd = tmp_path / "wrong-cwd"
    wrong_cwd.mkdir()
    monkeypatch.chdir(wrong_cwd)
    for route in ("repl", "headless", "worker"):
        exec_ctx = engine_context(ctx.store, workspace, agent_id=route)
        llm = ScriptedLLM([task_complete("done")])
        asyncio.run(run_react_loop(
            context=exec_ctx, objective="recon", engagement_id="eng-1", llm_client=llm,
            config=ReActConfig(enforce_completion_gates=False)))
        payload = json.loads((outdir / "session_start.json").read_text())
        assert payload["workspace"] == str(workspace)
        assert payload["engagement_id"] == "eng-1"


# --------------------------------------------------------------------------- A3


def test_session_end_on_engine_exception(tmp_path, monkeypatch):
    ctx = context(tmp_path, monkeypatch)
    workspace = tmp_path / "ws"
    workspace.mkdir()
    outdir = tmp_path / "captured"
    capture_hooks(tmp_path, ["session_end"], outdir)
    create_scope(ctx.store, "eng-1")
    exec_ctx = engine_context(ctx.store, workspace)

    import nexus_core.agent.react as react_module

    async def explode(**kwargs):
        raise RuntimeError("engine exploded")

    monkeypatch.setattr(react_module, "_run_react_loop_impl", explode)
    with pytest.raises(RuntimeError, match="exploded"):
        asyncio.run(run_react_loop(
            context=exec_ctx, objective="recon", engagement_id="eng-1", llm_client=None,
            config=ReActConfig(enforce_completion_gates=False)))
    payload = json.loads((outdir / "session_end.json").read_text())
    assert payload["event"] == "session_end"
    assert payload["status"] == "exception"
    assert payload["reason"] == "exception"


def test_session_end_audit_trail_on_crash(tmp_path, monkeypatch):
    ctx = context(tmp_path, monkeypatch)
    workspace = tmp_path / "ws"
    workspace.mkdir()
    outdir = tmp_path / "captured"
    # A session_end hook that *blocks* must still not swallow the engine error.
    capture_hooks(
        tmp_path, ["session_end"], outdir,
        decision_code='print(\'{"decision":"block","reason":"stop refused"}\')')
    create_scope(ctx.store, "eng-1")
    exec_ctx = engine_context(ctx.store, workspace)

    import nexus_core.agent.react as react_module

    async def explode(**kwargs):
        raise RuntimeError("engine exploded")

    monkeypatch.setattr(react_module, "_run_react_loop_impl", explode)
    with pytest.raises(RuntimeError, match="exploded"):
        asyncio.run(run_react_loop(
            context=exec_ctx, objective="recon", engagement_id="eng-1", llm_client=None,
            config=ReActConfig(enforce_completion_gates=False)))
    events = AuditWriter(ctx.store).export("system")
    assert any(
        e["action"] == "hook.blocked" and e["payload"]["event"] == "session_end"
        for e in events
    )
