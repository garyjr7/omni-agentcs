"""P2-D3 closure: the operator decides what happens to ``unknown`` invocations.

``omni resume <run>`` lists the steps whose outcome is unknown; a retry needs a
durable human approval bound to that very invocation, and a skip records the
operator's no-effect decision. Headless runs choose a policy instead of
prompting, and ``approve`` never fabricates an approval.
"""
from __future__ import annotations

import pytest

from nexus_core.cli.resume_cli import apply_resume_policy, run_resume_command
from nexus_core.kernel.invocation_journal import InvocationJournal
from nexus_core.tests.unit.test_hooks_lifecycle import context


def unknown_invocation(ctx):
    journal = InvocationJournal(ctx.store)
    item = journal.prepare(ctx, "probe", {}, "")
    journal.start(item["invocation_id"], "system")
    journal.recover(ctx, lease_id="test-worker")
    return item


def test_resume_lists_unknown_invocations(tmp_path, monkeypatch, capsys):
    ctx = context(tmp_path, monkeypatch)
    item = unknown_invocation(ctx)
    code = run_resume_command([item["run_id"]], ctx.store, "system")
    out = capsys.readouterr().out
    assert code == 0
    assert item["invocation_id"] in out
    assert "tool=probe" in out


def test_resume_of_clean_run_is_empty(tmp_path, monkeypatch, capsys):
    ctx = context(tmp_path, monkeypatch)
    assert run_resume_command(["no-such-run"], ctx.store, "system") == 0
    assert "unknown" in capsys.readouterr().out


def test_resume_requires_approval_for_retry(tmp_path, monkeypatch):
    ctx = context(tmp_path, monkeypatch)
    item = unknown_invocation(ctx)
    # Without a durable approval the headless policy blocks.
    assert apply_resume_policy(ctx.store, "system", item["run_id"], "approve") == "blocked"
    assert run_resume_command(
        ["--retry", item["invocation_id"]], ctx.store, "system") == 0
    # The approval is bound to this invocation and unblocks the run.
    assert apply_resume_policy(ctx.store, "system", item["run_id"], "approve") == "continue"


def test_resume_skip_marks_failed_no_effect(tmp_path, monkeypatch):
    ctx = context(tmp_path, monkeypatch)
    item = unknown_invocation(ctx)
    assert run_resume_command(
        ["--skip", item["invocation_id"]], ctx.store, "system") == 0
    assert InvocationJournal(ctx.store).get(
        item["invocation_id"], "system")["state"] == "failed"


def test_resume_rejects_unknown_invocation(tmp_path, monkeypatch):
    ctx = context(tmp_path, monkeypatch)
    assert run_resume_command(["--retry", "nope"], ctx.store, "system") == 2
    assert run_resume_command([], ctx.store, "system") == 2


def test_headless_resume_policies(tmp_path, monkeypatch):
    ctx = context(tmp_path, monkeypatch)
    assert apply_resume_policy(ctx.store, "system", "clean-run", "approve") == "continue"
    item = unknown_invocation(ctx)
    assert apply_resume_policy(ctx.store, "system", item["run_id"], "fail") == "failed"
    assert apply_resume_policy(ctx.store, "system", item["run_id"], "approve") == "blocked"
    assert apply_resume_policy(ctx.store, "system", item["run_id"], "skip") == "continue"
    assert InvocationJournal(ctx.store).get(
        item["invocation_id"], "system")["state"] == "failed"


def test_headless_resume_policy_rejects_unknown_value(tmp_path, monkeypatch):
    ctx = context(tmp_path, monkeypatch)
    with pytest.raises(ValueError):
        apply_resume_policy(ctx.store, "system", "r", "yolo")
