"""P2-D2 closure: lease fencing never mistakes a live worker for a crashed one.

``kernel_invocations.lease_id`` records the worker that owns an in-flight
invocation. Recovery only reconciles invocations whose lease is empty or belongs
to the recovering worker, so a *second* worker cannot touch a step another live
worker is still running, and a reclaimed step is left ``unknown`` (never
replayed automatically).
"""
from __future__ import annotations

import asyncio
from dataclasses import replace

from nexus_core.kernel.audit import AuditWriter
from nexus_core.kernel.invocation_journal import InvocationJournal
from nexus_core.tests.unit.test_hooks_lifecycle import context
from nexus_core.tests.unit.test_invocation_journal import gateway


def running_invocation(ctx, *, lease):
    journal = InvocationJournal(ctx.store)
    item = journal.prepare(ctx, "probe", {}, "", lease_id=lease)
    journal.start(item["invocation_id"], "system")
    return journal, item


def test_running_invocation_not_touched_while_lease_active(tmp_path, monkeypatch):
    ctx = context(tmp_path, monkeypatch)
    journal, item = running_invocation(ctx, lease="worker-A")
    assert journal.recover(replace(ctx, worker_id="worker-B"), lease_id="worker-B") == 0
    assert journal.get(item["invocation_id"], "system")["state"] == "running"


def test_expired_lease_marks_unknown(tmp_path, monkeypatch):
    ctx = context(tmp_path, monkeypatch)
    journal, item = running_invocation(ctx, lease="worker-A")
    # The worker restarts and re-claims its own (now stale) lease.
    assert journal.recover(replace(ctx, worker_id="worker-A"), lease_id="worker-A") == 1
    assert journal.get(item["invocation_id"], "system")["state"] == "unknown"


def test_unowned_invocation_is_reconciled(tmp_path, monkeypatch):
    ctx = context(tmp_path, monkeypatch)
    journal, item = running_invocation(ctx, lease=None)
    assert journal.recover(ctx, lease_id="any-lease") == 1
    assert journal.get(item["invocation_id"], "system")["state"] == "unknown"


def test_recover_without_lease_is_a_noop(tmp_path, monkeypatch):
    ctx = context(tmp_path, monkeypatch)
    journal, item = running_invocation(ctx, lease="worker-A")
    assert journal.recover(ctx) == 0  # cannot assert ownership → touch nothing
    assert journal.get(item["invocation_id"], "system")["state"] == "running"


def test_two_workers_cannot_replay_same_step(tmp_path, monkeypatch):
    ctx = context(tmp_path, monkeypatch)
    journal, _ = running_invocation(ctx, lease="worker-A")
    calls = []
    governed = gateway(ctx, lambda a, c: calls.append(1))
    # Fencing still prevents the second execution; the answer is now the
    # determinate ``in_flight`` result (see test_invocation_journal), not a
    # ``PermissionError`` that reads like a broken tool.
    result = asyncio.run(governed.invoke("probe", {}, replace(ctx, worker_id="worker-B")))
    assert result["outcome"] == "in_flight"
    assert not calls


def test_lease_fencing_audit(tmp_path, monkeypatch):
    ctx = context(tmp_path, monkeypatch)
    journal, item = running_invocation(ctx, lease="worker-A")
    assert journal.recover(ctx, lease_id="worker-A") == 1
    events = AuditWriter(ctx.store).export("system")
    recovered = next(e for e in events if e["action"] == "invocation.recovered")
    assert recovered["payload"]["lease_id"] == "worker-A"
    assert item["invocation_id"] in recovered["payload"]["invocations"]
