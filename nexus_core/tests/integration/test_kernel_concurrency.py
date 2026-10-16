"""Transactional invariants over independent SQLite/optional PostgreSQL sessions."""
from __future__ import annotations

import os
import time
from collections.abc import Callable, Iterator
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import Barrier, Event
from typing import Any, TypeVar
from unittest.mock import patch
from uuid import uuid4

import pytest

from nexus_core.kernel.audit import AuditWriter
from nexus_core.kernel.budget_ledger import BudgetLedger
from nexus_core.kernel.control_store import ControlStore
from nexus_core.kernel.errors import BudgetExceeded, LeaseLost
from nexus_core.kernel.workflows import DurableWorkflowEngine

T = TypeVar("T")


@pytest.fixture(params=["sqlite", "postgres"])
def concurrent_store(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[ControlStore]:
    if request.param == "sqlite":
        store = ControlStore(tmp_path / "concurrent.db")
        store.initialize()
        yield store
        return
    dsn = os.getenv("NEXUS_TEST_PG_DSN", "")
    if not dsn.startswith(("postgresql://", "postgres://")):
        pytest.skip("requires explicit NEXUS_TEST_PG_DSN; never uses the production DSN")
    psycopg = pytest.importorskip("psycopg")
    from psycopg import sql
    from psycopg.rows import dict_row
    from nexus_core.kernel.postgres_store import PostgresControlStore, _PostgresConnection

    namespace = "concurrency_" + uuid4().hex
    with psycopg.connect(dsn, autocommit=True) as admin:
        admin.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(namespace)))

    class IsolatedStore(PostgresControlStore):
        def connect(self) -> _PostgresConnection:
            return _PostgresConnection(psycopg.connect(
                self.database_url, row_factory=dict_row,
                options=f"-c search_path={namespace}",
            ))

    try:
        pg_store = IsolatedStore(dsn)
        pg_store.initialize()
        yield pg_store
    finally:
        with psycopg.connect(dsn, autocommit=True) as admin:
            admin.execute(sql.SQL("DROP SCHEMA {} CASCADE").format(sql.Identifier(namespace)))


def race(count: int, operation: Callable[[int], T]) -> list[T]:
    barrier = Barrier(count)

    def run(index: int) -> T:
        barrier.wait(timeout=15)
        return operation(index)

    with ThreadPoolExecutor(max_workers=count) as pool:
        return list(pool.map(run, range(count)))


def enqueue(store: ControlStore, *, attempts: int = 3) -> dict[str, Any]:
    run = store.create_run("system", {})
    return store.enqueue_task(
        tenant_id="system", run_id=run["id"], task_type="noop", payload={},
        max_attempts=attempts,
    )


def claim(store: ControlStore, owner: str = "same-worker") -> dict[str, Any]:
    task = store.claim_task(owner)
    assert task is not None
    return task


def expire(store: ControlStore, task: dict[str, Any]) -> None:
    with store.connect() as conn:
        conn.execute("UPDATE kernel_tasks SET lease_until=? WHERE id=?",
                     ("2000-01-01T00:00:00+00:00", task["id"]))


def test_budget_reservations_never_overdraw(concurrent_store: ControlStore) -> None:
    ledger = BudgetLedger(concurrent_store)

    def reserve(index: int) -> bool:
        try:
            ledger.reserve("system", root_id="root", run_id=str(index), parent_id="",
                           tokens=30, global_budget=100)
            return True
        except BudgetExceeded:
            return False

    assert sum(race(12, reserve)) == 3
    assert ledger.committed("system", "root") == 90
    # Exhaustion of one root must not affect another root or tenant.
    ledger.reserve("system", root_id="other", run_id="r", parent_id="", tokens=100, global_budget=100)
    ledger.reserve("other", root_id="root", run_id="r", parent_id="", tokens=100, global_budget=100)


def test_settlement_is_single_use(concurrent_store: ControlStore) -> None:
    ledger = BudgetLedger(concurrent_store)
    identifier = ledger.reserve("system", root_id="root", run_id="r", parent_id="",
                                tokens=50, global_budget=100)

    def settle(index: int) -> bool:
        try:
            if index % 2:
                ledger.settle(identifier, 40)
            else:
                ledger.release(identifier)
            return True
        except PermissionError:
            return False

    assert sum(race(8, settle)) == 1
    assert ledger.committed("system", "root") in {0, 40}


def test_audit_has_one_linear_global_chain(concurrent_store: ControlStore) -> None:
    writer = AuditWriter(concurrent_store)

    def append(index: int) -> str:
        return writer.append(
            tenant_id="system" if index % 2 else "other", trace_id=str(index),
            actor_id="worker", action="concurrent", resource_type="test",
            resource_id=str(index), payload={"index": index, "password": "redact-me"},
        )

    ids = race(24, append)
    assert len(set(ids)) == 24
    assert writer.verify_chain() == (True, None)
    with concurrent_store.connect() as conn:
        rows = conn.execute("SELECT previous_hash,payload FROM kernel_audit_events").fetchall()
    assert len(rows) == len({row["previous_hash"] for row in rows}) == 24
    assert all("redact-me" not in row["payload"] for row in rows)


def test_expired_lease_cannot_write_or_revive(concurrent_store: ControlStore) -> None:
    enqueue(concurrent_store)
    task = claim(concurrent_store)
    expire(concurrent_store, task)
    token = task["lease_generation"]
    before = concurrent_store.list_task_transitions(task["id"])
    assert not concurrent_store.renew_task_lease(task["id"], "same-worker", lease_generation=token)
    with pytest.raises(LeaseLost):
        concurrent_store.complete_task(task["id"], "same-worker", lease_generation=token)
    with pytest.raises(LeaseLost):
        concurrent_store.fail_or_retry_task(task["id"], "same-worker", "late", lease_generation=token)
    assert concurrent_store.list_task_transitions(task["id"]) == before


def test_generation_fences_reused_worker_name(concurrent_store: ControlStore) -> None:
    enqueue(concurrent_store)
    old = claim(concurrent_store)
    expire(concurrent_store, old)
    new = claim(concurrent_store)
    assert new["lease_generation"] == old["lease_generation"] + 1
    before = concurrent_store.list_task_transitions(old["id"])
    assert not concurrent_store.renew_task_lease(old["id"], "same-worker",
                                               lease_generation=old["lease_generation"])
    with pytest.raises(LeaseLost):
        concurrent_store.complete_task(old["id"], "same-worker",
                                       lease_generation=old["lease_generation"], result={"stale": True})
    with pytest.raises(LeaseLost):
        concurrent_store.fail_or_retry_task(old["id"], "same-worker", "stale",
                                           lease_generation=old["lease_generation"])
    assert concurrent_store.list_task_transitions(old["id"]) == before
    concurrent_store.complete_task(new["id"], "same-worker",
                                   lease_generation=new["lease_generation"], result={"current": True})
    run = concurrent_store.get_run(new["run_id"], "system")
    assert run is not None and run["result"] == {"current": True}


def test_completion_and_failure_have_one_winner(concurrent_store: ControlStore) -> None:
    enqueue(concurrent_store, attempts=1)
    task = claim(concurrent_store)

    def finish(index: int) -> bool:
        try:
            if index % 2:
                concurrent_store.complete_task(task["id"], "same-worker",
                                               lease_generation=task["lease_generation"])
            else:
                concurrent_store.fail_or_retry_task(task["id"], "same-worker", "failed",
                                                    lease_generation=task["lease_generation"])
            return True
        except LeaseLost:
            return False

    assert sum(race(8, finish)) == 1
    assert len(concurrent_store.list_task_transitions(task["id"])) == 3
    with concurrent_store.connect() as conn:
        assert conn.execute("SELECT COUNT(*) AS n FROM kernel_dead_letters").fetchone()["n"] <= 1


def pending_workflow(store: ControlStore) -> tuple[DurableWorkflowEngine, dict[str, Any]]:
    engine = DurableWorkflowEngine(store)
    workflow = engine.register("system", "parallel", "1", {
        "steps": [{"key": "one", "task_type": "noop"}],
    })
    with patch.object(engine, "reconcile", return_value={}):
        run = engine.start("system", workflow["id"], {}, "test")
    return engine, run


def test_parallel_reconcile_enqueues_once(concurrent_store: ControlStore) -> None:
    engine, run = pending_workflow(concurrent_store)
    race(12, lambda _: engine.reconcile(run["id"], "system"))
    with concurrent_store.connect() as conn:
        tasks = conn.execute("SELECT id FROM kernel_tasks WHERE run_id=?", (run["id"],)).fetchall()
    assert len(tasks) == 1
    assert engine.history(run["id"], "system")[0]["task_id"] == tasks[0]["id"]
    assert len(concurrent_store.list_task_transitions(tasks[0]["id"])) == 1


def test_workflow_claim_rolls_back_if_task_transaction_fails(concurrent_store: ControlStore) -> None:
    engine, run = pending_workflow(concurrent_store)
    with patch.object(concurrent_store, "_transition", side_effect=RuntimeError("injected failure")):
        with pytest.raises(RuntimeError, match="injected failure"):
            engine.reconcile(run["id"], "system")
    step = engine.history(run["id"], "system")[0]
    assert step["task_id"] is None and step["status"] == "pending"
    with concurrent_store.connect() as conn:
        assert conn.execute("SELECT COUNT(*) AS n FROM kernel_tasks").fetchone()["n"] == 0
    engine.reconcile(run["id"], "system")
    assert engine.history(run["id"], "system")[0]["task_id"] is not None


def test_compensation_enqueues_once(concurrent_store: ControlStore) -> None:
    engine = DurableWorkflowEngine(concurrent_store)
    workflow = engine.register("system", "undo", "1", {"steps": [
        {"key": "write", "task_type": "write", "compensation_type": "undo"},
        {"key": "notify", "task_type": "notify", "depends_on": ["write"], "max_attempts": 1},
    ]})
    run = engine.start("system", workflow["id"], {}, "test")
    first = claim(concurrent_store)
    concurrent_store.complete_task(first["id"], "same-worker", lease_generation=first["lease_generation"])
    engine.reconcile(run["id"], "system")
    second = claim(concurrent_store)
    concurrent_store.fail_or_retry_task(second["id"], "same-worker", "fail",
                                       lease_generation=second["lease_generation"])
    race(12, lambda _: engine.reconcile(run["id"], "system"))
    with concurrent_store.connect() as conn:
        tasks = conn.execute("SELECT id FROM kernel_tasks WHERE task_type='undo'").fetchall()
    assert len(tasks) == 1
    steps = {s["step_key"]: s for s in engine.history(run["id"], "system")}
    assert steps["write"]["compensation_task_id"] == tasks[0]["id"]


def test_legacy_lease_migration_is_idempotent(concurrent_store: ControlStore) -> None:
    enqueue(concurrent_store)
    with concurrent_store.connect() as conn:
        conn.execute("ALTER TABLE kernel_tasks DROP COLUMN lease_generation")
    concurrent_store.initialize()
    concurrent_store.initialize()
    task = claim(concurrent_store)
    assert task["lease_generation"] == 1
    concurrent_store.complete_task(task["id"], "same-worker", lease_generation=1)


@pytest.mark.parametrize("operation", ["renew", "complete", "retry"])
def test_expiration_is_checked_after_waiting_for_row_lock(
    concurrent_store: ControlStore, operation: str,
) -> None:
    enqueue(concurrent_store)
    task = claim(concurrent_store)
    deadline = (datetime.now(timezone.utc) + timedelta(seconds=0.25)).isoformat()
    with concurrent_store.connect() as conn:
        conn.execute("UPDATE kernel_tasks SET lease_until=? WHERE id=?", (deadline, task["id"]))
    started = Event()

    def mutate() -> bool:
        started.set()
        token = task["lease_generation"]
        try:
            if operation == "renew":
                return concurrent_store.renew_task_lease(
                    task["id"], "same-worker", lease_generation=token,
                )
            if operation == "complete":
                concurrent_store.complete_task(task["id"], "same-worker", lease_generation=token)
            else:
                concurrent_store.fail_or_retry_task(task["id"], "same-worker", "late",
                                                   lease_generation=token)
            return True
        except LeaseLost:
            return False

    with ThreadPoolExecutor(max_workers=1) as pool:
        # Lock only the task row in PostgreSQL, without changing its version.
        # An UPDATE which checks clock_timestamp() *before* this wait is unsafe.
        conn = concurrent_store.connect()
        try:
            with conn:
                if not concurrent_store.task_row_lock_sql:
                    conn.execute("BEGIN IMMEDIATE")
                concurrent_store._locked_task(conn, task["id"])
                future = pool.submit(mutate)
                assert started.wait(timeout=5)
                time.sleep(0.4)
        finally:
            conn.close()
        assert future.result(timeout=10) is False
