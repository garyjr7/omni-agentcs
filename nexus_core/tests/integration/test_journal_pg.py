"""P2-D5 closure: the invocation journal on real PostgreSQL (opt-in).

Runs only when ``NEXUS_TEST_PG_DSN`` (or ``DATABASE_URL``) points at a PostgreSQL
instance. Every test builds its own schema and drops it afterwards, so a hosted
database is never modified. Without a DSN these tests **skip** and the PostgreSQL
certification stays explicitly unproven.
"""
from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from uuid import uuid4

import pytest

from nexus_core.kernel.invocation_journal import InvocationJournal
from nexus_core.kernel.models import Identity, RunContext

DSN = os.getenv("NEXUS_TEST_PG_DSN") or os.getenv("DATABASE_URL") or ""

pytestmark = pytest.mark.skipif(
    not DSN.startswith(("postgresql://", "postgres://")),
    reason="requires NEXUS_TEST_PG_DSN (or DATABASE_URL) pointing at PostgreSQL",
)


@pytest.fixture()
def pg_store():
    psycopg = pytest.importorskip("psycopg")
    from psycopg import sql
    from psycopg.rows import dict_row

    from nexus_core.kernel.postgres_store import PostgresControlStore, _PostgresConnection

    namespace = "journal_test_" + uuid4().hex
    with psycopg.connect(DSN, autocommit=True) as admin:
        admin.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(namespace)))

    class IsolatedStore(PostgresControlStore):
        def connect(self):
            return _PostgresConnection(psycopg.connect(
                self.database_url, row_factory=dict_row,
                options=f"-c search_path={namespace}"))

    store = IsolatedStore(DSN)
    store.initialize()
    try:
        yield store
    finally:
        with psycopg.connect(DSN, autocommit=True) as admin:
            admin.execute(sql.SQL("DROP SCHEMA {} CASCADE").format(sql.Identifier(namespace)))


def context(store, run_id="r"):
    return RunContext("system", Identity("agent", "system"), run_id=run_id, store=store)


def test_journal_works_on_postgresql(pg_store):
    journal = InvocationJournal(pg_store)
    ctx = context(pg_store)
    item = journal.prepare(ctx, "probe", {"target": "10.0.0.5"}, "10.0.0.5")
    assert item["state"] == "prepared"
    journal.start(item["invocation_id"], "system")
    journal.finish(item["invocation_id"], "system", {"ok": True})
    row = journal.get(item["invocation_id"], "system")
    assert row["state"] == "succeeded"
    assert row["result_ref"]
    # The migration added the P2-D columns to the PostgreSQL table.
    assert row["step_key"] and "lease_id" in row


def test_fencing_and_migration_on_postgresql(pg_store):
    journal = InvocationJournal(pg_store)
    ctx = context(pg_store, run_id="r2")
    item = journal.prepare(ctx, "probe", {}, "", lease_id="worker-A")
    journal.start(item["invocation_id"], "system")
    assert journal.recover(ctx, lease_id="worker-B") == 0  # A's lease is live
    assert journal.recover(ctx, lease_id="worker-A") == 1  # the owner reclaims it
    assert journal.get(item["invocation_id"], "system")["state"] == "unknown"


def test_concurrent_workers_on_postgresql(pg_store):
    journal = InvocationJournal(pg_store)
    ctx = context(pg_store, run_id="r-concurrent")
    barrier = Barrier(2)

    def prepare(_):
        barrier.wait(timeout=10)
        try:
            return journal.prepare(ctx, "probe", {}, "")["invocation_id"]
        except Exception as exc:  # a unique partial index or the state guard
            return exc

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(prepare, range(2)))
    # Exactly one worker may own the in-flight step.
    assert sum(isinstance(result, str) for result in results) == 1
