"""PostgreSQL adapter contracts and opt-in real transactional consumption."""
import os
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from unittest.mock import MagicMock
from uuid import uuid4

import pytest

from nexus_core.kernel.approvals import ApprovalService
from nexus_core.kernel.models import Identity, RunContext
from nexus_core.kernel.postgres_store import PostgresControlStore, _PostgresConnection


def test_adapter_exposes_commit_and_rollback():
    raw = MagicMock()
    conn = _PostgresConnection(raw)
    conn.commit()
    conn.rollback()
    raw.commit.assert_called_once_with()
    raw.rollback.assert_called_once_with()


def test_initialize_migrates_existing_postgres(monkeypatch):
    raw = MagicMock()
    store = PostgresControlStore('unused')
    monkeypatch.setattr(store, 'connect', lambda: _PostgresConnection(raw))
    store.initialize()
    queries = [call.args[0] for call in raw.execute.call_args_list]
    assert any('ADD COLUMN IF NOT EXISTS consumed_at' in sql for sql in queries)
    assert 'consumed_at TEXT' in queries[0]
    assert 'CREATE TABLE IF NOT EXISTS kernel_sessions' in queries[0]


def test_consume_uses_one_conditional_update_without_backend_guessing():
    raw = MagicMock()
    raw.execute.return_value.rowcount = 1
    store = MagicMock()
    store.connect.side_effect = lambda: _PostgresConnection(raw)
    context = RunContext('system', Identity('requester', 'system'))
    assert ApprovalService(store).consume('approval', context, 'test')
    sql, params = raw.execute.call_args.args
    assert 'UPDATE kernel_approvals' in sql and 'consumed_at IS NULL' in sql
    assert 'tenant_id=%s' in sql and 'run_id=%s' in sql and 'action=%s' in sql
    assert len(params) == 5
    assert raw.execute.call_count == 1
    raw.__exit__.assert_called_once_with(None, None, None)


@pytest.mark.skipif(not os.getenv('DATABASE_URL', '').startswith(('postgresql://', 'postgres://')),
                    reason='requires PostgreSQL DATABASE_URL')
def test_postgres_approval_can_only_be_consumed_once():
    # Isolated schema: never initialize or modify application tables.
    psycopg = pytest.importorskip('psycopg')
    from psycopg import sql
    from psycopg.rows import dict_row
    database_url = os.environ['DATABASE_URL']
    namespace = 'approval_test_' + uuid4().hex
    with psycopg.connect(database_url, autocommit=True) as admin:
        admin.execute(sql.SQL('CREATE SCHEMA {}').format(sql.Identifier(namespace)))
        try:
            class IsolatedStore(PostgresControlStore):
                def connect(self):
                    return _PostgresConnection(psycopg.connect(
                        self.database_url, row_factory=dict_row,
                        options=f'-c search_path={namespace}'))
            store = IsolatedStore(database_url)
            store.initialize()
            context = RunContext('system', Identity('requester', 'system'))
            service = ApprovalService(store)
            approval = service.request(context, 'test')
            service.decide(approval['id'], 'system', 'reviewer', True)
            barrier = Barrier(4)
            def consume(_):
                barrier.wait(timeout=10)
                return service.consume(approval['id'], context, 'test')
            with ThreadPoolExecutor(max_workers=4) as workers:
                results = list(workers.map(consume, range(4)))
            assert results.count(True) == 1
            assert not service.consume(approval['id'], context, 'test')
        finally:
            admin.execute(sql.SQL('DROP SCHEMA {} CASCADE').format(sql.Identifier(namespace)))
