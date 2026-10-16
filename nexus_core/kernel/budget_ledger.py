"""Durable, tree-scoped token reservations.

A per-run budget (``kernel_usage_ledger``) records what was *spent*; it cannot
stop a request that would push a shared tree past its ceiling, because the spend
is only known afterwards. This ledger reserves tokens **before** the provider
call and settles the reservation afterwards, so a fan-out of child agents cannot
oversubscribe the root budget in the window before usage is recorded.

It is deliberately conservative:

* ``reserve`` fails closed with :class:`BudgetExceeded` when the tree has no room;
* ``settle`` records the real usage (which may exceed the estimate) but never
  refunds more than was reserved;
* ``release`` frees the reservation when the call never happened.

Exactly-once accounting across a crash is not promised here; the reservation is
a durable guardrail, not a distributed lock.
"""

from __future__ import annotations

import json
from typing import Any
from uuid import uuid4

from .control_store import ControlStore
from .errors import BudgetExceeded
from .models import utc_now

SCHEMA = '''CREATE TABLE IF NOT EXISTS kernel_budget_reservations (
 reservation_id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, root_id TEXT NOT NULL,
 run_id TEXT NOT NULL, parent_id TEXT NOT NULL, tokens_reserved INTEGER NOT NULL,
 tokens_used INTEGER NOT NULL DEFAULT 0, state TEXT NOT NULL,
 created_at TEXT NOT NULL, released_at TEXT)'''


class BudgetLedger:
    def __init__(self, store: ControlStore) -> None:
        self.store = store
        with store.connect() as conn:
            conn.execute(SCHEMA)
            conn.execute(
                'CREATE INDEX IF NOT EXISTS budget_reservations_root '
                'ON kernel_budget_reservations(tenant_id,root_id,state)'
            )

    def committed(self, tenant_id: str, root_id: str) -> int:
        """Tokens already committed by the tree (reserved + settled)."""
        with self.store.connect() as conn:
            row = conn.execute(
                '''SELECT COALESCE(SUM(CASE WHEN state='reserved' THEN tokens_reserved
                    ELSE tokens_used END),0) AS total FROM kernel_budget_reservations
                    WHERE tenant_id=? AND root_id=?''',
                (tenant_id, root_id),
            ).fetchone()
        return int(row['total'])

    def reserve(self, tenant_id: str, *, root_id: str, run_id: str, parent_id: str,
                tokens: int, global_budget: int) -> str:
        """Reserve tokens for one provider request or fail before the call."""
        amount = int(tokens)
        if amount <= 0:
            raise ValueError('reservation must be positive')
        with self.store.locked_transaction(self._lock_key(tenant_id, root_id)) as conn:
            committed = conn.execute(
                '''SELECT COALESCE(SUM(CASE WHEN state='reserved' THEN tokens_reserved
                    ELSE tokens_used END),0) AS total FROM kernel_budget_reservations
                    WHERE tenant_id=? AND root_id=?''',
                (tenant_id, root_id),
            ).fetchone()['total']
            if int(committed) + amount > int(global_budget):
                raise BudgetExceeded(
                    f'tree budget exceeded: {int(committed)}+{amount} > {int(global_budget)}'
                )
            reservation_id = f'reservation_{uuid4().hex}'
            conn.execute(
                '''INSERT INTO kernel_budget_reservations
                (reservation_id,tenant_id,root_id,run_id,parent_id,tokens_reserved,
                 tokens_used,state,created_at) VALUES(?,?,?,?,?,?,?,?,?)''',
                (reservation_id, tenant_id, root_id, run_id, parent_id, amount, 0,
                 'reserved', utc_now()),
            )
        return reservation_id

    @staticmethod
    def _lock_key(tenant_id: str, root_id: str) -> str:
        return json.dumps(["budget", tenant_id, root_id], separators=(",", ":"))

    def _reservation_key(self, reservation_id: str) -> str:
        # The reservation's tenant/root never changes. Discover the key before
        # locking, then guard the state transition in the locked transaction.
        with self.store.connect() as conn:
            row = conn.execute(
                "SELECT tenant_id,root_id FROM kernel_budget_reservations "
                "WHERE reservation_id=?", (reservation_id,),
            ).fetchone()
        if row is None:
            raise PermissionError("reservation is not open")
        return self._lock_key(row["tenant_id"], row["root_id"])

    def settle(self, reservation_id: str, actual_tokens: int) -> None:
        amount = max(0, int(actual_tokens))
        with self.store.locked_transaction(self._reservation_key(reservation_id)) as conn:
            updated = conn.execute(
                '''UPDATE kernel_budget_reservations SET tokens_used=?,state='settled',
                released_at=? WHERE reservation_id=? AND state='reserved' ''',
                (amount, utc_now(), reservation_id),
            ).rowcount
        if updated != 1:
            raise PermissionError('reservation is not open')

    def release(self, reservation_id: str) -> None:
        with self.store.locked_transaction(self._reservation_key(reservation_id)) as conn:
            updated = conn.execute(
                '''UPDATE kernel_budget_reservations SET state='released',tokens_used=0,
                released_at=? WHERE reservation_id=? AND state='reserved' ''',
                (utc_now(), reservation_id),
            ).rowcount
        if updated != 1:
            raise PermissionError('reservation is not open')

    def get(self, reservation_id: str, tenant_id: str) -> dict[str, Any] | None:
        with self.store.connect() as conn:
            row = conn.execute(
                'SELECT * FROM kernel_budget_reservations WHERE reservation_id=? AND tenant_id=?',
                (reservation_id, tenant_id),
            ).fetchone()
        return dict(row) if row else None
