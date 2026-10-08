"""Conservative durable effect journal: unknown never means safe to retry.

The journal answers one question before a governed tool runs: *has this exact
effect already happened, is it happening now, or is its outcome unknown?* It is
deliberately conservative:

* ``step_key`` identifies the **intent** of a step (tool + canonical arguments +
  kill-chain phase + objective prefix), not just the argument hash, so a new
  intent that happens to share arguments is not mistaken for a replay. The key is
  derived by the gateway from engine-supplied context, never by the model.
* A same-tenant ``succeeded`` result for a non-idempotent tool is reused instead
  of repeated, so a retry cannot duplicate an effect.
* ``running``/``prepared`` block a second call outright.
* ``unknown`` (a crash after the effect began) requires a durable human approval
  before a retry, and the retry must *fence* the previous lease.

``lease_id`` fences recovery: a run only reconciles ``running`` invocations whose
lease it (or nobody) holds, so a live worker is never mistaken for a crashed one.
"""
from __future__ import annotations
import hashlib
import json
from uuid import uuid4

from .audit import AuditWriter
from .models import utc_now

SCHEMA = '''CREATE TABLE IF NOT EXISTS kernel_invocations (
 invocation_id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, run_id TEXT NOT NULL,
 tool_id TEXT NOT NULL, arguments_hash TEXT NOT NULL, target TEXT NOT NULL,
 state TEXT NOT NULL, result_ref TEXT, started_at TEXT, ended_at TEXT,
 retry_of TEXT, step_key TEXT, lease_id TEXT, created_at TEXT NOT NULL)'''


class InvocationJournal:
    def __init__(self, store):
        self.store = store
        with store.connect() as conn:
            conn.execute(SCHEMA)
            self._migrate(conn, store)
            conn.execute(
                'CREATE INDEX IF NOT EXISTS invocations_lookup ON kernel_invocations'
                '(tenant_id,run_id,tool_id,arguments_hash)'
            )
            conn.execute(
                'CREATE INDEX IF NOT EXISTS invocations_step ON kernel_invocations'
                '(tenant_id,run_id,step_key)'
            )
            conn.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS invocations_inflight ON kernel_invocations"
                "(tenant_id,run_id,tool_id,arguments_hash) WHERE state IN ('prepared','running')"
            )
            conn.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS invocations_step_inflight ON kernel_invocations"
                "(tenant_id,run_id,step_key) WHERE state IN ('prepared','running') AND step_key IS NOT NULL"
            )

    @staticmethod
    def _migrate(conn, store=None) -> None:
        """Add the P2-D closing columns to pre-existing journals.

        The backend is detected from the store, never by probing with
        ``PRAGMA``: on PostgreSQL a failing statement aborts the surrounding
        transaction, so a speculative PRAGMA would poison the migration.
        """
        if getattr(store, 'database_url', None) is not None:
            # PostgreSQL path: idempotent ADD COLUMN IF NOT EXISTS.
            conn.execute('ALTER TABLE kernel_invocations ADD COLUMN IF NOT EXISTS step_key TEXT')
            conn.execute('ALTER TABLE kernel_invocations ADD COLUMN IF NOT EXISTS lease_id TEXT')
            return
        columns = {row[1] for row in conn.execute('PRAGMA table_info(kernel_invocations)')}
        for name in ('step_key', 'lease_id'):
            if name not in columns:
                conn.execute(f'ALTER TABLE kernel_invocations ADD COLUMN {name} TEXT')

    @staticmethod
    def arguments_hash(arguments):
        # Raw arguments are never persisted; hash still distinguishes secrets.
        return hashlib.sha256(
            json.dumps(arguments, sort_keys=True, separators=(',', ':'), default=str).encode()
        ).hexdigest()

    @staticmethod
    def step_key(tool_id, arguments, *, phase='', objective=''):
        """Stable intent key: tool + canonical args + phase + objective prefix."""
        payload = json.dumps(
            [str(tool_id), arguments, str(phase or ''),
             str(objective or '')[:200]],
            sort_keys=True, separators=(',', ':'), default=str,
        )
        return hashlib.sha256(payload.encode()).hexdigest()

    def get(self, invocation_id, tenant_id):
        with self.store.connect() as conn:
            row = conn.execute(
                'SELECT * FROM kernel_invocations WHERE invocation_id=? AND tenant_id=?',
                (invocation_id, tenant_id),
            ).fetchone()
        return dict(row) if row else None

    def matching(self, context, tool_id, arguments, *, step_key=None):
        """Latest invocation for this exact step (step_key preferred)."""
        key = step_key or self.step_key(tool_id, arguments)
        with self.store.connect() as conn:
            row = conn.execute(
                '''SELECT * FROM kernel_invocations WHERE tenant_id=? AND run_id=?
                AND step_key=? ORDER BY created_at DESC LIMIT 1''',
                (context.tenant_id, context.run_id, key),
            ).fetchone()
        return dict(row) if row else None

    def prepare(self, context, tool_id, arguments, target, *, retry_of=None,
                step_key=None, lease_id=None):
        identifier = context.invocation_id or uuid4().hex
        key = step_key or self.step_key(tool_id, arguments)
        lease = lease_id if lease_id is not None else getattr(context, 'worker_id', '') or None
        with self.store.connect() as conn:
            conn.execute('BEGIN IMMEDIATE')
            latest = conn.execute(
                '''SELECT state FROM kernel_invocations WHERE tenant_id=? AND run_id=?
                AND step_key=? ORDER BY created_at DESC LIMIT 1''',
                (context.tenant_id, context.run_id, key),
            ).fetchone()
            if latest and latest['state'] in {'prepared', 'running'}:
                raise PermissionError('invocation is already running or prepared')
            conn.execute(
                '''INSERT INTO kernel_invocations
                (invocation_id,tenant_id,run_id,tool_id,arguments_hash,target,state,
                 retry_of,step_key,lease_id,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)''',
                (identifier, context.tenant_id, context.run_id, tool_id,
                 self.arguments_hash(arguments), str(target), 'prepared', retry_of,
                 key, lease, utc_now()),
            )
        return self.get(identifier, context.tenant_id)

    def start(self, invocation_id, tenant_id):
        with self.store.connect() as conn:
            updated = conn.execute(
                "UPDATE kernel_invocations SET state='running',started_at=? "
                "WHERE invocation_id=? AND tenant_id=? AND state='prepared'",
                (utc_now(), invocation_id, tenant_id),
            ).rowcount
        if updated != 1:
            raise PermissionError('invocation is not prepared')

    def finish(self, invocation_id, tenant_id, result, *, artifact_store=None):
        """Mark ``succeeded`` with a durable result reference.

        With an artifact store the sanitized payload is content-addressed and the
        journal keeps only the artifact id + its sha256; without one it falls back
        to an inline sanitized JSON blob (never a raw secret).
        """
        from .redaction import sanitize

        encoded = json.dumps(sanitize(result), default=str).encode()
        reference = encoded.decode()
        digest = hashlib.sha256(encoded).hexdigest()
        if artifact_store is not None:
            stored = artifact_store.put(
                tenant_id, encoded, 'application/json',
                run_id=None, metadata={'source': 'invocation_journal'},
            )
            reference = stored['id']
            digest = stored['sha256']
        with self.store.connect() as conn:
            updated = conn.execute(
                "UPDATE kernel_invocations SET state='succeeded',result_ref=?,ended_at=? "
                "WHERE invocation_id=? AND tenant_id=? AND state='running'",
                (f'{reference}|{digest}', utc_now(), invocation_id, tenant_id),
            ).rowcount
        if updated != 1:
            raise PermissionError('invocation is not running')

    def result_of(self, item, *, artifact_store=None):
        """Read back a stored result (artifact store first, inline otherwise)."""
        reference = item.get('result_ref') or ''
        if not reference:
            return None
        value, _, digest = reference.partition('|')
        if artifact_store is not None and not value.lstrip().startswith('{'):
            raw = artifact_store.get(item['tenant_id'], value)
            if hashlib.sha256(raw).hexdigest() != digest:
                raise RuntimeError('invocation result integrity check failed')
            return json.loads(raw)
        return json.loads(value)

    def unknown(self, invocation_id, tenant_id):
        with self.store.connect() as conn:
            conn.execute(
                "UPDATE kernel_invocations SET state='unknown',ended_at=? "
                "WHERE invocation_id=? AND tenant_id=? AND state='running'",
                (utc_now(), invocation_id, tenant_id),
            )

    def recover(self, context, *, lease_id=None):
        """Mark a crashed run's ``running`` invocations ``unknown``.

        ``lease_id`` is the worker that currently owns the run's task lease (a
        fencing token). When it is provided, only invocations whose own lease is
        empty or matches are reconciled, so a *live* worker's in-flight
        invocations are never touched. When it is ``None`` (the caller cannot
        assert ownership) nothing is reconciled.
        """
        if not lease_id:
            return 0
        with self.store.connect() as conn:
            rows = conn.execute(
                '''SELECT invocation_id FROM kernel_invocations WHERE tenant_id=?
                AND run_id=? AND state='running' AND ended_at IS NULL
                AND (lease_id IS NULL OR lease_id=?)''',
                (context.tenant_id, context.run_id, lease_id),
            ).fetchall()
            ids = [row['invocation_id'] for row in rows]
            for invocation_id in ids:
                conn.execute(
                    "UPDATE kernel_invocations SET state='unknown' WHERE invocation_id=?",
                    (invocation_id,),
                )
        if ids:
            AuditWriter(self.store).append(
                tenant_id=context.tenant_id, trace_id=context.trace_id,
                actor_id=context.identity.subject_id, action='invocation.recovered',
                resource_type='run', resource_id=context.run_id,
                payload={'lease_id': lease_id, 'invocations': ids}, decision='allow',
            )
        return len(ids)

    def mark_failed(self, invocation_id, tenant_id, reason='operator_skip'):
        """Operator decided an ``unknown`` invocation had no effect; no replay."""
        with self.store.connect() as conn:
            updated = conn.execute(
                "UPDATE kernel_invocations SET state='failed',ended_at=? "
                "WHERE invocation_id=? AND tenant_id=? AND state='unknown'",
                (utc_now(), invocation_id, tenant_id),
            ).rowcount
        if updated != 1:
            raise PermissionError('invocation is not awaiting a resume decision')
        AuditWriter(self.store).append(
            tenant_id=tenant_id, trace_id=invocation_id, actor_id='operator',
            action='invocation.skipped', resource_type='invocation',
            resource_id=invocation_id, payload={'reason': reason}, decision='deny',
        )

    def unknown_for_run(self, tenant_id, run_id):
        """All invocations of a run still awaiting a resume decision."""
        with self.store.connect() as conn:
            rows = conn.execute(
                "SELECT * FROM kernel_invocations WHERE tenant_id=? AND run_id=? "
                "AND state='unknown' ORDER BY created_at",
                (tenant_id, run_id),
            ).fetchall()
        return [dict(row) for row in rows]

    def claim_retry(self, invocation_id, tenant_id):
        """Validate that an ``unknown`` invocation may be retried under approval."""
        item = self.get(invocation_id, tenant_id)
        if not item or item['state'] != 'unknown':
            raise PermissionError('unknown invocation retry already claimed')
