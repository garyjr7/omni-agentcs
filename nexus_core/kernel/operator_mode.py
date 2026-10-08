"""Durable operator permission mode. Not exposed as a model tool."""
from dataclasses import replace
import hashlib
from uuid import uuid4
from .audit import AuditWriter

SCHEMA = '''CREATE TABLE IF NOT EXISTS kernel_operator_modes (
 tenant_id TEXT NOT NULL, session_id TEXT NOT NULL, mode TEXT NOT NULL,
 plan_text TEXT NOT NULL, plan_hash TEXT NOT NULL,
 PRIMARY KEY(tenant_id, session_id))'''

class OperatorMode:
    def __init__(self, store):
        self.store = store
        with store.connect() as conn:
            conn.execute(SCHEMA)

    def key(self, context):
        return context.session_id or 'run:' + context.run_id

    def get(self, context):
        with self.store.connect() as conn:
            row = conn.execute('SELECT * FROM kernel_operator_modes WHERE tenant_id=? AND session_id=?',
                               (context.tenant_id,self.key(context))).fetchone()
        return dict(row) if row else {'mode':'interactive','plan_text':'','plan_hash':''}

    def _audit(self, context, action, payload, *, actor=None, decision='allow'):
        AuditWriter(self.store).append(tenant_id=context.tenant_id,trace_id=context.trace_id,
            actor_id=actor or context.identity.subject_id,action=action,resource_type='operator_session',
            resource_id=self.key(context),payload=payload,decision=decision)

    def plan(self, context, plan_text):
        if not str(plan_text).strip():
            raise ValueError('a reviewed plan must have text')
        # A fresh revision prevents old approvals from becoming valid after ABA edits.
        digest = hashlib.sha256((uuid4().hex+'\n'+plan_text).encode()).hexdigest()
        self._audit(context,'mode.plan_requested',{'plan_hash':digest})
        with self.store.connect() as conn:
            conn.execute('''INSERT INTO kernel_operator_modes VALUES(?,?,?,?,?)
             ON CONFLICT(tenant_id,session_id) DO UPDATE SET mode=excluded.mode,
             plan_text=excluded.plan_text, plan_hash=excluded.plan_hash''',
             (context.tenant_id,self.key(context),'plan',plan_text,digest))
        return self.get(context)

    def approve(self, context, plan_hash, operator):
        if (operator.kind != 'human' or operator.tenant_id != context.tenant_id
            or operator.subject_id == context.identity.subject_id
            or not set(operator.roles).intersection({'operator','admin'})):
            raise PermissionError('only the human operator may approve a plan')
        current = self.get(context)
        if current['mode'] != 'plan' or current['plan_hash'] != plan_hash:
            raise PermissionError('plan revision is stale or not in plan mode')
        self._audit(context,'mode.plan_approved',{'plan_hash':plan_hash},actor=operator.subject_id)
        with self.store.connect() as conn:
            updated = conn.execute('''UPDATE kernel_operator_modes SET mode='exec'
                WHERE tenant_id=? AND session_id=? AND mode='plan' AND plan_hash=?''',
                (context.tenant_id,self.key(context),plan_hash)).rowcount
        if updated != 1:
            raise PermissionError('plan changed during approval')

    def constrain(self, context, definition, decision=None):
        state = self.get(context)
        if state['mode'] not in {'interactive','plan','exec'}:
            raise PermissionError('unknown operator mode')
        active = definition.effect != 'read_only'
        if state['mode'] == 'plan' and active:
            self._audit(context,'mode.denied',{'tool_id':definition.tool_id,'reason':'plan_read_only'},decision='deny')
            raise PermissionError('plan mode allows read_only tools only')
        if state['mode'] == 'exec' and active and decision is not None and decision.allowed:
            return replace(decision, requires_approval=True)
        return decision
