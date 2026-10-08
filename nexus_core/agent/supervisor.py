"""Real child conversations; the existing ReAct loop remains the execution engine."""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, replace
import json
import os

from nexus_core.kernel.audit import AuditWriter
from nexus_core.kernel.blackboard import Blackboard, is_verified_fact
from nexus_core.kernel.budget_ledger import BudgetLedger
from nexus_core.kernel.models import utc_now
from nexus_core.kernel.runtime import ExecutionContext, _build_run_context
from .subagents import SUBAGENTS_BY_ID

#: Default minimum target budget (tokens) for an automatic spawn to be worth it.
AUTOSPAWN_MIN_BUDGET_ENV = "NEXUS_AUTOSPAWN_MIN_BUDGET"
DEFAULT_AUTOSPAWN_MIN_BUDGET = 20_000
#: A phase expected to finish in fewer iterations than this never spawns.
AUTOSPAWN_MIN_ITERATIONS_ENV = "NEXUS_AUTOSPAWN_MIN_ITERATIONS"
DEFAULT_AUTOSPAWN_MIN_ITERATIONS = 4

SCHEMA = '''CREATE TABLE IF NOT EXISTS kernel_supervisor_roots (
 run_id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, root_id TEXT NOT NULL,
 parent_run_id TEXT, depth INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL)'''


class SupervisorTree:
    """Durable parent/root registry, so the tree survives a restart."""

    def __init__(self, store):
        self.store = store
        with store.connect() as conn:
            conn.execute(SCHEMA)

    def register(self, tenant_id: str, run_id: str, parent_run_id: str | None = None) -> dict:
        """Register ``run_id`` in the tree, creating a root when it has no parent.

        Idempotent and non-clobbering: looking a node up (``root_of``/``depth_of``)
        must never re-anchor it as a new root, so an existing row is only updated
        when an explicit (possibly new) parent is supplied.
        """
        existing = self.get(tenant_id, run_id)
        if existing is not None and parent_run_id is None:
            return existing
        if existing is not None and existing.get('parent_run_id') == parent_run_id:
            return existing
        parent = self.get(tenant_id, parent_run_id) if parent_run_id else None
        root_id = parent['root_id'] if parent else run_id
        depth = (int(parent['depth']) + 1) if parent else 0
        with self.store.connect() as conn:
            conn.execute(
                '''INSERT INTO kernel_supervisor_roots
                (run_id,tenant_id,root_id,parent_run_id,depth,created_at)
                VALUES(?,?,?,?,?,?)
                ON CONFLICT(run_id) DO UPDATE SET root_id=excluded.root_id,
                parent_run_id=excluded.parent_run_id, depth=excluded.depth''',
                (run_id, tenant_id, root_id, parent_run_id, depth, utc_now()),
            )
        return self.get(tenant_id, run_id)

    def get(self, tenant_id: str, run_id: str | None):
        if not run_id:
            return None
        with self.store.connect() as conn:
            row = conn.execute(
                'SELECT * FROM kernel_supervisor_roots WHERE tenant_id=? AND run_id=?',
                (tenant_id, run_id),
            ).fetchone()
        return dict(row) if row else None

    def root_of(self, tenant_id: str, run_id: str) -> str:
        return self.register(tenant_id, run_id)['root_id']

    def depth_of(self, tenant_id: str, run_id: str) -> int:
        return int(self.register(tenant_id, run_id)['depth'])


def autospawn_min_budget() -> int:
    try:
        return max(0, int(os.getenv(AUTOSPAWN_MIN_BUDGET_ENV, DEFAULT_AUTOSPAWN_MIN_BUDGET)))
    except (TypeError, ValueError):
        return DEFAULT_AUTOSPAWN_MIN_BUDGET


def autospawn_min_iterations() -> int:
    try:
        return max(0, int(os.getenv(AUTOSPAWN_MIN_ITERATIONS_ENV, DEFAULT_AUTOSPAWN_MIN_ITERATIONS)))
    except (TypeError, ValueError):
        return DEFAULT_AUTOSPAWN_MIN_ITERATIONS


def should_autospawn(
    previous_subagent_id: str | None,
    subagent_id: str,
    *,
    enabled: bool = True,
    expected_iterations: int | None = None,
    min_budget: int | None = None,
    min_iterations: int | None = None,
) -> bool:
    """Whether a phase change justifies spawning a real child conversation.

    Spawns only on a *family* transition (a different kill-chain phase) toward a
    well-funded profile. A refinement inside the same phase (``web`` →
    ``services``, both ``enumeration``) and a short phase never spawn: the cost
    of a child conversation is not worth it.
    """
    if not enabled:
        return False
    target = SUBAGENTS_BY_ID.get(subagent_id)
    if target is None:
        return False
    previous = SUBAGENTS_BY_ID.get(previous_subagent_id) if previous_subagent_id else None
    # Same kill-chain phase = a refinement, not a new front.
    if previous is not None and previous.phase == target.phase:
        return False
    threshold_budget = autospawn_min_budget() if min_budget is None else int(min_budget)
    if target.token_budget <= threshold_budget:
        return False
    threshold_iterations = (
        autospawn_min_iterations() if min_iterations is None else int(min_iterations)
    )
    if expected_iterations is not None and expected_iterations < threshold_iterations:
        return False
    return True


@dataclass(frozen=True)
class SubAgentRun:
    run_id: str
    conversation_id: str
    operator_session_id: str
    subagent_id: str
    tokens_used: int
    termination_reason: str
    summary: dict
    root_id: str = ""


class AgentSupervisor:
    def __init__(self, context, llm_client, *, engagement_id, global_budget,
                 depth=0, config=None, tool_catalog=None, root_id=None,
                 autospawn=False):
        if global_budget <= 0:
            raise ValueError('global token budget must be positive')
        self.context = context
        self.client = llm_client
        self.engagement_id = engagement_id
        self.global_budget = global_budget
        self.depth = depth
        self.config = config
        self.tool_catalog = tool_catalog
        self.autospawn = autospawn
        self.tree = SupervisorTree(context.store)
        # The durable root of this tree; every descendant references it.
        self.root_id = root_id or self.tree.root_of(context.tenant_id, context.run_id)
        self.tokens_used = 0
        self.reserved = 0
        self.active = 0
        self.peak_concurrency = 0
        self._lock = asyncio.Lock()

    @classmethod
    def root(cls, context, llm_client, *, engagement_id, global_budget, **kwargs):
        """Return the supervisor anchored at the durable root of ``context``."""
        tree = SupervisorTree(context.store)
        root_id = tree.root_of(context.tenant_id, context.run_id)
        depth = tree.depth_of(context.tenant_id, context.run_id)
        return cls(context, llm_client, engagement_id=engagement_id,
                   global_budget=global_budget, depth=depth, root_id=root_id, **kwargs)

    def maybe_spawn(self, previous_subagent_id, subagent_id, *, enabled=True, expected_iterations=None):
        """Whether a phase transition should delegate to a child this iteration."""
        return should_autospawn(
            previous_subagent_id, subagent_id,
            enabled=self.autospawn and enabled,
            expected_iterations=expected_iterations,
        )

    async def spawn(self, subagent_id, objective, budget):
        from .react import ReActConfig, run_react_loop
        if subagent_id not in SUBAGENTS_BY_ID:
            raise ValueError('unknown subagent profile')
        tokens = int(budget['tokens']); iterations = int(budget['iterations'])
        if not objective.strip() or tokens <= 0 or iterations <= 0:
            raise ValueError('objective and positive child budget required')
        tokens = min(tokens, SUBAGENTS_BY_ID[subagent_id].token_budget)
        ctx = self.context; store = ctx.store; tenant = ctx.tenant_id
        tree = self.tree
        # Depth is durable (the tree is the source of truth) but a caller that
        # asserts a deeper position is still honoured: the stricter of the two
        # wins, so a mis-anchored supervisor can never spawn past the limit.
        child_depth = max(int(self.depth), tree.depth_of(tenant, ctx.run_id)) + 1
        if child_depth > 2:
            raise ValueError('maximum child depth reached')
        async with self._lock:
            if self.active >= 4:
                raise ValueError('maximum child concurrency reached')
            if self.tokens_used + self.reserved + tokens > self.global_budget:
                raise ValueError('global token budget cannot be oversubscribed')
            self.reserved += tokens; self.active += 1
            self.peak_concurrency = max(self.peak_concurrency, self.active)
        used = 0; reason = 'failed'; child_run = None; record = None
        child_id = None; spawned = None; ledger = BudgetLedger(store)
        try:
            outer = ctx.task.get('payload') or {}
            parent_permission = _build_run_context({**outer, 'engagement_id': self.engagement_id}, ctx)
            scope = parent_permission.scope
            facts = [f for f in Blackboard(store).list_facts(tenant, self.engagement_id)
                     if is_verified_fact(f)] if self.engagement_id else []
            existing = {f.get('invocation_id') for f in facts}
            child_run = store.create_run(tenant, {
                'parent_run_id': ctx.run_id, 'root_id': self.root_id,
                'subagent_id': subagent_id,
                'scope_snapshot': scope.to_dict() if scope and hasattr(scope, 'to_dict') else None})
            child_id = child_run['id']
            tree.register(tenant, child_id, parent_run_id=ctx.run_id)
            conversation = store.create_conversation(tenant, parent_permission.identity.subject_id,
                f'Child {subagent_id}', agent_id=outer.get('agent_id'))
            conversation_id = conversation['id']
            payload = {key: outer[key] for key in ('identity', 'permissions', 'project_root') if key in outer}
            payload.update(subagent=subagent_id, session_id=parent_permission.session_id,
                           engagement_id=self.engagement_id, agent_id=outer.get('agent_id', 'omni'))
            child_context = ExecutionContext(store, {'tenant_id': tenant, 'run_id': child_id, 'payload': payload},
                                             ctx.worker_id, ctx.cancel_event)
            audit = AuditWriter(store)

            def record(action, **details):
                audit.append(tenant_id=tenant, trace_id=child_id,
                    actor_id=parent_permission.identity.subject_id, action=action,
                    resource_type='run', resource_id=child_id,
                    payload={'parent_run_id': ctx.run_id, 'root_id': self.root_id,
                             'run_id': child_id, 'conversation_id': conversation_id,
                             'subagent_id': subagent_id, 'depth': tree.depth_of(tenant, child_id),
                             **details}, decision='allow')

            spawned = utc_now()
            record('subagent.started', spawned_at=spawned)
            ctx.event('subagent.started', task_id=child_id, subagent_id=subagent_id,
                      parent_run_id=ctx.run_id, root_id=self.root_id)
            store.append_message(tenant, conversation_id, 'system',
                json.dumps({'facts_verified': facts}, default=str), run_id=child_id,
                metadata={'kind': 'supervisor.verified_context'})
            client = self.client

            class BudgetClient:
                def __getattr__(self, name):
                    return getattr(client, name)

                async def complete(self, *args, **kwargs):
                    nonlocal used
                    if used >= tokens:
                        raise PermissionError('child token budget exhausted')
                    response = await client.complete(*args, **kwargs)
                    used += max(0, int(getattr(response, 'tokens_input', 0) or 0)) + max(
                        0, int(getattr(response, 'tokens_output', 0) or 0))
                    return response

                supports_streaming = False

            def before(estimated: int):
                # Reserve from the shared tree budget before the provider call.
                return ledger.reserve(tenant, root_id=self.root_id, run_id=child_id,
                                      parent_id=ctx.run_id, tokens=max(1, int(estimated)),
                                      global_budget=self.global_budget)

            def after(handle, actual: int):
                if handle is None:
                    return
                if actual and actual > 0:
                    ledger.settle(handle, actual)
                else:
                    ledger.release(handle)

            config = self.config or ReActConfig()
            profile = SUBAGENTS_BY_ID[subagent_id]
            config = replace(
                config,
                max_iterations=min(iterations, config.max_iterations, profile.max_iterations),
                before_provider_call=before, after_provider_call=after,
                root_id=self.root_id,
            )
            result = await run_react_loop(context=child_context, objective=objective,
                engagement_id=self.engagement_id, llm_client=BudgetClient(), config=config,
                conversation_id=conversation_id, budget_tokens=tokens,
                tool_catalog=self.tool_catalog, isolated_child=True)
            reason = result.status
            if used > tokens:
                reason = 'budget_exceeded'
            new_facts = [f for f in Blackboard(store).list_facts(tenant, self.engagement_id)
                         if is_verified_fact(f) and f.get('invocation_id') not in existing
                         and f.get('run_id') == child_id] if self.engagement_id else []
            findings = [{k: v for k, v in f.items() if k != 'declared_finding'}
                        for f in result.findings
                        if f.get('verification_status') == 'confirmed_finding' and f.get('run_id') == child_id]
            summary = {'findings': findings, 'facts_added': new_facts,
                       'phase_reached': (result.plan or {}).get('current'),
                       'blockers': list(result.completion_objections) or ([] if reason == 'completed' else [reason]),
                       'next_steps_suggested': []}
            record('subagent.ended', spawned_at=spawned, terminated_at=utc_now(),
                   termination_reason=reason, tokens_used=used)
            ctx.event('subagent.ended', task_id=child_id, subagent_id=subagent_id,
                      status='ok' if reason == 'completed' else 'failed', tokens_used=used)
            return SubAgentRun(child_id, conversation_id, parent_permission.session_id,
                               subagent_id, used, reason, summary, self.root_id)
        except BaseException as exc:
            reason = 'cancelled' if isinstance(exc, asyncio.CancelledError) else type(exc).__name__
            if record is not None:
                record('subagent.ended', spawned_at=spawned, terminated_at=utc_now(),
                       termination_reason=reason, tokens_used=used)
                ctx.event('subagent.ended', task_id=child_id, subagent_id=subagent_id,
                          status='cancelled' if reason == 'cancelled' else 'failed', tokens_used=used)
            raise
        finally:
            async with self._lock:
                self.reserved -= tokens; self.active -= 1; self.tokens_used += used
