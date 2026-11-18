"""Durable, provider-neutral execution runtime for NEXUS Sovereign."""

from __future__ import annotations

import inspect
import os
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Awaitable, Callable, Dict

from nexus_core.llm.abstraction import LLMFactory, LLMMessage, BaseLLMClient, NexusLLM

from .models import utc_now
from .telemetry import metrics, telemetry

if TYPE_CHECKING:
    from .models import RunContext

Executor = Callable[[dict[str, Any], "ExecutionContext"], dict[str, Any] | Awaitable[dict[str, Any]]]


@dataclass(frozen=True)
class ExecutionContext:
    store: Any
    task: dict[str, Any]
    worker_id: str
    #: Cooperative cancellation signal consumed by long-running executors
    #: (the ReAct loop and the worker heartbeat). ``None`` = never cancelled.
    cancel_event: Any = None

    @property
    def tenant_id(self) -> str:
        return str(self.task["tenant_id"])

    @property
    def run_id(self) -> str:
        return str(self.task["run_id"])

    def event(self, event_type: str, **payload: Any) -> None:
        self.store.append_run_event(self.tenant_id, self.run_id, event_type, payload)


class ExecutorRegistry:
    def __init__(self) -> None:
        self._executors: Dict[str, Executor] = {}

    def register(self, task_type: str, executor: Executor) -> None:
        if task_type in self._executors:
            raise ValueError(f"executor already registered: {task_type}")
        self._executors[task_type] = executor

    @property
    def task_types(self) -> tuple[str, ...]:
        return tuple(sorted(self._executors))

    async def execute(self, task: dict[str, Any], context: ExecutionContext) -> dict[str, Any]:
        executor = self._executors.get(task["task_type"])
        if not executor:
            raise ValueError(f"unsupported durable task type: {task['task_type']}")
        if int(task.get('attempts', 1)) > 1 and context.worker_id:
            from .invocation_journal import InvocationJournal
            # Only a claimed, renewed lease may reconcile a previous owner.
            if not context.store.renew_task_lease(
                task['id'], context.worker_id, lease_generation=task['lease_generation'],
            ):
                from .errors import LeaseLost

                raise LeaseLost('cannot recover invocations without active task lease')
            # P2-D2: fencing — only reconcile the previous owner's running
            # invocations while this worker provably holds the task lease.
            InvocationJournal(context.store).recover(
                _build_run_context(task.get('payload') or {}, context),
                lease_id=context.worker_id,
            )
        context.event("task.started", task_id=task["id"], task_type=task["task_type"])
        with telemetry.span("nexus.runtime.execute", {
            "nexus.tenant.id": context.tenant_id,
            "nexus.run.id": context.run_id,
            "nexus.task.id": task["id"],
            "nexus.task.type": task["task_type"],
        }):
            result = executor(task["payload"], context)
            if inspect.isawaitable(result):
                result = await result
        if not isinstance(result, dict):
            raise TypeError("durable executor results must be objects")
        context.event("task.completed", task_id=task["id"], result=result)
        metrics.increment("nexus_runtime_tasks_total", tenant_id=context.tenant_id,
                          task_type=task["task_type"], status="completed")
        return result


def _configured_chain(clients: dict[str, Any]) -> list[str]:
    """``NEXUS_LLM_FALLBACK_CHAIN`` resolved against the clients with keys.

    The value is the ``[llm] fallback_chain`` list ``apply_environment`` exports
    as a comma-separated string. When it is set it *is* the order, and every
    named provider with a usable key is kept - not only the second one. A chain
    that names nothing available returns ``["fake"]``: the offline fake, never
    silently another cloud.
    """
    raw = os.getenv("NEXUS_LLM_FALLBACK_CHAIN", "")
    names = [name.strip().lower() for name in raw.split(",") if name.strip()]
    if not names:
        return []
    available = [name for name in names if name in clients and name != "fake"]
    return available or ["fake"]


def select_llm_client() -> NexusLLM:
    """Build the resilient LLM client used by agentic executors.

    ``LLMFactory.create_from_env()`` always yields the deterministic ``fake``
    provider; real providers therefore take precedence and ``fake`` stays as the
    last-resort fallback. Shared by ``execute_react`` and the ``omni`` CLI so a
    human-driven session runs on exactly the same provider resolution, and now
    on the same *chain* (Tanda C, Fix 4.1).
    """
    from nexus_core.llm.abstraction import NexusLLM

    clients = LLMFactory.create_from_env()
    if not clients:
        raise RuntimeError("no LLM provider configured")
    providers = [name for name in clients if name != "fake"] or ["fake"]
    selected = os.getenv("NEXUS_LLM_DEFAULT_PROVIDER")
    configured = _configured_chain(clients)
    if selected:
        # Missing keys use offline fake, never silently choose a different cloud.
        providers = [selected] if selected in clients else ["fake"]
    elif configured:
        providers = configured
    else:
        # No chain configured: the historical pair -primary plus at most one
        # fallback-, byte for byte what a run did before Tanda C (Fix 4.1).
        providers = providers[:2]
    chain = [clients[name] for name in providers]
    return NexusLLM(
        primary=chain[0],
        fallback=chain[1] if len(chain) > 1 else None,
        chain=chain,
    )


def _build_run_context(payload: dict[str, Any], context: ExecutionContext) -> RunContext:
    """Build the governed RunContext of one tool invocation.

    Shared by ``execute_tool`` and the ReAct approval gate so both authorize
    with exactly the same identity, engagement scope, trace and store. This is
    an internal helper: the executor signatures are unchanged.
    """
    from .models import Identity, RunContext
    from .scope_loader import load_engagement_scope

    actor = payload.get("identity") or {}
    identity = Identity(
        subject_id=str(actor.get("subject_id") or "nexus-worker"),
        tenant_id=context.tenant_id,
        kind=str(actor.get("kind") or "workload"),
        roles=tuple(actor["roles"]) if actor.get("roles") is not None else ("operator",),
    )
    scope = load_engagement_scope(
        context.store, context.tenant_id, payload.get("engagement_id")
    )
    from nexus_core.agent.memory import ensure_work_conversation
    outer = context.task.get('payload') or {}
    session_id = outer.get('session_id') or outer.get('conversation_id') or payload.get('session_id')
    if not session_id:
        session_id = ensure_work_conversation(context.store, context.tenant_id,
                                             outer.get('agent_id') or 'omni', payload.get('engagement_id'))
    from .job_authority import parse_authority

    return RunContext(
        job_authority=parse_authority(payload["job_authority"]) if "job_authority" in payload else None,
        authorized_permissions=tuple(payload.get("permissions") or ()),
        session_id=str(session_id or ''),
        project_root=str(outer.get('project_root') or ''),
        phase=str(payload.get('phase') or outer.get('phase') or ''),
        objective=str(payload.get('objective') or outer.get('objective') or ''),
        # Engine-owned: how an ``unknown`` retry is resolved in this run. Empty
        # outside ``--trust-mode``, so the journal keeps failing closed.
        resume_policy=str(payload.get('resume_policy') or outer.get('resume_policy') or ''),
        tenant_id=context.tenant_id,
        identity=identity,
        run_id=context.run_id,
        trace_id=str(payload.get("trace_id") or context.run_id),
        scope=scope,
        store=context.store,
        worker_id=context.worker_id,
    )


def _select_client(route: str | None = None) -> BaseLLMClient:
    clients = LLMFactory.create_from_env()
    requested = (route or os.getenv("LLM_PROVIDER") or "fake").lower()
    if requested in clients:
        return clients[requested]
    if requested != "fake" and os.getenv("NEXUS_ALLOW_MODEL_FALLBACK", "false").lower() != "true":
        raise RuntimeError(f"configured model provider is unavailable: {requested}")
    return clients["fake"]


async def execute_llm(payload: dict[str, Any], context: ExecutionContext) -> dict[str, Any]:
    messages = payload.get("messages")
    if not messages and "message" in payload:
        messages = [{"role": "user", "content": str(payload["message"])}]
    if not isinstance(messages, list) or not messages:
        raise ValueError("messages must be a non-empty array")
    normalized = [LLMMessage(role=str(item["role"]), content=str(item["content"]))
                  for item in messages]
    client = _select_client(payload.get("model_route"))
    response = await client.complete(normalized, scenario=payload.get("scenario", "echo"))
    context.store.record_usage(context.tenant_id, context.run_id, "model",
                               response.model, "tokens", response.total_tokens,
                               {"provider": response.provider.value})
    return {"content": response.content, "model": response.model,
            "provider": response.provider.value, "tokens_input": response.tokens_input,
            "tokens_output": response.tokens_output, "duration_ms": response.duration_ms}


async def execute_agent(payload: dict[str, Any], context: ExecutionContext) -> dict[str, Any]:
    agent_id = str(payload.get("agent_id") or "nexus")
    definitions = context.store.list_definitions("kernel_agents", context.tenant_id)
    agent = next((item for item in definitions if item.get("agent_id") == agent_id), None)
    if agent_id != "nexus" and not agent:
        raise ValueError("agent is not registered in this tenant")
    objective = str(payload.get("objective") or "").strip()
    if not objective:
        raise ValueError("agent objective is required")
    system = (agent or {}).get("system_prompt") or (
        "Eres NEXUS, un operador soberano. Responde con hechos, declara límites, "
        "no inventes acceso a herramientas y propone acciones verificables."
    )
    llm_result = await execute_llm({
        "model_route": (agent or {}).get("model_route", payload.get("model_route")),
        "scenario": payload.get("scenario", "echo"),
        "messages": [{"role": "system", "content": system},
                     {"role": "user", "content": objective}],
    }, context)
    return {"agent_id": agent_id, **llm_result}


async def execute_chat(payload: dict[str, Any], context: ExecutionContext) -> dict[str, Any]:
    conversation_id = str(payload["conversation_id"])
    conversation = context.store.get_conversation(context.tenant_id, conversation_id)
    if not conversation:
        raise ValueError("conversation not found")
    history = context.store.list_messages(context.tenant_id, conversation_id, limit=40)
    model_route = payload.get("model_route")
    client = _select_client(model_route)
    messages = [LLMMessage(role=item["role"], content=item["content"])
                for item in history if item["role"] in {"system", "user", "assistant"}]
    if not messages:
        raise ValueError("conversation has no messages")
    context.event("model.started", provider=client.config.provider.value,
                  model=client.config.model)
    response = await client.complete(messages, scenario=payload.get("scenario", "echo"))
    message = context.store.append_message(
        context.tenant_id, conversation_id, "assistant", response.content,
        run_id=context.run_id,
        metadata={"provider": response.provider.value, "model": response.model,
                  "tokens_input": response.tokens_input,
                  "tokens_output": response.tokens_output,
                  "duration_ms": response.duration_ms},
        classification=conversation["classification"],
    )
    context.store.record_usage(context.tenant_id, context.run_id, "model",
                               response.model, "tokens", response.total_tokens,
                               {"provider": response.provider.value})
    context.event("message.created", message_id=message["id"], role="assistant")
    return {"conversation_id": conversation_id, "message": message,
            "provider": response.provider.value, "model": response.model}


async def execute_memory(payload: dict[str, Any], context: ExecutionContext) -> dict[str, Any]:
    content = str(payload.get("content") or "").strip()
    if not content:
        raise ValueError("memory content is required")
    from .memory import MemoryStore
    memory = MemoryStore(context.store)
    result = memory.save_message(
        tenant_id=context.tenant_id, agent_id=str(payload.get("agent_id", "nexus")),
        agent_name=str(payload.get("agent_name", "NEXUS")),
        role=str(payload.get("role", "system")), content=content,
        session_id=payload.get("session_id"),
        classification=str(payload.get("classification", "internal")),
    )
    return {"memory_id": result, "indexed_at": utc_now()}


async def execute_evaluation(payload: dict[str, Any], context: ExecutionContext) -> dict[str, Any]:
    expected = payload.get("expected")
    actual = payload.get("actual")
    checks = {"non_empty": bool(actual), "matches_expected": expected is None or actual == expected}
    return {"passed": all(checks.values()), "checks": checks}


async def execute_tool(payload: dict[str, Any], context: ExecutionContext) -> dict[str, Any]:
    """Invoke only first-party tools through the policy-enforced gateway."""
    from nexus_core.scope import make_roe_validator, make_scope_validator
    from nexus_core.scope.roe import load_enforcer
    from nexus_core.tools.registry import durable_tool_definitions

    from .approvals import ApprovalService
    from .audit import AuditWriter
    from .policy import PolicyEngine
    from .scope_loader import scope_signing_secret
    from .tool_gateway import ToolGateway

    tool_id = str(payload.get("tool_id") or "")
    arguments = payload.get("arguments") or {}
    run_context = _build_run_context(payload, context)
    # Rules of Engagement are opt-in per engagement; absent one, the signed
    # scope alone governs. Present, they narrow it and can halt everything.
    roe_enforcer = load_enforcer(
        getattr(getattr(run_context, "scope", None), "engagement_id", None)
    )
    gateway = ToolGateway(
        PolicyEngine(context.store),
        AuditWriter(context.store),
        ApprovalService(context.store),
        scope_validator=make_scope_validator(signing_secret=scope_signing_secret()),
        roe_validator=make_roe_validator(roe_enforcer) if roe_enforcer else None,
    )

    catalog = durable_tool_definitions(context.tenant_id)
    if tool_id not in catalog:
        raise ValueError("tool is not in the first-party runtime catalog")
    definition, handler = catalog[tool_id]
    from .job_authority import check_authority, verify_job_reservation

    if payload.get("job_owner"):
        if run_context.job_authority is None:
            raise PermissionError("legacy job has no delegation envelope; enqueue again")
        check_authority(run_context.job_authority, run_context, definition)
        verify_job_reservation(run_context.job_authority, run_context)
    gateway.register(definition, handler)
    result = await gateway.invoke(tool_id, arguments, run_context,
                                  permissions=tuple(payload.get("permissions") or ()),
                                  approval_id=payload.get("approval_id"),
                                  retry_approval_id=payload.get('retry_approval_id'))
    return {"tool_id": tool_id, "output": result}


async def execute_brain(payload: dict[str, Any], context: ExecutionContext) -> dict[str, Any]:
    """Durable intake → verified action(s) → evaluate pipeline.

    ``steps`` is deliberately data, not executable model output: each item is
    routed through ``execute_tool`` and therefore through policy, approval,
    sandboxing and the ToolResult post-condition gate.  A future planner may
    propose these steps, but only this persisted loop is allowed to advance
    them.
    """
    objective = str(payload.get("objective") or "").strip()
    if not objective:
        raise ValueError("brain objective is required")
    context.event("brain.intake", objective_length=len(objective))
    requested_steps = payload.get("steps", [])
    if not isinstance(requested_steps, list):
        raise ValueError("brain steps must be an array")
    if len(requested_steps) > 8:
        raise ValueError("brain supports at most 8 verified steps per run")
    plan = [{"step": "understand", "status": "completed"}]
    plan.extend({"step": f"tool:{item.get('tool_id', 'unknown')}", "status": "pending"}
                for item in requested_steps)
    plan.extend([
        {"step": "respond", "status": "pending"},
        {"step": "evaluate", "status": "pending"},
    ])
    context.event("brain.plan", steps=plan)
    observations = []
    for index, step in enumerate(requested_steps, start=1):
        if not isinstance(step, dict) or not step.get("tool_id"):
            raise ValueError("each brain step requires tool_id")
        plan[index]["status"] = "running"
        context.event("brain.step.started", index=index, tool_id=step["tool_id"])
        invocation = await execute_tool({
            "tool_id": step["tool_id"],
            "arguments": step.get("arguments", {}),
            "identity": payload.get("identity", {}),
            "permissions": payload.get("permissions", ()),
            "approval_id": step.get("approval_id"),
            "trace_id": payload.get("trace_id"),
            "engagement_id": payload.get("engagement_id"),
        }, context)
        evidence = invocation["output"]
        if not evidence.get("success") or not evidence.get("verified"):
            raise RuntimeError(f"brain step {index} did not satisfy its post-condition")
        observations.append(invocation)
        plan[index]["status"] = "completed"
        context.event("brain.step.verified", index=index, tool_id=step["tool_id"],
                      verification_method=evidence["verification_method"],
                      evidence=evidence["evidence"])

    response_index = len(requested_steps) + 1
    plan[response_index]["status"] = "running"
    answer = await execute_agent({"agent_id": payload.get("agent_id", "nexus"),
                                  "objective": objective,
                                  "model_route": payload.get("model_route"),
                                  "scenario": payload.get("scenario", "echo")}, context)
    plan[response_index]["status"] = "completed"
    evaluation = await execute_evaluation({
        "actual": answer.get("content"),
        "expected": payload.get("expected_response"),
    }, context)
    evaluation["tool_postconditions_verified"] = all(
        item["output"].get("verified") for item in observations
    )
    evaluation["passed"] = evaluation["passed"] and evaluation["tool_postconditions_verified"]
    plan[response_index + 1]["status"] = "completed" if evaluation["passed"] else "failed"
    if not evaluation["passed"]:
        raise RuntimeError("brain evaluation failed")
    context.event("brain.evaluated", **evaluation)
    return {"objective": objective, "plan": plan, "answer": answer,
            "observations": observations, "evaluation": evaluation}


async def execute_react(payload: dict[str, Any], context: ExecutionContext) -> dict[str, Any]:
    """Durable ReAct loop: the model decides one governed step per iteration.

    Expected payload: ``objective`` (required), ``engagement_id``,
    ``max_iterations`` (default 12), ``agent_id`` (default ``"omni"``), plus the
    ``identity``/``permissions``/``approval_id`` forwarded to every tool call.
    """
    from nexus_core.agent.react import ReActConfig, run_react_loop

    objective = str(payload.get("objective") or "").strip()
    if not objective:
        raise ValueError("objective is required")

    llm = select_llm_client()
    config = ReActConfig(
        max_iterations=max(1, int(payload.get("max_iterations") or 12)),
        # Work-time budget for a queued run: the same clock the CLI passes.
        time_budget_seconds=max(0, int(payload.get("time_budget_seconds") or 0)),
    )
    budget = str(payload.get("budget_tokens") or os.getenv("NEXUS_RUN_BUDGET_TOKENS", "0"))
    try:
        budget_tokens = max(0, int(budget))
    except (TypeError, ValueError):
        budget_tokens = 0
    from dataclasses import replace
    from nexus_core.agent.memory import ensure_work_conversation
    session_id = payload.get('session_id') or payload.get('conversation_id') or ensure_work_conversation(
        context.store, context.tenant_id, payload.get('agent_id') or 'omni', payload.get('engagement_id'))
    context = replace(context, task={**context.task, 'payload': {**payload, 'session_id':session_id}})
    result = await run_react_loop(
        context=context,
        conversation_id=session_id,
        objective=objective,
        engagement_id=payload.get("engagement_id"),
        llm_client=llm,
        config=config,
        budget_tokens=budget_tokens,
    )
    return {
        "status": result.status,
        "completion_verified": result.completion_verified,
        "termination_reason": result.status,
        "iterations": result.iterations,
        "summary": result.final_summary,
        "findings": result.findings,
        "conversation_id": result.conversation_id,
        "actions": result.actions,
        "question": result.question,
    }


def build_default_registry() -> ExecutorRegistry:
    registry = ExecutorRegistry()
    registry.register("debug.fake_llm", execute_llm)
    registry.register("llm.complete", execute_llm)
    registry.register("agent.run", execute_agent)
    registry.register("conversation.respond", execute_chat)
    registry.register("tool.invoke", execute_tool)
    registry.register("brain.run", execute_brain)
    registry.register("react.run", execute_react)
    registry.register("memory.index", execute_memory)
    registry.register("evaluation.run", execute_evaluation)
    return registry
