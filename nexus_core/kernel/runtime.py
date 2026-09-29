"""Durable, provider-neutral execution runtime for NEXUS Sovereign."""

from __future__ import annotations

import inspect
import os
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Awaitable, Callable, Dict

from nexus_core.llm.abstraction import LLMFactory, LLMMessage

from .models import utc_now
from .telemetry import metrics, telemetry

if TYPE_CHECKING:
    from .models import RunContext

Executor = Callable[[dict, "ExecutionContext"], dict | Awaitable[dict]]


@dataclass(frozen=True)
class ExecutionContext:
    store: Any
    task: dict
    worker_id: str

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

    async def execute(self, task: dict, context: ExecutionContext) -> dict:
        executor = self._executors.get(task["task_type"])
        if not executor:
            raise ValueError(f"unsupported durable task type: {task['task_type']}")
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


def select_llm_client():
    """Build the resilient LLM client used by agentic executors.

    ``LLMFactory.create_from_env()`` always yields the deterministic ``fake``
    provider; real providers therefore take precedence and ``fake`` stays as the
    last-resort fallback. Shared by ``execute_react`` and the ``omni`` CLI so a
    human-driven session runs on exactly the same provider resolution.
    """
    from nexus_core.llm.abstraction import NexusLLM

    clients = LLMFactory.create_from_env()
    if not clients:
        raise RuntimeError("no LLM provider configured")
    providers = [name for name in clients if name != "fake"] or ["fake"]
    return NexusLLM(
        primary=clients[providers[0]],
        fallback=clients[providers[1]] if len(providers) > 1 else None,
    )


def _build_run_context(payload: dict, context: ExecutionContext) -> RunContext:
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
        roles=tuple(actor.get("roles") or ("operator",)),
    )
    scope = load_engagement_scope(
        context.store, context.tenant_id, payload.get("engagement_id")
    )
    return RunContext(
        tenant_id=context.tenant_id,
        identity=identity,
        run_id=context.run_id,
        trace_id=str(payload.get("trace_id") or context.run_id),
        scope=scope,
        store=context.store,
        worker_id=context.worker_id,
    )


def _select_client(route: str | None = None):
    clients = LLMFactory.create_from_env()
    requested = (route or os.getenv("LLM_PROVIDER") or "fake").lower()
    if requested in clients:
        return clients[requested]
    if requested != "fake" and os.getenv("NEXUS_ALLOW_MODEL_FALLBACK", "false").lower() != "true":
        raise RuntimeError(f"configured model provider is unavailable: {requested}")
    return clients["fake"]


async def execute_llm(payload: dict, context: ExecutionContext) -> dict:
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


async def execute_agent(payload: dict, context: ExecutionContext) -> dict:
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


async def execute_chat(payload: dict, context: ExecutionContext) -> dict:
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


async def execute_memory(payload: dict, context: ExecutionContext) -> dict:
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


async def execute_evaluation(payload: dict, context: ExecutionContext) -> dict:
    expected = payload.get("expected")
    actual = payload.get("actual")
    checks = {"non_empty": bool(actual), "matches_expected": expected is None or actual == expected}
    return {"passed": all(checks.values()), "checks": checks}


async def execute_tool(payload: dict, context: ExecutionContext) -> dict:
    """Invoke only first-party tools through the policy-enforced gateway."""
    from nexus_core.scope import make_scope_validator
    from nexus_core.tools.registry import durable_tool_definitions

    from .approvals import ApprovalService
    from .audit import AuditWriter
    from .policy import PolicyEngine
    from .scope_loader import scope_signing_secret
    from .tool_gateway import ToolGateway

    tool_id = str(payload.get("tool_id") or "")
    arguments = payload.get("arguments") or {}
    run_context = _build_run_context(payload, context)
    gateway = ToolGateway(
        PolicyEngine(context.store),
        AuditWriter(context.store),
        ApprovalService(context.store),
        scope_validator=make_scope_validator(signing_secret=scope_signing_secret()),
    )

    catalog = durable_tool_definitions(context.tenant_id)
    if tool_id not in catalog:
        raise ValueError("tool is not in the first-party runtime catalog")
    definition, handler = catalog[tool_id]
    gateway.register(definition, handler)
    result = await gateway.invoke(tool_id, arguments, run_context,
                                  permissions=tuple(payload.get("permissions") or ()),
                                  approval_id=payload.get("approval_id"))
    return {"tool_id": tool_id, "output": result}


async def execute_brain(payload: dict, context: ExecutionContext) -> dict:
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


async def execute_react(payload: dict, context: ExecutionContext) -> dict:
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
    config = ReActConfig(max_iterations=max(1, int(payload.get("max_iterations") or 12)))
    result = await run_react_loop(
        context=context,
        objective=objective,
        engagement_id=payload.get("engagement_id"),
        llm_client=llm,
        config=config,
    )
    return {
        "status": result.status,
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
