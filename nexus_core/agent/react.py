"""Durable ReAct (Reason + Act) loop for OmniAgent.

The loop is the *only* component allowed to translate model output into tool
execution, and it never executes anything the model did not request in JSON:

* every tool call is routed through ``execute_tool`` (policy, scope, approval,
  sandbox and audit), never through a handler directly;
* a tool the model invents is rejected and reported back as an observation;
* a target outside the signed engagement aborts the loop immediately;
* three consecutive tool failures abort the loop with ``status="failed"``;
* every iteration is persisted in ``kernel_conversations``/``kernel_messages``
  and audited with ``action="react.step"``, so a died worker can resume and a
  live worker can be cancelled through the ``react.cancel_requested`` run event.
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass, field
from typing import Any, Callable

from nexus_core.kernel.audit import AuditWriter
from nexus_core.llm.abstraction import LLMMessage
from nexus_core.scope import ScopeViolation

from . import memory
from .parser import (
    ACTION_REQUEST_CLARIFICATION,
    ACTION_TASK_COMPLETE,
    ACTION_TOOL_CALL,
    ReActAction,
    ReActParseError,
    parse_react_response,
)
from .prompts import describe_scope, render_system_prompt

DEFAULT_AGENT_ID = "omni"
MAX_CONSECUTIVE_TOOL_FAILURES = 3
CANCEL_EVENT_TYPE = "react.cancel_requested"

#: Observations longer than this are truncated before persisting (the durable
#: message store is text; full artifacts belong in the artifact store).
MAX_OBSERVATION_CHARS = 20_000

STATUS_COMPLETED = "completed"
STATUS_MAX_ITERATIONS = "max_iterations"
STATUS_CLARIFICATION = "clarification"
STATUS_FAILED = "failed"
STATUS_CANCELLED = "cancelled"
STATUS_SCOPE_VIOLATION = "scope_violation_aborted"


@dataclass(frozen=True)
class ApprovalDecision:
    """Answer of a human operator to one high-risk tool request.

    ``edited_arguments`` lets the operator amend the target or the flags before
    the call is authorized; the amended call still goes through policy, scope
    and sandbox, so an operator cannot widen an engagement.
    """

    approved: bool
    approval_id: str | None = None
    edited_arguments: dict[str, Any] | None = None
    reason: str = ""


@dataclass(frozen=True)
class ReActConfig:
    """Tunables of one ReAct run."""

    max_iterations: int = 12
    timeout_per_tool_seconds: int = 600
    enable_summarization: bool = True
    max_history_messages: int = 40
    #: Interactive approval hook. When set, the loop asks policy *before* every
    #: tool invocation and, if the decision requires human approval, calls this
    #: callback with ``(tool_id, arguments, decision)``. Returning ``None`` or a
    #: denying :class:`ApprovalDecision` injects a ``denied_by_operator``
    #: observation and continues (a human refusal is not a tool failure). Without
    #: a callback, the gateway fails the call with ``PermissionError`` as before.
    on_approval_needed: Callable[[str, dict[str, Any], Any], ApprovalDecision | None] | None = None


@dataclass
class ReActResult:
    """Outcome of a ReAct run."""

    status: str
    iterations: int
    final_summary: str
    findings: list[dict[str, Any]]
    conversation_id: str
    actions: list[dict[str, Any]] = field(default_factory=list)
    question: str | None = None


# --------------------------------------------------------------------- helpers
def _task_payload(context: Any) -> dict[str, Any]:
    payload = context.task.get("payload") if isinstance(context.task, dict) else None
    return payload if isinstance(payload, dict) else {}


def _cancellation_requested(store: Any, tenant_id: str, run_id: str) -> bool:
    """Cooperative cancel: a ``react.cancel_requested`` run event."""
    events = store.list_run_events(tenant_id, run_id)
    return any(event.get("event_type") == CANCEL_EVENT_TYPE for event in events)


def _audit_step(
    audit: AuditWriter,
    *,
    tenant_id: str,
    run_id: str,
    agent_id: str,
    iteration: int,
    action: str,
    decision: str,
    **payload: Any,
) -> None:
    audit.append(
        tenant_id=tenant_id,
        trace_id=run_id,
        actor_id=agent_id,
        action="react.step",
        resource_type="run",
        resource_id=run_id,
        payload={"iteration": iteration, "action": action, **payload},
        decision=decision,
    )


def _truncate_observation(value: dict[str, Any]) -> tuple[str, bool]:
    encoded = json.dumps(value, default=str, ensure_ascii=False)
    if len(encoded) <= MAX_OBSERVATION_CHARS:
        return encoded, False
    return encoded[:MAX_OBSERVATION_CHARS], True


def _persisted_actions(messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Rebuild the action log from persisted history (used when resuming)."""
    pending: dict[Any, dict[str, Any]] = {}
    actions: list[dict[str, Any]] = []
    for message in messages:
        metadata = message.get("metadata") or {}
        if not isinstance(metadata, dict):
            continue
        kind = metadata.get("kind")
        if kind == "react.action":
            entry = {
                "iteration": metadata.get("iteration"),
                "action": metadata.get("action"),
                "thought": metadata.get("thought") or "",
                "tool_id": metadata.get("tool_id"),
                "arguments": metadata.get("arguments"),
                "tool_result": None,
                "warnings": list(metadata.get("warnings") or []),
            }
            actions.append(entry)
            if entry["iteration"] is not None:
                pending[entry["iteration"]] = entry
        elif kind == "react.observation":
            entry = pending.get(metadata.get("iteration"))
            if entry is not None:
                entry["tool_result"] = metadata.get("tool_result")
    return actions


def _last_persisted_iteration(actions: list[dict[str, Any]]) -> int:
    latest = 0
    for entry in actions:
        try:
            latest = max(latest, int(entry.get("iteration") or 0))
        except (TypeError, ValueError):
            continue
    return latest


def _action_entry(
    iteration: int,
    action: str,
    *,
    thought: str = "",
    tool_id: str | None = None,
    arguments: dict[str, Any] | None = None,
    warnings: Any = (),
    tool_result: dict[str, Any] | None = None,
    **extra: Any,
) -> dict[str, Any]:
    """One entry of ``ReActResult.actions`` (also the audit substrate)."""
    entry: dict[str, Any] = {
        "iteration": iteration,
        "action": action,
        "thought": thought,
        "tool_id": tool_id,
        "arguments": arguments,
        "tool_result": tool_result,
        "warnings": list(warnings or ()),
    }
    entry.update(extra)
    return entry


def _operator_approval_gate(
    *,
    config: ReActConfig,
    context: Any,
    definition: Any,
    tool_payload: dict[str, Any],
) -> dict[str, Any] | None:
    """Run the pre-invocation approval handshake for one tool call.

    Reuses the very same :class:`PolicyEngine` and RunContext that
    ``execute_tool`` will use, so the loop never diverges from the gateway.
    Returns a denial observation when the operator refuses, or ``None`` after
    annotating ``tool_payload`` with the approved ``approval_id`` and any
    operator-edited arguments.
    """
    from nexus_core.kernel.models import Resource
    from nexus_core.kernel.policy import PolicyEngine
    from nexus_core.kernel.runtime import _build_run_context

    tool_id = str(tool_payload["tool_id"])
    run_context = _build_run_context(tool_payload, context)
    decision = PolicyEngine(context.store).decide(
        run_context.identity,
        "execute:tool",
        Resource(tool_id, definition.tenant_id, "tool"),
        tuple(tool_payload.get("permissions") or ()),
        definition,
    )
    if not decision.requires_approval or config.on_approval_needed is None:
        return None

    answer = config.on_approval_needed(tool_id, dict(tool_payload["arguments"]), decision)
    if answer is None or not answer.approved:
        reason = (answer.reason if answer is not None else "") or "operator did not authorize"
        return {
            "success": False,
            "status": "denied_by_operator",
            "tool_id": tool_id,
            "reason": str(reason)[:500],
        }
    if answer.edited_arguments is not None:
        if not isinstance(answer.edited_arguments, dict):
            return {
                "success": False,
                "status": "denied_by_operator",
                "tool_id": tool_id,
                "reason": "operator returned invalid edited arguments",
            }
        tool_payload["arguments"] = dict(answer.edited_arguments)
    if answer.approval_id:
        tool_payload["approval_id"] = answer.approval_id
    return None


def _observation_payload(invocation: dict[str, Any]) -> dict[str, Any]:
    output = invocation.get("output") if isinstance(invocation, dict) else None
    if not isinstance(output, dict):
        return {"success": False, "error": "tool returned no structured output"}
    return {
        "success": bool(output.get("success")),
        "verification_method": output.get("verification_method"),
        "evidence": output.get("evidence"),
        "output": output.get("output"),
    }


# ------------------------------------------------------------------- the loop
async def run_react_loop(
    *,
    context: Any,
    objective: str,
    engagement_id: str | None,
    llm_client: Any,
    config: ReActConfig = ReActConfig(),
    tool_catalog: dict[str, Any] | None = None,
) -> ReActResult:
    """Run the durable ReAct loop until completion, abort or iteration budget."""
    from nexus_core.kernel import runtime as runtime_module
    from nexus_core.kernel.scope_loader import load_engagement_scope
    from nexus_core.tools.registry import durable_tool_definitions

    store = context.store
    tenant_id = context.tenant_id
    run_id = context.run_id
    payload = _task_payload(context)
    agent_id = str(payload.get("agent_id") or DEFAULT_AGENT_ID)
    catalog = tool_catalog if tool_catalog is not None else durable_tool_definitions(tenant_id)
    audit = AuditWriter(store)
    scope = load_engagement_scope(store, tenant_id, engagement_id)

    conversation_id = memory.ensure_conversation(store, tenant_id, run_id, agent_id)
    history = memory.load_history(store, tenant_id, conversation_id, limit=500)
    if not any(
        memory.message_kind(message) == memory.SYSTEM_MESSAGE_KIND for message in history
    ):
        memory.append_step(
            store,
            tenant_id,
            conversation_id,
            "system",
            objective,
            {"kind": memory.SYSTEM_MESSAGE_KIND, "objective": objective, "run_id": run_id},
        )
        history = memory.load_history(store, tenant_id, conversation_id, limit=500)

    actions = _persisted_actions(history)
    iteration = _last_persisted_iteration(actions)
    status = STATUS_MAX_ITERATIONS
    final_summary = ""
    findings: list[dict[str, Any]] = []
    question: str | None = None
    consecutive_failures = 0

    while iteration < config.max_iterations:
        if _cancellation_requested(store, tenant_id, run_id):
            status = STATUS_CANCELLED
            store.append_run_event(
                tenant_id, run_id, "react.cancelled", {"iteration": iteration}
            )
            break

        iteration += 1
        history = memory.load_history(store, tenant_id, conversation_id, limit=500)
        history_summary = memory.latest_summary(history)
        if config.enable_summarization:
            summary = await memory.summarize_history_if_large(
                store,
                tenant_id,
                conversation_id,
                llm_client,
                force=len(history) > config.max_history_messages,
            )
            if summary:
                history_summary = summary
                history = memory.load_history(store, tenant_id, conversation_id, limit=500)

        system_prompt = render_system_prompt(
            catalog=catalog,
            objective=objective,
            engagement_id=engagement_id,
            scope_summary=describe_scope(scope),
            history_summary=history_summary or "(sin historial previo)",
        )
        messages = [LLMMessage(role="system", content=system_prompt)]
        messages.extend(
            LLMMessage(role=str(message["role"]), content=str(message["content"]))
            for message in history
            if message.get("role") in {"user", "assistant"}
            and memory.message_kind(message) not in memory.COMPACTION_KINDS
        )

        response = await llm_client.complete(messages)
        raw_response = str(getattr(response, "content", "") or "")

        try:
            action = parse_react_response(raw_response)
        except ReActParseError as exc:
            actions.append(
                _action_entry(iteration, "parse_error", error=str(exc)[:500])
            )
            memory.append_step(
                store,
                tenant_id,
                conversation_id,
                "assistant",
                raw_response,
                {
                    "kind": "react.action",
                    "iteration": iteration,
                    "action": "parse_error",
                    "warnings": [],
                    "run_id": run_id,
                },
            )
            memory.append_step(
                store,
                tenant_id,
                conversation_id,
                "user",
                "Tu respuesta anterior no era JSON válido y no se ejecutó nada. "
                f"Error del parser: {str(exc)[:300]}. Responde de nuevo con UN solo "
                "objeto JSON que cumpla el contrato (tool_call, task_complete o "
                "request_clarification).",
                {"kind": "react.correction", "iteration": iteration, "run_id": run_id},
            )
            context.event("react.parse_error", iteration=iteration, error=str(exc)[:300])
            _audit_step(
                audit,
                tenant_id=tenant_id,
                run_id=run_id,
                agent_id=agent_id,
                iteration=iteration,
                action="parse_error",
                decision="deny",
                error=str(exc)[:300],
                raw_response=raw_response[:2000],
            )
            continue

        memory.append_step(
            store,
            tenant_id,
            conversation_id,
            "assistant",
            action.raw_response or raw_response,
            {
                "kind": "react.action",
                "iteration": iteration,
                "action": action.action,
                "thought": action.thought,
                "tool_id": action.tool_id,
                "arguments": action.arguments,
                "warnings": list(action.warnings),
                "run_id": run_id,
            },
        )
        context.event(
            "react.action",
            iteration=iteration,
            action=action.action,
            tool_id=action.tool_id,
        )

        if action.action == ACTION_TASK_COMPLETE:
            status = STATUS_COMPLETED
            final_summary = action.summary or ""
            findings = list(action.findings)
            actions.append(
                _action_entry(
                    iteration,
                    action.action,
                    thought=action.thought,
                    warnings=action.warnings,
                    summary=final_summary,
                    findings=findings,
                )
            )
            memory.append_step(
                store,
                tenant_id,
                conversation_id,
                "assistant",
                json.dumps(
                    {"summary": final_summary, "findings": findings},
                    ensure_ascii=False,
                ),
                {
                    "kind": "react.final",
                    "iteration": iteration,
                    "findings_count": len(findings),
                    "run_id": run_id,
                },
            )
            _audit_step(
                audit,
                tenant_id=tenant_id,
                run_id=run_id,
                agent_id=agent_id,
                iteration=iteration,
                action=action.action,
                decision="allow",
                thought=action.thought,
                findings_count=len(findings),
            )
            break

        if action.action == ACTION_REQUEST_CLARIFICATION:
            status = STATUS_CLARIFICATION
            question = action.question
            actions.append(
                _action_entry(
                    iteration,
                    action.action,
                    thought=action.thought,
                    warnings=action.warnings,
                    question=question,
                )
            )
            memory.append_step(
                store,
                tenant_id,
                conversation_id,
                "assistant",
                question or "",
                {"kind": "react.clarification", "iteration": iteration, "run_id": run_id},
            )
            store.append_run_event(
                tenant_id, run_id, "react.clarification_requested", {"question": question}
            )
            _audit_step(
                audit,
                tenant_id=tenant_id,
                run_id=run_id,
                agent_id=agent_id,
                iteration=iteration,
                action=action.action,
                decision="allow",
                thought=action.thought,
            )
            break

        if action.action != ACTION_TOOL_CALL:
            # Defensive: the parser only returns the three known actions.
            status = STATUS_FAILED
            final_summary = f"unsupported action: {action.action}"
            actions.append(
                _action_entry(iteration, str(action.action), unsupported=True)
            )
            _audit_step(
                audit,
                tenant_id=tenant_id,
                run_id=run_id,
                agent_id=agent_id,
                iteration=iteration,
                action=str(action.action),
                decision="deny",
            )
            break

        entry = _action_entry(
            iteration,
            action.action,
            thought=action.thought,
            tool_id=action.tool_id,
            arguments=action.arguments,
            warnings=action.warnings,
            expected_outcome=action.expected_outcome,
        )

        # Iron rule: never execute a tool the model did not request, and never
        # execute one that does not exist in the first-party catalog.
        if action.tool_id not in catalog:
            observation = {
                "success": False,
                "error": f"tool '{action.tool_id}' does not exist in the catalog",
                "available_tools": sorted(catalog),
            }
            consecutive_failures += 1
            entry["tool_result"] = observation
            actions.append(entry)
            _inject_observation(
                store, tenant_id, conversation_id, run_id, iteration, action, observation
            )
            _audit_step(
                audit,
                tenant_id=tenant_id,
                run_id=run_id,
                agent_id=agent_id,
                iteration=iteration,
                action=action.action,
                decision="deny",
                tool_id=action.tool_id,
                reason="unknown_tool",
            )
            if consecutive_failures >= MAX_CONSECUTIVE_TOOL_FAILURES:
                status = STATUS_FAILED
                final_summary = (
                    f"aborted after {consecutive_failures} consecutive tool failures "
                    f"(last: unknown tool '{action.tool_id}')"
                )
                break
            continue

        resolved = catalog[action.tool_id]
        definition = resolved[0] if isinstance(resolved, tuple) else resolved
        tool_payload = {
            "tool_id": action.tool_id,
            "arguments": dict(action.arguments or {}),
            "identity": payload.get("identity") or {},
            "engagement_id": engagement_id,
            "permissions": tuple(payload.get("permissions") or ()),
            "approval_id": payload.get("approval_id"),
            "trace_id": run_id,
        }
        if config.on_approval_needed is not None:
            denial = _operator_approval_gate(
                config=config, context=context, definition=definition, tool_payload=tool_payload
            )
            if denial is not None:
                # A human refusal is not a tool failure: the loop keeps its
                # failure budget and lets the model pick another strategy.
                entry["tool_result"] = denial
                actions.append(entry)
                _inject_observation(
                    store, tenant_id, conversation_id, run_id, iteration, action, denial
                )
                _audit_step(
                    audit,
                    tenant_id=tenant_id,
                    run_id=run_id,
                    agent_id=agent_id,
                    iteration=iteration,
                    action=action.action,
                    decision="deny",
                    tool_id=action.tool_id,
                    reason="denied_by_operator",
                    operator_reason=denial["reason"],
                )
                continue
        try:
            invocation = await asyncio.wait_for(
                runtime_module.execute_tool(tool_payload, context),
                timeout=config.timeout_per_tool_seconds,
            )
        except ScopeViolation as exc:
            # The scope is sacred: never retry with another target.
            status = STATUS_SCOPE_VIOLATION
            final_summary = f"scope violation aborted the loop: {exc}"
            observation = {
                "success": False,
                "error_type": type(exc).__name__,
                "error": str(exc)[:500],
                "scope_violation": True,
            }
            entry["tool_result"] = observation
            actions.append(entry)
            _inject_observation(
                store, tenant_id, conversation_id, run_id, iteration, action, observation
            )
            store.append_run_event(
                tenant_id,
                run_id,
                "react.scope_violation",
                {"iteration": iteration, "tool_id": action.tool_id, "error": str(exc)[:500]},
            )
            _audit_step(
                audit,
                tenant_id=tenant_id,
                run_id=run_id,
                agent_id=agent_id,
                iteration=iteration,
                action=action.action,
                decision="deny",
                tool_id=action.tool_id,
                reason="scope_violation",
                error_type=type(exc).__name__,
            )
            break
        except Exception as exc:  # noqa: BLE001 - surfaced to the LLM as an observation
            observation = {
                "success": False,
                "error_type": type(exc).__name__,
                "error": str(exc)[:1000],
            }
            consecutive_failures += 1
        else:
            observation = _observation_payload(invocation)
            if observation.get("success"):
                consecutive_failures = 0
            else:
                consecutive_failures += 1

        entry["tool_result"] = observation
        actions.append(entry)
        _inject_observation(
            store, tenant_id, conversation_id, run_id, iteration, action, observation
        )
        _audit_step(
            audit,
            tenant_id=tenant_id,
            run_id=run_id,
            agent_id=agent_id,
            iteration=iteration,
            action=action.action,
            decision="allow" if observation.get("success") else "deny",
            tool_id=action.tool_id,
            success=bool(observation.get("success")),
            consecutive_failures=consecutive_failures,
            error=observation.get("error"),
        )

        if consecutive_failures >= MAX_CONSECUTIVE_TOOL_FAILURES:
            status = STATUS_FAILED
            final_summary = (
                f"aborted after {consecutive_failures} consecutive tool failures"
            )
            break

    if status == STATUS_MAX_ITERATIONS and not final_summary:
        final_summary = (
            f"iteration budget exhausted ({config.max_iterations}) without task_complete"
        )

    context.event(
        "react.finished",
        status=status,
        iterations=iteration,
        conversation_id=conversation_id,
        findings_count=len(findings),
    )
    return ReActResult(
        status=status,
        iterations=iteration,
        final_summary=final_summary,
        findings=findings,
        conversation_id=conversation_id,
        actions=actions,
        question=question,
    )


def _inject_observation(
    store: Any,
    tenant_id: str,
    conversation_id: str,
    run_id: str,
    iteration: int,
    action: ReActAction,
    observation: dict[str, Any],
) -> None:
    """Feed a tool outcome (success or error) back to the model as history."""
    content, truncated = _truncate_observation(
        {"tool_id": action.tool_id, **observation}
    )
    memory.append_step(
        store,
        tenant_id,
        conversation_id,
        "user",
        content,
        {
            "kind": "react.observation",
            "iteration": iteration,
            "tool_id": action.tool_id,
            "success": bool(observation.get("success")),
            "tool_result": {
                key: value
                for key, value in observation.items()
                if key not in {"evidence", "output"}
            },
            "truncated": truncated,
            "run_id": run_id,
        },
    )
