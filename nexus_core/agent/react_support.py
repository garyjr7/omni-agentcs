"""Compatibility helpers for persistence, budgeting and ReAct telemetry."""

from __future__ import annotations
import re

_THOUGHT_RE = re.compile(r'"thought"\s*:\s*"((?:[^"\\]|\\.)*)')

import asyncio
import json
import os
import time
from typing import Any, Callable, cast

from nexus_core.kernel.audit import AuditWriter
from nexus_core.llm.abstraction import LLMMessage

from . import memory
from nexus_core.kernel.domain_dto import Action
from .evidence import fabricated_evidence
from .injection import scan_untrusted_text
from .observations import prepare_observation
from .parser import (
    ReActAction,
)

from .react_types import (
    MAX_CONSECUTIVE_TOOL_FAILURES,
    CANCEL_EVENT_TYPE,
    PHASE_TIMEOUT_ENV,
    REACT_MAX_TOKENS_ENV,
    REACT_DEFAULT_MAX_TOKENS,
    REACT_MIN_MAX_TOKENS,
    KICKOFF_USER_PROMPT,
    FINAL_PHASE_ID,
    BUDGET_SUBJECT_TYPE,
    BUDGET_SUBJECT_ID,
    BUDGET_METRIC,
    ReActConfig,
)


def _task_payload(context: Any) -> dict[str, Any]:
    payload = context.task.get("payload") if isinstance(context.task, dict) else None
    return payload if isinstance(payload, dict) else {}


def _cancellation_requested(store: Any, tenant_id: str, run_id: str) -> bool:
    """Cooperative cancel: a ``react.cancel_requested`` run event."""
    events = store.list_run_events(tenant_id, run_id)
    return any(event.get("event_type") == CANCEL_EVENT_TYPE for event in events)


def _blackboard_facts(store: Any, tenant_id: str, engagement_id: str | None) -> str:
    """Render the engagement blackboard for the prompt (never raises)."""
    return _blackboard_view(store, tenant_id, engagement_id)[1]


def _blackboard_view(store: Any, tenant_id: str, engagement_id: str | None) -> tuple[Any, str]:
    """Return ``(plan, facts_text)`` for one iteration (never raises).

    The plan is derived deterministically from the blackboard summary, so the
    model plans inside a stable frame; the rendered facts stay in the prompt as
    before. Memory failures degrade to an empty plan instead of aborting.
    """
    from .planner import build_plan, plan_from_summary

    empty = "(sin hechos registrados)"
    if not engagement_id or store is None:
        return build_plan(engagement_id=engagement_id), empty
    try:
        from nexus_core.kernel.blackboard import Blackboard

        board = Blackboard(store)
        summary = board.summary(tenant_id, engagement_id)
        rendered = board.render(tenant_id, engagement_id)
    except Exception:  # noqa: BLE001 - memory must never kill a run
        return build_plan(engagement_id=engagement_id), empty
    return plan_from_summary(summary, engagement_id=engagement_id), (rendered or empty)


def _playbook_guidance(store: Any, tenant_id: str, engagement_id: str | None,
                       *, run_id: str = "") -> str:
    """Render the applicable deterministic playbooks for the prompt.

    Fase 4.0: the chains already existed (``nexus_core.agent.playbooks``) but
    only reached the model through a tool it had to *choose* to call, so the E2E
    #5 walked into the wrong service. Never raises: guidance must not kill a run.
    """
    if not engagement_id or store is None:
        return ""
    try:
        from nexus_core.kernel.blackboard import Blackboard

        from .playbooks import render_playbook_matches, select_playbooks

        facts = Blackboard(store).list_facts(tenant_id, engagement_id)
        from .playbook_proofs import execution_proofs

        proofs = execution_proofs(store, tenant_id, run_id, engagement_id)
        return str(render_playbook_matches(select_playbooks(facts, proofs=proofs)))
    except Exception:  # noqa: BLE001 - guidance must never kill a run
        return ""


def _audit_step(
    audit: AuditWriter,
    *,
    tenant_id: str,
    run_id: str,
    agent_id: str,
    iteration: int,
    action: str,
    decision: str,
    subagent_id: str | None = None,
    **payload: Any,
) -> None:
    body = {"iteration": iteration, "action": action}
    if subagent_id:
        # Every step is attributable to the subagent that proposed it (3C).
        body["subagent_id"] = subagent_id
    body.update(payload)
    audit.append(
        tenant_id=tenant_id,
        trace_id=run_id,
        actor_id=agent_id,
        action="react.step",
        resource_type="run",
        resource_id=run_id,
        payload=body,
        decision=decision,
    )


def _failure_kind(exc: BaseException) -> str:
    """Classify a tool exception as ``"input"`` or ``"tool"``.

    Invalid input (schema violations, forbidden flags) raises a ``ValueError``
    from the gateway/handler; a governance denial raises ``PermissionError``.
    Neither means the tool is broken, so neither retires it: a model that keeps
    sending bad arguments or hitting a policy gate must not be able to exhaust
    the phase's toolset. A broken/absent binary surfaces as anything else
    (``RuntimeError`` post-condition, ``OSError``, timeouts) and does (B3).
    """
    return "input" if isinstance(exc, (ValueError, PermissionError)) else "tool"


def _elapsed_ms(started: float) -> int:
    """Whole milliseconds since a ``time.perf_counter()`` mark (never negative)."""
    return max(0, int((time.perf_counter() - float(started)) * 1000))


def _phase_timeout_seconds() -> float:
    """Read the optional per-phase wall-clock budget (seconds; 0 disables)."""
    raw = os.getenv(PHASE_TIMEOUT_ENV, "0")
    try:
        return max(0.0, float(str(raw).strip() or 0))
    except (TypeError, ValueError):
        return 0.0


def react_max_tokens() -> int:
    """Output-token ceiling of one ReAct turn (env-overridable)."""
    raw = os.getenv(REACT_MAX_TOKENS_ENV, "")
    try:
        return int(max(REACT_MIN_MAX_TOKENS, int(str(raw).strip())))
    except (TypeError, ValueError):
        return int(REACT_DEFAULT_MAX_TOKENS)


def _usable_tool_count(subagent: Any, unavailable: set[str]) -> int:
    """How many of the profile's tools are still usable."""
    return len(_remaining_tools(subagent, unavailable))


def _keep_going_after_failures(
    subagent: Any, unavailable: set[str], consecutive_failures: int
) -> bool:
    """Whether the loop continues instead of aborting after failures (B3).

    Fatal only when the failure threshold is reached *and* the active profile
    has no usable tool left; otherwise the run pivots to another route.
    """
    if consecutive_failures < MAX_CONSECUTIVE_TOOL_FAILURES:
        return True
    return _usable_tool_count(subagent, unavailable) > 0


def _remaining_tools(subagent: Any, unavailable: set[str]) -> list[str]:
    """Tools of the active profile that are still usable."""
    return sorted(str(tool) for tool in subagent.tools if str(tool) not in unavailable)


def _run_messages(messages: list[dict[str, Any]], run_id: str) -> list[dict[str, Any]]:
    """The messages that belong to ``run_id`` only (B8.2.1).

    A shared work session accumulates every run's turns; a run must reason over
    *its own* observations, so the raw history handed to the model is filtered by
    ``run_id``. The engagement blackboard stays shared (that is the point of the
    work session), and prior objectives still reach the model through the
    summarised history block in the system prompt.
    """
    wanted = str(run_id)
    return [message for message in messages if str(message.get("run_id") or "") == wanted]


def _completion_objections(
    plan: Any,
    *,
    enforce_completion_gates: bool,
    evidence_stats: dict[str, int] | None = None,
    engagement_id: str | None = None,
) -> list[str]:
    """Why this ``task_complete`` must not be accepted yet (B8.2.2/B8.2.3).

    Two independent checks, both deterministic:

    * the plan is not on its final phase yet, so required phases are missing;
    * the findings cite evidence that no observation of this run supports.

    The plan check only applies to an **engagement** run: with no signed scope
    there is no blackboard, so every phase would stay ``pending`` forever and no
    objective could ever complete. The kill-chain frame is a property of an
    engagement, not of a bare objective.
    """
    objections: list[str] = []
    if enforce_completion_gates and engagement_id and plan is not None:
        current = getattr(plan, "current", None)
        if current != FINAL_PHASE_ID:
            from .planner import STATUS_PENDING

            pending = [
                item.label
                for item in plan.phases
                if item.status == STATUS_PENDING and not item.optional
            ]
            done, total = plan.progress
            label = getattr(getattr(plan, "phase", None), "label", current)
            objections.append(
                f"el plan sigue en la fase '{label}' ({done}/{total} fases de la "
                "kill chain con evidencia): faltan "
                + (", ".join(pending) if pending else "fases obligatorias")
            )
    if enforce_completion_gates and evidence_stats and fabricated_evidence(evidence_stats):
        objections.append(
            f"{evidence_stats.get('stale')} hallazgo(s) citan evidencia que no "
            "aparece en ninguna observación de este run (stale_evidence)"
        )
    return objections


def with_kickoff_user_turn(messages: list[LLMMessage], objective: str) -> list[LLMMessage]:
    """Append a ``user`` turn when the context has none (Fase 3.8).

    Some chat templates (Qwen) reject a conversation that carries no user
    message, and the first ReAct iteration historically sent only the system
    prompt. Idempotent: a context that already has a user turn is returned
    unchanged, so providers that worked with the old shape are unaffected.
    """
    if any(getattr(message, "role", None) == "user" for message in messages):
        return messages
    return [
        *messages,
        LLMMessage(role="user", content=KICKOFF_USER_PROMPT.format(objective=objective)),
    ]


def _premature_completion_message(objections: list[str], plan: Any) -> str:
    """Correction injected into the history when a completion is refused."""
    lines = [
        "Tu 'task_complete' ha sido RECHAZADO: la tarea no está terminada.",
    ]
    lines.extend(f"- {item}" for item in objections)
    if plan is not None:
        lines.append("")
        lines.append("PLAN VIGENTE:")
        lines.append(plan.render())
    lines.append("")
    lines.append(
        "Continúa con la fase actual: propone UNA acción (tool_call) que produzca "
        "evidencia NUEVA de este run. Solo puedes cerrar la tarea cuando el plan "
        f"esté en la fase '{FINAL_PHASE_ID}' y tu evidencia provenga de "
        "observaciones de este run."
    )
    return "\n".join(lines)


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
            entry: dict[str, Any] = {
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
            pending_entry = pending.get(metadata.get("iteration"))
            if pending_entry is not None:
                pending_entry["tool_result"] = metadata.get("tool_result")
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
    *, config: ReActConfig, context: Any, definition: Any, tool_payload: dict[str, Any]
) -> dict[str, Any] | None:
    from .react_services import ApprovalCoordinator

    return ApprovalCoordinator().review(
        config=config, context=context, definition=definition, tool_payload=tool_payload
    )


def _observation_payload(invocation: dict[str, Any]) -> dict[str, Any]:
    output = invocation.get("output") if isinstance(invocation, dict) else None
    if not isinstance(output, dict):
        return {"success": False, "error": "tool returned no structured output"}
    return {
        "success": bool(output.get("success")),
        "verification_method": output.get("verification_method"),
        "evidence": output.get("evidence"),
        "invocation_id": output.get("invocation_id"),
        "assertions": output.get("assertions", []),
        "output": output.get("output"),
    }


def _budget_tokens(payload: dict[str, Any], explicit: int | None) -> int:
    """Resolve the per-run token budget from the payload, env or explicit arg."""
    if explicit is not None:
        raw: Any = explicit
    elif payload.get("budget_tokens") not in (None, ""):
        raw = payload.get("budget_tokens")
    else:
        raw = os.getenv("NEXUS_RUN_BUDGET_TOKENS", "0")
    try:
        return max(0, int(raw))
    except (TypeError, ValueError):
        return 0


def _budget_used(
    store: Any, tenant_id: str, run_id: str, subject_id: str = BUDGET_SUBJECT_ID
) -> int:
    """Tokens the loop already booked for this run/subject (0 when unreadable).

    The run total is booked under ``BUDGET_SUBJECT_ID``; each subagent also
    books its own lane (``react:<subagent_id>``) so one phase cannot drain
    another phase's allowance.
    """
    try:
        return int(
            store.usage_total(tenant_id, run_id, BUDGET_SUBJECT_TYPE, subject_id, BUDGET_METRIC)
        )
    except Exception:  # noqa: BLE001 - accounting must not abort a run
        return 0


def subagent_budget_subject(subagent_id: str) -> str:
    """Usage lane a subagent books its tokens under."""
    return f"{BUDGET_SUBJECT_ID}:{subagent_id}"


def extract_partial_thought(raw: str) -> str:
    """Best-effort ``thought`` value from a partial/incomplete ReAct JSON reply.

    The loop asks for ``{"thought": "...", ...}`` with ``thought`` first, so the
    value can be surfaced while the JSON is still being generated. Incomplete
    escapes fall back to a light unescape instead of failing.
    """
    match = _THOUGHT_RE.search(str(raw or ""))
    if match is None:
        return ""
    fragment = match.group(1)
    try:
        return str(json.loads(f'"{fragment}"'))
    except (ValueError, TypeError):
        return fragment.replace('\\"', '"').replace("\\n", "\n")


def _notify(callback: Callable[..., None] | None, *args: Any) -> None:
    """Call a UI hook without ever letting it break the run."""
    if callback is None:
        return
    try:
        callback(*args)
    except Exception:  # noqa: BLE001 - presentation must not abort the loop
        pass


async def _complete_turn(llm_client: Any, messages: list[Any], config: ReActConfig) -> Any:
    """One model turn, streaming the reasoning when a hook and provider allow it.

    Falls back to a plain ``complete`` on any streaming error so the reasoning
    UI can never turn into a dead end. ``CancelledError`` propagates untouched.
    The output ceiling is bounded (see :func:`react_max_tokens`) so a request
    fits inside a provider's tokens-per-minute budget.
    """
    max_tokens = react_max_tokens()
    options: dict[str, Any] = {"max_tokens": max_tokens}
    provider_client = getattr(llm_client, "primary", llm_client)
    if getattr(provider_client, "supports_action_json", False):
        options["response_format"] = {"type": "json_object"}
    can_stream = (
        config.on_thought is not None
        and bool(getattr(llm_client, "supports_streaming", False))
        and hasattr(llm_client, "stream")
    )
    if not can_stream:
        return await llm_client.complete(messages, **options)
    collected: list[str] = []
    last = ""
    try:
        async for chunk in llm_client.stream(messages, **options):
            collected.append(chunk)
            thought = extract_partial_thought("".join(collected))
            if thought and thought != last:
                last = thought
                _notify(config.on_thought, thought)
    except Exception:  # noqa: BLE001 - retry the whole turn without streaming
        _notify(config.on_thought_done)
        return await llm_client.complete(messages, **options)
    finally:
        _notify(config.on_thought_done)
    response = getattr(llm_client, "last_stream_response", None)
    if response is not None:
        return response
    # A provider that streams without reporting usage: synthesize a response so
    # token recording and parsing stay identical to the non-streaming path.
    from nexus_core.llm.abstraction import LLMProvider, LLMResponse

    text = "".join(collected)
    # Never claim a provider we cannot prove: report the client's own configured
    # provider (the previous code hardcoded GROQ regardless of the real one).
    # ``FAKE`` marks a synthesized response whose origin is unknown.
    provider = getattr(getattr(llm_client, "config", None), "provider", None)
    if not isinstance(provider, LLMProvider):
        provider = LLMProvider.FAKE
    return LLMResponse(
        content=text,
        model=str(getattr(getattr(llm_client, "config", None), "model", "") or ""),
        provider=provider,
        tokens_output=max(1, len(text.split())),
    )


def _record_response_tokens(
    store: Any,
    tenant_id: str,
    run_id: str,
    response: Any,
    *,
    subject_ids: tuple[str, ...] = (BUDGET_SUBJECT_ID,),
) -> int:
    """Book the tokens of one model response; returns the amount recorded.

    The amount is booked once under every lane in ``subject_ids`` (the run total
    plus the active subagent), so the same spend is visible run-wide and per
    phase without double-counting within a lane.
    """
    amount = int(getattr(response, "total_tokens", 0) or 0)
    if amount <= 0:
        return 0
    for subject_id in subject_ids:
        try:
            store.record_usage(
                tenant_id,
                run_id,
                BUDGET_SUBJECT_TYPE,
                subject_id,
                BUDGET_METRIC,
                amount,
                {"source": "react-loop"},
            )
        except Exception:  # noqa: BLE001 - accounting must not abort a run
            continue
    return amount


async def _await_tool(
    awaitable: Any, *, timeout: float, cancel_event: asyncio.Event | None
) -> tuple[Any, bool]:
    from .react_services import ToolExecutionService

    return cast("tuple[Any, bool]", await ToolExecutionService().await_tool(
        awaitable, timeout=timeout, cancel_event=cancel_event
    ))


def _estimate_request_tokens(messages: Any) -> int:
    """Cheap pre-flight token estimate for a reservation (chars/4)."""
    total = 0
    for message in messages:
        content = getattr(message, "content", None)
        if content is None and isinstance(message, dict):
            content = message.get("content")
        total += len(str(content or ""))
    return (total + 3) // 4


def _inject_observation(
    store: Any,
    tenant_id: str,
    conversation_id: str,
    run_id: str,
    iteration: int,
    action: ReActAction | Action,
    observation: dict[str, Any],
    *,
    subagent_id: str | None = None,
) -> None:
    """Feed a tool outcome (success or error) back to the model as history.

    The stored ``content`` stays pure JSON (the report extractor and the TUI read
    it back); the untrusted-output delimiters are applied when the message is
    handed to the model (see :func:`nexus_core.agent.injection.render_for_model`).
    Suspicious phrases are flagged here and persisted as ``injection_signals`` so
    the boundary can warn the model without ever hiding the raw evidence.
    """
    # Tool output can be huge (nmap XML, nuclei JSON). Keep the model on a
    # bounded summary and archive the full payload content-addressed (B4).
    content, compacted, artifact = prepare_observation(
        str(action.tool_id),
        observation,
        store=store,
        tenant_id=tenant_id,
        run_id=run_id,
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
            "truncated": compacted,
            "injection_signals": scan_untrusted_text(content),
            "run_id": run_id,
            **({"artifact": artifact} if artifact else {}),
            **({"subagent_id": subagent_id} if subagent_id else {}),
        },
    )


async def _maybe_autospawn(
    *,
    store: Any,
    tenant_id: str,
    run_id: str,
    context: Any,
    llm_client: Any,
    config: ReActConfig,
    engagement_id: str | None,
    objective: str,
    previous_subagent_id: str | None,
    subagent_id: str,
    payload: dict[str, Any],
    conversation_id: str,
    iteration: int,
    audit_step: Any,
) -> None:
    """Delegate to a real child conversation on a family transition (opt-in).

    Disabled unless the run payload sets ``autospawn``. When the transition is
    valid (different kill-chain family, a well-funded target) the child runs its
    own isolated conversation to completion and the parent receives only its
    structured summary as a system observation — never the child's transcript.
    Any failure degrades to "no delegation" and is audited, never aborts the run.
    """
    if not payload.get("autospawn") or not previous_subagent_id:
        return
    from nexus_core.agent.supervisor import AgentSupervisor
    from .subagents import SUBAGENTS_BY_ID

    global_budget = int(payload.get("supervisor_budget") or 0)
    if global_budget <= 0:
        return
    profile = SUBAGENTS_BY_ID.get(subagent_id)
    if profile is None:
        return
    try:
        supervisor = AgentSupervisor.root(
            context,
            llm_client,
            engagement_id=engagement_id,
            global_budget=global_budget,
            config=config,
            autospawn=True,
        )
        if not supervisor.maybe_spawn(previous_subagent_id, subagent_id):
            return
        child = await supervisor.spawn(
            subagent_id,
            objective,
            {"tokens": profile.token_budget, "iterations": profile.max_iterations},
        )
    except Exception as exc:  # noqa: BLE001 - delegation must never break the parent
        audit_step(
            iteration=iteration,
            action="autospawn_failed",
            decision="degrade",
            error=type(exc).__name__,
        )
        return
    audit_step(
        iteration=iteration,
        action="autospawn",
        decision="allow",
        child_run_id=child.run_id,
        root_id=child.root_id,
        termination_reason=child.termination_reason,
    )
    store.append_run_event(
        tenant_id,
        run_id,
        "orchestrator.autospawn",
        {
            "child_run_id": child.run_id,
            "root_id": child.root_id,
            "subagent_id": subagent_id,
            "previous": previous_subagent_id,
            "tokens_used": child.tokens_used,
            "iteration": iteration,
        },
    )
    memory.append_step(
        store,
        tenant_id,
        conversation_id,
        "system",
        json.dumps(
            {
                "kind": "supervisor.child_summary",
                "subagent_id": subagent_id,
                "summary": child.summary,
            },
            ensure_ascii=False,
            default=str,
        ),
        {
            "kind": "supervisor.child_summary",
            "child_run_id": child.run_id,
            "run_id": run_id,
            "iteration": iteration,
        },
    )
