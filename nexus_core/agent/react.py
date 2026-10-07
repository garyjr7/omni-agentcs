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
import os
import re
import time
from dataclasses import dataclass, field
from typing import Any, Callable

from nexus_core.kernel.audit import AuditWriter
from nexus_core.llm.abstraction import LLMMessage
from nexus_core.scope import ScopeViolation

from . import memory
from .evidence import annotate_findings, fabricated_evidence
from .injection import render_for_model, scan_untrusted_text
from .observations import bounded_context, prepare_observation
from .preflight import unavailable_tools_from_env
from .project_context import load_project_instruction, render_project_instruction
from .skills import activate_skills, render_skills
from .subagents import filter_catalog, permits, select_for_plan, with_phase_grace
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
#: A tool that fails this many times *as a tool* (not as invalid input) is
#: marked unavailable for the rest of the run, so the agent pivots instead of
#: the whole engagement dying (B3).
MAX_TOOL_FAILURES_BEFORE_UNAVAILABLE = 3
TOOL_UNAVAILABLE_EVENT_TYPE = "react.tool_unavailable"
PHASE_TIMEOUT_EVENT_TYPE = "react.phase_timeout"
#: Optional per-phase wall-clock budget (0 disables it). When exceeded the
#: phase's already-failing tools are retired and the event is audited.
PHASE_TIMEOUT_ENV = "NEXUS_PHASE_TIMEOUT_SECONDS"
#: Output-token ceiling for one ReAct turn. Providers with a low tokens-per-
#: minute budget count the *reserved* ``max_tokens`` against the request, so an
#: oversized default (4096) makes every call fail even when the prompt is small
#: (B4 / Groq TPM=8000 in the E2E run #2). A ReAct reply is a small JSON object,
#: so a lean ceiling keeps requests inside the budget.
REACT_MAX_TOKENS_ENV = "NEXUS_REACT_MAX_TOKENS"
REACT_DEFAULT_MAX_TOKENS = 1536
REACT_MIN_MAX_TOKENS = 256

#: Kick-off user turn (Fase 3.8). The loop rebuilds the conversation on every
#: iteration as ``[system] + bounded history``; on the *first* iteration the
#: history is empty, so the request carried no ``user`` message at all. Most
#: OpenAI-style models accept that, but a strict chat template does not: Qwen
#: rejects it with HTTP 400 ("No user query found in messages"), which made
#: ``qwen/qwen3.8-27b`` unusable as the default. The turn is inserted only when
#: the context has no user message, so a model that already accepted the
#: system-only prompt keeps the exact same input as before.
KICKOFF_USER_PROMPT = (
    "OBJETIVO DE LA MISIÓN: {objective}\n\n"
    "Comienza o continúa la misión proponiendo UN único objeto JSON con la "
    "siguiente acción a ejecutar."
)

#: Last phase of the deterministic plan. Only when the planner has reached it
#: (every earlier required phase backed by blackboard evidence) may a
#: ``task_complete`` be accepted (B8.2.2). Kept as a literal so this module keeps
#: importing the planner lazily; a test asserts it matches ``PHASES[-1].id``.
FINAL_PHASE_ID = "reporting"
PREMATURE_COMPLETION_EVENT_TYPE = "react.premature_completion"
#: How many times a premature ``task_complete`` is refused before the loop stops
#: with ``premature_completion``. A model that will not continue must not burn
#: the whole iteration budget arguing with the frame (and the operator needs a
#: distinct status, not a fake ``completed``).
MAX_PREMATURE_COMPLETIONS = 3
#: Observations of the current run kept as the evidence corpus for findings.
RUN_EVIDENCE_MAX_OBSERVATIONS = 40

STATUS_COMPLETED = "completed"
STATUS_MAX_ITERATIONS = "max_iterations"
STATUS_CLARIFICATION = "clarification"
STATUS_FAILED = "failed"
#: The model kept declaring the task complete while the plan said otherwise, or
#: while its findings cited evidence from nowhere (B8.2.2/B8.2.3).
STATUS_PREMATURE_COMPLETION = "premature_completion"
STATUS_CANCELLED = "cancelled"
STATUS_SCOPE_VIOLATION = "scope_violation_aborted"
STATUS_BUDGET_EXCEEDED = "budget_exceeded"
#: A subagent exhausted its own iteration/token allowance.
STATUS_SUBAGENT_BUDGET = "subagent_budget_exceeded"
SUBAGENT_EVENT_TYPE = "orchestrator.subagent"
BUDGET_EVENT_TYPE = "react.budget_exceeded"
#: Subject under which the loop books its own token spend.
BUDGET_SUBJECT_TYPE = "model_route"
BUDGET_SUBJECT_ID = "react"
BUDGET_METRIC = "tokens"


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
    #: Enforce the completion gates (B8.2.2/B8.2.3): refuse a ``task_complete``
    #: while the deterministic plan still has pending phases, and refuse one whose
    #: findings cite evidence no observation of this run supports. Disable only
    #: for a caller that deliberately scripts a completion out of order (e.g.
    #: loop-mechanics tests); production always leaves it on.
    enforce_completion_gates: bool = True
    #: Interactive approval hook. When set, the loop asks policy *before* every
    #: tool invocation and, if the decision requires human approval, calls this
    #: callback with ``(tool_id, arguments, decision)``. Returning ``None`` or a
    #: denying :class:`ApprovalDecision` injects a ``denied_by_operator``
    #: observation and continues (a human refusal is not a tool failure). Without
    #: a callback, the gateway fails the call with ``PermissionError`` as before.
    on_approval_needed: Callable[[str, dict[str, Any], Any], ApprovalDecision | None] | None = None
    #: Live reasoning hook: receives the partial ``thought`` text as the model
    #: writes it, so the CLI can stream the cognitive loop. Only used when the
    #: client reports ``supports_streaming``; otherwise the loop calls
    #: ``complete`` exactly as before.
    on_thought: Callable[[str], None] | None = None
    #: Called once when a streamed turn ends (success, error or fallback), so the
    #: live indicator closes before the durable thought is rendered.
    on_thought_done: Callable[[], None] | None = None


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
    #: Final plan snapshot (``Plan.to_dict()``) when the loop produced one.
    plan: dict[str, Any] | None = None
    #: Subagent that owned the last iteration (audited in the action log).
    subagent_id: str | None = None
    #: Evidence-grounding counters of the accepted completion (B8.2.3).
    evidence_stats: dict[str, int] | None = None
    #: Why the completion was refused, when ``status`` is
    #: ``premature_completion``.
    completion_objections: list[str] = field(default_factory=list)


# --------------------------------------------------------------------- helpers
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


def _blackboard_view(
    store: Any, tenant_id: str, engagement_id: str | None
) -> tuple[Any, str]:
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


def _playbook_guidance(
    store: Any, tenant_id: str, engagement_id: str | None
) -> str:
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
        return render_playbook_matches(select_playbooks(facts))
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
        return max(REACT_MIN_MAX_TOKENS, int(str(raw).strip()))
    except (TypeError, ValueError):
        return REACT_DEFAULT_MAX_TOKENS


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
    return [
        message for message in messages if str(message.get("run_id") or "") == wanted
    ]


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


def with_kickoff_user_turn(
    messages: list[LLMMessage], objective: str
) -> list[LLMMessage]:
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
            store.usage_total(
                tenant_id, run_id, BUDGET_SUBJECT_TYPE, subject_id, BUDGET_METRIC
            )
        )
    except Exception:  # noqa: BLE001 - accounting must not abort a run
        return 0


def subagent_budget_subject(subagent_id: str) -> str:
    """Usage lane a subagent books its tokens under."""
    return f"{BUDGET_SUBJECT_ID}:{subagent_id}"


#: First string value of the ``thought`` field of a (possibly partial) JSON object.
_THOUGHT_RE = re.compile(r'"thought"\s*:\s*"((?:[^"\\]|\\.)*)')


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
        return json.loads(f'"{fragment}"')
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
    can_stream = (
        config.on_thought is not None
        and bool(getattr(llm_client, "supports_streaming", False))
        and hasattr(llm_client, "stream")
    )
    if not can_stream:
        return await llm_client.complete(messages, max_tokens=max_tokens)
    collected: list[str] = []
    last = ""
    try:
        async for chunk in llm_client.stream(messages, max_tokens=max_tokens):
            collected.append(chunk)
            thought = extract_partial_thought("".join(collected))
            if thought and thought != last:
                last = thought
                _notify(config.on_thought, thought)
    except Exception:  # noqa: BLE001 - retry the whole turn without streaming
        _notify(config.on_thought_done)
        return await llm_client.complete(messages, max_tokens=max_tokens)
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
                tenant_id, run_id, BUDGET_SUBJECT_TYPE, subject_id, BUDGET_METRIC,
                amount, {"source": "react-loop"},
            )
        except Exception:  # noqa: BLE001 - accounting must not abort a run
            continue
    return amount


async def _await_tool(
    awaitable: Any,
    *,
    timeout: float,
    cancel_event: asyncio.Event | None,
) -> tuple[Any, bool]:
    """Await one tool call, racing it against ``cancel_event``.

    Returns ``(result, cancelled)``. On cancellation the in-flight tool task is
    cancelled and drained, which lets the sandbox kill its process group before
    the loop returns.
    """
    task = asyncio.ensure_future(awaitable)
    if cancel_event is None:
        return await asyncio.wait_for(task, timeout=timeout), False
    cancel_waiter = asyncio.ensure_future(cancel_event.wait())
    try:
        done, _ = await asyncio.wait(
            {task, cancel_waiter}, timeout=timeout, return_when=asyncio.FIRST_COMPLETED
        )
        if task in done:
            return await task, False
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        if cancel_waiter in done:
            return None, True
        raise asyncio.TimeoutError
    finally:
        if not cancel_waiter.done():
            cancel_waiter.cancel()
            await asyncio.gather(cancel_waiter, return_exceptions=True)


async def run_react_loop(
    *,
    context: Any,
    objective: str,
    engagement_id: str | None,
    llm_client: Any,
    config: ReActConfig = ReActConfig(),
    tool_catalog: dict[str, Any] | None = None,
    conversation_id: str | None = None,
    budget_tokens: int | None = None,
    cancel_event: asyncio.Event | None = None,
) -> ReActResult:
    """Run the durable ReAct loop until completion, abort or iteration budget.

    ``conversation_id`` lets the caller pin the durable conversation (the CLI's
    persistent work session). When omitted the loop keeps its historic
    behaviour of deriving one conversation per run. ``cancel_event`` (or
    ``context.cancel_event`` when omitted) aborts the loop between iterations
    and interrupts an in-flight tool call, whose sandbox then kills its
    process group.
    """
    from nexus_core.kernel import runtime as runtime_module
    from nexus_core.kernel.scope_loader import load_engagement_scope
    from nexus_core.tools.registry import durable_tool_definitions

    store = context.store
    tenant_id = context.tenant_id
    run_id = context.run_id
    payload = _task_payload(context)
    agent_id = str(payload.get("agent_id") or DEFAULT_AGENT_ID)
    catalog = tool_catalog if tool_catalog is not None else durable_tool_definitions(tenant_id)
    # An operator may pin the profile; the model never picks its own subagent.
    subagent_override = payload.get("subagent") or None
    audit = AuditWriter(store)
    scope = load_engagement_scope(store, tenant_id, engagement_id)

    # Project instructions (OMNI.md) and activated skills are quasi-trusted
    # prompt channels from files a cloned repository could poison. They are read
    # once per run, delimited, scanned, and their provenance is audited so the
    # exact bytes that shaped the run are provable afterwards.
    project_root = payload.get("project_root") or None
    project_instruction = load_project_instruction(project_root)
    from nexus_core.kernel.scope_loader import scope_signing_secret

    active_skills, refused_skills = activate_skills(
        payload.get("active_skills") or [],
        project_root,
        secret=scope_signing_secret(),
    )
    if project_instruction is not None or active_skills or refused_skills:
        audit.append(
            tenant_id=tenant_id,
            trace_id=run_id,
            actor_id=agent_id,
            action="project.context_loaded",
            resource_type="run",
            resource_id=run_id,
            payload={
                "project": project_instruction.to_dict() if project_instruction else None,
                "skills": [skill.to_dict() for skill in active_skills],
                "refused_skills": list(refused_skills),
            },
            decision="allow",
        )

    conversation_id = conversation_id or memory.ensure_conversation(
        store, tenant_id, run_id, agent_id
    )
    if cancel_event is None:
        cancel_event = getattr(context, "cancel_event", None)
    budget = _budget_tokens(payload, budget_tokens)
    history = memory.load_history(store, tenant_id, conversation_id, limit=500)
    # In a shared work session every run records its own objective; in a per-run
    # conversation this is identical to the historic "first message" behaviour.
    if not any(
        memory.message_kind(message) == memory.SYSTEM_MESSAGE_KIND
        and str(message.get("run_id") or "") == str(run_id)
        for message in history
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

    # A shared work session holds the messages of several runs. Resume
    # bookkeeping (action log + iteration cursor) is scoped to this run so a
    # new objective does not inherit the iteration budget of the previous one.
    run_history = _run_messages(history, run_id)
    actions = _persisted_actions(run_history)
    iteration = _last_persisted_iteration(actions)
    status = STATUS_MAX_ITERATIONS
    final_summary = ""
    findings: list[dict[str, Any]] = []
    question: str | None = None
    consecutive_failures = 0
    last_phase: str | None = None
    last_plan: Any = None
    last_subagent_id: str | None = None
    last_selected: Any = None
    previous_profile: Any = None
    active_subagent_id: str | None = None
    subagent_iterations = 0
    # Degradation state (B3): a tool that keeps failing *as a tool* is retired
    # and the phase continues by another route; a tool that fails only on bad
    # input is never retired. Tools whose binary is absent start retired so the
    # run never spends an iteration on a guaranteed ``FileNotFoundError`` (B6).
    unavailable_tools: set[str] = set(unavailable_tools_from_env())
    tool_failures: dict[str, int] = {}
    phase_started = time.monotonic()
    phase_timeout_seconds = _phase_timeout_seconds()
    # Evidence of *this* run only: the corpus a finding is grounded against, plus
    # the grounding counters of the accepted completion (B8.2.3).
    run_evidence: list[dict[str, Any]] = []
    evidence_stats: dict[str, int] | None = None
    premature_rejections = 0
    completion_objections: list[str] = []
    for tool_id in sorted(unavailable_tools):
        store.append_run_event(
            tenant_id,
            run_id,
            TOOL_UNAVAILABLE_EVENT_TYPE,
            {"tool_id": tool_id, "reason": "binary_missing", "iteration": 0},
        )

    def audit_step(*, iteration: int, action: str, decision: str, **extra: Any) -> None:
        """Audit one step, always tagged with the active subagent (3C)."""
        _audit_step(
            audit,
            tenant_id=tenant_id,
            run_id=run_id,
            agent_id=agent_id,
            subagent_id=active_subagent_id,
            iteration=iteration,
            action=action,
            decision=decision,
            **extra,
        )

    while iteration < config.max_iterations:
        used = _budget_used(store, tenant_id, run_id) if budget else 0
        if budget and used >= budget:
            status = STATUS_BUDGET_EXCEEDED
            final_summary = (
                f"token budget exhausted: {used} >= {budget} without task_complete"
            )
            store.append_run_event(
                tenant_id,
                run_id,
                BUDGET_EVENT_TYPE,
                {"used": used, "budget": budget, "iteration": iteration},
            )
            break

        if cancel_event is not None and cancel_event.is_set():
            status = STATUS_CANCELLED
            store.append_run_event(
                tenant_id,
                run_id,
                "react.cancelled",
                {"iteration": iteration, "phase": "between_iterations"},
            )
            break

        if _cancellation_requested(store, tenant_id, run_id):
            status = STATUS_CANCELLED
            store.append_run_event(
                tenant_id, run_id, "react.cancelled", {"iteration": iteration}
            )
            break

        iteration += 1
        history = memory.load_history(store, tenant_id, conversation_id, limit=500)
        # B8.2.1: the run reads (and compacts) only its own turns. The shared
        # work session keeps the blackboard, not the other runs' transcripts.
        run_history = _run_messages(history, run_id)
        history_summary = memory.latest_summary(run_history)
        if config.enable_summarization:
            summary = await memory.summarize_history_if_large(
                store,
                tenant_id,
                conversation_id,
                llm_client,
                force=len(run_history) > config.max_history_messages,
                run_id=run_id,
            )
            if summary:
                history_summary = summary
                history = memory.load_history(store, tenant_id, conversation_id, limit=500)
                run_history = _run_messages(history, run_id)

        # In a shared work session the model must be able to build on the
        # objectives executed earlier in the engagement, not just the current
        # one. Surface them explicitly in the session context.
        prior = memory.prior_objectives(history, run_id)
        if prior:
            base = history_summary or "(sin historial previo)"
            bullets = "\n".join(f"- {objective}" for objective in prior)
            history_summary = (
                f"{base}\n\nObjetivos previos de esta sesión de trabajo:\n{bullets}"
            )

        plan, facts_text = _blackboard_view(store, tenant_id, engagement_id)
        last_plan = plan
        selected = select_for_plan(plan, override=subagent_override)
        if plan.current != last_phase:
            # A new phase gets a fresh wall-clock allowance.
            phase_started = time.monotonic()
        changed = selected.id != last_subagent_id
        if changed:
            subagent_iterations = 0
            # The profile this one replaces. It stays frozen for the grace
            # window, so the inherited read-only tools last more than the
            # transition iteration itself.
            previous_profile = last_selected
        subagent_iterations += 1
        # P1 (Fase 3.7): the first iterations of a new profile keep the previous
        # profile's read-only tools, so the tools that discovered a service are
        # not withdrawn in the very iteration that must enumerate it.
        subagent = with_phase_grace(
            selected, previous_profile, iterations=subagent_iterations
        )
        last_selected = selected
        active_subagent_id = subagent.id
        if changed:
            store.append_run_event(
                tenant_id,
                run_id,
                SUBAGENT_EVENT_TYPE,
                {
                    "subagent_id": subagent.id,
                    "previous": last_subagent_id,
                    "phase": plan.current,
                    "read_only": subagent.read_only,
                    "token_budget": subagent.token_budget,
                    # P3 (Fase 3.7): the profile's subset, so a lock like the one
                    # this phase fixes is visible live in the NDJSON (a binary
                    # missing at preflight is announced separately, at
                    # iteration 0, by ``react.tool_unavailable``).
                    "tools": sorted(subagent.tools),
                    "iteration": iteration,
                },
            )
            last_subagent_id = selected.id
        # Fail closed on a subagent that exhausted its own allowance: the next
        # phase (or a human) picks up, instead of one profile burning the run.
        if subagent_iterations > subagent.max_iterations:
            status = STATUS_SUBAGENT_BUDGET
            final_summary = (
                f"subagent '{subagent.id}' exceeded its iteration budget "
                f"({subagent.max_iterations})"
            )
            break
        if subagent.token_budget:
            spent = _budget_used(
                store, tenant_id, run_id, subagent_budget_subject(subagent.id)
            )
            if spent >= subagent.token_budget:
                status = STATUS_SUBAGENT_BUDGET
                final_summary = (
                    f"subagent '{subagent.id}' exhausted its token budget: "
                    f"{spent} >= {subagent.token_budget}"
                )
                break
        # Phase timeout (B3): a stall is visible and bounded. The already-failing
        # tools of the phase are retired so the model is pushed to another route.
        # The phase itself is NOT auto-advanced: the planner is deterministic and
        # blackboard-driven, so fabricating progress would corrupt the plan.
        if phase_timeout_seconds and (time.monotonic() - phase_started) > phase_timeout_seconds:
            stalled = sorted(
                tool_id
                for tool_id in tool_failures
                if tool_id in subagent.tools and tool_id not in unavailable_tools
            )
            if stalled:
                unavailable_tools.update(stalled)
            store.append_run_event(
                tenant_id,
                run_id,
                PHASE_TIMEOUT_EVENT_TYPE,
                {
                    "phase": plan.current,
                    "subagent_id": subagent.id,
                    "elapsed_seconds": round(time.monotonic() - phase_started, 3),
                    "iteration": iteration,
                    "retired_tools": stalled,
                },
            )
            audit_step(
                iteration=iteration,
                action="phase_timeout",
                decision="degrade",
                phase=plan.current,
                retired_tools=stalled,
            )
            phase_started = time.monotonic()

        # The loop may only draw from the active profile's subset; the full
        # catalog stays around to tell an invented tool from a denied one.
        # Retired (repeatedly broken) tools are removed from what it may propose.
        allowed_catalog = {
            tool_id: entry
            for tool_id, entry in filter_catalog(subagent, catalog).items()
            if tool_id not in unavailable_tools
        }
        if plan.current != last_phase:
            store.append_run_event(
                tenant_id,
                run_id,
                "orchestrator.plan",
                {
                    "phase": plan.current,
                    "previous": last_phase,
                    "progress": list(plan.progress),
                    "facts_total": plan.facts_total,
                    "subagent_id": subagent.id,
                    "iteration": iteration,
                },
            )
            last_phase = plan.current
        system_prompt = render_system_prompt(
            catalog=allowed_catalog,
            objective=objective,
            engagement_id=engagement_id,
            scope_summary=describe_scope(scope),
            history_summary=history_summary or "(sin historial previo)",
            facts_summary=facts_text,
            plan_summary=plan.render(),
            subagent_summary=subagent.describe(),
            project_summary=render_project_instruction(project_instruction),
            skills_summary=render_skills(active_skills),
            playbook_summary=_playbook_guidance(store, tenant_id, engagement_id),
        )
        messages = [LLMMessage(role="system", content=system_prompt)]
        # Bound the raw history: a shared work session accumulates every prior
        # run's messages, and paying for all of them on every turn can exceed a
        # provider's per-request token limit (B4). The summarised history block
        # in the system prompt still carries the older context.
        context_messages = bounded_context(
            [
                message
                for message in run_history
                if message.get("role") in {"user", "assistant"}
                and memory.message_kind(message) not in memory.COMPACTION_KINDS
            ]
        )
        messages.extend(
            # Tool output is untrusted data: observation messages are wrapped in
            # the untrusted-output delimiters at the model boundary (H1).
            LLMMessage(role=str(message["role"]), content=render_for_model(message))
            for message in context_messages
        )

        messages = with_kickoff_user_turn(messages, objective)

        response = await _complete_turn(llm_client, messages, config)
        _record_response_tokens(
            store,
            tenant_id,
            run_id,
            response,
            subject_ids=(BUDGET_SUBJECT_ID, subagent_budget_subject(subagent.id)),
        )
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
            audit_step(
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
                # Persist a redacted copy only; the handler below still runs
                # with the original credentials.
                "arguments": memory._redact_arguments(action.arguments),
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
            # Evidence first: every finding is annotated with where its support
            # comes from, before any gate reads it (B8.2.3).
            annotated, evidence_stats = annotate_findings(
                action.findings, observations=run_evidence
            )
            completion_objections = _completion_objections(
                plan,
                enforce_completion_gates=config.enforce_completion_gates,
                evidence_stats=evidence_stats,
                engagement_id=engagement_id,
            )
            if completion_objections and premature_rejections < MAX_PREMATURE_COMPLETIONS:
                # Refuse to close an engagement the plan says is unfinished: tell
                # the model why and let it keep working (B8.2.2).
                premature_rejections += 1
                actions.append(
                    _action_entry(
                        iteration,
                        action.action,
                        thought=action.thought,
                        warnings=action.warnings,
                        summary=action.summary or "",
                        findings=annotated,
                        rejected=True,
                        objections=list(completion_objections),
                    )
                )
                store.append_run_event(
                    tenant_id,
                    run_id,
                    PREMATURE_COMPLETION_EVENT_TYPE,
                    {
                        "iteration": iteration,
                        "phase": plan.current,
                        "attempt": premature_rejections,
                        "objections": list(completion_objections),
                        "evidence": evidence_stats,
                        "subagent_id": active_subagent_id,
                    },
                )
                memory.append_step(
                    store,
                    tenant_id,
                    conversation_id,
                    "user",
                    _premature_completion_message(completion_objections, plan),
                    {
                        "kind": "react.correction",
                        "iteration": iteration,
                        "rejected_action": ACTION_TASK_COMPLETE,
                        "run_id": run_id,
                    },
                )
                audit_step(
                    iteration=iteration,
                    action=action.action,
                    decision="deny",
                    reason="premature_task_complete",
                    attempt=premature_rejections,
                    objections=list(completion_objections),
                    evidence=evidence_stats,
                )
                continue
            if completion_objections:
                # The model insisted past every warning. Stop loudly with its own
                # status instead of reporting a completion nobody verified.
                status = STATUS_PREMATURE_COMPLETION
                final_summary = (
                    "task_complete rechazado "
                    f"{premature_rejections} veces sin evidencia suficiente: "
                    + "; ".join(completion_objections)
                )
                findings = annotated
                actions.append(
                    _action_entry(
                        iteration,
                        action.action,
                        thought=action.thought,
                        warnings=action.warnings,
                        summary=action.summary or "",
                        findings=annotated,
                        rejected=True,
                        objections=list(completion_objections),
                    )
                )
                audit_step(
                    iteration=iteration,
                    action=action.action,
                    decision="deny",
                    reason="premature_completion_exhausted",
                    objections=list(completion_objections),
                    evidence=evidence_stats,
                )
                break
            status = STATUS_COMPLETED
            final_summary = action.summary or ""
            findings = annotated
            actions.append(
                _action_entry(
                    iteration,
                    action.action,
                    thought=action.thought,
                    warnings=action.warnings,
                    summary=final_summary,
                    findings=findings,
                    evidence=evidence_stats,
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
                    "evidence": evidence_stats,
                    "run_id": run_id,
                },
            )
            audit_step(
                iteration=iteration,
                action=action.action,
                decision="allow",
                thought=action.thought,
                findings_count=len(findings),
                evidence=evidence_stats,
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
            audit_step(
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
            audit_step(
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
            arguments=memory._redact_arguments(action.arguments),
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
                store,
                tenant_id,
                conversation_id,
                run_id,
                iteration,
                action,
                observation,
                subagent_id=active_subagent_id,
            )
            audit_step(
                iteration=iteration,
                action=action.action,
                decision="deny",
                tool_id=action.tool_id,
                reason="unknown_tool",
            )
            if not _keep_going_after_failures(
                subagent, unavailable_tools, consecutive_failures
            ):
                status = STATUS_FAILED
                final_summary = (
                    f"aborted after {consecutive_failures} consecutive tool failures "
                    f"(last: unknown tool '{action.tool_id}'; no usable tools remain "
                    f"for subagent '{subagent.id}')"
                )
                break
            consecutive_failures = 0
            continue

        # A tool that exists but sits outside the active subagent's subset is
        # refused exactly like an invented one (fail-closed) and audited with the
        # profile that refused it. The full catalog decides "invented"; the subset
        # decides "not mine".
        if not permits(subagent, action.tool_id):
            observation = {
                "success": False,
                "error": (
                    f"tool '{action.tool_id}' is outside subagent '{subagent.id}' subset"
                ),
                "subagent_id": subagent.id,
                "available_tools": sorted(allowed_catalog),
            }
            consecutive_failures += 1
            entry["tool_result"] = observation
            actions.append(entry)
            _inject_observation(
                store,
                tenant_id,
                conversation_id,
                run_id,
                iteration,
                action,
                observation,
                subagent_id=active_subagent_id,
            )
            audit_step(
                iteration=iteration,
                action=action.action,
                decision="deny",
                tool_id=action.tool_id,
                reason="subagent_tool_denied",
            )
            if not _keep_going_after_failures(
                subagent, unavailable_tools, consecutive_failures
            ):
                status = STATUS_FAILED
                final_summary = (
                    f"aborted after {consecutive_failures} consecutive tool failures "
                    f"(last: '{action.tool_id}' outside subagent '{subagent.id}'; no "
                    f"usable tools remain)"
                )
                break
            consecutive_failures = 0
            continue

        # A retired tool (too many *tool* failures) is refused without counting
        # as a failure, so the model is told what it may still use (B3).
        if action.tool_id in unavailable_tools:
            observation = {
                "success": False,
                "tool_id": action.tool_id,
                "error": (
                    f"tool '{action.tool_id}' is unavailable after repeated failures; "
                    "use another tool from the available list"
                ),
                "subagent_id": subagent.id,
                "available_tools": sorted(allowed_catalog),
            }
            entry["tool_result"] = observation
            actions.append(entry)
            _inject_observation(
                store,
                tenant_id,
                conversation_id,
                run_id,
                iteration,
                action,
                observation,
                subagent_id=active_subagent_id,
            )
            audit_step(
                iteration=iteration,
                action=action.action,
                decision="deny",
                tool_id=action.tool_id,
                reason="tool_unavailable",
            )
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
                    store,
                    tenant_id,
                    conversation_id,
                    run_id,
                    iteration,
                    action,
                    denial,
                    subagent_id=active_subagent_id,
                )
                audit_step(
                    iteration=iteration,
                    action=action.action,
                    decision="deny",
                    tool_id=action.tool_id,
                    reason="denied_by_operator",
                    operator_reason=denial["reason"],
                )
                continue
        try:
            invocation, cancelled_now = await _await_tool(
                runtime_module.execute_tool(tool_payload, context),
                timeout=config.timeout_per_tool_seconds,
                cancel_event=cancel_event,
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
                store,
                tenant_id,
                conversation_id,
                run_id,
                iteration,
                action,
                observation,
                subagent_id=active_subagent_id,
            )
            store.append_run_event(
                tenant_id,
                run_id,
                "react.scope_violation",
                {"iteration": iteration, "tool_id": action.tool_id, "error": str(exc)[:500]},
            )
            audit_step(
                iteration=iteration,
                action=action.action,
                decision="deny",
                tool_id=action.tool_id,
                reason="scope_violation",
                error_type=type(exc).__name__,
            )
            break
        except Exception as exc:  # noqa: BLE001 - surfaced to the LLM as an observation
            kind = _failure_kind(exc)
            observation = {
                "success": False,
                "error_type": type(exc).__name__,
                "error": str(exc)[:1000],
                "failure_kind": kind,
            }
            failed_tool = str(action.tool_id)
            if kind == "tool":
                count = tool_failures.get(failed_tool, 0) + 1
                tool_failures[failed_tool] = count
                if (
                    count >= MAX_TOOL_FAILURES_BEFORE_UNAVAILABLE
                    and failed_tool not in unavailable_tools
                ):
                    unavailable_tools.add(failed_tool)
                    observation["tool_retired"] = True
                    observation["available_tools"] = sorted(
                        tool
                        for tool in subagent.tools
                        if tool not in unavailable_tools
                    )
                    store.append_run_event(
                        tenant_id,
                        run_id,
                        TOOL_UNAVAILABLE_EVENT_TYPE,
                        {
                            "tool_id": action.tool_id,
                            "subagent_id": subagent.id,
                            "failures": count,
                            "iteration": iteration,
                        },
                    )
                    audit_step(
                        iteration=iteration,
                        action="tool_unavailable",
                        decision="degrade",
                        tool_id=action.tool_id,
                        failures=count,
                    )
            consecutive_failures += 1
        else:
            if cancelled_now:
                status = STATUS_CANCELLED
                final_summary = "cancellation requested during a tool call"
                entry["tool_result"] = {"success": False, "cancelled": True}
                actions.append(entry)
                store.append_run_event(
                    tenant_id,
                    run_id,
                    "react.cancelled",
                    {"iteration": iteration, "phase": "tool", "tool_id": action.tool_id},
                )
                break
            observation = _observation_payload(invocation)
            if observation.get("success"):
                consecutive_failures = 0
                # Only a *verified* observation can ground a finding later
                # (B8.2.3); the corpus stays bounded across a long run.
                run_evidence.append(
                    {
                        "tool_id": action.tool_id,
                        "evidence": observation.get("evidence"),
                        "output": observation.get("output"),
                    }
                )
                del run_evidence[:-RUN_EVIDENCE_MAX_OBSERVATIONS]
            else:
                consecutive_failures += 1

        entry["tool_result"] = observation
        actions.append(entry)
        _inject_observation(
            store,
            tenant_id,
            conversation_id,
            run_id,
            iteration,
            action,
            observation,
            subagent_id=active_subagent_id,
        )
        audit_step(
            iteration=iteration,
            action=action.action,
            decision="allow" if observation.get("success") else "deny",
            tool_id=action.tool_id,
            success=bool(observation.get("success")),
            consecutive_failures=consecutive_failures,
            error=observation.get("error"),
        )

        if not _keep_going_after_failures(
            subagent, unavailable_tools, consecutive_failures
        ):
            status = STATUS_FAILED
            final_summary = (
                f"aborted after {consecutive_failures} consecutive tool failures "
                f"(no usable tools remain for subagent '{subagent.id}')"
            )
            break
        if consecutive_failures >= MAX_CONSECUTIVE_TOOL_FAILURES:
            # Threshold reached but other routes exist: pivot instead of dying.
            consecutive_failures = 0

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
        subagent_id=last_subagent_id,
    )
    return ReActResult(
        status=status,
        iterations=iteration,
        final_summary=final_summary,
        findings=findings,
        conversation_id=conversation_id,
        actions=actions,
        question=question,
        plan=last_plan.to_dict() if last_plan is not None else None,
        subagent_id=last_subagent_id,
        evidence_stats=evidence_stats,
        completion_objections=list(completion_objections),
    )


def _inject_observation(
    store: Any,
    tenant_id: str,
    conversation_id: str,
    run_id: str,
    iteration: int,
    action: ReActAction,
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
