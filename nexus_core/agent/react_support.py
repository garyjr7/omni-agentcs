"""Compatibility helpers for persistence, budgeting and ReAct telemetry."""

from __future__ import annotations
import re

_THOUGHT_RE = re.compile(r'"thought"\s*:\s*"((?:[^"\\]|\\.)*)')

import asyncio
import json
import os
import time
from typing import Any, Callable, Mapping, cast

from nexus_core.kernel.audit import AuditWriter
from nexus_core.llm.abstraction import LLMMessage

from . import memory
from nexus_core.kernel.domain_dto import Action
from .evidence import CITATION_DETAIL_LIMIT, fabricated_evidence
from .injection import scan_untrusted_text
from .observations import prepare_observation
from .parser import (
    ReActAction,
)

from .react_types import (
    MAX_CONSECUTIVE_TOOL_FAILURES,
    CANCEL_EVENT_TYPE,
    PHASE_TIMEOUT_ENV,
    STUCK_THRESHOLD_ENV,
    DEFAULT_STUCK_THRESHOLD,
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


def _blackboard_view(
    store: Any,
    tenant_id: str,
    engagement_id: str | None,
    *,
    phase_turns: Mapping[str, int] | None = None,
) -> tuple[Any, str]:
    """Return ``(plan, facts_text)`` for one iteration (never raises).

    The plan is derived deterministically from the blackboard summary, so the
    model plans inside a stable frame; the rendered facts stay in the prompt as
    before. Memory failures degrade to an empty plan instead of aborting.

    ``phase_turns`` is the loop's own turn history, forwarded so a phase that
    declares ``min_turns`` is held open until it has had its turn (V1-46).
    """
    from .planner import build_plan, plan_from_summary

    empty = "(sin hechos registrados)"
    if not engagement_id or store is None:
        return build_plan(engagement_id=engagement_id, phase_turns=phase_turns), empty
    try:
        from nexus_core.kernel.blackboard import Blackboard

        board = Blackboard(store)
        summary = board.summary(tenant_id, engagement_id)
        rendered = board.render(tenant_id, engagement_id)
    except Exception:  # noqa: BLE001 - memory must never kill a run
        return build_plan(engagement_id=engagement_id, phase_turns=phase_turns), empty
    return (
        plan_from_summary(summary, engagement_id=engagement_id, phase_turns=phase_turns),
        (rendered or empty),
    )


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


def unavailable_guidance(tool_id: Any, reason: str) -> str:
    """Model-facing sentence for a tool whose backend stopped serving (Fase 3b).

    The agent has to learn three things at once from the observation: *which*
    tool is out, *why* (so it stops retrying a dead backend), and that the rest
    of the phase is still open—so it pivots instead of insisting. Measured in
    run_434f5eeadb104b11ba0c80bce16f8d08: the dead MSF RPC had no such message
    and the whole run ended with it.
    """
    return (
        f"tool '{tool_id}' is temporarily unavailable (reason: {reason}). "
        "Consider using an alternative or continuing with the other routes of the phase."
    )


def timeout_guidance(tool_id: Any) -> str:
    """Model-facing sentence for a tool that ran out of its time budget (V1-27).

    The agent has to learn three things from the observation: the call was *cut
    off* (so nothing was observed about the target), repeating it unchanged will
    be cut off again, and the phase still has other routes. Measured in the rerun
    #7 (attempt 1, 2026-10-15): a timed-out ``nmap -p-`` had no such message and
    the whole run closed as ``provider_error`` from iteration 1.
    """
    return (
        f"tool '{tool_id}' exceeded its time budget and was aborted: it observed "
        "nothing about the target. Reduce the work it has to do (fewer ports or "
        "options) or use another route of the phase; repeating the same call will "
        "run out of time again."
    )


def repeated_action_correction(tool_id: Any) -> str:
    """Model-facing correction for an identical repeat of a failed action (V1-26).

    Measured in the rerun #7 (2026-10-15): the ``msf_exploit`` call of iteration 9
    failed and iteration 10 proposed it byte-identically. The gateway keeps a
    failed invocation journaled as ``unknown`` (its effect may have happened), so
    the repeat demanded a human approval that the ``--trust-mode`` run does not
    hold, and the loop closed as ``blocked`` with budget to spare. In the rerun #6
    the same failure produced a correction and the model pivoted to ``psexec``,
    which opened the session. What the correction has to say is *what to do next*,
    never a silent refusal.
    """
    return (
        f"Repetiste la invocación de '{tool_id}' con los mismos argumentos. La "
        "anterior falló o no tuvo efecto, así que repetirla no aporta información "
        "nueva. Propón UNA acción NUEVA: otra tool, otros argumentos, o "
        "task_complete si ya no quedan rutas viables."
    )


def _invocation_signature(tool_id: Any, arguments: Any) -> str:
    """Canonical signature of one tool call (tool id + redacted arguments).

    The loop uses it to tell a repeat of the *immediately preceding* action from a
    new attempt (V1-26). The arguments are redacted with the same field policy
    used to persist them, so the signature never carries a credential and still
    matches the copy kept in the action log.
    """
    import hashlib

    payload = [str(tool_id or ""), memory._redact_arguments(arguments or {})]
    try:
        text = json.dumps(payload, sort_keys=True, default=str)
    except (TypeError, ValueError, RecursionError):
        text = str(payload)
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()


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


def stuck_threshold() -> int:
    """Turns in a row without a new verified fact that count as stuck.

    ``NEXUS_STUCK_THRESHOLD`` overrides it; the default (5) is the value the run
    of 2026-10-15 justifies: it burned 10 turns with ``blackboard_delta = 0``
    before dying of subagent budget, so half of those are enough signal to tell
    the model to pivot. A malformed or non-positive value falls back to the
    default instead of disabling the signal by accident.
    """
    raw = os.getenv(STUCK_THRESHOLD_ENV, "")
    try:
        value = int(str(raw).strip())
    except (TypeError, ValueError):
        return int(DEFAULT_STUCK_THRESHOLD)
    return value if value > 0 else int(DEFAULT_STUCK_THRESHOLD)


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


def _citation_objections(evidence_stats: Mapping[str, Any] | None) -> list[str]:
    """Per-finding detail of a refused completion (V1-48).

    The counters say *how many* findings failed; without this the model cannot
    know *which* citation to repair, which is what rerun 13 measured: the gate
    refused eight findings (four ``stale_evidence``) with nothing but the counts,
    and the run died before it could try again. Each line names the finding, what
    it cited, whether that invocation exists at all in the corpus, and the closest
    observation there is -plus the tool call that lets the model check for itself.
    """
    stats = evidence_stats or {}
    rejected = stats.get("rejected_findings") or []
    lines: list[str] = []
    for item in rejected[:CITATION_DETAIL_LIMIT]:
        if not isinstance(item, Mapping):
            continue
        cited: Mapping[str, Any] = {}
        raw_cited = item.get("cited")
        if isinstance(raw_cited, Mapping):
            cited = raw_cited
        ref = str(item.get("finding_ref") or "finding")
        invocation = str(cited.get("invocation_id") or "(sin invocation_id)")
        fact_type = str(cited.get("fact_type") or "(sin fact_type)")
        target = str(cited.get("target") or "(sin target)")
        reason = str(item.get("reason") or "stale_evidence")
        line = (
            f"Hallazgo '{ref}' ({reason}) citó invocation_id={invocation} "
            f"fact_type={fact_type} target={target}, pero no coincide con ninguna "
            "observación de este run. Usa query_facts para obtener el ID correcto "
            "antes de reintentar."
        )
        if not item.get("found_in_corpus") and cited.get("invocation_id"):
            line += f" Ese invocation_id ({invocation}) no aparece en ninguna observación de este run."
        match = item.get("closest_match")
        if isinstance(match, Mapping):
            line += (
                " La observación más cercana del corpus: "
                f"invocation_id={match.get('invocation_id') or '(ninguno)'} "
                f"fact_type={match.get('fact_type') or '(ninguno)'} "
                f"target={match.get('target') or '(ninguno)'}."
            )
        lines.append(line)
    remaining = len(rejected) - len(lines)
    if remaining > 0:
        lines.append(
            f"… y {remaining} hallazgo(s) más rechazado(s) por la misma causa "
            "(el detalle completo está en el evento react.premature_completion)."
        )
    return lines


def missing_evidence(evidence_stats: Mapping[str, Any] | None) -> list[dict[str, str]]:
    """Machine-readable detail of every refused finding (WP2, Fix 3).

    ``premature_completion`` used to expose only counters, so the next turn could
    not know *which* citation to repair. Each entry names the finding, why it was
    refused and the observation reference that would satisfy it (the closest
    verified observation of this run). Empty when nothing was refused.
    """
    entries: list[dict[str, str]] = []
    for item in (evidence_stats or {}).get("rejected_findings") or []:
        if not isinstance(item, Mapping):
            continue
        match = item.get("closest_match")
        expected = (
            str(match.get("invocation_id") or "")
            if isinstance(match, Mapping)
            else ""
        )
        entries.append(
            {
                "finding_id": str(item.get("finding_ref") or ""),
                "reason": str(item.get("reason") or "stale_evidence"),
                "observation_ref_expected": expected,
            }
        )
    return entries


def _completion_objections(
    plan: Any,
    *,
    enforce_completion_gates: bool,
    evidence_stats: dict[str, Any] | None = None,
    engagement_id: str | None = None,
    require_plan_phase: bool = True,
) -> list[str]:
    """Why this ``task_complete`` must not be accepted yet (B8.2.2/B8.2.3).

    Two independent checks, both deterministic:

    * the plan is not on its final phase yet, so required phases are missing;
    * the findings cite evidence that no observation of this run supports.

    The plan check only applies to an **engagement** run: with no signed scope
    there is no blackboard, so every phase would stay ``pending`` forever and no
    objective could ever complete. The kill-chain frame is a property of an
    engagement, not of a bare objective.

    V1-48 adds *detail* to the second check and nothing else: the gate itself is
    untouched (``fabricated_evidence`` still refuses the completion).

    WP2 adds ``require_plan_phase``: the default loop passes ``False`` so the
    phase is a hint and never refuses a closure the board supports; the legacy
    path keeps ``True`` for the old regression suite.
    """
    objections: list[str] = []
    if require_plan_phase and enforce_completion_gates and engagement_id and plan is not None:
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
        counts = (
            f"{evidence_stats.get('stale')} hallazgo(s) citan evidencia que no "
            "aparece en ninguna observación de este run (stale_evidence)"
        )
        if evidence_stats.get("unsupported"):
            # Otherwise the line above reads "0 hallazgo(s)…" while the refusal is
            # real: the same counter pair the gate uses, stated accurately.
            counts += (
                f" y {evidence_stats['unsupported']} no citan evidencia alguna "
                "(no_evidence)"
            )
        objections.append(counts)
        objections.extend(_citation_objections(evidence_stats))
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
        # Explicit classification of the invocation (V0-22/Fase 3b). The loop
        # reads it to tell a tool that *failed* from one whose backend is not
        # serving (``unavailable``), which must not end the run.
        "outcome": output.get("outcome") or "",
        "verification_method": output.get("verification_method"),
        "evidence": output.get("evidence"),
        "invocation_id": output.get("invocation_id"),
        "assertions": output.get("assertions", []),
        "output": output.get("output"),
    }


#: WP2 global ceiling of one run. It is the only budget that can stop the loop;
#: the per-subagent numbers are soft telemetry. 250k is the plan's default.
DEFAULT_RUN_BUDGET_TOKENS = 250_000


def _budget_tokens(payload: dict[str, Any], explicit: int | None) -> int:
    """Resolve the per-run token budget from the payload, env or explicit arg.

    An explicit ``0`` (payload or argument) keeps its documented meaning:
    unlimited. Only an *absent* configuration falls back to the WP2 default.
    """
    if explicit is not None:
        raw: Any = explicit
    elif payload.get("budget_tokens") not in (None, ""):
        raw = payload.get("budget_tokens")
    else:
        raw = os.getenv("NEXUS_RUN_BUDGET_TOKENS")
        if raw is None or str(raw).strip() == "":
            raw = DEFAULT_RUN_BUDGET_TOKENS
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
