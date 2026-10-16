"""Fine-grained per-turn operational telemetry for the ReAct loop.

The deterministic parts of the engine were already observable *per event* (audit
steps, run events), but one ReAct iteration — the unit the operator actually
pays for — was not: token spend, how long the model reasoned, how long the tool
took, whether the turn was fought against friction (a parse error, a retired
tool, an operator denial) and what the blackboard learned during it were spread
across four code paths and never joined.

This module joins them into one immutable :class:`TurnTelemetry` record per
iteration and fans it out to the three sinks the project already has:

* **OpenTelemetry** — one ``nexus.react.turn`` span per turn (``kernel.telemetry``);
* **in-process metrics** — ``nexus_react_*`` counters a scraper can read;
* **durable run events** — ``react.turn_telemetry`` on the control store, so the
  turn stream survives the run and lands in the same place as every other
  audited event.

Nothing here calls the LLM and nothing here can abort a run: a telemetry failure
degrades to "no record", never to a broken engagement.

Declarative playbooks (``nexus_core/playbooks/*.yaml``) name the signals they
require in their ``telemetry:`` block; those names are exactly
:data:`TURN_TELEMETRY_SIGNALS`, so a phase cannot ask for a signal the loop does
not produce.
"""

from __future__ import annotations

import asyncio
import queue
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Mapping


class TelemetryDispatcher:
    """One daemon consumer, bounded backlog; producers never wait for a sink.

    Events are best effort. A full queue drops the new event explicitly; it
    never falls back to synchronous I/O. The durable journal is independent.
    """

    def __init__(self, capacity: int = 256) -> None:
        self._queue: queue.Queue[tuple[Callable[[], None], threading.Event]] = queue.Queue(capacity)
        self._thread = threading.Thread(target=self._consume, daemon=True, name="nexus-turn-telemetry")
        self._thread.start()

    def submit(self, publish: Callable[[], None]) -> threading.Event | None:
        done = threading.Event()
        try:
            self._queue.put_nowait((publish, done))
        except queue.Full:
            return None
        return done

    def _consume(self) -> None:
        while True:
            publish, done = self._queue.get()
            try:
                publish()
            except Exception:
                pass  # callback failures cannot kill the dispatcher
            finally:
                done.set()
                self._queue.task_done()


_DISPATCHER: TelemetryDispatcher | None = None
_DISPATCHER_LOCK = threading.Lock()


def _dispatcher() -> TelemetryDispatcher:
    global _DISPATCHER
    with _DISPATCHER_LOCK:
        if _DISPATCHER is None:
            _DISPATCHER = TelemetryDispatcher()
        return _DISPATCHER


def _nonnegative(value: Any) -> int:
    try:
        return max(0, int(value or 0))
    except (TypeError, ValueError, OverflowError):
        return 0


class FrictionFlag(str, Enum):
    """Ways a turn was *resisted* by the environment instead of progressing.

    Friction is not the same thing as a tool failure: a parse error, a governance
    denial and a retired tool all cost the operator tokens without moving the
    engagement, and telling them apart is what makes a run diagnosable.
    """

    #: The model answered with something that was not a valid ReAct JSON action.
    PARSE_ERROR = "parse_error"
    #: The gateway/handler rejected the arguments (schema, forbidden flag).
    INPUT_REJECTED = "input_rejected"
    #: The tool itself failed (missing binary, non-zero post-condition).
    TOOL_FAILURE = "tool_failure"
    #: The tool was retired for the rest of the run after repeated failures.
    TOOL_RETIRED = "tool_retired"
    #: Policy/scope/approval refused the call before executing it.
    GOVERNANCE_DENIAL = "governance_denial"
    #: A human operator refused the approval request.
    OPERATOR_DENIAL = "operator_denial"
    #: The budget reservation refused the turn before contacting the provider.
    BUDGET_REFUSED = "budget_refused"
    #: The tool call hit its timeout.
    TIMEOUT = "timeout"
    #: The same (tool, arguments) pair as the previous turn: a stalled loop.
    REPEATED_ACTION = "repeated_action"
    #: ``task_complete`` was refused because the completion gates said otherwise.
    PREMATURE_COMPLETION = "premature_completion"
    #: The subagent was over its token ceiling and the turn was allowed anyway
    #: because the objective is already complete on the board (V1-38).
    BUDGET_EXEMPT = "budget_exempt_if_objective_complete"
    #: The tool call was cancelled by the operator.
    CANCELLED = "cancelled"
    #: The call violated the signed engagement scope (the run aborts on this one).
    SCOPE_VIOLATION = "scope_violation"


#: Signal vocabulary shared with the declarative playbooks: a phase's
#: ``telemetry:`` block may only name a key of this mapping.
TURN_TELEMETRY_SIGNALS: Mapping[str, str] = {
    "tokens": "total_tokens",
    "reasoning_duration": "reasoning_ms",
    "tool_duration": "tool_ms",
    "friction_flags": "friction",
    "blackboard_delta": "blackboard_delta",
    "tool_outcome": "outcome",
    "plan_phase": "phase",
}

#: Metric names emitted per turn (kept stable for scrapers/dashboards).
METRIC_TURNS = "nexus_react_turn_total"
METRIC_TOKENS = "nexus_react_turn_tokens_total"
METRIC_DURATION_MS = "nexus_react_turn_duration_ms"
METRIC_FRICTION = "nexus_react_friction_total"

#: Durable run-event type carrying one turn's record.
TURN_EVENT_TYPE = "react.turn_telemetry"

#: Span name of one turn.
TURN_SPAN_NAME = "nexus.react.turn"


@dataclass(frozen=True)
class TurnTelemetry:
    """Everything one ReAct iteration cost and learned (immutable snapshot)."""

    iteration: int
    phase: str
    subagent_id: str | None
    action: str
    tool_id: str | None
    outcome: str
    #: Wall-clock of the model call (the ``thought``/action generation).
    reasoning_ms: int
    #: Wall-clock of the tool call of this turn (0 when the turn had no tool).
    tool_ms: int
    #: Wall-clock of action processing after context and profile selection.
    turn_ms: int
    #: Pre-flight estimate (chars/4) used for the budget reservation.
    request_tokens_estimated: int
    prompt_tokens: int
    completion_tokens: int
    total_tokens: int
    #: Friction flags, as plain strings (JSON-friendly, deduplicated, ordered).
    friction: tuple[str, ...] = ()
    #: Verified-fact state *after* the turn and how much it grew. Counts match
    #: what the planner sees (``Blackboard.summary``), so a turn's delta is the
    #: evidence the engagement actually gained.
    blackboard_facts: int = 0
    blackboard_delta: int = 0
    blackboard_added: tuple[str, ...] = ()
    #: Turns in a row (including this one) that ended without a new verified
    #: fact. Audit trail of the ``react.stuck_detected`` signal (Fase 3 fixes):
    #: the record and the event are computed from the same counter.
    consecutive_no_progress: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "iteration": self.iteration,
            "phase": self.phase,
            "subagent_id": self.subagent_id,
            "action": self.action,
            "tool_id": self.tool_id,
            "outcome": self.outcome,
            "reasoning_ms": self.reasoning_ms,
            "tool_ms": self.tool_ms,
            "turn_ms": self.turn_ms,
            "request_tokens_estimated": self.request_tokens_estimated,
            "prompt_tokens": self.prompt_tokens,
            "completion_tokens": self.completion_tokens,
            "total_tokens": self.total_tokens,
            "friction": list(self.friction),
            "blackboard_facts": self.blackboard_facts,
            "blackboard_delta": self.blackboard_delta,
            "blackboard_added": list(self.blackboard_added),
            "consecutive_no_progress": self.consecutive_no_progress,
        }

    def attributes(self) -> dict[str, Any]:
        """Span attributes: flat primitives only (OTel rejects nested objects)."""
        attrs: dict[str, Any] = {
            "turn.iteration": self.iteration,
            "turn.phase": self.phase,
            "turn.action": self.action,
            "turn.outcome": self.outcome,
            "turn.reasoning_ms": self.reasoning_ms,
            "turn.tool_ms": self.tool_ms,
            "turn.duration_ms": self.turn_ms,
            "turn.tokens.total": self.total_tokens,
            "turn.tokens.prompt": self.prompt_tokens,
            "turn.tokens.completion": self.completion_tokens,
            "turn.blackboard.facts": self.blackboard_facts,
            "turn.blackboard.delta": self.blackboard_delta,
            "turn.blackboard.no_progress": self.consecutive_no_progress,
            "turn.friction": ",".join(self.friction) or "none",
        }
        if self.subagent_id:
            attrs["turn.subagent_id"] = self.subagent_id
        if self.tool_id:
            attrs["turn.tool_id"] = self.tool_id
        return attrs


@dataclass
class _TurnDraft:
    """Mutable accumulator of the turn currently in flight."""

    iteration: int
    phase: str
    subagent_id: str | None
    facts_total: int
    counts: Mapping[str, int]
    action: str = "pending"
    tool_id: str | None = None
    request_tokens_estimated: int = 0
    prompt_tokens: int = 0
    completion_tokens: int = 0
    reasoning_ms: int = 0
    tool_ms: int = 0
    consecutive_no_progress: int = 0
    friction: list[str] = field(default_factory=list)


def _int_attr(source: Any, name: str) -> int:
    """Best-effort positive int read of a provider usage field (never raises)."""
    try:
        return max(0, int(getattr(source, name, 0) or 0))
    except (TypeError, ValueError, OverflowError):
        return 0


def blackboard_delta(
    previous: Mapping[str, int] | None, current: Mapping[str, int] | None
) -> tuple[int, tuple[str, ...]]:
    """Facts added since the previous turn plus the fact types that grew.

    Counts are per fact type, so the total is the sum of the counts and the
    "added" list names the types whose count increased.
    """
    before = {str(key): _nonnegative(value) for key, value in (previous or {}).items()}
    after = {str(key): _nonnegative(value) for key, value in (current or {}).items()}
    total_before = sum(before.values())
    total_after = sum(after.values())
    grown = tuple(
        sorted(
            fact_type
            for fact_type, amount in after.items()
            if amount > before.get(fact_type, 0)
        )
    )
    return max(0, total_after - total_before), grown


class TurnTelemetryRecorder:
    """Collects one record per iteration and publishes it to the sinks.

    The coordinator drives it explicitly (begin → notes → finish); every method
    is safe to call out of order, and ``finish`` always returns a record even
    when the turn died mid-way (a failed turn is exactly what the operator needs
    to see).
    """

    def __init__(
        self,
        *,
        store: Any = None,
        tenant_id: str = "",
        run_id: str = "",
        emit: bool = True,
    ) -> None:
        self.store = store
        self.tenant_id = tenant_id
        self.run_id = run_id
        self.emit = emit
        self._draft: _TurnDraft | None = None
        self._previous_counts: Mapping[str, int] = {}
        self._previous_action: tuple[str | None, str] | None = None
        self.turns: list[TurnTelemetry] = []
        self.dropped_events = 0
        self.publish_failures = 0
        self._pending: deque[threading.Event] = deque()

    # -------------------------------------------------------------- recording
    @property
    def has_open_turn(self) -> bool:
        return self._draft is not None

    def begin_turn(
        self,
        *,
        iteration: int,
        phase: str,
        subagent_id: str | None,
        facts_total: int = 0,
        counts: Mapping[str, int] | None = None,
    ) -> None:
        """Open a new turn, publishing the previous one if it was left open."""
        if self._draft is not None:  # defensive: never lose an open turn
            self.finish(outcome="abandoned")
        self._previous_counts = dict(counts or {})
        self._draft = _TurnDraft(
            iteration=iteration,
            phase=phase,
            subagent_id=subagent_id,
            facts_total=_nonnegative(facts_total),
            counts=dict(counts or {}),
        )

    def note_action(self, *, action: str, tool_id: str | None = None, arguments: Any = None) -> None:
        """Record the decoded action and flag a repeated (tool, arguments) pair."""
        draft = self._draft
        if draft is None:
            return
        draft.action = str(action or "unknown")
        draft.tool_id = str(tool_id) if tool_id else None
        signature = (draft.tool_id, _signature(arguments))
        if draft.tool_id and self._previous_action == signature:
            self.flag(FrictionFlag.REPEATED_ACTION)
        self._previous_action = signature if draft.tool_id else None

    def note_reasoning(self, response: Any, *, estimated: int, duration_ms: int) -> None:
        """Record token usage and reasoning wall-clock of the model call."""
        draft = self._draft
        if draft is None:
            return
        draft.request_tokens_estimated = _nonnegative(estimated)
        draft.reasoning_ms = _nonnegative(duration_ms)
        draft.prompt_tokens = _int_attr(response, "tokens_input")
        draft.completion_tokens = _int_attr(response, "tokens_output")

    def note_tool(self, *, duration_ms: int, success: bool, error_type: str | None = None) -> None:
        """Record the tool call wall-clock and the outcome of a failed call."""
        draft = self._draft
        if draft is None:
            return
        draft.tool_ms = _nonnegative(duration_ms)
        if not success:
            self.flag(flag_for_error(error_type))

    def flag(self, flag: FrictionFlag | str) -> None:
        """Add a friction flag (idempotent, keeps first-seen order)."""
        draft = self._draft
        if draft is None:
            return
        value = flag.value if isinstance(flag, FrictionFlag) else str(flag)
        if value not in draft.friction:
            draft.friction.append(value)

    def note_blackboard(self, *, facts_total: int, counts: Mapping[str, int] | None = None) -> None:
        """Override the blackboard state of the open turn (state after the tool)."""
        draft = self._draft
        if draft is None:
            return
        draft.facts_total = _nonnegative(facts_total)
        if counts is not None:
            draft.counts = dict(counts)

    def note_no_progress(self, *, consecutive: int) -> None:
        """Record the run's no-progress streak *including* the open turn."""
        draft = self._draft
        if draft is None:
            return
        draft.consecutive_no_progress = _nonnegative(consecutive)

    def current_delta(self) -> int | None:
        """Delta of the open turn, or ``None`` when its state is incomplete.

        Read *after* :meth:`note_blackboard` and *before* :meth:`finish`, so the
        loop can act on the same number the record will publish instead of
        recomputing it (a second implementation is a second truth).
        """
        draft = self._draft
        if draft is None:
            return None
        delta, _ = blackboard_delta(self._previous_counts, draft.counts)
        return delta

    # -------------------------------------------------------------- publishing
    def finish(self, *, outcome: str, turn_ms: int = 0) -> TurnTelemetry | None:
        """Close the open turn, publish it and return the record."""
        draft, self._draft = self._draft, None
        if draft is None:
            return None
        delta, added = blackboard_delta(self._previous_counts, draft.counts)
        self._previous_counts = dict(draft.counts)
        record = TurnTelemetry(
            iteration=draft.iteration,
            phase=draft.phase,
            subagent_id=draft.subagent_id,
            action=draft.action,
            tool_id=draft.tool_id,
            outcome=str(outcome or "unknown"),
            reasoning_ms=draft.reasoning_ms,
            tool_ms=draft.tool_ms,
            turn_ms=_nonnegative(turn_ms),
            request_tokens_estimated=draft.request_tokens_estimated,
            prompt_tokens=draft.prompt_tokens,
            completion_tokens=draft.completion_tokens,
            total_tokens=draft.prompt_tokens + draft.completion_tokens,
            friction=tuple(draft.friction),
            blackboard_facts=draft.facts_total,
            blackboard_delta=delta,
            blackboard_added=added,
            consecutive_no_progress=draft.consecutive_no_progress,
        )
        self.turns.append(record)
        if self.emit:
            while self._pending and self._pending[0].is_set():
                self._pending.popleft()
            try:
                pending = _dispatcher().submit(lambda: self._publish(record))
            except Exception:
                pending = None
            if pending is None:
                self.dropped_events += 1
            else:
                self._pending.append(pending)
        return record

    async def flush(self, timeout: float = 0.25) -> bool:
        """Best-effort bounded drain at run termination; never joins a thread."""
        deadline = time.monotonic() + max(0.0, timeout)
        while self._pending:
            while self._pending and self._pending[0].is_set():
                self._pending.popleft()
            if not self._pending:
                return True
            if time.monotonic() >= deadline:
                return False
            await asyncio.sleep(0.005)
        return True

    def as_dicts(self) -> list[dict[str, Any]]:
        """The whole turn stream, JSON-ready (goes into ``ReActResult``)."""
        return [turn.to_dict() for turn in self.turns]

    def _publish(self, record: TurnTelemetry) -> None:
        """Fan the record out to every sink; a sink failure never propagates."""
        if not self.emit:
            return
        from nexus_core.kernel.telemetry import metrics, telemetry

        labels = {"phase": record.phase, "subagent": record.subagent_id or "none"}
        try:
            with telemetry.span(TURN_SPAN_NAME, record.attributes()):
                pass
        except Exception:  # noqa: BLE001 - telemetry must never abort a run
            self.publish_failures += 1
        try:
            metrics.increment(METRIC_TURNS, 1, **labels)
            metrics.increment(METRIC_DURATION_MS, record.turn_ms, **labels)
            if record.total_tokens:
                metrics.increment(METRIC_TOKENS, record.total_tokens, **labels)
            for flag in record.friction:
                metrics.increment(METRIC_FRICTION, 1, flag=flag, **labels)
        except Exception:  # noqa: BLE001 - same contract as the span
            self.publish_failures += 1
        if self.store is None or not self.tenant_id or not self.run_id:
            return
        try:
            self.store.append_run_event(
                self.tenant_id, self.run_id, TURN_EVENT_TYPE, record.to_dict()
            )
        except Exception:  # noqa: BLE001 - the durable sink is best-effort too
            self.publish_failures += 1


def flag_for_error(error_type: str | None) -> FrictionFlag:
    """Map the failure classification used by the loop onto a friction flag."""
    name = str(error_type or "").rsplit(".", 1)[-1]
    if name == "CancelledError":
        return FrictionFlag.CANCELLED
    if name == "TimeoutError":
        return FrictionFlag.TIMEOUT
    if name in {"PermissionError", "ApprovalRequired"}:
        return FrictionFlag.GOVERNANCE_DENIAL
    if name in {"ValueError", "SchemaValidationError", "ValidationError"}:
        return FrictionFlag.INPUT_REJECTED
    return FrictionFlag.TOOL_FAILURE


def _signature(arguments: Any) -> str:
    """Stable, bounded signature of one tool call's arguments."""
    import json

    try:
        text = json.dumps(arguments, sort_keys=True, default=str)
    except (TypeError, ValueError, RecursionError):
        text = str(arguments)
    import hashlib

    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


__all__ = [
    "FrictionFlag",
    "METRIC_DURATION_MS",
    "METRIC_FRICTION",
    "METRIC_TOKENS",
    "METRIC_TURNS",
    "TURN_EVENT_TYPE",
    "TURN_SPAN_NAME",
    "TURN_TELEMETRY_SIGNALS",
    "TurnTelemetry",
    "TurnTelemetryRecorder",
    "blackboard_delta",
    "flag_for_error",
]
