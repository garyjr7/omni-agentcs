"""Stable public configuration and result types for ReAct."""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any, Callable
from nexus_core.kernel.domain_dto import ApprovalDecisionDTO

DEFAULT_AGENT_ID = "omni"
MAX_CONSECUTIVE_TOOL_FAILURES = 3
#: A model answer that is not the JSON object the contract asks for is an
#: *answer* problem, not a dead provider. The loop injects a correction and asks
#: again; after this many turns in a row it gives up and closes the run. Measured
#: in Simple CTF Run 3 (2026-10-17): DeepSeek answered garbage on iteration 3 and
#: the engine aborted with exit 3 while the target was still live.
MAX_INVALID_JSON_TURNS = 3
INVALID_JSON_EVENT_TYPE = "react.invalid_json_retry"
#: The exact correction the model reads on the next turn. It names the required
#: shape so the retry is actionable, not just a complaint.
INVALID_JSON_CORRECTION = (
    "Tu respuesta anterior no fue un JSON válido. Debes devolver un objeto JSON "
    "con la acción (tool_call, task_complete o request_clarification)."
)
CANCEL_EVENT_TYPE = "react.cancel_requested"
#: A tool that fails this many times **in a row** *as a tool* (not as invalid
#: input) is marked unavailable for the rest of the run, so the agent pivots
#: instead of the whole engagement dying (B3). Any successful turn clears the
#: streak: an isolated failure between successful calls is not a broken tool.
MAX_TOOL_FAILURES_BEFORE_UNAVAILABLE = 3
TOOL_UNAVAILABLE_EVENT_TYPE = "react.tool_unavailable"
PHASE_TIMEOUT_EVENT_TYPE = "react.phase_timeout"
#: Optional per-phase wall-clock budget (0 disables it). When exceeded the
#: phase's already-failing tools are retired and the event is audited.
PHASE_TIMEOUT_ENV = "NEXUS_PHASE_TIMEOUT_SECONDS"
#: Emitted when the loop has spent N turns in a row without a single new
#: verified fact (measured in run_abe04509c5064c6e8e475f46ba8f8c60: 10 turns
#: with ``blackboard_delta = 0``). It is a *signal*: it never stops the run and
#: never changes the phase by itself; the next prompt tells the model to pivot.
STUCK_EVENT_TYPE = "react.stuck_detected"
#: Env var that overrides the no-progress threshold (default 5 turns).
STUCK_THRESHOLD_ENV = "NEXUS_STUCK_THRESHOLD"
DEFAULT_STUCK_THRESHOLD = 5
#: Appended to the system prompt once the loop is stuck (P2, Fase 3 fixes).
STUCK_PROMPT_LINE = (
    "Detectado estancamiento: {iterations} turnos sin hechos nuevos. "
    "Cambia de estrategia o propón task_complete si ya no hay rutas viables."
)
#: WP4: turns in a row that repeat the *same* tool without a new fact before the
#: loop offers the skill catalogue. Narrower than the stuck threshold on purpose:
#: asking one capability three times is not exploring, it is guessing at the same
#: door. Measured in the RootMe run, 21 calls between ``shell.exec`` and
#: ``web.upload`` never uploaded the webshell and the run died at
#: ``stuck_detected``; a recipe the model can load is the cheapest way out.
SKILL_NUDGE_TURNS = 3
#: Seconds a tool call has to take before an identical, fact-free repeat of it is
#: intercepted. Nothing fast is worth a dedicated guard -the gateway's dedup and
#: the ``repeated_action`` correction already cover failures-; the target is the
#: measured 500 s sqlmap probe that the model relaunched byte-identically in
#: run_1052d63f9bba4838902b3aa21bd27d21 (2026-10-19), which cost 9 of the run's
#: 25 minutes and returned the same empty result.
BARREN_REPEAT_MIN_SECONDS = 30
#: Fast calls are governed by the gateway's dedup... except that dedup is keyed
#: on the *invocation id*, so a new turn is always a new invocation and nothing
#: stopped an identical cheap call from being replayed every turn. Measured in
#: run_c71035d9818047eaa80dfd859e887b7c (Joomla, 2026-10-20): three identical
#: 0.3 s SQLi probes and four identical ``hashcat`` sweeps, 49 barren turns, 0
#: findings. From this many barren turns, a call whose exact signature already
#: ran inside the recent window is corrected like a slow one.
FAST_REPEAT_MIN_NO_PROGRESS = 3
#: How many recent actions the fast-repeat brake looks back over. A model that
#: alternates two probes (A, B, A, B) never repeats *adjacently*, so the window
#: has to be wider than one turn.
FAST_REPEAT_WINDOW = 6
#: Emitted once when the repeated-tool streak reaches :data:`SKILL_NUDGE_TURNS`.
SKILL_NUDGE_EVENT_TYPE = "react.skill_nudge"
#: Appended to the next prompt when the repeated-tool streak is reached. The
#: wording is the product contract of WP4 (FIX 3): the model has to be told both
#: that it is stuck and how to get unstuck.
SKILL_NUDGE_PROMPT = (
    "Estás atascado. Considera usar `nexus.skill.list()` y cargar una skill "
    "que se adapte a tu problema (ej. methodology-senior si te falta "
    "enumeración o web-upload-webshell si el vector es una subida)."
)
#: Emitted once when the smart-budget rule fires: the run has spent more than
#: ``SMART_BUDGET_MIN_ITERATION`` turns mapping a wide surface without any access
#: (Simple CTF 2026-10-18, ``run_c034eeeb…``: 17 endpoints and >150k tokens)
#: before it reaches the endpoint it should attack.
SMART_BUDGET_EVENT_TYPE = "react.budget_hint"
#: Emitted once when the run has spent ``WEBSHELL_STALL_TURNS`` turns building or
#: moving files through a webshell without a new fact. Measured in Vulnversity
#: (2026-10-19): 35 turns compiling ``pwnkit`` and shipping it in base64 chunks
#: through ``curl`` while a reverse shell was one turn away. From that turn the
#: prompt orders the interactive channel (``session.pty`` / ``listener``).
WEBSHELL_STALL_EVENT_TYPE = "react.webshell_stall"
#: Emitted once when the surface ledger's correction fires: the run is aimed at
#: a service already documented as ``descartado`` (a ``barrier`` fact) or it has
#: spent the stuck threshold on one branch while another service is unexplored.
#: Measured in the Blackbox run (2026-10-19): the agent kept probing the patched
#: service while the internal web target was still pending. The hint orders the
#: next branch; it never changes the plan nor authorizes a tool.
COVERAGE_PIVOT_EVENT_TYPE = "react.coverage_pivot"
#: Emitted when the run read an index file (``robots.txt``/``sitemap.xml``) and
#: moved on without requesting the routes it lists. Measured in
#: ``/tmp/bruteit-run-v2.ndjson`` (Brute It, 2026-10-20): ``/robots.txt`` was
#: fetched at iteration 22 and the branch was closed on the next turn, so the
#: run asked the operator for a hint with the cheapest route still unvisited.
#: The order is deterministic (``planner.robots_paths_hint``) and names the
#: concrete URLs; it authorizes no tool.
ROBOTS_HINT_EVENT_TYPE = "react.robots_paths"
#: Emitted when the *loop*, not the model, closes a branch. The pivot above asks
#: the model to record a ``barrier`` fact and move on; when it keeps hammering the
#: same service instead, the ledger never moves and the run spends its remaining
#: budget on a branch it was already told to leave. Measured in
#: run_c71035d9818047eaa80dfd859e887b7c (Joomla, 2026-10-20): the pivot fired at
#: iteration 7 and, 43 barren turns later, the two services were still listed as
#: open. The fact is unverified and its ``source`` names the loop, so the operator
#: can tell an engine decision from a model claim.
LOOP_BARRIER_EVENT_TYPE = "react.branch_closed"
#: How many stuck thresholds the loop waits before writing that barrier. The first
#: threshold is the advisory line; this is the margin the model gets to act on it
#: before the loop takes the decision itself (the shape of
#: :data:`TARGET_REACHED_GRACE_TURNS`).
STALL_BARRIER_MULTIPLIER = 2
#: Recent actions inspected to decide *which* branch is being hammered. The
#: attribution must be unanimous: alternating two services is breadth, not a stall
#: on one, and closing either of them would be a guess.
STALLED_BRANCH_WINDOW = 6
#: Emitted once when the board (or the successful output of this run) proves the
#: flags the objective asked for were captured. From that turn on the prompt
#: carries :data:`TARGET_REACHED_PROMPT` and the loop counts the tool calls the
#: model still makes before closing (WP5).
TARGET_REACHED_EVENT_TYPE = "react.target_reached"
#: Emitted when the 3-turn margin ran out and the loop closed the run itself.
TARGET_REACHED_FORCED_EVENT_TYPE = "react.target_reached_forced"
#: Tool calls the model may still spend after the warning before the loop
#: intercepts the next one and closes with a synthesized ``task_complete``.
TARGET_REACHED_GRACE_TURNS = 3
#: Appended to the prompt of every turn while the objective is reached. The
#: wording is the product contract: name the success, order the closure and
#: forbid more tools.
TARGET_REACHED_PROMPT = (
    "OBJETIVO CUMPLIDO: Has capturado las flags. Llama a task_complete AHORA "
    "con los hallazgos. No sigas ejecutando herramientas."
)
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
#: A subagent exhausted its own iteration/token allowance. In the WP2 default
#: loop this status is unreachable (the limits are soft); it stays for the
#: ``NEXUS_LEGACY_PROFILES=1`` path and its regression tests.
STATUS_SUBAGENT_BUDGET = "subagent_budget_exceeded"
SUBAGENT_EVENT_TYPE = "orchestrator.subagent"
#: Emitted once when the planner sees the objective *completed* on the board:
#: a verified top privilege plus verified loot. It is a signal with a hint, never
#: an order -the model still decides to close with ``task_complete`` (V1-35).
OBJECTIVE_COMPLETE_EVENT_TYPE = "orchestrator.objective_complete"
BUDGET_EVENT_TYPE = "react.budget_exceeded"
#: Emitted when the active subagent is over its token ceiling but the objective is
#: already complete: the loop spends the turn closing instead of dying without a
#: ``task_complete`` (V1-38). Payload carries ``budget_exempt_if_objective_complete``.
BUDGET_EXEMPT_EVENT_TYPE = "react.budget_exempt"
#: WP2: emitted once when the board proves objective completion. It grants the
#: run ``OBJECTIVE_GRACE_TURNS`` extra turns (and, if the global budget is hit,
#: the same number of budget-grace turns) so the model can close with
#: ``task_complete`` instead of dying with the work done.
OBJECTIVE_GRACE_EVENT_TYPE = "react.objective_grace"
BUDGET_GRACE_EVENT_TYPE = "react.budget_grace"
OBJECTIVE_GRACE_TURNS = 5
#: WP2: a per-subagent budget was exceeded but the loop kept going, because the
#: per-profile numbers are soft limits (telemetry) and only the global run
#: budget may stop a run.
SUBAGENT_SOFT_LIMIT_EVENT_TYPE = "react.subagent_soft_limit"
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

    def __post_init__(self) -> None:
        self.to_dto()

    def to_dto(self) -> ApprovalDecisionDTO:
        return ApprovalDecisionDTO(
            approved=self.approved,
            approval_id=self.approval_id,
            edited_arguments=self.edited_arguments,
            reason=self.reason,
        )


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
    #: What a retry of an invocation the journal holds ``unknown`` may do in a
    #: headless ``--trust-mode`` run (``approve``/``skip``/``fail``). The CLI
    #: forwards ``--resume-policy`` only when trust mode is on; empty keeps the
    #: fail-closed ``ApprovalRequired``. It reaches the gateway as engine data
    #: (``RunContext.resume_policy``), never as a tool argument.
    resume_policy: str = ""
    #: Live reasoning hook: receives the partial ``thought`` text as the model
    #: writes it, so the CLI can stream the cognitive loop. Only used when the
    #: client reports ``supports_streaming``; otherwise the loop calls
    #: ``complete`` exactly as before.
    on_thought: Callable[[str], None] | None = None
    #: Called once when a streamed turn ends (success, error or fallback), so the
    #: live indicator closes before the durable thought is rendered.
    on_thought_done: Callable[[], None] | None = None
    #: Durable budget reservation, run *before* the provider call (P2-C2).
    #: Receives the estimated request tokens and returns an opaque handle (or
    #: ``None`` to skip). Raising :class:`BudgetExceeded` aborts the turn cleanly
    #: with ``status='budget_exceeded'`` *before* the provider is contacted.
    before_provider_call: Callable[[int], Any] | None = None
    #: Settle (or release) the handle returned by ``before_provider_call`` with
    #: the real token usage reported by the provider.
    after_provider_call: Callable[[Any, int], None] | None = None
    #: Durable root of the spawning tree, for budget attribution and audit.
    root_id: str = ""


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
    #: One operational telemetry record per iteration (token consumption,
    #: reasoning duration, friction flags and blackboard delta). The same
    #: records are emitted durably as ``react.turn_telemetry`` run events; they
    #: travel in the result so a caller can render a cost/friction summary
    #: without re-reading the store.
    turns: list[dict[str, Any]] = field(default_factory=list)
    #: Why the completion was refused, when ``status`` is
    #: ``premature_completion``.
    completion_objections: list[str] = field(default_factory=list)
    completion_verified: bool = False
