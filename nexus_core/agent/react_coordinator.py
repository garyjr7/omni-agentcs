"""Explicit ReAct transitions with per-run state and injected boundary services."""

from __future__ import annotations

import asyncio
import json
import os
import time
from typing import Any

from nexus_core.kernel.audit import AuditWriter
from nexus_core.llm.abstraction import LLMMessage, is_invalid_json_error
from nexus_core.scope import ScopeViolation

from . import memory
from nexus_core.kernel.errors import (
    ApprovalRequired,
    ProviderFailure,
    ReplayApprovalRequired,
)
from .preflight import unavailable_tools_from_env
from .project_context import load_project_instruction
from .skills import activate_skills
from .subagents import (
    filter_catalog,
    legacy_profiles,
    permits,
    select_run_profile,
    with_phase_grace,
)
from .parser import (
    ACTION_TASK_COMPLETE,
    ReActParseError,
)
from .branch_discipline import (
    BARRIER_ATTEMPT_WINDOW,
    barrier_refusal,
    closed_branch_refusal,
)

from .react_types import (
    BUDGET_EXEMPT_EVENT_TYPE,
    BUDGET_GRACE_EVENT_TYPE,
    DEFAULT_AGENT_ID,
    OBJECTIVE_GRACE_EVENT_TYPE,
    OBJECTIVE_GRACE_TURNS,
    SUBAGENT_SOFT_LIMIT_EVENT_TYPE,
    OBJECTIVE_COMPLETE_EVENT_TYPE,
    MAX_CONSECUTIVE_TOOL_FAILURES,
    MAX_FREE_ARGUMENT_REJECTIONS,
    MAX_TOOL_FAILURES_BEFORE_UNAVAILABLE,
    TOOL_UNAVAILABLE_EVENT_TYPE,
    PHASE_TIMEOUT_EVENT_TYPE,
    STUCK_EVENT_TYPE,
    PREMATURE_COMPLETION_EVENT_TYPE,
    MAX_PREMATURE_COMPLETIONS,
    MAX_INVALID_JSON_TURNS,
    INVALID_JSON_EVENT_TYPE,
    INVALID_JSON_CORRECTION,
    RUN_EVIDENCE_MAX_OBSERVATIONS,
    STATUS_COMPLETED,
    STATUS_MAX_ITERATIONS,
    STATUS_CLARIFICATION,
    STATUS_FAILED,
    STATUS_PREMATURE_COMPLETION,
    STATUS_CANCELLED,
    STATUS_SCOPE_VIOLATION,
    STATUS_BLOCKED,
    STATUS_BUDGET_EXCEEDED,
    STATUS_SUBAGENT_BUDGET,
    SUBAGENT_EVENT_TYPE,
    BUDGET_EVENT_TYPE,
    BUDGET_SUBJECT_ID,
    SKILL_NUDGE_EVENT_TYPE,
    SKILL_NUDGE_TURNS,
    BARREN_REPEAT_MIN_SECONDS,
    FAST_REPEAT_MIN_NO_PROGRESS,
    FAST_REPEAT_WINDOW,
    SMART_BUDGET_EVENT_TYPE,
    WEBSHELL_STALL_EVENT_TYPE,
    COVERAGE_PIVOT_EVENT_TYPE,
    ROBOTS_HINT_EVENT_TYPE,
    LOOP_BARRIER_EVENT_TYPE,
    STALL_BARRIER_MULTIPLIER,
    STALLED_BRANCH_WINDOW,
    TARGET_REACHED_EVENT_TYPE,
    TARGET_REACHED_FORCED_EVENT_TYPE,
    TARGET_REACHED_GRACE_TURNS,
    ReActConfig,
    ReActResult,
)
from .turn_telemetry import FrictionFlag, TurnTelemetryRecorder
from .react_support import (
    _task_payload,
    _cancellation_requested,
    _audit_step,
    _elapsed_ms,
    _failure_kind,
    _phase_timeout_seconds,
    stuck_threshold,
    _keep_going_after_failures,
    _run_messages,
    _premature_completion_message,
    missing_evidence,
    _persisted_actions,
    _last_persisted_iteration,
    _action_entry,
    _observation_payload,
    unavailable_guidance,
    timeout_guidance,
    command_failed_guidance,
    replay_guidance,
    repeated_action_correction,
    barren_repeat_correction,
    _invocation_signature,
    MEASURED_TOKENS_PER_TURN,
    _budget_tokens,
    _budget_used,
    subagent_budget_subject,
    _complete_turn,
    _record_response_tokens,
    _estimate_request_tokens,
    _inject_observation,
    _maybe_autospawn,
)
from enum import Enum
from .planner import (
    CREDENTIAL_FOUND_REASON,
    flag_tokens,
    target_reached,
    ENUMERATION_ENDPOINT_REASON,
    ENUMERATION_EXHAUSTED_REASON,
    SESSION_ESTABLISHED_REASON,
    CredentialHandover,
    EnumerationEscalation,
    Plan,
    SessionHandover,
    apply_objective_completion,
    credential_handover,
    endpoint_ceiling,
    enumeration_budget_hint,
    enumeration_escalation,
    enumeration_still_open,
    escalate_credential,
    escalate_enumeration,
    escalate_session,
    established_msf_session,
    LOGIN_PROBE_WITHHELD_TOOLS,
    login_probe_hint,
    login_probe_pending,
    objective_completion,
    pivot_gate,
    pivot_hint,
    pivot_target_host,
    robots_paths_hint,
    session_handover,
    verified_credential,
    webshell_stall_hint,
)
from .subagents import SubAgentDefinition
from .project_context import ProjectInstruction
from .skills import Skill
from typing import TYPE_CHECKING

#: Effects that act *on the objective*. With no engagement plan, the PLAN-FIRST
#: gate refuses every one of them: recon and scanning are already an action
#: against a target, and the plan is what says which action is worth taking.
#: ``state_write`` (the plan tools themselves, the blackboard) and
#: ``read_only`` stay available so the model can write the plan it needs.
ATTACK_EFFECTS = frozenset(
    {
        "active",
        "recon",
        "network_scan",
        "target_write",
        "exploit",
        "execution",
        "post_exploitation",
        "credential_access",
        "credential_dump",
        "lateral_movement",
        "pivoting",
        "c2_implant_build",
    }
)


def _touches_target(entry: Any) -> bool:
    """Whether this catalog entry acts on the objective (needs the plan)."""
    definition = entry[0] if isinstance(entry, tuple) and entry else entry
    if definition is None:
        return False
    tool_id = str(getattr(definition, "tool_id", "") or "")
    if tool_id.startswith("nexus.orchestrator."):
        return False
    if bool(getattr(definition, "scope_required", False)):
        return True
    return str(getattr(definition, "effect", "")) in ATTACK_EFFECTS


if TYPE_CHECKING:
    from nexus_core.hooks import HookRunner
from nexus_core.kernel.control_store import ControlStore
from nexus_core.scope import EngagementScope
from nexus_core.kernel.domain_dto import (
    Action,
    RequestClarification,
    TaskComplete,
    ToolCall,
    ToolCallBatch,
    ToolCallSpec,
)
from .parallel import (
    CallExecution,
    call_timeout,
    consolidate,
    execute_calls,
    parallel_limit,
)
from .react_services import (
    ContextBuilder,
    ContextSnapshot,
    ActionDecoder,
    ApprovalCoordinator,
    ToolExecutionService,
    CompletionVerifier,
)


class Transition(str, Enum):
    READY = "ready"
    NEXT_TURN = "next_turn"
    STOP = "stop"


#: Synthetic tool id of the single observation a parallel turn leaves behind. It
#: keys compaction and the artifact store; it is never a catalog entry.
BATCH_TOOL_ID = "parallel.tools"


class _BatchObservationAction:
    """What ``_inject_observation`` needs from an action: its tool id."""

    __slots__ = ("tool_id",)

    def __init__(self, tool_id: str) -> None:
        self.tool_id = tool_id


#: A tool that names an out-of-scope target is refused as an observation, not as
#: the end of the engagement (measured in blackbox-10.67.183.218: a single
#: ``https://bit.ly/...`` lookup aborted the run with exit code 4). Only a model
#: that insists on the *same* target this many turns in a row closes the run.
MAX_CONSECUTIVE_SCOPE_DENIALS = 3
#: Sweeps refused in a row because the operator has no route to their target,
#: and replays refused in a row because their effect is unconfirmed. Each is a
#: correction; insisting on the same blocked move this many turns ends the run as
#: ``blocked`` (the operator has to open the tunnel or approve the replay), never
#: as a silent failure.
MAX_CONSECUTIVE_PIVOT_GATES = 3
MAX_REPLAY_REFUSALS = 3
#: Denials of the *gateway* (policy, an approval that does not match the call,
#: a journal state) that a run tolerates in a row before closing. One denial is
#: about one invocation, not about the engagement: measured in the Hijack V1 run
#: (2026-10-29), the loop answered the very first ``install_tool`` denial -caused
#: by an approval registered for a different action string- with
#: ``governance_denial`` and ``Transition.STOP``, ending a run that had a verified
#: credential on the board, 1 M tokens of budget left and 82 iterations unused.
MAX_CONSECUTIVE_GOVERNANCE_DENIALS = 3


class ReActCoordinator:
    """One run's state and explicit transitions; services own boundary logic."""

    store: ControlStore
    tenant_id: str
    run_id: str
    payload: dict[str, Any]
    agent_id: str
    catalog: dict[str, Any]
    subagent_override: Any
    audit: AuditWriter
    scope: EngagementScope | None
    project_instruction: ProjectInstruction | None
    active_skills: list[Skill]
    hooks: HookRunner
    budget: int
    actions: list[dict[str, Any]]
    iteration: int
    status: str
    final_summary: str
    findings: list[dict[str, Any]]
    question: str | None
    consecutive_failures: int
    #: Model answers in a row that were not the requested JSON object. Reset by
    #: every usable answer; after ``MAX_INVALID_JSON_TURNS`` the run closes as
    #: ``provider_error`` (a provider that only emits garbage is truly unhealthy).
    invalid_json_turns: int
    last_phase: str | None
    last_plan: Plan | None
    last_subagent_id: str | None
    last_selected: SubAgentDefinition | None
    previous_profile: SubAgentDefinition | None
    active_subagent_id: str | None
    subagent_iterations: int
    unavailable_tools: set[str]
    tool_failures: dict[str, int]
    phase_started: float
    phase_timeout_seconds: float
    run_evidence: list[dict[str, Any]]
    evidence_stats: dict[str, int] | None
    premature_rejections: int
    completion_objections: list[str]
    #: Target of the current run of consecutive ``ScopeViolation`` refusals and
    #: how many times in a row the model named it. Any other tool call resets it.
    scope_denial_target: str | None
    scope_denial_streak: int
    #: Turns in a row without a new verified fact (Fase 3 fixes). Drives the
    #: ``react.stuck_detected`` signal and the enumeration→exploit hand-over.
    consecutive_no_progress: int
    stuck_threshold: int
    #: WP4: turns in a row that repeated the *same* tool with no new fact. At
    #: ``SKILL_NUDGE_TURNS`` the next prompt offers the skill catalogue.
    same_tool_no_progress: int
    last_turn_tool: str | None
    #: Reason of the last deterministic phase change, copied into the
    #: ``orchestrator.plan`` event so the hand-over is auditable and never reads
    #: as a model inference.
    plan_reason: str | None
    #: The enumeration→exploit hand-over is one-way. The plan is rebuilt from the
    #: blackboard on every turn, so without this the phase would flap back to
    #: ``enumeration`` as soon as the active profile is ``exploit`` - which is
    #: exactly what the hand-over asked for (Fase 3 fixes).
    enumeration_escalated: bool
    #: The session→post-exploitation hand-over (V1-25) is one-way for the same
    #: reason: ``session`` evidence is what closes ``exploitation`` for the plan
    #: table, so a non-sticky rule would be undone by the next rebuild.
    session_handed_over: bool
    #: The credential→initial-access hand-over (V1-34) is one-way while the plan
    #: still computes ``enumeration`` (the profile that owns credential-testing
    #: cannot close its own phase); it is dropped as soon as the evidence moves
    #: the phase forward, so it never drags the plan backwards.
    credential_handed_over: bool
    #: The endpoint-ceiling hand-over (Simple CTF 2026-10-18) is one-way while
    #: the plan still computes ``enumeration``: once 5 endpoints are mapped the
    #: phase is closed by decision and must not flap back on the next rebuild.
    endpoint_ceiling_applied: bool
    #: Smart-budget correction for the prompt of this turn ("" when the rule does
    #: not apply) and whether its ``react.budget_hint`` event was already audited.
    budget_hint: str
    budget_hint_emitted: bool
    #: Surface-ledger correction for the prompt of this turn ("" when the rule
    #: does not apply) and whether its ``react.coverage_pivot`` event was already
    #: audited. It orders the next branch when the run is attacking a documented
    #: dead end or stalling while another service is unexplored.
    coverage_hint: str
    coverage_hint_emitted: bool
    #: Index-file correction for the prompt of this turn ("" when the rule does
    #: not apply) and whether its ``react.robots_paths`` event was already
    #: audited. It orders the GETs of the routes a ``robots.txt``/``sitemap.xml``
    #: listed and this run never requested.
    robots_hint: str
    robots_hint_emitted: bool
    login_hint: str
    login_hint_emitted: bool
    #: Order to open the SOCKS pivot (P8: nineteen iterations aimed at the DC
    #: from a host with no route to it).
    pivot_hint: str
    #: The exact texts already injected. The rule has two strengths ("nothing
    #: probed" and "probed with invented payloads"), and the second one must
    #: reach the model even though the first already fired -while neither may
    #: be repeated turn after turn.
    login_hints_sent: set[str]
    #: The board already proves the objective (verified top privilege + verified
    #: loot). Refreshed every turn from the facts; it adds the closure hint to the
    #: plan and exempts the active profile's token ceiling (V1-35, V1-38).
    objective_complete: bool
    #: Whether the ``orchestrator.objective_complete`` event was already emitted
    #: for this run (the signal is per run, not per turn).
    objective_complete_emitted: bool
    #: Whether the last budget check was waived because the objective is complete.
    budget_exempt: bool
    #: WP5: the objective's flags were captured (verified loot on the board or in
    #: the successful output of this run). Once true it latches for the run: the
    #: prompt orders the closure and the margin below is spent.
    target_reached: bool
    target_reached_emitted: bool
    #: flag -> source (invocation id, target, ref) of every captured flag.
    captured_flag_refs: dict[str, dict[str, Any]]
    #: Tool calls the model proposed after the warning; at
    #: ``TARGET_REACHED_GRACE_TURNS`` the next one is intercepted.
    tool_calls_since_target_reached: int
    #: The run was closed by the loop (not by the model) because the objective was
    #: reached and the margin ran out. ``completion_verified`` is then decided by
    #: the captured evidence, not by the old "no objections" derivation.
    forced_completion: bool
    completion_verified_override: bool | None
    #: Per-turn operational telemetry (tokens, reasoning duration, friction,
    #: blackboard delta). Built in ``_initialize`` and published one record per
    #: iteration; it is the only place those four signals are joined.
    telemetry: TurnTelemetryRecorder
    snapshot: ContextSnapshot
    plan: Plan
    #: The engagement's own contract (``loot/ENGAGEMENT_PLAN.md``), loaded and
    #: reconciled against the board every turn. ``None`` when the engagement has
    #: no plan yet -which is exactly what the PLAN-FIRST gate refuses to work
    #: around.
    engagement_plan: Any | None
    engagement_plan_text: str
    subagent: SubAgentDefinition
    allowed_catalog: dict[str, Any]
    messages: list[LLMMessage]
    raw_response: str
    action: Action
    entry: dict[str, Any]
    tool_payload: dict[str, Any]
    observation: dict[str, Any]

    def __init__(
        self,
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
        isolated_child: bool = False,
        phase_timeout_seconds: float | None = None,
        initial_unavailable_tools: set[str] | None = None,
        context_builder: ContextBuilder | None = None,
        action_decoder: ActionDecoder | None = None,
        approval_coordinator: ApprovalCoordinator | None = None,
        tool_execution: ToolExecutionService | None = None,
        completion_verifier: CompletionVerifier | None = None,
        model_selector: Any | None = None,
    ) -> None:
        self.context = context
        self.objective = objective
        self.engagement_id = engagement_id
        self.llm_client = llm_client
        #: ``[model_routing]`` resolved once per run. ``None`` (the default, and
        #: what an unconfigured operator gets) keeps the historical single
        #: client: every task runs on ``llm_client``.
        self.model_selector = model_selector
        self.config = config
        self.tool_catalog = tool_catalog
        self.conversation_id = conversation_id or ""
        self.budget_tokens = budget_tokens
        self.cancel_event = cancel_event
        self.isolated_child = isolated_child
        self.context_builder = context_builder or ContextBuilder()
        self.action_decoder = action_decoder or ActionDecoder()
        self.approval_coordinator = approval_coordinator or ApprovalCoordinator()
        self.tool_execution = tool_execution or ToolExecutionService()
        self.completion_verifier = completion_verifier or CompletionVerifier()
        self._phase_timeout_override = phase_timeout_seconds
        self._initial_unavailable_tools = initial_unavailable_tools

    async def _initialize(self) -> None:
        from nexus_core.kernel import runtime as runtime_module
        from nexus_core.kernel.scope_loader import load_engagement_scope
        from nexus_core.tools.registry import durable_tool_definitions

        self.store = self.context.store
        self.tenant_id = self.context.tenant_id
        self.run_id = self.context.run_id
        self.payload = _task_payload(self.context)
        self.agent_id = str(self.payload.get("agent_id") or DEFAULT_AGENT_ID)
        self.catalog = (
            self.tool_catalog
            if self.tool_catalog is not None
            else durable_tool_definitions(self.tenant_id)
        )
        self.subagent_override = self.payload.get("subagent") or None
        self.audit = AuditWriter(self.store)
        from nexus_core.kernel.sandbox_modes import SandboxPolicy

        SandboxPolicy.resolve()
        self.scope = load_engagement_scope(self.store, self.tenant_id, self.engagement_id)
        project_root = self.payload.get("project_root") or None
        self.project_instruction = (
            None if self.isolated_child else load_project_instruction(project_root)
        )
        self.engagement_plan = None
        self.engagement_plan_text = ""
        from nexus_core.kernel.scope_loader import scope_signing_secret

        #: R2: skills whose body this run already delivered to the prompt. From
        #: the next successful turn the block carries the index line only.
        self.skill_bodies_sent: set[str] = set()
        self.active_skills, refused_skills = activate_skills(
            [] if self.isolated_child else self.payload.get("active_skills") or [],
            project_root,
            secret=scope_signing_secret(),
        )
        if self.project_instruction is not None or self.active_skills or refused_skills:
            self.audit.append(
                tenant_id=self.tenant_id,
                trace_id=self.run_id,
                actor_id=self.agent_id,
                action="project.context_loaded",
                resource_type="run",
                resource_id=self.run_id,
                payload={
                    "project": self.project_instruction.to_dict()
                    if self.project_instruction
                    else None,
                    "skills": [skill.to_dict() for skill in self.active_skills],
                    "refused_skills": list(refused_skills),
                },
                decision="allow",
            )
        self.conversation_id = self.conversation_id or memory.ensure_conversation(
            self.store, self.tenant_id, self.run_id, self.agent_id
        )
        from nexus_core.hooks import HookRunner

        hook_context = runtime_module._build_run_context(
            {
                **self.payload,
                "engagement_id": self.engagement_id,
                "session_id": self.conversation_id,
            },
            self.context,
        )
        self.hooks = HookRunner(
            hook_context,
            project_root=project_root,
            engagement_id=self.engagement_id,
            workspace=project_root or os.getenv("NEXUS_WORKSPACE_ROOT") or os.getcwd(),
        )
        await self.hooks.emit(
            "session_start", objective=self.objective, engagement_id=self.engagement_id
        )
        if self.cancel_event is None:
            self.cancel_event = getattr(self.context, "cancel_event", None)
        # R1: the token ceiling follows the iteration ceiling. A run asked for 50
        # turns with a fixed 250k dies at ~21 of them (HackPark V12); the
        # operator's ``--max-iterations`` is a promise the budget has to keep.
        self.budget = _budget_tokens(
            self.payload, self.budget_tokens, max_iterations=self.config.max_iterations
        )
        self.store.append_run_event(
            self.tenant_id,
            self.run_id,
            "react.budget_plan",
            {
                "budget_tokens": self.budget,
                "max_iterations": self.config.max_iterations,
                "tokens_per_turn_estimate": MEASURED_TOKENS_PER_TURN,
                "budget_turns": (
                    self.budget // MEASURED_TOKENS_PER_TURN if self.budget else 0
                ),
                "source": (
                    "explicit"
                    if self.budget_tokens is not None
                    or self.payload.get("budget_tokens") not in (None, "")
                    else "derived"
                ),
            },
        )
        history = memory.load_history(self.store, self.tenant_id, self.conversation_id, limit=500)
        if not any(
            (
                memory.message_kind(message) == memory.SYSTEM_MESSAGE_KIND
                and str(message.get("run_id") or "") == str(self.run_id)
                for message in history
            )
        ):
            memory.append_step(
                self.store,
                self.tenant_id,
                self.conversation_id,
                "system",
                self.objective,
                {
                    "kind": memory.SYSTEM_MESSAGE_KIND,
                    "objective": self.objective,
                    "run_id": self.run_id,
                },
            )
            history = memory.load_history(
                self.store, self.tenant_id, self.conversation_id, limit=500
            )
        run_history = _run_messages(history, self.run_id)
        self.actions = _persisted_actions(run_history)
        self.iteration = _last_persisted_iteration(self.actions)
        self.status = STATUS_MAX_ITERATIONS
        self.final_summary = ""
        self.findings = []
        self.question = None
        self.consecutive_failures = 0
        self.scope_denial_target = None
        self.scope_denial_streak = 0
        self.governance_denial_streak = 0
        self.invalid_json_turns = 0
        self.last_phase = None
        self.last_plan = None
        self.last_subagent_id = None
        self.last_selected = None
        self.previous_profile = None
        self.active_subagent_id = None
        self.subagent_iterations = 0
        self.unavailable_tools = set(
            unavailable_tools_from_env()
            if self._initial_unavailable_tools is None
            else self._initial_unavailable_tools
        )
        self.tool_failures = {}
        self.phase_started = time.monotonic()
        self.phase_timeout_seconds = (
            self._phase_timeout_override
            if self._phase_timeout_override is not None
            else _phase_timeout_seconds()
        )
        self.run_evidence = []
        #: Completed turns spent with each phase as ``current`` (V1-46). The plan
        #: for a turn is built with this history, so a phase that declares
        #: ``min_turns`` cannot be closed by its evidence before it has had its
        #: turn. Empty means "no turn spent yet in any phase", which is exactly the
        #: state the loop starts in -and why ``post_exploitation`` can never close
        #: instantly. A run resumed from history starts untracked for the phases it
        #: already ran, which at worst costs one extra turn.
        self.phase_turns: dict[str, int] = {}
        #: WP2: the only hard ceiling of a run (``NEXUS_RUN_BUDGET_TOKENS``) and
        #: the 5-turn grace the board grants once the objective is complete.
        self.iteration_limit = self.config.max_iterations
        self.grace_turns_remaining: int | None = None
        self.grace_granted = False
        self.soft_limits_reported: set[str] = set()
        self.evidence_stats = None
        self.premature_rejections = 0
        self.completion_objections = []
        self.consecutive_no_progress = 0
        #: R7: consecutive turns rejected for their *arguments* (schema, flag,
        #: placeholder, ``invalid_*`` verdict). They are friction, not a target
        #: verdict, so they do not move the pivot until the free budget is spent.
        self.argument_rejections = 0
        self.stuck_threshold = stuck_threshold()
        self.same_tool_no_progress = 0
        self.last_turn_tool = None
        #: Wall time of the previous *executed* tool call, used to tell a slow,
        #: fact-free repeat from a fast idempotent one (see
        #: ``_repeated_barren_action``).
        self.last_tool_elapsed_ms = 0
        self.plan_reason = None
        self.enumeration_escalated = False
        self.session_handed_over = False
        self.credential_handed_over = False
        self.endpoint_ceiling_applied = False
        self.budget_hint = ""
        self.budget_hint_emitted = False
        self.webshell_hint = ""
        self.webshell_hint_emitted = False
        self.coverage_hint = ""
        self.coverage_hint_emitted = False
        self.robots_hint = ""
        self.robots_hint_emitted = False
        self.login_hint = ""
        self.login_hint_emitted = False
        self.login_hints_sent = set()
        # B3: what the board proved and no action has spent yet. Text-keyed so a
        # stalled run is not re-told the same list on every turn.
        self.reflection_hint = ""
        self.reflection_hints_sent: set[str] = set()
        #: Tools withheld while the login form has no canonical probe (P9: the
        #: order arrived and the run still went to gobuster).
        self.login_withheld: set[str] = set()
        self.login_withheld_announced = False
        self.pivot_hint = ""
        self.pivot_hint_emitted = False
        #: Sweeps refused *before* running because the operator has no route to
        #: their target (P10: the order arrived after 600 s of nmap). Refusals in
        #: a row close the run; a single one is a correction.
        self.pivot_gate_streak = 0
        #: Replays of an invocation whose effect is unconfirmed (P10 iteration 47:
        #: the fence was right, ending the run was not). Same counting.
        self.replay_refusals = 0
        #: ``host:port`` refs the *loop* closed with a barrier fact this run (see
        #: ``_close_stalled_branch``). Two reasons to keep them: never write the
        #: same barrier twice, and never let the loop's own reflex read as
        #: progress -it would reset the streak that made it act.
        self.closed_branches: set[str] = set()
        #: Iteration each of those branches was closed on. The name survives in
        #: ``closed_branches`` for the code that only asks "was it closed?", but
        #: the gate needs *when*, because a branch the loop closed stays refused
        #: for :data:`branch_discipline.CLOSED_BRANCH_BLOCK_TURNS` turns instead
        #: of being refused forever (measured in DeadDrop P12: the loop closed
        #: ``192.168.11.200:80`` at iteration 44 and the model kept calling
        #: ``web.*`` on it for fifteen more turns).
        self.closed_branch_at: dict[str, int] = {}
        self.objective_complete = False
        self.objective_complete_emitted = False
        self.budget_exempt = False
        self.target_reached = False
        self.target_reached_emitted = False
        self.captured_flag_refs = {}
        self.tool_calls_since_target_reached = 0
        self.forced_completion = False
        self.completion_verified_override = None
        self.telemetry = TurnTelemetryRecorder(
            store=self.store, tenant_id=self.tenant_id, run_id=self.run_id
        )
        for tool_id in sorted(self.unavailable_tools):
            self.store.append_run_event(
                self.tenant_id,
                self.run_id,
                TOOL_UNAVAILABLE_EVENT_TYPE,
                {"tool_id": tool_id, "reason": "binary_missing", "iteration": 0},
            )

    def audit_step(self, *, iteration: int, action: str, decision: str, **extra: Any) -> None:
        "Audit one step, always tagged with the active subagent (3C)."
        _audit_step(
            self.audit,
            tenant_id=self.tenant_id,
            run_id=self.run_id,
            agent_id=self.agent_id,
            subagent_id=self.active_subagent_id,
            iteration=iteration,
            action=action,
            decision=decision,
            **extra,
        )

    def _grant_objective_grace(self, completion: Any = None) -> None:
        """Extend the run by ``OBJECTIVE_GRACE_TURNS`` once the board is complete.

        WP2: a run with root + loot verified does not die of bookkeeping. The
        grace is granted once, extends the iteration ceiling the model can use to
        emit ``task_complete``, and is measured separately from the legacy
        per-profile waiver so telemetry can tell them apart.
        """
        if getattr(self, "grace_granted", False) or legacy_profiles():
            return
        self.grace_granted = True
        self.grace_turns_remaining = OBJECTIVE_GRACE_TURNS
        limit = getattr(self, "iteration_limit", None)
        if limit is None:
            limit = getattr(getattr(self, "config", None), "max_iterations", 0)
        self.iteration_limit = max(int(limit or 0), self.iteration + OBJECTIVE_GRACE_TURNS)
        payload: dict[str, Any] = {
            "grace_turns": OBJECTIVE_GRACE_TURNS,
            "iteration_limit": self.iteration_limit,
            "iteration": self.iteration,
            "phase": str(getattr(self.plan, "current", "") or ""),
        }
        if completion is not None and hasattr(completion, "to_payload"):
            payload.update(completion.to_payload())
        self.store.append_run_event(
            self.tenant_id,
            self.run_id,
            OBJECTIVE_GRACE_EVENT_TYPE,
            payload,
        )

    def _guard(self) -> Transition:
        used = _budget_used(self.store, self.tenant_id, self.run_id) if self.budget else 0
        if self.budget and used >= self.budget:
            grace = False
            if not legacy_profiles():
                # The board is re-read here on purpose: the fact that completes
                # the objective may have landed in the turn that just spent the
                # last token, and the next guard used to kill the run before the
                # context turn could even see it (the rerun-13 shape).
                if not self.objective_complete:
                    completion = objective_completion(
                        self._blackboard_facts(), subagent_id=self.last_subagent_id
                    )
                    if completion.complete:
                        self.objective_complete = True
                        self._grant_objective_grace(completion)
                if self.objective_complete:
                    if not self.grace_granted:
                        self._grant_objective_grace()
                    remaining = int(self.grace_turns_remaining or 0)
                    if remaining > 0:
                        self.grace_turns_remaining = remaining - 1
                        grace = True
                        self.store.append_run_event(
                            self.tenant_id,
                            self.run_id,
                            BUDGET_GRACE_EVENT_TYPE,
                            {
                                "used": used,
                                "budget": self.budget,
                                "grace_turns_remaining": self.grace_turns_remaining,
                                "iteration": self.iteration,
                            },
                        )
                        self.telemetry.flag(FrictionFlag.BUDGET_EXEMPT)
            if not grace:
                self.status = STATUS_BUDGET_EXCEEDED
                self.final_summary = (
                    f"token budget exhausted: {used} >= {self.budget} without task_complete"
                )
                self.store.append_run_event(
                    self.tenant_id,
                    self.run_id,
                    BUDGET_EVENT_TYPE,
                    {"used": used, "budget": self.budget, "iteration": self.iteration},
                )
                return Transition.STOP
        if self.cancel_event is not None and self.cancel_event.is_set():
            self.status = STATUS_CANCELLED
            self.store.append_run_event(
                self.tenant_id,
                self.run_id,
                "react.cancelled",
                {"iteration": self.iteration, "phase": "between_iterations"},
            )
            return Transition.STOP
        if _cancellation_requested(self.store, self.tenant_id, self.run_id):
            self.status = STATUS_CANCELLED
            self.store.append_run_event(
                self.tenant_id, self.run_id, "react.cancelled", {"iteration": self.iteration}
            )
            return Transition.STOP
        return Transition.READY

    def _model_client(self, task: str, *, journal: bool = False) -> Any:
        """The client for one kind of turn, and the reason it was chosen.

        ``[model_routing]`` may pin a different provider/model per task. This is
        the only place the loop asks for one, so every turn (and the context
        summariser that runs before it) goes through the same policy. A selector
        that cannot answer never ends a run: ``llm_client`` -the client the run
        was started with- is the floor.

        With ``journal`` the decision is written as ``model.route`` *before* the
        call, so a provider failure later in the turn still leaves the operator
        the model that failed and the policy that picked it.
        """
        selector = self.model_selector
        if selector is None:
            return self.llm_client
        try:
            routed = selector.routed(task, event_sink=self._model_event)
        except Exception:  # noqa: BLE001 - routing never aborts a run
            return self.llm_client
        if journal:
            from nexus_core.llm.dynamic_selector import ROUTE_EVENT_TYPE

            decision = getattr(routed, "decision", None)
            if decision is not None:
                self._model_event(
                    ROUTE_EVENT_TYPE,
                    {**decision.as_payload(), "iteration": self.iteration},
                )
        return routed

    def _model_event(self, event_type: str, payload: dict[str, Any]) -> None:
        """Route model telemetry to the run journal; never break the turn."""
        try:
            self.store.append_run_event(self.tenant_id, self.run_id, event_type, payload)
        except Exception:  # noqa: BLE001 - telemetry is best-effort
            return

    async def _build_context(self) -> Transition:
        self.iteration += 1
        self.snapshot = await self.context_builder.gather(
            store=self.store,
            tenant_id=self.tenant_id,
            run_id=self.run_id,
            conversation_id=self.conversation_id,
            # Context compaction is a *reflection* turn: it can run on a cheaper
            # model than the executor without affecting the action quality.
            llm_client=self._model_client("reflection"),
            config=self.config,
            hooks=self.hooks,
            engagement_id=self.engagement_id,
            phase_turns=self.phase_turns,
        )
        self.plan = self.snapshot.plan
        # The reason of a deterministic hand-over is *per iteration*: the plan is
        # rebuilt from the blackboard on every turn, so a reason from an earlier
        # turn must never ride along on a later, organic phase change.
        self.plan_reason = None
        # WP2: the hand-overs existed because a phase locked the tool subset. The
        # default loop has one profile with every tool, so they are dead code
        # there; they stay exactly as measured behind the legacy flag.
        if legacy_profiles():
            self._apply_enumeration_exhaustion()
            self._apply_credential_handover()
            self._apply_session_handover()
        # The endpoint ceiling is a property of the board, not of the legacy
        # profile gate: it applies to the default loop too.
        self._apply_endpoint_ceiling()
        self._refresh_objective_complete()
        # WP5: the same board (plus the flags this run already saw in a tool
        # output) decides whether the objective's flags are in hand. It is read
        # every turn, so a flag captured after the previous turn is announced on
        # the very next prompt instead of when the budget runs out.
        self._refresh_target_reached()
        # PLAN MODE's contract: the TODOs of ``ENGAGEMENT_PLAN.md`` are ticked from
        # the verified facts before the prompt is built, so the model reads the
        # real state of the plan (never its own memory of it).
        self._refresh_engagement_plan()
        # WP6: a wide surface after ten turns without access gets one explicit
        # order to stop enumerating (see ``enumeration_budget_hint``).
        self._refresh_budget_hint()
        # The Vulnversity stall: build/pack work pushed through a webshell for
        # ten turns without a new fact gets one explicit order to stabilize.
        self._refresh_webshell_hint()
        # The surface ledger: a service already documented as a dead end, or a
        # branch held while another port is unexplored, gets one order to move.
        self._refresh_coverage_hint()
        # The index files: reading ``robots.txt``/``sitemap.xml`` is not
        # following them; the routes it lists get one explicit order.
        self._refresh_robots_hint()
        # A login form read but never probed gets the three deterministic
        # probes, before any wordlist (DeadDrop P1/P3).
        self._refresh_login_hint()
        self._refresh_reflection_hint()
        # A host in another network reached from a proven access needs the SOCKS
        # tunnel, not a local tool that has no route (DeadDrop P8).
        self._refresh_pivot_hint()
        self.last_plan = self.plan
        return Transition.READY

    def _apply_enumeration_exhaustion(self) -> None:
        """Hand an exhausted enumeration over to initial access (Fase 3 fixes).

        The rule lives in the planner (deterministic, unit-tested); here it is
        only *applied* to the plan of this iteration. The new phase makes the
        profile selector pick ``exploit`` on its own, and ``_advance_phase``
        audits the change with its reason. Nothing is authorized by this: the
        gateway keeps governing every tool of the new profile.
        """
        if self.enumeration_escalated:
            # Already handed over: keep it handed over *while the evidence still
            # describes an enumeration phase*, instead of falling back to the
            # profile that just failed. Evidence that closes the phase (a
            # credential, an access) moves ``current`` forward on its own, and
            # from that turn on the latch lets go (V1-36): an unconditional
            # re-apply monopolised the phase forever, so a run that once escaped
            # an exhausted enumeration could never reach
            # ``privilege_escalation``/``post_exploitation`` again.
            if enumeration_still_open(self.plan):
                self.plan = escalate_enumeration(
                    self.plan,
                    EnumerationEscalation(
                        phase="exploitation",
                        subagent="exploit",
                        reason=ENUMERATION_EXHAUSTED_REASON,
                    ),
                )
                self.plan_reason = ENUMERATION_EXHAUSTED_REASON
            return
        escalation = enumeration_escalation(
            self.plan,
            subagent_id=self.last_subagent_id,
            no_progress=self.consecutive_no_progress,
            services=self._blackboard_services(),
        )
        if escalation is None:
            return
        self.plan = escalate_enumeration(self.plan, escalation)
        self.plan_reason = escalation.reason
        self.enumeration_escalated = True

    def _apply_credential_handover(self) -> None:
        """Hand a validated credential over to initial access (V1-34).

        The rule lives in the planner (deterministic, unit-tested); here it is
        only *applied* to the plan of this iteration, exactly like the enumeration
        and session hand-overs. Measured in rerun 9: ``cred`` held the validated
        credential but carries no access tool, so without this it re-enumerated FTP
        and re-ran hydra until its 6-iteration budget killed the run.
        """
        if self.credential_handed_over:
            # Already handed over: keep it handed over only while the plan still
            # computes ``enumeration``. Evidence that closes the phase (a session,
            # an access) moves ``current`` forward and the rule stops applying,
            # so it can never drag a later phase backwards.
            if str(getattr(self.plan, "current", "")) == "enumeration":
                self.plan = escalate_credential(
                    self.plan,
                    CredentialHandover(
                        phase="exploitation",
                        subagent="exploit",
                        reason=CREDENTIAL_FOUND_REASON,
                    ),
                )
                self.plan_reason = CREDENTIAL_FOUND_REASON
            return
        handover = credential_handover(
            self.plan,
            subagent_id=self.last_subagent_id,
            credential_found=self._verified_credential(),
        )
        if handover is None:
            return
        self.plan = escalate_credential(self.plan, handover)
        self.plan_reason = handover.reason
        self.credential_handed_over = True

    def _apply_endpoint_ceiling(self) -> None:
        """Force ``enumeration`` → ``exploitation`` once the surface is mapped.

        The rule lives in the planner (deterministic, unit-tested); here it is
        only *applied*. Measured in Simple CTF (2026-10-18 02:35 UTC): gobuster
        put 17 endpoints on the board and the model kept enumerating routes, so
        the run spent >150k tokens before reaching ``/simple/``. The ceiling
        closes the phase by decision, keeping the statuses coherent, and the
        change is audited with :data:`ENUMERATION_ENDPOINT_REASON`.

        It is latched for the same reason as the other hand-overs: the plan is
        rebuilt from the blackboard every turn, so a non-sticky rule would be
        undone by the next rebuild while the same endpoints remain on the board.
        """
        if self.endpoint_ceiling_applied:
            if str(getattr(self.plan, "current", "")) == "enumeration":
                self.plan = endpoint_ceiling(self.plan) or self.plan
                self.plan_reason = ENUMERATION_ENDPOINT_REASON
            return
        closed = endpoint_ceiling(self.plan)
        if closed is None:
            return
        self.plan = closed
        self.plan_reason = ENUMERATION_ENDPOINT_REASON
        self.endpoint_ceiling_applied = True

    def _refresh_budget_hint(self) -> None:
        """Tell a run that keeps mapping routes to pick one and exploit it.

        The rule lives in the planner (deterministic, unit-tested); the loop only
        injects its text into this turn's prompt and audits it once. It never
        stops the run, never changes the plan and never authorizes a tool: it is
        the cheapest correction before the token budget does the deciding.
        """
        self.budget_hint = enumeration_budget_hint(self.plan, iteration=self.iteration)
        if not self.budget_hint or self.budget_hint_emitted:
            return
        self.store.append_run_event(
            self.tenant_id,
            self.run_id,
            SMART_BUDGET_EVENT_TYPE,
            {
                "iteration": self.iteration,
                "phase": str(getattr(self.plan, "current", "") or ""),
                "services": int(self.plan.counts.get("service", 0)),
                "endpoints": int(self.plan.counts.get("endpoint", 0)),
                "endpoint_leads": int((getattr(self.plan, "leads", {}) or {}).get("endpoint", 0)),
                "budget": self.budget,
                "used": _budget_used(self.store, self.tenant_id, self.run_id) if self.budget else 0,
                "hint": self.budget_hint,
            },
        )
        self.budget_hint_emitted = True

    def _refresh_webshell_hint(self) -> None:
        """Order a real interactive shell out of a webshell build loop.

        The rule lives in the planner (deterministic, unit-tested); the loop only
        injects its text into this turn's prompt and audits it once per run. It
        never stops the run, never changes the plan and never authorizes a tool:
        the model still has to open the session (``nexus.session.pty``) or the
        listener (``nexus.post.listener``).
        """
        self.webshell_hint = webshell_stall_hint(
            self.actions, no_progress=self.consecutive_no_progress
        )
        if not self.webshell_hint or self.webshell_hint_emitted:
            return
        # ``_build_context`` runs before ``_select_profile``: on the first turn
        # the profile of *this* turn is not chosen yet, so fall back to the last.
        subagent = getattr(self, "subagent", None)
        self.store.append_run_event(
            self.tenant_id,
            self.run_id,
            WEBSHELL_STALL_EVENT_TYPE,
            {
                "iteration": self.iteration,
                "phase": str(getattr(self.plan, "current", "") or ""),
                "subagent_id": str(
                    getattr(subagent, "id", "") or self.last_subagent_id or ""
                ),
                "no_progress": self.consecutive_no_progress,
                "last_tools": self._last_tools(),
                "hint": self.webshell_hint,
            },
        )
        self.webshell_hint_emitted = True

    def _refresh_coverage_hint(self) -> None:
        """Stop a run from insisting on a branch the ledger already closed.

        The rule lives in :mod:`nexus_core.agent.coverage` (deterministic and
        unit-tested); the loop only injects its text and audits it once. It has
        two triggers, both measured as real stalls: the turn's action aims at a
        service a ``barrier`` fact already closed (the Blackbox run kept probing
        the patched service instead of documenting it and moving on), or the
        run reached the stuck threshold while the ledger still has open work.

        It never changes the plan, never stops the run and never authorizes a
        tool: the model still chooses the branch and the gateway still governs
        it.
        """
        from nexus_core.agent.coverage import (
            STATUS_CLOSED,
            focus_entry,
            parse_directive,
            pivot_hint,
        )

        coverage = getattr(self.snapshot, "coverage", None)
        arguments = getattr(getattr(self, "action", None), "arguments", None)
        focus = focus_entry(coverage, arguments if isinstance(arguments, dict) else None)
        # The human's objective is the highest-order instruction the run has; the
        # ledger is a heuristic map. Parsed here (not stored) so a resumed run
        # reads the objective it was given, not a cached copy.
        directive = parse_directive(getattr(self, "objective", ""))
        # A branch the ledger reports as closed is one the loop has already
        # declared dead -and the pivot below is about to order the model off it-,
        # so this is the moment to start the refusal window. The window needs a
        # *when*, and ``closed_branch_at`` only knew the closures
        # ``_close_stalled_branch`` wrote itself: the measured DeadDrop P12 v2 run
        # resumed with a persisted ``barrier`` on ``192.168.11.200:80``, the pivot
        # fired on iteration 4 and the model kept calling ``web.*`` on that host
        # for 43 turns because nothing stamped it. An active directive is the
        # exception: an objective that names the branch outranks the ledger.
        #   It is stamped **once**: the window is five turns from the moment the
        #   loop acknowledged the closure, not five turns from the last attempt -
        #   re-stamping on every attempt would never expire while the model
        #   insists, and ``branch_discipline`` already measured that the window
        #   has to end so a real retry is still possible-.
        if (
            focus is not None
            and focus.status == STATUS_CLOSED
            and not directive.active
            and focus.ref not in (getattr(self, "closed_branch_at", None) or {})
        ):
            self._mark_branch_closed(focus.ref)
        self.coverage_hint = pivot_hint(
            coverage,
            no_progress=self.consecutive_no_progress,
            threshold=self.stuck_threshold,
            focus=focus,
            directive=directive,
        )
        if not self.coverage_hint or self.coverage_hint_emitted:
            return
        self.store.append_run_event(
            self.tenant_id,
            self.run_id,
            COVERAGE_PIVOT_EVENT_TYPE,
            {
                "iteration": self.iteration,
                "phase": str(getattr(self.plan, "current", "") or ""),
                "no_progress": self.consecutive_no_progress,
                "focus": focus.ref if focus is not None else None,
                "focus_status": focus.status if focus is not None else None,
                "counts": dict(getattr(coverage, "counts", {}) or {}),
                "open_work": [item.ref for item in getattr(coverage, "open_work", ())][:12],
                "directive": directive.to_dict(),
                "hint": self.coverage_hint,
            },
        )
        self.audit_step(
            iteration=self.iteration,
            action="coverage_pivot",
            decision="degrade",
            focus=focus.ref if focus is not None else None,
        )
        self.coverage_hint_emitted = True

    def _refresh_robots_hint(self) -> None:
        """Order the GETs of an index file the run read but never followed.

        The rule lives in the planner (``robots_paths_hint``, deterministic and
        unit-tested over the persisted action history); the loop only injects
        its text and audits it once. It never stops the run, never changes the
        plan and never authorizes a tool.
        """
        self.robots_hint = robots_paths_hint(self.actions)
        if not self.robots_hint or self.robots_hint_emitted:
            return
        self.store.append_run_event(
            self.tenant_id,
            self.run_id,
            ROBOTS_HINT_EVENT_TYPE,
            {
                "iteration": self.iteration,
                "phase": str(getattr(self.plan, "current", "") or ""),
                "last_tools": self._last_tools(),
                "hint": self.robots_hint,
            },
        )
        self.audit_step(
            iteration=self.iteration,
            action="robots_paths",
            decision="degrade",
        )
        self.robots_hint_emitted = True

    def _refresh_login_hint(self) -> None:
        """Order the three login probes on a form the run read but never tested.

        The rule lives in the planner (``login_probe_hint``, deterministic and
        unit-tested over the persisted action history); the loop only injects
        its text and audits it once.
        """
        # A read form with no canonical probe also withholds the directory
        # sweeps: asking twice was not enough (P9, 2026-10-22).
        pending = login_probe_pending(self.actions)
        self.login_withheld = set(LOGIN_PROBE_WITHHELD_TOOLS) if pending else set()
        if pending and not self.login_withheld_announced:
            self.store.append_run_event(
                self.tenant_id,
                self.run_id,
                "react.login_probe_withheld",
                {
                    "iteration": self.iteration,
                    "withheld": sorted(self.login_withheld),
                    "reason": "login_form_not_probed",
                },
            )
            self.login_withheld_announced = True
        self.login_hint = login_probe_hint(self.actions)
        if not self.login_hint or self.login_hint in self.login_hints_sent:
            return
        self.login_hints_sent.add(self.login_hint)
        self.store.append_run_event(
            self.tenant_id,
            self.run_id,
            "react.login_probe",
            {
                "iteration": self.iteration,
                "phase": str(getattr(self.plan, "current", "") or ""),
                "last_tools": self._last_tools(),
                "hint": self.login_hint,
            },
        )
        self.audit_step(
            iteration=self.iteration,
            action="login_probe",
            decision="degrade",
        )
        self.login_hint_emitted = True

    def _refresh_reflection_hint(self) -> None:
        """Name the verified facts this run has not spent yet, once per list.

        The rule lives in ``agent/reflection.py`` (deterministic: substring over
        the action history, no model). The loop injects the text and audits it;
        it never changes the plan, stops the run or authorizes a tool.
        """
        from nexus_core.agent.reflection import render_reflection

        hint = render_reflection(
            self._blackboard_facts(),
            self.actions,
            no_progress=self.consecutive_no_progress,
        )
        self.reflection_hint = hint
        if not hint or hint in self.reflection_hints_sent:
            return
        self.reflection_hints_sent.add(hint)
        self.store.append_run_event(
            self.tenant_id,
            self.run_id,
            "react.reflection",
            {
                "iteration": self.iteration,
                "phase": str(getattr(self.plan, "current", "") or ""),
                "no_progress": self.consecutive_no_progress,
                "hint": hint,
            },
        )
        self.audit_step(
            iteration=self.iteration,
            action="reflection",
            decision="degrade",
        )

    def _refresh_pivot_hint(self) -> None:
        """Order the SOCKS pivot when the run aims at a host it cannot route to.

        The rule lives in the planner (``pivot_hint``, deterministic over the
        persisted action history); the loop injects its text once.
        """
        self.pivot_hint = pivot_hint(self.actions, facts=self._blackboard_facts())
        if not self.pivot_hint or self.pivot_hint_emitted:
            return
        self.store.append_run_event(
            self.tenant_id,
            self.run_id,
            "react.pivot",
            {
                "iteration": self.iteration,
                "phase": str(getattr(self.plan, "current", "") or ""),
                "last_tools": self._last_tools(),
                "hint": self.pivot_hint,
            },
        )
        self.audit_step(iteration=self.iteration, action="pivot", decision="degrade")
        self.pivot_hint_emitted = True

    def _stalled_branch(self, coverage: Any) -> Any | None:
        """The one service the recent actions were aimed at (``None`` if unclear).

        Attribution reads the *arguments* of the last :data:`STALLED_BRANCH_WINDOW`
        actions through the ledger's own resolver, so it inherits its rules (an
        explicit port, or a bare ``http(s)://host`` for the scheme default).
        Unanimity is required: a window that touches two services is breadth, not
        a stall on one, and closing either of them would be a guess -the loop
        only acts where the evidence names a single target.
        """
        from nexus_core.agent.coverage import focus_entry

        if coverage is None or not getattr(coverage, "entries", None):
            return None
        refs: list[str] = []
        for record in self.actions[-STALLED_BRANCH_WINDOW:]:
            arguments = record.get("arguments")
            focus = focus_entry(
                coverage, arguments if isinstance(arguments, dict) else None
            )
            if focus is not None:
                refs.append(focus.ref)
        # One attributable call is a sample, not a stall: the loop waits until the
        # window itself is evidence of insistence.
        if len(refs) < 2 or len(set(refs)) != 1:
            return None
        return coverage.find(refs[0])

    def _close_stalled_branch(self) -> str | None:
        """Write the ``barrier`` the pivot ordered and the model never wrote.

        The advisory line tells the model to close a dead branch with
        ``nexus.knowledge.record_fact``; measured in
        ``run_c71035d9818047eaa80dfd859e887b7c`` (Joomla, 2026-10-20) that text
        was ignored for 43 turns while the ledger kept the two services as open
        work, so nothing in the planner or the prompt could move to the next
        branch. From :data:`STALL_BARRIER_MULTIPLIER` stuck thresholds the loop
        takes the decision: one ``barrier`` fact on the branch the recent actions
        unanimously targeted, unverified and attributed to ``react.loop``.

        Three refusals keep it honest:

        * it acts only when the recent window names a single service (see
          ``_stalled_branch``): closing one of two hammered branches is a guess;
        * a branch with a registered ``vulnerability`` is not closed -hiding a
          proven vector behind a dead branch is worse than stalling, and the
          ledger would then send the run to a port the vector does not live on;
        * a branch the ledger already marks ``descartado`` (or one this loop
          already closed) is left alone: the correction is idempotent.

        ``build_coverage`` reopens a closed branch when a *newer* vulnerability
        appears on it, so a later finding still wins over this verdict.
        """
        from nexus_core.agent.coverage import STATUS_CLOSED

        snapshot = getattr(self, "snapshot", None)
        entry = self._stalled_branch(getattr(snapshot, "coverage", None))
        if entry is None or entry.status == STATUS_CLOSED:
            return None
        if entry.ref in self.closed_branches or entry.vector_count:
            return None
        if not self.engagement_id or not getattr(self, "store", None):
            return None
        reason = (
            "el bucle cerró la rama: "
            f"{self.consecutive_no_progress} turnos consecutivos sin hechos nuevos "
            f"sobre {entry.label}"
        )
        try:
            from nexus_core.kernel.blackboard import Blackboard

            Blackboard(self.store).record(
                tenant_id=self.tenant_id,
                engagement_id=self.engagement_id,
                fact_type="barrier",
                key=entry.ref,
                value={
                    "reason": reason,
                    "source": "loop",
                    "barren_turns": int(self.consecutive_no_progress),
                    "last_tools": self._last_tools(),
                    # R6: this barrier carries its provenance. The vector *was*
                    # attempted (the measured stall is the attempt), so it may
                    # close the branch; a model-written barrier without a tested
                    # attempt may not (see ``coverage.barrier_is_conclusive``).
                    "sweep_attempted": True,
                    "outcome": "stalled",
                },
                source="react.loop",
                created_by="react.loop",
                verified=False,
            )
        except Exception:  # noqa: BLE001 - memory must never abort a run
            return None
        self.closed_branches.add(entry.ref)
        self._mark_branch_closed(entry.ref)
        self.store.append_run_event(
            self.tenant_id,
            self.run_id,
            LOOP_BARRIER_EVENT_TYPE,
            {
                "iteration": self.iteration,
                "phase": str(getattr(self.plan, "current", "") or ""),
                "branch": entry.ref,
                "label": entry.label,
                "barren_turns": int(self.consecutive_no_progress),
                "last_tools": self._last_tools(),
            },
        )
        self.audit_step(
            iteration=self.iteration,
            action="branch_closed",
            decision="degrade",
            branch=entry.ref,
            barren_turns=int(self.consecutive_no_progress),
        )
        return entry.ref

    def _mark_branch_closed(self, ref: str) -> None:
        """Start the refusal window of ``ref`` on this iteration.

        Two callers, one rule: the loop's own stall barrier
        (:meth:`_close_stalled_branch`) and the pivot's acknowledgement that the
        ledger already marks the branch ``descartado``
        (:meth:`_refresh_coverage_hint`). ``__init__`` owns the dict in a real run;
        a coordinator rebuilt by a test (or resumed from an older object) must not
        lose the closure, so the dict is created on demand.
        """
        name = str(ref or "").strip()
        if not name:
            return
        closed_at = getattr(self, "closed_branch_at", None)
        if closed_at is None:
            closed_at = self.closed_branch_at = {}
        closed_at[name] = int(self.iteration)

    def _note_completed_turn(self) -> None:
        """Record that the phase of this turn has been *current* once more (V1-46).

        The plan of a turn is built with this history, so ``min_turns`` holds a
        phase open until it has really had its turn. Called only after the turn
        finished: a turn that raised never counts as spent.
        """
        phase = str(getattr(self.plan, "current", "") or "")
        if not phase:
            return
        self.phase_turns[phase] = self.phase_turns.get(phase, 0) + 1

    def _refresh_objective_complete(self) -> None:
        """Detect that the engagement's objective is already met (V1-35).

        The rule lives in the planner (deterministic, unit-tested); here it is
        only *applied*: the plan carries a hint that says the objective is met,
        and the run audits the verdict once with the refs that prove it. Nothing
        is authorized and nothing is closed by this - the phases were closed by
        their own evidence, and ``task_complete`` stays the model's decision.
        """
        # WP2: board only. The profile that happens to hold the turn is not an
        # input of the verdict anymore (rerun 13 died with root+loot verified and
        # the reporter profile active).
        completion = objective_completion(
            self._blackboard_facts(), subagent_id=self.last_subagent_id
        )
        self.objective_complete = completion.complete
        if not completion.complete:
            return
        self.plan = apply_objective_completion(self.plan, completion)
        self._grant_objective_grace(completion)
        if self.objective_complete_emitted:
            return
        self.store.append_run_event(
            self.tenant_id,
            self.run_id,
            OBJECTIVE_COMPLETE_EVENT_TYPE,
            {
                **completion.to_payload(),
                "hint": completion.hint,
                "iteration": self.iteration,
                "phase": self.plan.current,
                "subagent_id": self.last_subagent_id,
            },
        )
        self.objective_complete_emitted = True

    def _refresh_target_reached(self) -> None:
        """Detect that the flags the objective asked for were captured (WP5).

        The rule lives in the planner (deterministic, unit-tested); here it is
        only *applied*. Once reached the state latches for the run -captured
        evidence never disappears- so the margin counter cannot be reset by a
        later turn that writes no new fact.
        """
        if self.target_reached:
            return
        verdict = target_reached(
            self._blackboard_facts(),
            objective=self.objective,
            observed_flags=self.captured_flag_refs,
        )
        for source in verdict.sources:
            flag = str(source.get("flag") or "")
            if flag and flag not in self.captured_flag_refs:
                self.captured_flag_refs[flag] = dict(source)
        if not verdict.reached:
            return
        self.target_reached = True
        self.store.append_run_event(
            self.tenant_id,
            self.run_id,
            TARGET_REACHED_EVENT_TYPE,
            {
                **verdict.to_payload(),
                "iteration": self.iteration,
                "phase": str(getattr(self.plan, "current", "") or ""),
                "subagent_id": self.last_subagent_id,
            },
        )
        self.target_reached_emitted = True

    def _refresh_engagement_plan(self) -> None:
        """Load ``ENGAGEMENT_PLAN.md`` and tick what the board already proves.

        The file is the source of truth (shared with the human and with any
        isolated child of the run); this only refreshes it with the facts that
        landed since the last turn. A TODO ticked here is a verifier assertion,
        never a model claim.

        Never raises: a plan that cannot be read degrades to "no plan" and the
        gate below decides what that means for this run.
        """
        from nexus_core.agent.engagement_plan import (
            load_plan_for,
            prompt_block,
            reconcile,
            save_plan,
        )

        # The same directory the CLI wrote the plan into: the payload's
        # ``project_root`` (the operator's workspace), never an implicit cwd. A
        # bound local workspace lives in ``scope.notes``, so the two can differ.
        root = str(self.payload.get("project_root") or "") or None
        plan = None
        try:
            plan = load_plan_for(self.engagement_id, root)
            if plan is not None:
                facts = [
                    fact
                    for fact in self._blackboard_facts()
                    if fact.get("verified") is True
                ]
                # Flags this run read out of a tool output are evidence too, and
                # the verifier does not always derive a loot fact for them.
                facts.extend(
                    {
                        "fact_type": "loot",
                        "key": str(source.get("ref") or "flag"),
                        "value": {"flag": flag},
                        "verified": True,
                    }
                    for flag, source in self.captured_flag_refs.items()
                )
                updated, ticks = reconcile(
                    plan, facts, engagement_id=self.engagement_id
                )
                if ticks and updated is not None:
                    save_plan(updated, root)
                    plan = updated
                    self.store.append_run_event(
                        self.tenant_id,
                        self.run_id,
                        "orchestrator.plan_todos",
                        {
                            "iteration": self.iteration,
                            "done": list(ticks),
                            "pending": [todo.id for todo in plan.pending],
                        },
                    )
        except Exception:  # noqa: BLE001 - the plan must never abort a turn
            plan = None
        self.engagement_plan = plan
        self.engagement_plan_text = prompt_block(plan)

    def _plan_required_missing(self) -> bool:
        """Whether this turn must refuse an attack tool until there is a plan."""
        return bool(
            self.config.require_plan_first
            and self.engagement_id
            and self.engagement_plan is None
        )

    def _flag_todos_pending(self) -> bool:
        """Whether the plan still promises a flag that was not captured."""
        plan = self.engagement_plan
        return bool(plan is not None and plan.flags_pending)

    def _note_observed_flags(self, spec: Any | None = None) -> None:
        """Keep every flag seen in the successful output of this run (WP5).

        The verifier only derives ``loot`` for the tools it parses; a webshell
        command (``nexus.shell.exec``) reports a flag in its stdout with no
        assertion at all. The literal token in a *successful* tool output is the
        same evidence the bench scores, so it is recorded here and fed to
        :func:`target_reached` as an observation source.
        """
        observation = self.observation or {}
        if not observation.get("success"):
            return
        tokens = flag_tokens(observation.get("output"))
        if not tokens:
            return
        # ``spec`` is the call that produced the observation. A parallel batch
        # passes it explicitly: ``self.action`` names several tools and only the
        # one that ran may be credited with the flag.
        action = spec if spec is not None else self.action
        arguments = getattr(action, "arguments", None) or {}
        target = str(
            arguments.get("target") or arguments.get("url") or arguments.get("host") or ""
        )
        for token in tokens:
            if token in self.captured_flag_refs:
                continue
            self.captured_flag_refs[token] = {
                "flag": token,
                "ref": str(getattr(action, "tool_id", "") or ""),
                "fact_type": "loot",
                "invocation_id": str(observation.get("invocation_id") or ""),
                "verification_method": str(
                    observation.get("verification_method") or ""
                ),
                "target": target,
                "source": "observation",
                "verified": True,
            }
        self._refresh_target_reached()

    def _blackboard_facts(self) -> list[dict[str, Any]]:
        """Every fact of the engagement, up to the board's key ceiling.

        The ceiling is passed explicitly: with the default page (100 keys) a
        large board silently dropped facts from coverage, reflection and the
        planner (V0-2). Most recent keys win when the ceiling is reached.
        """
        if not self.engagement_id or not getattr(self, "store", None):
            return []
        try:
            from nexus_core.kernel.blackboard import FACT_KEYS_CEILING, Blackboard

            return list(
                Blackboard(self.store).list_facts(
                    self.tenant_id, self.engagement_id, limit=FACT_KEYS_CEILING
                )
            )
        except Exception:  # noqa: BLE001 - a missing board must not abort a run
            return []

    def _verified_credential(self) -> bool:
        """Whether the board holds a verified credential fact (never raises)."""
        if not self.engagement_id or not getattr(self, "store", None):
            return False
        try:
            from nexus_core.kernel.blackboard import Blackboard

            facts = Blackboard(self.store).list_facts(
                self.tenant_id, self.engagement_id, fact_type="credential"
            )
            return verified_credential(facts)
        except Exception:  # noqa: BLE001 - a missing board must not abort a run
            return False

    def _apply_session_handover(self) -> None:
        """Hand an established session over to post-exploitation (V1-25).

        The rule lives in the planner (deterministic, unit-tested); here it is
        only *applied* to the plan of this iteration, exactly like the
        enumeration hand-over above. Measured in rerun 6: the MSF session was
        verified and registered but the plan stayed on ``exploitation`` until the
        ``exploit`` profile exhausted its token budget, because nothing connected
        the session to the profile that owns ``session.*`` / ``post.*`` tools.
        """
        if self.session_handed_over:
            # Already handed over: keep it handed over while the session evidence
            # is on the board, instead of falling back, every turn, to the phase
            # the blackboard's own counts compute (``privilege_escalation``).
            self.plan = escalate_session(
                self.plan,
                SessionHandover(
                    phase="post_exploitation",
                    subagent="postexploit",
                    reason=SESSION_ESTABLISHED_REASON,
                ),
            )
            self.plan_reason = SESSION_ESTABLISHED_REASON
            return
        handover = session_handover(
            self.plan,
            subagent_id=self.last_subagent_id,
            session_established=self._msf_session_established(),
        )
        if handover is None:
            return
        self.plan = escalate_session(self.plan, handover)
        self.plan_reason = handover.reason
        self.session_handed_over = True

    def _msf_session_established(self) -> bool:
        """Whether the board holds a verified MSF session fact (never raises).

        Read from the facts, not from counts: the flag must be able to tell a
        session this engine proved from the lead the model records by hand.
        """
        if not self.engagement_id or not getattr(self, "store", None):
            return False
        try:
            from nexus_core.kernel.blackboard import Blackboard

            facts = Blackboard(self.store).list_facts(
                self.tenant_id, self.engagement_id, fact_type="session"
            )
            return established_msf_session(facts)
        except Exception:  # noqa: BLE001 - a missing board must not abort a run
            return False

    def _note_soft_limit(self, kind: str, detail: dict[str, Any]) -> None:
        """Record a per-profile limit once; it never stops the run (WP2).

        The per-subagent numbers survived as *telemetry*: they tell the operator
        when a phase spent its calibrated allowance, but only the global run
        budget (and the model's own completion) can end the engagement.
        """
        key = f"{self.subagent.id}:{kind}"
        if key in self.soft_limits_reported:
            return
        self.soft_limits_reported.add(key)
        self.store.append_run_event(
            self.tenant_id,
            self.run_id,
            SUBAGENT_SOFT_LIMIT_EVENT_TYPE,
            {
                "subagent_id": self.subagent.id,
                "limit": kind,
                "soft": True,
                "iteration": self.iteration,
                **detail,
            },
        )
        self.audit_step(
            iteration=self.iteration,
            action="subagent_soft_limit",
            decision="allow",
            limit=kind,
            **detail,
        )

    async def _select_profile(self) -> Transition:
        selected = select_run_profile(self.plan, override=self.subagent_override)
        if self.plan.current != self.last_phase:
            self.phase_started = time.monotonic()
        changed = selected.id != self.last_subagent_id
        if changed:
            self.subagent_iterations = 0
            self.previous_profile = self.last_selected
        self.subagent_iterations += 1
        self.subagent = with_phase_grace(
            selected, self.previous_profile, iterations=self.subagent_iterations
        )
        self.last_selected = selected
        self.active_subagent_id = self.subagent.id
        if changed:
            self.store.append_run_event(
                self.tenant_id,
                self.run_id,
                SUBAGENT_EVENT_TYPE,
                {
                    "subagent_id": self.subagent.id,
                    "previous": self.last_subagent_id,
                    "phase": self.plan.current,
                    "read_only": self.subagent.read_only,
                    "token_budget": self.subagent.token_budget,
                    "tools": (
                        sorted(self.catalog)
                        if self.subagent.unrestricted
                        else sorted(self.subagent.tools)
                    ),
                    "tools_count": (
                        len(self.catalog)
                        if self.subagent.unrestricted
                        else len(self.subagent.tools)
                    ),
                    "unrestricted": self.subagent.unrestricted,
                    "iteration": self.iteration,
                },
            )
            await _maybe_autospawn(
                store=self.store,
                tenant_id=self.tenant_id,
                run_id=self.run_id,
                context=self.context,
                llm_client=self.llm_client,
                config=self.config,
                engagement_id=self.engagement_id,
                objective=self.objective,
                previous_subagent_id=self.last_subagent_id,
                subagent_id=selected.id,
                payload=self.payload,
                conversation_id=self.conversation_id,
                iteration=self.iteration,
                audit_step=self.audit_step,
            )
            self.last_subagent_id = selected.id
        legacy = legacy_profiles()
        if self.subagent_iterations > self.subagent.max_iterations:
            if legacy:
                self.status = STATUS_SUBAGENT_BUDGET
                self.final_summary = f"subagent '{self.subagent.id}' exceeded its iteration budget ({self.subagent.max_iterations})"
                return Transition.STOP
            self._note_soft_limit(
                "iterations",
                {"iterations": self.subagent_iterations,
                 "max_iterations": self.subagent.max_iterations},
            )
        if self.subagent.token_budget:
            spent = _budget_used(
                self.store, self.tenant_id, self.run_id, subagent_budget_subject(self.subagent.id)
            )
            if spent >= self.subagent.token_budget:
                # V1-38: an engagement whose objective is already met does not die
                # of bookkeeping. Spending a few more turns closing (with
                # ``task_complete``) is worth more than stopping with the work done
                # and the run reported as failed (measured in rerun 10: 63 224 of
                # 60 000 tokens spent by ``privesc`` *after* root.txt was on the
                # board, and the run ended without ``task_complete``). The ceiling
                # is waived, audited and counted as friction - never silently.
                if not legacy:
                    self._note_soft_limit(
                        "tokens",
                        {"spent": spent, "token_budget": self.subagent.token_budget},
                    )
                elif self.objective_complete:
                    self.budget_exempt = True
                    self.store.append_run_event(
                        self.tenant_id,
                        self.run_id,
                        BUDGET_EXEMPT_EVENT_TYPE,
                        {
                            "subagent_id": self.subagent.id,
                            "spent": spent,
                            "token_budget": self.subagent.token_budget,
                            "budget_exempt_if_objective_complete": True,
                            "iteration": self.iteration,
                        },
                    )
                    self.telemetry.flag(FrictionFlag.BUDGET_EXEMPT)
                else:
                    self.status = STATUS_SUBAGENT_BUDGET
                    self.final_summary = f"subagent '{self.subagent.id}' exhausted its token budget: {spent} >= {self.subagent.token_budget}"
                    return Transition.STOP
        return Transition.READY

    def _advance_phase(self) -> Transition:
        if (
            self.phase_timeout_seconds
            and time.monotonic() - self.phase_started > self.phase_timeout_seconds
        ):
            stalled = sorted(
                (
                    tool_id
                    for tool_id in self.tool_failures
                    if tool_id in self.subagent.tools and tool_id not in self.unavailable_tools
                )
            )
            if stalled:
                self.unavailable_tools.update(stalled)
            self.store.append_run_event(
                self.tenant_id,
                self.run_id,
                PHASE_TIMEOUT_EVENT_TYPE,
                {
                    "phase": self.plan.current,
                    "subagent_id": self.subagent.id,
                    "elapsed_seconds": round(time.monotonic() - self.phase_started, 3),
                    "iteration": self.iteration,
                    "retired_tools": stalled,
                },
            )
            self.audit_step(
                iteration=self.iteration,
                action="phase_timeout",
                decision="degrade",
                phase=self.plan.current,
                retired_tools=stalled,
            )
            self.phase_started = time.monotonic()
        self.allowed_catalog = {
            tool_id: entry
            for tool_id, entry in filter_catalog(self.subagent, self.catalog).items()
            if tool_id not in self.unavailable_tools
            and tool_id not in getattr(self, "login_withheld", set())
        }
        if self.plan.current != self.last_phase:
            self.store.append_run_event(
                self.tenant_id,
                self.run_id,
                "orchestrator.plan",
                {
                    "phase": self.plan.current,
                    "previous": self.last_phase,
                    "progress": list(self.plan.progress),
                    "facts_total": self.plan.facts_total,
                    "subagent_id": self.subagent.id,
                    "iteration": self.iteration,
                    # Present only when the change came from a deterministic
                    # rule (never from the model); absent on organic progress.
                    **({"reason": self.plan_reason} if self.plan_reason else {}),
                },
            )
            self.last_phase = self.plan.current
        return Transition.READY

    async def _request_action(self) -> Transition:
        self.messages = self.context_builder.render(
            self.snapshot,
            allowed_catalog=self.allowed_catalog,
            objective=self.objective,
            engagement_id=self.engagement_id,
            scope=self.scope,
            subagent=self.subagent,
            project_instruction=self.project_instruction,
            active_skills=self.active_skills,
            # R2: the body travels once. Marked in ``_decode_action`` (after a
            # successful decode) so a JSON retry still sees the recipe.
            skill_bodies=frozenset(
                skill.name
                for skill in self.active_skills
                if skill.name not in self.skill_bodies_sent
            ),
            store=self.store,
            tenant_id=self.tenant_id,
            no_progress=self.consecutive_no_progress,
            stuck_threshold=self.stuck_threshold,
            same_tool_no_progress=self.same_tool_no_progress,
            target_reached=self.target_reached,
            iteration=self.iteration,
            budget_hint=self.budget_hint,
            webshell_hint=self.webshell_hint,
            coverage_hint=self.coverage_hint,
            robots_hint=self.robots_hint,
            login_hint=self.login_hint,
            reflection_hint=self.reflection_hint,
            pivot_hint=self.pivot_hint,
            engagement_plan_summary=self.engagement_plan_text,
        )
        reservation = None
        estimated = _estimate_request_tokens(self.messages)
        if self.config.before_provider_call is not None:
            from nexus_core.kernel.errors import BudgetExceeded

            try:
                reservation = self.config.before_provider_call(estimated)
            except BudgetExceeded as exc:
                self.status = STATUS_BUDGET_EXCEEDED
                self.final_summary = f"budget reservation refused: {exc}"
                self.telemetry.flag(FrictionFlag.BUDGET_REFUSED)
                self.audit_step(
                    iteration=self.iteration,
                    action="budget_exceeded",
                    decision="deny",
                    reason="reservation_refused",
                )
                return Transition.STOP
        reasoning_started = time.perf_counter()
        try:
            response = await _complete_turn(
                self._model_client("executor", journal=True), self.messages, self.config
            )
        except ProviderFailure as exc:
            # A provider failure raised directly by the client ends the run with
            # a typed terminal status instead of escaping ``run()`` (B8.2).
            return self._provider_error_stop(
                exc, estimated=estimated, started=reasoning_started, reservation=reservation
            )
        except Exception as exc:
            # A malformed answer is not a dead provider: retry the turn with a
            # correction before giving up (Run 3, Simple CTF 2026-10-17).
            if (
                is_invalid_json_error(exc)
                and self.invalid_json_turns < MAX_INVALID_JSON_TURNS
            ):
                return self._invalid_json_retry(
                    exc,
                    estimated=estimated,
                    started=reasoning_started,
                    reservation=reservation,
                )
            if is_invalid_json_error(exc):
                # The retry budget is spent: a provider that only emits garbage
                # is unhealthy, and the operator needs that reason in the
                # terminal summary (Run 3, Simple CTF 2026-10-17).
                return self._provider_error_stop(
                    ProviderFailure(
                        "model answered invalid JSON "
                        f"{self.invalid_json_turns} times in a row"
                    ),
                    estimated=estimated,
                    started=reasoning_started,
                    reservation=reservation,
                )
            # The failed turn still carries what it cost (the estimate) and how
            # long the provider took before it died; the run closes with the
            # terminal status instead of propagating ``ProviderFailure`` (B8.2).
            return self._provider_error_stop(
                ProviderFailure(type(exc).__name__),
                estimated=estimated,
                started=reasoning_started,
                reservation=reservation,
            )
        # A usable answer clears the malformed-answer streak: the budget is for
        # consecutive garbage, never for the whole run.
        self.invalid_json_turns = 0
        self.telemetry.note_reasoning(
            response, estimated=estimated, duration_ms=_elapsed_ms(reasoning_started)
        )
        if reservation is not None and self.config.after_provider_call is not None:
            actual = int(getattr(response, "tokens_input", 0) or 0) + int(
                getattr(response, "tokens_output", 0) or 0
            )
            self.config.after_provider_call(reservation, actual)
        _record_response_tokens(
            self.store,
            self.tenant_id,
            self.run_id,
            response,
            subject_ids=(BUDGET_SUBJECT_ID, subagent_budget_subject(self.subagent.id)),
        )
        self.raw_response = str(getattr(response, "content", "") or "")
        return Transition.READY

    def _invalid_json_retry(
        self,
        exc: Exception,
        *,
        estimated: int,
        started: float,
        reservation: Any,
    ) -> Transition:
        """Ask the model again after a non-JSON answer (Simple CTF Run 3).

        ``DeepSeekClient._check_content`` raises before the loop can see the
        text, so this path has no raw answer to decode: the only way to keep the
        mission alive is to re-issue the turn with a correction in the history.
        The failed attempt still books its estimate with zero actual tokens and
        releases its reservation, exactly like ``_provider_error_stop``, so no
        hold is left open. The streak is capped by
        :data:`MAX_INVALID_JSON_TURNS`; a provider that only emits garbage ends
        the run as ``provider_error`` instead of looping forever.
        """
        self.invalid_json_turns += 1
        self.telemetry.note_reasoning(
            None, estimated=estimated, duration_ms=_elapsed_ms(started)
        )
        if reservation is not None and self.config.after_provider_call is not None:
            self.config.after_provider_call(reservation, 0)
        memory.append_step(
            self.store,
            self.tenant_id,
            self.conversation_id,
            "user",
            INVALID_JSON_CORRECTION,
            {
                "kind": "react.correction",
                "iteration": self.iteration,
                "run_id": self.run_id,
                "reason": "invalid_json",
                "attempt": self.invalid_json_turns,
            },
        )
        self.telemetry.flag(FrictionFlag.PARSE_ERROR)
        self.context.event(
            INVALID_JSON_EVENT_TYPE,
            iteration=self.iteration,
            attempt=self.invalid_json_turns,
            limit=MAX_INVALID_JSON_TURNS,
            error=str(exc)[:300],
        )
        self.audit_step(
            iteration=self.iteration,
            action="parse_error",
            decision="deny",
            reason="invalid_json",
            attempt=self.invalid_json_turns,
            limit=MAX_INVALID_JSON_TURNS,
            error=str(exc)[:300],
        )
        return Transition.NEXT_TURN

    def _provider_error_stop(
        self,
        exc: ProviderFailure,
        *,
        estimated: int,
        started: float,
        reservation: Any,
    ) -> Transition:
        """Close the run with ``provider_error`` when the model call fails (B8.2).

        A failed provider call must not escape :meth:`run` as ``ProviderFailure``:
        the process used to die without a terminal result or ``run.complete``
        (the Bounty Hacker RUN #6 abort). It becomes the same terminal status
        ``_execute_tool`` already assigns to a provider failure during a tool
        call. The failed turn still books its estimated cost and releases the
        durable reservation, so no hold is ever left open.
        """
        self.telemetry.note_reasoning(
            None, estimated=estimated, duration_ms=_elapsed_ms(started)
        )
        if reservation is not None and self.config.after_provider_call is not None:
            self.config.after_provider_call(reservation, 0)
        self.status = "provider_error"
        self.final_summary = f"provider failure during a model turn: {exc}"
        return Transition.STOP

    def _decode_action(self) -> Transition:
        try:
            self.action = self.action_decoder.decode(self.raw_response)
        except ReActParseError as exc:
            self.actions.append(_action_entry(self.iteration, "parse_error", error=str(exc)[:500]))
            memory.append_step(
                self.store,
                self.tenant_id,
                self.conversation_id,
                "assistant",
                self.raw_response,
                {
                    "kind": "react.action",
                    "iteration": self.iteration,
                    "action": "parse_error",
                    "warnings": [],
                    "run_id": self.run_id,
                },
            )
            memory.append_step(
                self.store,
                self.tenant_id,
                self.conversation_id,
                "user",
                f"Tu respuesta anterior no era JSON válido y no se ejecutó nada. Error del parser: {str(exc)[:300]}. Responde de nuevo con UN solo objeto JSON que cumpla el contrato (tool_call, tool_calls, task_complete o request_clarification).",
                {"kind": "react.correction", "iteration": self.iteration, "run_id": self.run_id},
            )
            self.telemetry.note_action(action="parse_error")
            self.telemetry.flag(FrictionFlag.PARSE_ERROR)
            self.context.event("react.parse_error", iteration=self.iteration, error=str(exc)[:300])
            self.audit_step(
                iteration=self.iteration,
                action="parse_error",
                decision="deny",
                error=str(exc)[:300],
                raw_response=self.raw_response[:2000],
            )
            return Transition.NEXT_TURN
        memory.append_step(
            self.store,
            self.tenant_id,
            self.conversation_id,
            "assistant",
            self.action.raw_response or self.raw_response,
            {
                "kind": "react.action",
                "iteration": self.iteration,
                "action": self.action.action,
                "thought": self.action.thought,
                "tool_id": self.action.tool_id,
                "arguments": memory._redact_arguments(self.action.arguments),
                "warnings": list(self.action.warnings),
                "run_id": self.run_id,
                # A batch names every call: the transcript keeps what the model
                # actually asked for, not only the first one.
                **(
                    {
                        "calls": [
                            {
                                "tool_id": call.tool_id,
                                "arguments": memory._redact_arguments(call.arguments),
                            }
                            for call in self.action.calls
                        ]
                    }
                    if isinstance(self.action, ToolCallBatch)
                    else {}
                ),
            },
        )
        self.telemetry.note_action(
            action=self.action.action,
            tool_id=getattr(self.action, "tool_id", None),
            arguments=getattr(self.action, "arguments", None),
        )
        # R2: the bodies that travelled in this turn's prompt were delivered.
        # Marking here (not at render time) keeps them available to a retry after
        # an invalid JSON answer.
        self.skill_bodies_sent.update(skill.name for skill in self.active_skills)
        self.context.event(
            "react.action",
            iteration=self.iteration,
            action=self.action.action,
            tool_id=self.action.tool_id,
        )
        return Transition.READY

    async def _complete(self) -> Transition:
        assessment = await self.completion_verifier.verify(
            findings=self.action.findings,
            observations=self.run_evidence,
            run_id=self.run_id,
            plan=self.plan,
            config=self.config,
            engagement_id=self.engagement_id,
            store=self.store,
            tenant_id=self.tenant_id,
            hooks=self.hooks,
            objective=self.objective,
            # WP2: in the default loop the phase is a hint; only the legacy path
            # keeps refusing a task_complete because the plan is not on reporting.
            require_plan_phase=legacy_profiles(),
            # The engagement's own TODOs close the run (PLAN-FIRST): a plan the
            # model committed to outranks the phase hint.
            engagement_plan=self.engagement_plan,
            require_plan_first=self.config.require_plan_first,
        )
        annotated, self.evidence_stats = (assessment.findings, assessment.evidence_stats)
        self.completion_objections = assessment.objections
        if self.completion_objections:
            self.telemetry.flag(FrictionFlag.PREMATURE_COMPLETION)
        if self.completion_objections and self.premature_rejections < MAX_PREMATURE_COMPLETIONS:
            self.premature_rejections += 1
            self.actions.append(
                _action_entry(
                    self.iteration,
                    self.action.action,
                    thought=self.action.thought,
                    warnings=self.action.warnings,
                    summary=self.action.summary or "",
                    findings=annotated,
                    rejected=True,
                    objections=list(self.completion_objections),
                )
            )
            self.store.append_run_event(
                self.tenant_id,
                self.run_id,
                PREMATURE_COMPLETION_EVENT_TYPE,
                {
                    "iteration": self.iteration,
                    "phase": self.plan.current,
                    "attempt": self.premature_rejections,
                    "objections": list(self.completion_objections),
                    "evidence": self.evidence_stats,
                    # WP2 (Fix 3): the exact finding and the reference that would
                    # satisfy it, not just a count of stale citations.
                    "missing_evidence": missing_evidence(self.evidence_stats),
                    "subagent_id": self.active_subagent_id,
                },
            )
            memory.append_step(
                self.store,
                self.tenant_id,
                self.conversation_id,
                "user",
                _premature_completion_message(self.completion_objections, self.plan),
                {
                    "kind": "react.correction",
                    "iteration": self.iteration,
                    "rejected_action": ACTION_TASK_COMPLETE,
                    "run_id": self.run_id,
                },
            )
            self.audit_step(
                iteration=self.iteration,
                action=self.action.action,
                decision="deny",
                reason="premature_task_complete",
                attempt=self.premature_rejections,
                objections=list(self.completion_objections),
                evidence=self.evidence_stats,
            )
            return Transition.NEXT_TURN
        if self.completion_objections:
            self.status = STATUS_PREMATURE_COMPLETION
            self.final_summary = (
                f"task_complete rechazado {self.premature_rejections} veces sin evidencia suficiente: "
                + "; ".join(self.completion_objections)
            )
            self.findings = annotated
            self.actions.append(
                _action_entry(
                    self.iteration,
                    self.action.action,
                    thought=self.action.thought,
                    warnings=self.action.warnings,
                    summary=self.action.summary or "",
                    findings=annotated,
                    rejected=True,
                    objections=list(self.completion_objections),
                )
            )
            self.audit_step(
                iteration=self.iteration,
                action=self.action.action,
                decision="deny",
                reason="premature_completion_exhausted",
                objections=list(self.completion_objections),
                evidence=self.evidence_stats,
            )
            return Transition.STOP
        self.status = STATUS_COMPLETED
        self.final_summary = self.action.summary or ""
        self.findings = annotated
        self.actions.append(
            _action_entry(
                self.iteration,
                self.action.action,
                thought=self.action.thought,
                warnings=self.action.warnings,
                summary=self.final_summary,
                findings=self.findings,
                evidence=self.evidence_stats,
            )
        )
        memory.append_step(
            self.store,
            self.tenant_id,
            self.conversation_id,
            "assistant",
            json.dumps(
                {"summary": self.final_summary, "findings": self.findings}, ensure_ascii=False
            ),
            {
                "kind": "react.final",
                "iteration": self.iteration,
                "findings_count": len(self.findings),
                "evidence": self.evidence_stats,
                "run_id": self.run_id,
            },
        )
        self.audit_step(
            iteration=self.iteration,
            action=self.action.action,
            decision="allow",
            thought=self.action.thought,
            findings_count=len(self.findings),
            evidence=self.evidence_stats,
        )
        return Transition.STOP

    def _clarify(self) -> Transition:
        self.status = STATUS_CLARIFICATION
        self.question = self.action.question
        self.actions.append(
            _action_entry(
                self.iteration,
                self.action.action,
                thought=self.action.thought,
                warnings=self.action.warnings,
                question=self.question,
            )
        )
        memory.append_step(
            self.store,
            self.tenant_id,
            self.conversation_id,
            "assistant",
            self.question or "",
            {"kind": "react.clarification", "iteration": self.iteration, "run_id": self.run_id},
        )
        self.store.append_run_event(
            self.tenant_id,
            self.run_id,
            "react.clarification_requested",
            {"question": self.question},
        )
        self.audit_step(
            iteration=self.iteration,
            action=self.action.action,
            decision="allow",
            thought=self.action.thought,
        )
        return Transition.STOP

    def _tool_entry(self) -> Transition:
        self.entry = _action_entry(
            self.iteration,
            self.action.action,
            thought=self.action.thought,
            tool_id=self.action.tool_id,
            arguments=memory._redact_arguments(self.action.arguments),
            warnings=self.action.warnings,
            expected_outcome=self.action.expected_outcome,
            # Canonical identity of this call, computed from the raw arguments: it
            # is what lets the next turn recognise an identical repeat (V1-26)
            # without comparing redacted copies of the persisted entry.
            invocation_signature=_invocation_signature(
                self.action.tool_id, self.action.arguments
            ),
        )
        return Transition.READY

    def _call_refusal(self, spec: Any) -> tuple[str, dict[str, Any]] | None:
        """Why this call may not reach the gateway, or ``None`` when it may.

        One predicate for both shapes of a turn: a call inside a parallel batch is
        refused by exactly the same rules as a lone one -catalog membership, the
        active subagent's subset, PLAN-FIRST and a retired tool- so ``tool_calls``
        can never widen what the model is allowed to invoke. The caller owns the
        bookkeeping; this only decides and builds the observation.
        """
        tool_id = str(getattr(spec, "tool_id", "") or "")
        if tool_id not in self.catalog:
            return "unknown_tool", {
                "success": False,
                "error": f"tool '{tool_id}' does not exist in the catalog",
                "available_tools": sorted(self.catalog),
            }
        if not permits(self.subagent, tool_id, self.catalog.get(tool_id)):
            return "subagent_tool_denied", {
                "success": False,
                "error": f"tool '{tool_id}' is outside subagent '{self.subagent.id}' subset",
                "subagent_id": self.subagent.id,
                "available_tools": sorted(self.allowed_catalog),
            }
        if self._plan_required_missing() and _touches_target(self.catalog.get(tool_id)):
            # PLAN-FIRST: an engagement does not start by attacking. The engine
            # refuses the call (it is not counted as a tool failure: it is an
            # ordering rule) and tells the model exactly what unblocks it.
            from nexus_core.tools.handlers.plan_engagement import CREATE_PLAN_TOOL

            return "plan_required", {
                "success": False,
                "status": "denied_no_plan",
                "tool_id": tool_id,
                "error": (
                    "hay que fijar el PLAN DEL ENGAGEMENT antes de atacar: "
                    f"llama a {CREATE_PLAN_TOOL} con los TODOs del objetivo "
                    "(id, description, fact_types). Mientras no exista el plan, "
                    "el motor solo admite lectura de contexto (query_facts, "
                    "workspace.read) y las tools nexus.orchestrator.*."
                ),
                "next": CREATE_PLAN_TOOL,
            }
        if tool_id in self.unavailable_tools:
            return "tool_unavailable", {
                "success": False,
                "tool_id": tool_id,
                "error": f"tool '{tool_id}' is unavailable after repeated failures; use another tool from the available list",
                "subagent_id": self.subagent.id,
                "available_tools": sorted(self.allowed_catalog),
            }
        return None

    def _check_tool(self) -> Transition:
        refusal = self._call_refusal(self.action)
        if refusal is not None and refusal[0] == "unknown_tool":
            self.observation = refusal[1]
            self.consecutive_failures += 1
            self.entry["tool_result"] = self.observation
            self.actions.append(self.entry)
            _inject_observation(
                self.store,
                self.tenant_id,
                self.conversation_id,
                self.run_id,
                self.iteration,
                self.action,
                self.observation,
                subagent_id=self.active_subagent_id,
            )
            self.telemetry.note_tool(duration_ms=0, success=False, error_type="ValueError")
            self.audit_step(
                iteration=self.iteration,
                action=self.action.action,
                decision="deny",
                tool_id=self.action.tool_id,
                reason="unknown_tool",
            )
            if not _keep_going_after_failures(
                self.subagent,
                self.unavailable_tools,
                self.consecutive_failures,
                self.catalog,
            ):
                self.status = STATUS_FAILED
                self.final_summary = f"aborted after {self.consecutive_failures} consecutive tool failures (last: unknown tool '{self.action.tool_id}'; no usable tools remain for subagent '{self.subagent.id}')"
                return Transition.STOP
            self.consecutive_failures = 0
            return Transition.NEXT_TURN
        if refusal is not None and refusal[0] == "subagent_tool_denied":
            self.observation = refusal[1]
            self.consecutive_failures += 1
            self.entry["tool_result"] = self.observation
            self.actions.append(self.entry)
            _inject_observation(
                self.store,
                self.tenant_id,
                self.conversation_id,
                self.run_id,
                self.iteration,
                self.action,
                self.observation,
                subagent_id=self.active_subagent_id,
            )
            self.audit_step(
                iteration=self.iteration,
                action=self.action.action,
                decision="deny",
                tool_id=self.action.tool_id,
                reason="subagent_tool_denied",
            )
            if not _keep_going_after_failures(
                self.subagent,
                self.unavailable_tools,
                self.consecutive_failures,
                self.catalog,
            ):
                self.status = STATUS_FAILED
                self.final_summary = f"aborted after {self.consecutive_failures} consecutive tool failures (last: '{self.action.tool_id}' outside subagent '{self.subagent.id}'; no usable tools remain)"
                return Transition.STOP
            self.consecutive_failures = 0
            return Transition.NEXT_TURN
        if refusal is not None and refusal[0] == "plan_required":
            self.observation = refusal[1]
            self.entry["tool_result"] = self.observation
            self.actions.append(self.entry)
            _inject_observation(
                self.store,
                self.tenant_id,
                self.conversation_id,
                self.run_id,
                self.iteration,
                self.action,
                self.observation,
                subagent_id=self.active_subagent_id,
            )
            self.store.append_run_event(
                self.tenant_id,
                self.run_id,
                "orchestrator.plan_required",
                {
                    "iteration": self.iteration,
                    "tool_id": self.action.tool_id,
                    "subagent_id": self.active_subagent_id,
                },
            )
            self.audit_step(
                iteration=self.iteration,
                action=self.action.action,
                decision="deny",
                tool_id=self.action.tool_id,
                reason="plan_required",
            )
            return Transition.NEXT_TURN
        if refusal is not None and refusal[0] == "tool_unavailable":
            self.observation = refusal[1]
            self.entry["tool_result"] = self.observation
            self.actions.append(self.entry)
            _inject_observation(
                self.store,
                self.tenant_id,
                self.conversation_id,
                self.run_id,
                self.iteration,
                self.action,
                self.observation,
                subagent_id=self.active_subagent_id,
            )
            self.audit_step(
                iteration=self.iteration,
                action=self.action.action,
                decision="deny",
                tool_id=self.action.tool_id,
                reason="tool_unavailable",
            )
            return Transition.NEXT_TURN
        return Transition.READY

    def _call_payload(self, spec: Any) -> dict[str, Any]:
        """The engine data one gateway invocation carries (never the model's word)."""
        from nexus_core.kernel.job_authority import JobAuthority

        payload = {
            "tool_id": str(spec.tool_id),
            "arguments": dict(spec.arguments or {}),
            "identity": self.payload.get("identity") or {},
            "engagement_id": self.engagement_id,
            "permissions": tuple(self.payload.get("permissions") or ()),
            "approval_id": self.payload.get("approval_id"),
            "trace_id": self.run_id,
            "session_id": self.conversation_id,
            "phase": getattr(self.plan, "current", "") or "",
            "objective": self.objective,
            # The operator's workspace, so a handler writes/reads the same
            # directory as the engine (the plan file, the loot, the wordlists).
            "project_root": str(self.payload.get("project_root") or ""),
            # V1-54: how a retry of an ``unknown`` invocation is resolved. The
            # engine set it from ``--resume-policy`` (only under trust mode).
            "resume_policy": str(getattr(self.config, "resume_policy", "") or ""),
        }
        payload["job_authority"] = JobAuthority(
            run_id=self.run_id, engagement_id=self.engagement_id or "", profile_id=self.subagent.id,
            tools=tuple(sorted(self.subagent.tools)),
            token_budget=self.subagent.token_budget,
            run_token_budget=max(0, self.budget),
            job_limit=max(0, self.subagent.max_iterations - self.subagent_iterations),
        ).model_dump(mode="json")
        return payload

    def _review_call(self, spec: Any, payload: dict[str, Any]) -> dict[str, Any] | None:
        """Policy + operator approval for one call; a denial observation or ``None``.

        Runs the very same :class:`ApprovalCoordinator` the single-call path uses,
        once per call: a batch of three tools asks three questions, never one
        blanket approval for all of them.
        """
        if self.config.on_approval_needed is None:
            return None
        resolved = self.catalog[str(spec.tool_id)]
        definition = resolved[0] if isinstance(resolved, tuple) else resolved
        return self.approval_coordinator.review(
            config=self.config,
            context=self.context,
            definition=definition,
            tool_payload=payload,
        )

    def _approve_tool(self) -> Transition:
        assert isinstance(self.action, ToolCall)
        self.tool_payload = self._call_payload(self.action)
        if self.config.on_approval_needed is not None:
            denial = self._review_call(self.action, self.tool_payload)
            if denial is not None:
                self.entry["tool_result"] = denial
                self.actions.append(self.entry)
                _inject_observation(
                    self.store,
                    self.tenant_id,
                    self.conversation_id,
                    self.run_id,
                    self.iteration,
                    self.action,
                    denial,
                    subagent_id=self.active_subagent_id,
                )
                self.telemetry.flag(FrictionFlag.OPERATOR_DENIAL)
                self.audit_step(
                    iteration=self.iteration,
                    action=self.action.action,
                    decision="deny",
                    tool_id=self.action.tool_id,
                    reason="denied_by_operator",
                    operator_reason=denial["reason"],
                )
                return Transition.NEXT_TURN
        return Transition.READY

    def _repeated_failed_action(self) -> str | None:
        """Tool id when this turn repeats, adjacently, an action that just failed (V1-26).

        Measured in the rerun #7 (2026-10-15): iteration 9 spent ``msf_exploit``
        (``method=msf_exploit_failed``) and iteration 10 proposed the byte-identical
        invocation. The gateway keeps a failed invocation journaled as ``unknown``
        -its effect may have happened- so the repeat demanded a human approval the
        ``--trust-mode`` run does not hold: ``termination_reason="blocked"`` with the
        ``exploit`` profile 10 iterations and ~17k tokens short of its budget. In the
        rerun #6 the same failure produced a correction instead, and the model
        pivoted to ``psexec``, which opened the session.

        The trigger is the measured one, and only that: same ``tool_id``, same
        canonical arguments, and the *immediately preceding* turn. A repeat somewhere
        else in the history, or a repeat of something that worked, is a different
        case (the latter belongs to the gateway's dedup, V1-14) and keeps its own
        governance.
        """
        previous = self.actions[-1] if self.actions else None
        if not previous or not isinstance(self.action, ToolCall):
            return None
        signature = previous.get("invocation_signature")
        if not signature:
            return None
        result = previous.get("tool_result")
        if not isinstance(result, dict) or result.get("success"):
            return None
        if signature != _invocation_signature(self.action.tool_id, self.action.arguments):
            return None
        return str(self.action.tool_id)

    def _note_scope_denial(self, target: str) -> int:
        """Count one refusal of *target* and return the current insistence streak.

        A different target starts a new streak; the streak is reset by any tool
        call that is not a scope denial (``_execute_tool`` does it on the result
        path), so only *consecutive* insistence on the same target can close.
        """
        if target and target == self.scope_denial_target:
            self.scope_denial_streak += 1
        else:
            self.scope_denial_target = target or None
            self.scope_denial_streak = 1
        return self.scope_denial_streak

    def _repeat_scope_denial(self, tool_id: str, previous: dict[str, Any]) -> Transition:
        """Count a byte-identical repeat of an already-denied target (V1-26).

        The repeat never reaches the gateway -the invocation journal would ask
        for an approval a trust-mode run cannot grant- so without this branch the
        insistence would be answered as a generic ``repeated_action`` and the
        scope streak would never grow. It counts as one more refusal of the same
        target: two corrections, the third closes the run.
        """
        target = str(previous.get("target") or "").strip()
        streak = self._note_scope_denial(target)
        aborted = streak >= MAX_CONSECUTIVE_SCOPE_DENIALS
        named = target or "el objetivo solicitado"
        self.telemetry.flag(FrictionFlag.SCOPE_VIOLATION)
        self.observation = {
            "success": False,
            "outcome": "scope_denied",
            "verified": False,
            "scope_violation": True,
            "target": target,
            "scope_denial_streak": streak,
            "repeated_action": True,
            "guidance": (
                f"El objetivo {named} está fuera del alcance firmado. "
                "Ignora esa URL y busca otra ruta."
            ),
            "available_tools": sorted(self.allowed_catalog),
        }
        if aborted:
            self.status = STATUS_SCOPE_VIOLATION
            self.final_summary = (
                "scope violation aborted the loop: the model insisted "
                f"{streak} times on {named}"
            )
            self.observation["aborted"] = True
        self.entry["tool_result"] = self.observation
        self.actions.append(self.entry)
        _inject_observation(
            self.store,
            self.tenant_id,
            self.conversation_id,
            self.run_id,
            self.iteration,
            self.action,
            self.observation,
            subagent_id=self.active_subagent_id,
        )
        self.store.append_run_event(
            self.tenant_id,
            self.run_id,
            "react.scope_violation",
            {
                "iteration": self.iteration,
                "tool_id": tool_id,
                "target": target,
                "streak": streak,
                "aborted": aborted,
                "repeated": True,
            },
        )
        self.audit_step(
            iteration=self.iteration,
            action=self.action.action,
            decision="deny",
            tool_id=tool_id,
            reason="scope_violation",
            error_type="ScopeViolation",
        )
        return Transition.STOP if aborted else Transition.NEXT_TURN

    def _correct_repeated_action(self, tool_id: str, *, barren: bool = False) -> Transition:
        """Answer an identical repeat of a failed or fact-free action with a correction.

        ``barren=True`` is the slow-but-successful variant: the previous call did
        not fail, it simply returned nothing new after burning seconds of the
        run's wall clock (see ``_repeated_barren_action``).

        The turn is a normal turn of the loop -it consumes the iteration and the
        tokens of the active subagent- and it never reaches the gateway. The policy
        gate of the turn (``_approve_tool``) already ran; what is avoided here is the
        journal's ``retry:invocation:<id>`` approval for an unknown outcome, which a
        ``--trust-mode`` run cannot grant and which closed the rerun #7 as
        ``blocked``. So no approval is requested or consumed and the run continues:
        the model gets text telling it what to do next, never a silent refusal.
        """
        previous_result = self.actions[-1].get("tool_result") if self.actions else None
        if isinstance(previous_result, dict) and previous_result.get("outcome") == "scope_denied":
            return self._repeat_scope_denial(tool_id, previous_result)
        self.telemetry.flag(FrictionFlag.REPEATED_ACTION)
        correction = (
            barren_repeat_correction(tool_id, max(1, self.last_tool_elapsed_ms // 1000))
            if barren
            else repeated_action_correction(tool_id)
        )
        self.observation = {
            "success": False,
            "outcome": "repeated_action",
            "tool_id": tool_id,
            "error": correction,
            "failure_kind": "repeated_action",
            "guidance": correction,
            "available_tools": sorted(self.allowed_catalog),
        }
        # The repeat counts as a tool failure (B3): a model that keeps insisting on a
        # route that produced nothing ends up with the tool retired after repeated
        # attempts -exactly as if it had failed again- so the next prompt only offers
        # the remaining routes. Without this, insisting could burn the whole profile
        # budget one correction at a time without ever retiring anything. It is the
        # per-tool counter that moves, never the run-level ``consecutive_failures``:
        # a correction must not be able to abort an engagement.
        self._note_tool_failure(tool_id)
        self.entry["tool_result"] = self.observation
        self.actions.append(self.entry)
        _inject_observation(
            self.store,
            self.tenant_id,
            self.conversation_id,
            self.run_id,
            self.iteration,
            self.action,
            self.observation,
            subagent_id=self.active_subagent_id,
        )
        self.audit_step(
            iteration=self.iteration,
            action=self.action.action,
            decision="deny",
            tool_id=tool_id,
            reason="repeated_barren_action" if barren else "repeated_failed_action",
        )
        return Transition.NEXT_TURN

    def _repeated_barren_action(self) -> str | None:
        """Tool id when this turn repeats, adjacently, a slow call that learned nothing.

        The V1-26 guard above only intercepts a repeat of a *failed* call; the
        gateway's dedup (V1-14) lets a repeat of a successful one through. Neither
        helps the measured failure of 2026-10-19
        (``run_1052d63f9bba4838902b3aa21bd27d21``): the agent ran the same sqlmap
        probe twice, 500 s each, with ``blackboard_delta = 0`` both times, while
        the coverage ledger still had two open branches, and burned its budget
        without a finding.

        The trigger is deliberately narrow: same ``tool_id``, same canonical
        arguments, the *immediately preceding* turn, that call succeeded, the run
        has not seen a new verified fact since, and it took at least
        ``BARREN_REPEAT_MIN_SECONDS``. Fast idempotent repeats keep their existing
        governance (dedup), and a first retry after a fact-producing turn is
        untouched.
        """
        previous = self.actions[-1] if self.actions else None
        if not previous or not isinstance(self.action, ToolCall):
            return None
        if self.consecutive_no_progress <= 0:
            return None
        current = _invocation_signature(self.action.tool_id, self.action.arguments)
        result = previous.get("tool_result")
        if isinstance(result, dict) and result.get("outcome") == "scope_denied":
            # A denied target never ran, so it produced no work to repeat: that
            # case belongs to the scope-insistence streak, which only counts the
            # same target consecutively (alternating two denied hosts is a
            # first-and-first, not an insistence).
            return None
        if (
            previous.get("invocation_signature") == current
            and isinstance(result, dict)
            and result.get("success")
            and self.last_tool_elapsed_ms >= BARREN_REPEAT_MIN_SECONDS * 1000
        ):
            return str(self.action.tool_id)
        # The light path: a *fast* call is not automatically harmless. The
        # gateway dedup this docstring used to defer to is keyed on the
        # invocation id, so every turn is a fresh invocation and an identical
        # cheap probe is never deduplicated. Measured in
        # run_c71035d9818047eaa80dfd859e887b7c (Joomla, 2026-10-20): the same
        # 0.3 s SQLi URL three times and the same ``hashcat`` sweep four times,
        # across 49 barren turns and 0 findings. From
        # ``FAST_REPEAT_MIN_NO_PROGRESS`` barren turns, a signature that already
        # ran inside the recent window gets the same correction the slow one
        # gets: after three turns with nothing new, re-sending the same request
        # is the loop, not a retry. A signature that is not in the window and any
        # turn that added a verified fact are untouched.
        if (
            self.consecutive_no_progress >= FAST_REPEAT_MIN_NO_PROGRESS
            and self._signature_occurrences(current) >= 1
        ):
            return str(self.action.tool_id)
        return None

    def _signature_occurrences(self, signature: str) -> int:
        """How many of the last :data:`FAST_REPEAT_WINDOW` actions used ``signature``.

        Wider than the immediately preceding turn because the measured loop
        alternated two probes (A, B, A, B) and so never repeated adjacently.
        Entries synthesised by a correction carry no signature and are skipped.
        """
        recent = self.actions[-FAST_REPEAT_WINDOW:]
        return sum(
            1 for entry in recent if entry.get("invocation_signature") == signature
        )

    def _coverage_snapshot(self) -> Any:
        """The ledger attached to this turn's snapshot (``None`` before recon)."""
        return getattr(getattr(self, "snapshot", None), "coverage", None)

    def _refuse_before_execution(
        self, *, outcome: str, guidance: str, extra: dict[str, Any] | None = None
    ) -> Transition:
        """Answer a deterministic refusal as an observation the model can use.

        Same shape as the pivot and replay gates: the call never reaches the
        gateway, the model gets the exact next step, and the refusal is audited
        and persisted as an event. It never aborts the run by itself; what stops
        a run is insisting on a *failed* call, which is the existing governance.
        """
        tool_id = str(self.action.tool_id)
        payload = dict(extra or {})
        self.observation = {
            "success": False,
            "outcome": outcome,
            "verified": False,
            "refused_before_execution": True,
            "tool_id": tool_id,
            "guidance": guidance,
            "available_tools": sorted(self.allowed_catalog),
            **payload,
        }
        self.entry["tool_result"] = self.observation
        self.actions.append(self.entry)
        _inject_observation(
            self.store,
            self.tenant_id,
            self.conversation_id,
            self.run_id,
            self.iteration,
            self.action,
            self.observation,
            subagent_id=self.active_subagent_id,
        )
        self.store.append_run_event(
            self.tenant_id,
            self.run_id,
            "react.branch_refused",
            {
                "iteration": self.iteration,
                "tool_id": tool_id,
                "reason": outcome,
                **payload,
            },
        )
        self.audit_step(
            iteration=self.iteration,
            action=self.action.action,
            decision="deny",
            tool_id=tool_id,
            reason=outcome,
        )
        return Transition.READY

    def _refuse_closed_branch(self) -> Transition | None:
        """Refuse ``web.*``/directory sweeps against a branch the loop closed.

        ``react.branch_closed`` used to be descriptive: it wrote the barrier and
        the model kept attacking the same ``host:port`` (DeadDrop P12, iteration
        44, fifteen more turns). The window lives in
        :data:`branch_discipline.CLOSED_BRANCH_BLOCK_TURNS` and coverage still
        owns reopening through a newer ``vulnerability`` fact.
        """
        arguments = self.action.arguments if isinstance(self.action.arguments, dict) else None
        guidance = closed_branch_refusal(
            tool_id=self.action.tool_id,
            arguments=arguments,
            coverage=self._coverage_snapshot(),
            closed_at=getattr(self, "closed_branch_at", {}),
            iteration=self.iteration,
        )
        if not guidance:
            return None
        return self._refuse_before_execution(
            outcome="branch_closed_recent",
            guidance=guidance,
            extra={"branch_closed_recent": True},
        )

    def _refuse_barrier_without_attempts(self) -> Transition | None:
        """Refuse a ``barrier`` that one guess does not justify.

        Two measured false verdicts motivate it: an executed ``/preview`` module
        read as plain text (DeadDrop P12, iteration 21) and a sweep that never
        ran reported as "no session" (HackPark V12, iteration 17). The second is
        already handled by ``sweep_attempted`` in the ledger; this gate answers
        before the fact is written, so the branch is not even marked.
        """
        arguments = self.action.arguments if isinstance(self.action.arguments, dict) else None
        guidance = barrier_refusal(
            self.actions, self._coverage_snapshot(), arguments
        )
        if not guidance:
            return None
        return self._refuse_before_execution(
            outcome="barrier_refused",
            guidance=guidance,
            extra={
                "barrier_refused": True,
                "attempt_window": BARRIER_ATTEMPT_WINDOW,
            },
        )

    async def _correct_unroutable_sweep(self) -> Transition | None:
        """Refuse a sweep that has no route, instead of paying its timeout.

        Measured in DeadDrop P10 (2026-10-22): with SSH on ``192.168.11.200`` and
        no tunnel, ``nmap`` against the DC ``192.168.11.100`` ran its whole 600 s
        budget and returned nothing -the order to pivot only arrived *after* it,
        because ``pivot_hint`` reads the history-. The same rule applied to the
        pending call, plus a one-second TCP probe, answers before the budget is
        committed. The refusal is an observation (the model gets the exact tunnel
        command); only insisting ``MAX_CONSECUTIVE_PIVOT_GATES`` times closes the
        run, and then as ``blocked`` on the tunnel, not as a failure.
        """
        tool_id = str(self.action.tool_id)
        target = pivot_target_host(tool_id, self.action.arguments)
        if not target:
            return None
        # The board, not the history, is what can turn the gate off: a verified
        # ``route`` fact is proof of reachability, and an attempted ``ssh -D`` is
        # not (DeadDrop P11 stayed gated on a tunnel that had already died).
        hint = await pivot_gate(
            tool_id,
            self.action.arguments,
            self.actions,
            facts=self._blackboard_facts(),
        )
        if not hint:
            return None
        self.pivot_gate_streak += 1
        aborted = self.pivot_gate_streak >= MAX_CONSECUTIVE_PIVOT_GATES
        self.observation = {
            "success": False,
            "outcome": "unroutable_target",
            "verified": False,
            "target": target,
            "tool_id": tool_id,
            "refused_before_execution": True,
            "pivot_gate_streak": self.pivot_gate_streak,
            "guidance": hint,
            "available_tools": sorted(self.allowed_catalog),
        }
        if aborted:
            self.status = STATUS_BLOCKED
            self.final_summary = (
                f"blocked on the pivot: {self.pivot_gate_streak} sweeps aimed at "
                f"{target} with no route from the operator and no tunnel opened"
            )
            self.observation["aborted"] = True
        self.entry["tool_result"] = self.observation
        self.actions.append(self.entry)
        _inject_observation(
            self.store,
            self.tenant_id,
            self.conversation_id,
            self.run_id,
            self.iteration,
            self.action,
            self.observation,
            subagent_id=self.active_subagent_id,
        )
        self.store.append_run_event(
            self.tenant_id,
            self.run_id,
            "react.pivot_gate",
            {
                "iteration": self.iteration,
                "tool_id": tool_id,
                "target": target,
                "streak": self.pivot_gate_streak,
                "aborted": aborted,
            },
        )
        self.audit_step(
            iteration=self.iteration,
            action=self.action.action,
            decision="deny",
            tool_id=tool_id,
            reason="unroutable_target",
        )
        return Transition.STOP if aborted else Transition.READY

    def _correct_replayed_invocation(self, exc: Exception) -> Transition:
        """Answer a fenced replay with what to do instead of closing the run.

        Measured in DeadDrop P10 (2026-10-22, iteration 47): an ``ssh_exec``
        timed out, the journal kept it ``unknown`` and the model's identical
        retry met ``unknown invocation requires human approval``. The refusal is
        correct -the effect may have happened-, but it closed the run as
        ``blocked`` (exit 2) with the room still reachable: a refusal is an
        observation, exactly like a scope denial. The streak is what stops a
        model that keeps asking for the same replay.
        """
        self.replay_refusals += 1
        aborted = self.replay_refusals >= MAX_REPLAY_REFUSALS
        tool_id = str(self.action.tool_id)
        self.observation = {
            "success": False,
            "outcome": "replay_refused",
            "verified": False,
            "error_type": type(exc).__name__,
            "error": str(exc)[:500],
            "failure_kind": "replay_requires_approval",
            "replay_refusals": self.replay_refusals,
            "guidance": replay_guidance(tool_id),
            "available_tools": sorted(self.allowed_catalog),
        }
        if aborted:
            self.status = STATUS_BLOCKED
            self.final_summary = (
                f"blocked: {self.replay_refusals} replays of an invocation whose "
                f"effect is unconfirmed ({tool_id}) and no approval to replay them"
            )
            self.observation["aborted"] = True
        self.entry["tool_result"] = self.observation
        self.actions.append(self.entry)
        _inject_observation(
            self.store,
            self.tenant_id,
            self.conversation_id,
            self.run_id,
            self.iteration,
            self.action,
            self.observation,
            subagent_id=self.active_subagent_id,
        )
        self.store.append_run_event(
            self.tenant_id,
            self.run_id,
            "react.replay_refused",
            {
                "iteration": self.iteration,
                "tool_id": tool_id,
                "streak": self.replay_refusals,
                "aborted": aborted,
            },
        )
        self.audit_step(
            iteration=self.iteration,
            action=self.action.action,
            decision="deny",
            tool_id=tool_id,
            reason="replay_requires_approval",
        )
        return Transition.STOP if aborted else Transition.READY

    # ------------------------------------------------------- parallel turns
    def _batch_entry(self, index: int, spec: ToolCallSpec, size: int) -> dict[str, Any]:
        """One action log entry per call, so the run stays audit-able per tool."""
        return _action_entry(
            self.iteration,
            "tool_call",
            thought=self.action.thought,
            tool_id=spec.tool_id,
            arguments=memory._redact_arguments(spec.arguments),
            warnings=self.action.warnings,
            expected_outcome=spec.expected_outcome,
            invocation_signature=_invocation_signature(spec.tool_id, spec.arguments),
            batch_index=index,
            batch_size=size,
        )

    def _record_batch_denial(
        self, spec: ToolCallSpec, entry: dict[str, Any], reason: str, observation: dict[str, Any]
    ) -> dict[str, Any]:
        """A call that never reached the gateway: refusal is local to that call."""
        entry["tool_result"] = observation
        self.actions.append(entry)
        if reason in {"unknown_tool", "subagent_tool_denied"}:
            self.consecutive_failures += 1
        if reason == "plan_required":
            self.store.append_run_event(
                self.tenant_id,
                self.run_id,
                "orchestrator.plan_required",
                {
                    "iteration": self.iteration,
                    "tool_id": spec.tool_id,
                    "subagent_id": self.active_subagent_id,
                    "batch": True,
                },
            )
        self.audit_step(
            iteration=self.iteration,
            action=self.action.action,
            decision="deny",
            tool_id=spec.tool_id,
            reason=reason,
            batch=True,
            **({"operator_reason": observation["reason"]} if "reason" in observation else {}),
        )
        detail = observation.get("error") or observation.get("reason") or reason
        return {
            "tool_id": spec.tool_id,
            "arguments": memory._redact_arguments(spec.arguments),
            "success": False,
            "outcome": "denied",
            "reason": reason,
            "error": str(detail)[:800],
            "guidance": str(observation.get("guidance") or detail)[:800],
            **({"next": observation["next"]} if observation.get("next") else {}),
        }

    def _account_call(self, spec: ToolCallSpec, execution: CallExecution) -> dict[str, Any]:
        """Turn one execution into its ``results`` entry, updating the run's counters.

        Same rules as the single-call path, applied in batch order: a success
        clears the failure streaks, ``command_failed`` is about the command (not
        the tool), ``timeout``/``unavailable`` retire the tool after repeated
        attempts, and a ``scope_denied`` target extends the insistence streak -so
        three denials of the same host still close the run, even spread across
        parallel calls.
        """
        result: dict[str, Any] = {
            "tool_id": spec.tool_id,
            "arguments": memory._redact_arguments(spec.arguments),
            "duration_ms": int(round(execution.duration_ms)),
        }
        if execution.cancelled:
            result.update(success=False, outcome="cancelled", error="cancelación solicitada")
            return result
        error = execution.error
        if error is not None:
            return self._account_call_error(spec, error, result)
        observation = _observation_payload(execution.invocation or {})
        self.observation = observation
        self._note_observed_flags(spec)
        success = bool(observation.get("success"))
        outcome = str(observation.get("outcome") or "")
        result.update(
            success=success,
            outcome=outcome,
            verification_method=observation.get("verification_method"),
            invocation_id=observation.get("invocation_id"),
            evidence=observation.get("evidence"),
            assertions=list(observation.get("assertions") or []),
            output=observation.get("output"),
            error=observation.get("error"),
        )
        self.telemetry.note_tool(duration_ms=result["duration_ms"], success=success)
        if success:
            self.scope_denial_target = None
            self.scope_denial_streak = 0
            self.consecutive_failures = 0
            self.tool_failures.clear()
            self.run_evidence.extend(result["assertions"])
            del self.run_evidence[:-RUN_EVIDENCE_MAX_OBSERVATIONS]
            return result
        if outcome == "scope_denied":
            handler_output = observation.get("output")
            if not isinstance(handler_output, dict):
                handler_output = {}
            target = str(
                observation.get("target") or handler_output.get("target") or ""
            ).strip()
            if handler_output.get("error") and not result.get("error"):
                result["error"] = handler_output["error"]
            if handler_output.get("guidance"):
                result["guidance"] = handler_output["guidance"]
            streak = self._note_scope_denial(target)
            result["scope_denial_streak"] = streak
            self.telemetry.flag(FrictionFlag.SCOPE_VIOLATION)
            self.store.append_run_event(
                self.tenant_id,
                self.run_id,
                "react.scope_violation",
                {
                    "iteration": self.iteration,
                    "tool_id": spec.tool_id,
                    "error": str(result.get("error") or "")[:500],
                    "target": target,
                    "streak": streak,
                    "aborted": streak >= MAX_CONSECUTIVE_SCOPE_DENIALS,
                    "batch": True,
                },
            )
        else:
            self.scope_denial_target = None
            self.scope_denial_streak = 0
        if outcome != "command_failed":
            self.consecutive_failures += 1
        if outcome in {"unavailable", "timeout"}:
            self.observation = result
            self._note_tool_failure(spec.tool_id)
            if outcome == "timeout":
                result["guidance"] = timeout_guidance(spec.tool_id)
            else:
                reason = observation.get("failure_kind") or "backend unavailable"
                evidence = observation.get("evidence")
                if isinstance(evidence, dict) and evidence.get("provider"):
                    reason = str(evidence["provider"])
                result["guidance"] = unavailable_guidance(spec.tool_id, reason)
        elif outcome == "command_failed":
            result["guidance"] = command_failed_guidance(spec.tool_id)
        return result

    def _account_call_error(
        self, spec: ToolCallSpec, error: BaseException, result: dict[str, Any]
    ) -> dict[str, Any]:
        """A call that raised: the batch keeps the others, the run learns why."""
        self.telemetry.note_tool(
            duration_ms=result.get("duration_ms", 0),
            success=False,
            error_type=type(error).__name__,
        )
        if isinstance(error, TimeoutError):
            self._note_tool_failure(spec.tool_id)
            result.update(
                success=False,
                outcome="timeout",
                error=(str(error) or "la llamada excedió su presupuesto de tiempo")[:1000],
                guidance=timeout_guidance(spec.tool_id),
            )
            self.consecutive_failures += 1
        elif isinstance(error, ScopeViolation):
            self.telemetry.flag(FrictionFlag.SCOPE_VIOLATION)
            target = str(getattr(error, "target", "") or "").strip()
            streak = self._note_scope_denial(target)
            result.update(
                success=False,
                outcome="scope_denied",
                error=str(error)[:500],
                target=target,
                scope_denial_streak=streak,
                guidance=(
                    f"El objetivo {target or 'solicitado'} está fuera del alcance "
                    "firmado. Ignora esa ruta y busca otra."
                ),
            )
            self.store.append_run_event(
                self.tenant_id,
                self.run_id,
                "react.scope_violation",
                {
                    "iteration": self.iteration,
                    "tool_id": spec.tool_id,
                    "error": str(error)[:500],
                    "target": target,
                    "streak": streak,
                    "aborted": streak >= MAX_CONSECUTIVE_SCOPE_DENIALS,
                    "batch": True,
                },
            )
        elif isinstance(error, ReplayApprovalRequired):
            result.update(
                success=False,
                outcome="replay_approval_required",
                error=str(error)[:500],
            )
            self.consecutive_failures += 1
        elif isinstance(error, ApprovalRequired):
            # Never local: without the approval the run cannot continue, exactly
            # as on the single-call path.
            result.update(
                success=False,
                outcome="approval_required",
                error=str(error)[:500],
                guidance=(
                    "La llamada necesita aprobación humana y no la tiene: el run "
                    "se detiene para que la concedas."
                ),
            )
            self.consecutive_failures += 1
        elif isinstance(error, PermissionError):
            # Another call of the same batch being authorized says nothing about
            # this one: the denial is this call's, and the batch reports it.
            result.update(
                success=False,
                outcome="governance_denial",
                error=str(error)[:500],
                guidance="La política denegó esta llamada; las demás ya pasaron la suya.",
            )
            self.consecutive_failures += 1
        else:
            kind = _failure_kind(error)
            result.update(
                success=False,
                outcome="error",
                error=str(error)[:1000],
                failure_kind=kind,
            )
            if kind == "tool":
                self._note_tool_failure(spec.tool_id)
            self.consecutive_failures += 1
        return result

    async def _batch_turn(self) -> Transition:
        """Run several independent tools at once and answer with one observation.

        Each call is governed exactly like a lone one -catalog/subagent/PLAN-FIRST
        refusal, then policy + operator approval, then the gateway, which repeats
        scope/RoE and audits- and only then are the survivors executed
        concurrently, bounded by ``PARALLEL_MAX_CONCURRENCY``. A refusal or a
        failure is local to its call: the others were authorized on their own
        merit, already hold their approvals and finish.

        ``ApprovalRequired`` is the one non-local outcome (the run stops, as
        always), and the scope-insistance streak still closes the run after
        ``MAX_CONSECUTIVE_SCOPE_DENIALS`` denials of the same target.
        """
        batch = self.action
        assert isinstance(batch, ToolCallBatch)
        calls = list(batch.calls)
        entries = {
            index: self._batch_entry(index, spec, len(calls))
            for index, spec in enumerate(calls)
        }
        results: dict[int, dict[str, Any]] = {}
        prepared: list[dict[str, Any]] = []
        for index, spec in enumerate(calls):
            refusal = self._call_refusal(spec)
            if refusal is not None:
                reason, observation = refusal
                results[index] = self._record_batch_denial(
                    spec, entries[index], reason, observation
                )
                continue
            payload = self._call_payload(spec)
            try:
                denial = self._review_call(spec, payload)
            except PermissionError as exc:
                # The policy engine refused this call at the approval gate. It is
                # this call's denial, not the batch's: the others are reviewed on
                # their own merits below.
                self.consecutive_failures += 1
                results[index] = self._record_batch_denial(
                    spec,
                    entries[index],
                    "governance_denial",
                    {"success": False, "error": str(exc)},
                )
                continue
            if denial is not None:
                self.telemetry.flag(FrictionFlag.OPERATOR_DENIAL)
                results[index] = self._record_batch_denial(
                    spec, entries[index], "denied_by_operator", denial
                )
                continue
            prepared.append(
                {
                    "index": index,
                    "tool_id": spec.tool_id,
                    "arguments": dict(spec.arguments),
                    "payload": payload,
                }
            )
        started = time.perf_counter()
        executions: list[CallExecution] = []
        if prepared:
            executions = await execute_calls(
                prepared,
                execute=lambda payload, timeout, cancel_event: self.tool_execution.execute(
                    payload, self.context, timeout=timeout, cancel_event=cancel_event
                ),
                limit=parallel_limit(),
                timeout=call_timeout(self.config.timeout_per_tool_seconds),
                cancel_event=self.cancel_event,
            )
        cancelled_now = False
        approval_required = ""
        for execution in executions:
            spec = calls[execution.index]
            result = self._account_call(spec, execution)
            results[execution.index] = result
            entries[execution.index]["tool_result"] = result
            self.actions.append(entries[execution.index])
            if execution.cancelled:
                cancelled_now = True
            self.audit_step(
                iteration=self.iteration,
                action=batch.action,
                decision="allow" if result.get("success") else "deny",
                tool_id=spec.tool_id,
                success=bool(result.get("success")),
                batch=True,
                batch_index=execution.index,
            )
            if isinstance(execution.error, ApprovalRequired):
                approval_required = str(execution.error)
        consolidated = consolidate([results[index] for index in sorted(results)])
        consolidated["duration_ms"] = int(round((time.perf_counter() - started) * 1000))
        consolidated["concurrency"] = parallel_limit()
        consolidated["executed"] = len(executions)
        consolidated["refused"] = len(calls) - len(prepared)
        if cancelled_now:
            consolidated["outcome"] = "cancelled"
        self.observation = consolidated
        self.entry = entries[0]
        # The model reads ONE message with every result; ``parallel.tools`` is the
        # synthetic tool id (the artifact/compaction key) of that block.
        _inject_observation(
            self.store,
            self.tenant_id,
            self.conversation_id,
            self.run_id,
            self.iteration,
            _BatchObservationAction(BATCH_TOOL_ID),
            consolidated,
            subagent_id=self.active_subagent_id,
        )
        self.last_tool_elapsed_ms = int(consolidated["duration_ms"])
        self.store.append_run_event(
            self.tenant_id,
            self.run_id,
            "react.parallel_batch",
            {
                "iteration": self.iteration,
                "subagent_id": self.active_subagent_id,
                "tool_ids": list(batch.tool_ids),
                "tool_calls": consolidated["tool_calls"],
                "succeeded": consolidated["succeeded"],
                "failed": consolidated["failed"],
                "executed": consolidated["executed"],
                "refused": consolidated["refused"],
                "concurrency": consolidated["concurrency"],
                "duration_ms": consolidated["duration_ms"],
            },
        )
        if cancelled_now:
            self.status = STATUS_CANCELLED
            self.final_summary = "cancellation requested during a parallel tool batch"
            self.store.append_run_event(
                self.tenant_id,
                self.run_id,
                "react.cancelled",
                {"iteration": self.iteration, "phase": "parallel_tools"},
            )
            return Transition.STOP
        if approval_required:
            self.status = STATUS_BLOCKED
            self.final_summary = approval_required
            return Transition.STOP
        if self.scope_denial_streak >= MAX_CONSECUTIVE_SCOPE_DENIALS:
            self.status = STATUS_SCOPE_VIOLATION
            self.final_summary = (
                "scope violation aborted the loop: the model insisted on a target "
                f"outside the signed scope {self.scope_denial_streak} times"
            )
            return Transition.STOP
        if not _keep_going_after_failures(
            self.subagent,
            self.unavailable_tools,
            self.consecutive_failures,
            self.catalog,
        ):
            self.status = STATUS_FAILED
            self.final_summary = (
                f"aborted after {self.consecutive_failures} consecutive tool failures "
                f"(no usable tools remain for subagent '{self.subagent.id}')"
            )
            return Transition.STOP
        if self.consecutive_failures >= MAX_CONSECUTIVE_TOOL_FAILURES:
            self.consecutive_failures = 0
        return Transition.READY

    def _record_governance_denial(
        self, exc: BaseException, *, reason: str = "governance_denial", guidance: str = ""
    ) -> None:
        """Persist a denied call as this turn's observation (never a crash)."""
        self.observation = {
            "success": False,
            "outcome": "governance_denial",
            "error_type": type(exc).__name__,
            "error": str(exc),
            "failure_kind": "governance",
        }
        if guidance:
            self.observation["guidance"] = guidance
        self.entry["tool_result"] = self.observation
        self.actions.append(self.entry)
        _inject_observation(
            self.store,
            self.tenant_id,
            self.conversation_id,
            self.run_id,
            self.iteration,
            self.action,
            self.observation,
            subagent_id=self.active_subagent_id,
        )
        self.audit_step(
            iteration=self.iteration,
            action=self.action.action,
            decision="deny",
            tool_id=self.action.tool_id,
            reason=reason,
        )

    async def _execute_tool(self) -> Transition:
        repeated_tool = self._repeated_failed_action()
        if repeated_tool is not None:
            return self._correct_repeated_action(repeated_tool)
        barren_tool = self._repeated_barren_action()
        if barren_tool is not None:
            return self._correct_repeated_action(barren_tool, barren=True)
        closed = self._refuse_closed_branch()
        if closed is not None:
            return closed
        premature_barrier = self._refuse_barrier_without_attempts()
        if premature_barrier is not None:
            return premature_barrier
        unroutable = await self._correct_unroutable_sweep()
        if unroutable is not None:
            return unroutable
        self.last_tool_elapsed_ms = 0
        tool_started = time.perf_counter()
        scope_aborted = False
        try:
            invocation, cancelled_now = await self.tool_execution.execute(
                self.tool_payload,
                self.context,
                timeout=self.config.timeout_per_tool_seconds,
                cancel_event=self.cancel_event,
            )
        except ScopeViolation as exc:
            self.telemetry.note_tool(
                duration_ms=_elapsed_ms(tool_started),
                success=False,
                error_type=type(exc).__name__,
            )
            self.telemetry.flag(FrictionFlag.SCOPE_VIOLATION)
            target = str(getattr(exc, "target", "") or "").strip()
            streak = self._note_scope_denial(target)
            aborted = streak >= MAX_CONSECUTIVE_SCOPE_DENIALS
            named = target or "el objetivo solicitado"
            self.observation = {
                "success": False,
                "outcome": "scope_denied",
                "verified": False,
                "error_type": type(exc).__name__,
                "error": str(exc)[:500],
                "scope_violation": True,
                "target": target,
                "scope_denial_streak": streak,
                "guidance": (
                    f"El objetivo {named} está fuera del alcance firmado. "
                    "Ignora esa URL y busca otra ruta."
                ),
                "available_tools": sorted(self.allowed_catalog),
            }
            if aborted:
                # The model spent the grace turns insisting on the same target:
                # the refusal is now the loop's verdict, not a correction.
                self.status = STATUS_SCOPE_VIOLATION
                self.final_summary = (
                    "scope violation aborted the loop: the model insisted "
                    f"{self.scope_denial_streak} times on {named}: {exc}"
                )
                self.observation["aborted"] = True
            self.entry["tool_result"] = self.observation
            self.actions.append(self.entry)
            _inject_observation(
                self.store,
                self.tenant_id,
                self.conversation_id,
                self.run_id,
                self.iteration,
                self.action,
                self.observation,
                subagent_id=self.active_subagent_id,
            )
            self.store.append_run_event(
                self.tenant_id,
                self.run_id,
                "react.scope_violation",
                {
                    "iteration": self.iteration,
                    "tool_id": self.action.tool_id,
                    "error": str(exc)[:500],
                    "target": target,
                    "streak": self.scope_denial_streak,
                    "aborted": aborted,
                },
            )
            self.audit_step(
                iteration=self.iteration,
                action=self.action.action,
                decision="deny",
                tool_id=self.action.tool_id,
                reason="scope_violation",
                error_type=type(exc).__name__,
            )
            # A refusal is an observation: the loop continues unless the model
            # insists on the same target ``MAX_CONSECUTIVE_SCOPE_DENIALS`` times.
            return Transition.STOP if aborted else Transition.READY
        except Exception as exc:
            self.telemetry.note_tool(
                duration_ms=_elapsed_ms(tool_started),
                success=False,
                error_type=type(exc).__name__,
            )
            if isinstance(exc, ReplayApprovalRequired):
                return self._correct_replayed_invocation(exc)
            if isinstance(exc, ApprovalRequired):
                # Nobody can answer an unattended run: without the approval the
                # loop cannot continue, so it stops -and says so as ``blocked``.
                self.status = STATUS_BLOCKED
                self.final_summary = str(exc)
                self._record_governance_denial(exc, reason=STATUS_BLOCKED)
                return Transition.STOP
            if isinstance(exc, PermissionError):
                # A governance denial is about *this* invocation, not about the
                # engagement: record it as the turn's observation and let the
                # model correct itself (another tool, other arguments, a
                # barrier). Only insisting on it closes the run. Measured in the
                # Hijack V1 run: the first denial ended a run with 82 iterations
                # and 1 M tokens of budget unused.
                self.governance_denial_streak += 1
                self.consecutive_failures += 1
                self.telemetry.flag(FrictionFlag.GOVERNANCE_DENIAL)
                self._record_governance_denial(
                    exc,
                    guidance=(
                        "El gateway denegó esta invocación (política, aprobación "
                        "inválida o estado del journal): NO la repitas. Elige otra "
                        "acción, otros argumentos u otra herramienta; si el vector "
                        "entero está bloqueado, registra un barrier y pivota."
                    ),
                )
                if self.governance_denial_streak >= MAX_CONSECUTIVE_GOVERNANCE_DENIALS:
                    self.status = "governance_denial"
                    self.final_summary = (
                        "governance denial repeated "
                        f"{self.governance_denial_streak} times in a row: {exc}"
                    )
                    return Transition.STOP
                return Transition.READY
            backend_unavailable = (
                isinstance(exc, ProviderFailure) and getattr(exc, "kind", "fatal") == "unavailable"
            )
            if isinstance(exc, TimeoutError):
                # V1-27: the per-call ceiling of the loop (or a timeout raised by
                # the tool layer) is the *tool* running out of time, never the
                # provider failing. It becomes the same determinate ``timeout``
                # observation the gateway returns for a handler that outlived its
                # contract (``tool_timeout_result``), so it counts as one tool
                # failure and the tool is retired after repeated attempts instead
                # of closing the run as ``provider_error`` -the measured death of
                # the rerun #7 attempt 1: a 600 s ``nmap -p-`` ended the whole run
                # with ``summary: "TimeoutError"`` (exit 3) from iteration 1.
                self.observation = {
                    "success": False,
                    "outcome": "timeout",
                    "error_type": type(exc).__name__,
                    "error": (str(exc) or "the tool call exceeded its time budget")[:1000],
                    "failure_kind": "tool_timeout",
                    "evidence": {
                        "tool_id": str(self.action.tool_id),
                        "timeout_seconds": self.config.timeout_per_tool_seconds,
                    },
                    "guidance": timeout_guidance(self.action.tool_id),
                }
                self._note_tool_failure(str(self.action.tool_id))
            elif backend_unavailable:
                # Fase 3b: a backend that is not serving *now* is not a fatal
                # provider error. It becomes the same ``unavailable`` observation
                # a handler returns (never ``negative``: nothing was observed),
                # counted like any other tool failure, so the tool is retired
                # after repeated attempts and the run pivots to the rest of the
                # phase (measured in run_434f5eeadb104b11ba0c80bce16f8d08).
                reason = str(exc) or type(exc).__name__
                self.observation = {
                    "success": False,
                    "outcome": "unavailable",
                    "error_type": type(exc).__name__,
                    "error": reason[:1000],
                    "failure_kind": "provider_unavailable",
                    "evidence": {"provider": reason},
                    "guidance": unavailable_guidance(self.action.tool_id, reason),
                }
                self._note_tool_failure(str(self.action.tool_id))
            elif isinstance(exc, (ProviderFailure, ConnectionError)):
                # A provider failure (the model call) still ends the run as
                # ``provider_error``; a *tool* timeout never reaches this branch
                # (V1-27, handled above).
                self.status = "provider_error"
                self.final_summary = type(exc).__name__
                return Transition.STOP
            else:
                kind = _failure_kind(exc)
                self.scope_denial_target = None
                self.scope_denial_streak = 0
                self.observation = {
                    "success": False,
                    "error_type": type(exc).__name__,
                    "error": str(exc)[:1000],
                    "failure_kind": kind,
                }
                if kind == "tool":
                    self._note_tool_failure(str(self.action.tool_id))
            self.consecutive_failures += 1
        else:
            # The call ran: whatever the model was insisting on no longer applies,
            # so the pivot-gate and replay streaks start over.
            self.pivot_gate_streak = 0
            self.replay_refusals = 0
            # The insistence streak is decided below: a successful turn or a
            # failure that is not a scope denial breaks it, while a handler that
            # returned ``scope_denied`` (``nexus.shell.exec`` validating the
            # destination of a ``curl``) extends it like the gateway's exception.
            if cancelled_now:
                self.telemetry.flag(FrictionFlag.CANCELLED)
                self.status = STATUS_CANCELLED
                self.final_summary = "cancellation requested during a tool call"
                self.entry["tool_result"] = {"success": False, "cancelled": True}
                self.actions.append(self.entry)
                self.store.append_run_event(
                    self.tenant_id,
                    self.run_id,
                    "react.cancelled",
                    {"iteration": self.iteration, "phase": "tool", "tool_id": self.action.tool_id},
                )
                return Transition.STOP
            self.observation = _observation_payload(invocation or {})
            self._note_observed_flags()
            self.telemetry.note_tool(
                duration_ms=_elapsed_ms(tool_started),
                success=bool(self.observation.get("success")),
            )
            if self.observation.get("success"):
                self.scope_denial_target = None
                self.scope_denial_streak = 0
                self.governance_denial_streak = 0
                self.consecutive_failures = 0
                # A successful turn breaks every per-tool failure streak: the
                # retirement below is about *consecutive* failures, never about
                # the accumulated count of a long run. Measured in
                # blackbox-10.67.183.218 (2026-10-19): ``shell.exec`` failed on
                # turns 12, 31 and 48 with 17 successful shell calls in between
                # and was retired anyway, so the agent lost the only tool that
                # could extract the credentials it had already located.
                self.tool_failures.clear()
                self.run_evidence.extend(self.observation.get("assertions") or [])
                del self.run_evidence[:-RUN_EVIDENCE_MAX_OBSERVATIONS]
            else:
                failure_outcome = str(self.observation.get("outcome") or "")
                if failure_outcome == "scope_denied":
                    # Same rule as the gateway path above, for the channels that
                    # report the refusal as a result instead of raising: three
                    # consecutive denials of the same target close the run.
                    # ``_observation_payload`` keeps the handler's own output
                    # nested, so the target and the message are read from there.
                    handler_output = self.observation.get("output")
                    if not isinstance(handler_output, dict):
                        handler_output = {}
                    target = str(
                        self.observation.get("target")
                        or handler_output.get("target")
                        or ""
                    ).strip()
                    if handler_output.get("error") and not self.observation.get("error"):
                        self.observation["error"] = handler_output["error"]
                    if handler_output.get("guidance"):
                        self.observation["guidance"] = handler_output["guidance"]
                    streak = self._note_scope_denial(target)
                    self.observation["scope_denial_streak"] = streak
                    scope_aborted = streak >= MAX_CONSECUTIVE_SCOPE_DENIALS
                    if scope_aborted:
                        self.status = STATUS_SCOPE_VIOLATION
                        self.final_summary = (
                            "scope violation aborted the loop: the model insisted "
                            f"{streak} times on {target or 'the requested target'}"
                        )
                        self.observation["aborted"] = True
                    self.store.append_run_event(
                        self.tenant_id,
                        self.run_id,
                        "react.scope_violation",
                        {
                            "iteration": self.iteration,
                            "tool_id": self.action.tool_id,
                            "error": str(self.observation.get("error") or "")[:500],
                            "target": target,
                            "streak": streak,
                            "aborted": scope_aborted,
                        },
                    )
                else:
                    # The model tried something other than the denied target:
                    # the insistence streak is broken, whatever the outcome.
                    self.scope_denial_target = None
                    self.scope_denial_streak = 0
                if failure_outcome == "command_failed":
                    # The tool worked: the channel reached the target and the
                    # command ran. A non-zero exit is about the command, so it is
                    # not the "this tool is broken" signal that aborts the run
                    # after N failures -three failed ``sudo`` invocations must not
                    # end the engagement. The stuck/no-progress counter still
                    # sees the barren turn.
                    self.consecutive_failures = 0
                else:
                    self.consecutive_failures += 1
                if failure_outcome == "unavailable":
                    # Fase 3b: a handler (or the gateway) declared that the
                    # backend did not serve the call. It is a *tool* failure -
                    # not invalid input- so it retires the tool after repeated
                    # attempts and the next prompt offers the remaining routes.
                    reason = self.observation.get("failure_kind") or "backend unavailable"
                    evidence = self.observation.get("evidence")
                    if isinstance(evidence, dict) and evidence.get("provider"):
                        reason = str(evidence["provider"])
                    self.observation["guidance"] = unavailable_guidance(
                        self.action.tool_id, reason
                    )
                    self._note_tool_failure(str(self.action.tool_id))
                elif failure_outcome == "timeout":
                    # V1-27: a tool that ran out of time is a *tool* failure. It
                    # counts, the model is told the call was cut off (so a repeat
                    # with the same arguments is pointless) and the tool is retired
                    # after repeated attempts so the phase pivots.
                    self.observation["guidance"] = timeout_guidance(self.action.tool_id)
                    self._note_tool_failure(str(self.action.tool_id))
                elif failure_outcome == "command_failed":
                    # The channel reached the target and the command ran: the
                    # credential is fine, so the tool does NOT retire. The model
                    # is told *what* failed and which strategy replaces it; an
                    # identical repeat is already intercepted by the V1-26 guard.
                    # Measured in Simple CTF: `sudo -n -l` failed after a working
                    # SSH login, the agent blamed the password and looped.
                    self.observation["guidance"] = command_failed_guidance(
                        self.action.tool_id
                    )
        self.entry["tool_result"] = self.observation
        self.actions.append(self.entry)
        _inject_observation(
            self.store,
            self.tenant_id,
            self.conversation_id,
            self.run_id,
            self.iteration,
            self.action,
            self.observation,
            subagent_id=self.active_subagent_id,
        )
        self.audit_step(
            iteration=self.iteration,
            action=self.action.action,
            decision="allow" if self.observation.get("success") else "deny",
            tool_id=self.action.tool_id,
            success=bool(self.observation.get("success")),
            consecutive_failures=self.consecutive_failures,
            error=self.observation.get("error"),
        )
        if not _keep_going_after_failures(
            self.subagent,
            self.unavailable_tools,
            self.consecutive_failures,
            self.catalog,
        ):
            self.status = STATUS_FAILED
            self.final_summary = f"aborted after {self.consecutive_failures} consecutive tool failures (no usable tools remain for subagent '{self.subagent.id}')"
            return Transition.STOP
        if self.consecutive_failures >= MAX_CONSECUTIVE_TOOL_FAILURES:
            self.consecutive_failures = 0
        self.last_tool_elapsed_ms = _elapsed_ms(tool_started)
        return Transition.STOP if scope_aborted else Transition.READY

    def _note_tool_failure(self, tool_id: str) -> int:
        """Count one *consecutive* tool failure and retire it once exhausted (B3).

        The counter is a streak, not a tally: any successful turn clears it
        (``_execute_tool``), so only three failures in a row retire a tool. The
        accumulated reading was measured in blackbox-10.67.183.218 (2026-10-19):
        ``shell.exec`` failed on turns 12, 31 and 48 with successful shell calls
        in between, was retired at turn 48, and the agent lost the tool that was
        one command away from the credentials.

        A retired tool leaves the phase's catalog (``_advance_phase``), so the
        next prompt offers the remaining routes and the refusal path names what
        is left. Fase 3b routes a backend that stopped serving through here as
        well: ``unavailable`` is a tool failing *now*, and that is what turns
        "MSF RPC is down" into a pivot instead of the end of the run (measured in
        run_434f5eeadb104b11ba0c80bce16f8d08).
        """
        count = self.tool_failures.get(tool_id, 0) + 1
        self.tool_failures[tool_id] = count
        if (
            count >= MAX_TOOL_FAILURES_BEFORE_UNAVAILABLE
            and tool_id not in self.unavailable_tools
        ):
            self.unavailable_tools.add(tool_id)
            self.telemetry.flag(FrictionFlag.TOOL_RETIRED)
            self.observation["tool_retired"] = True
            self.observation["available_tools"] = sorted(
                (tool for tool in self.subagent.tools if tool not in self.unavailable_tools)
            )
            self.store.append_run_event(
                self.tenant_id,
                self.run_id,
                TOOL_UNAVAILABLE_EVENT_TYPE,
                {
                    "tool_id": tool_id,
                    "subagent_id": self.subagent.id,
                    "failures": count,
                    "iteration": self.iteration,
                },
            )
            self.audit_step(
                iteration=self.iteration,
                action="tool_unavailable",
                decision="degrade",
                tool_id=tool_id,
                failures=count,
            )
        return count

    def _blackboard_counts(self) -> dict[str, int] | None:
        """Counts of the blackboard *after* the turn's tool call (never raises).

        The plan snapshot the loop renders was built before the tool ran, so the
        per-turn telemetry reads the board again: the whole point of the signal
        is what the turn actually learned.

        Both proven facts *and* the agent's own registrations count. Only the
        verifier can mark a fact ``verified``, so counting proven facts alone
        made every turn that recorded a finding read as barren: measured in
        ``run_7661dda481784eebb17a76e037c5722b`` (2026-10-20), where the run
        extracted the DB version, the table prefix and the complete ``jonah``
        hash through ``nexus.knowledge.record_fact`` and still accumulated 35
        ``consecutive_no_progress`` turns, three ``stuck_detected`` and a budget
        death. A repeated registration does not grow a count, so the streak can
        only be reset by a fact the board did not already hold.
        """
        if not self.engagement_id or not getattr(self, "store", None):
            return None
        try:
            from nexus_core.kernel.blackboard import Blackboard

            summary = Blackboard(self.store).summary(self.tenant_id, self.engagement_id)
            if not isinstance(summary, dict):
                return None
            counts: dict[str, int] = {}
            for bucket in (summary.get("counts"), summary.get("leads")):
                if not isinstance(bucket, dict):
                    continue
                for key, value in bucket.items():
                    counts[str(key)] = counts.get(str(key), 0) + int(value or 0)
            if self.closed_branches:
                # The barriers the *loop* wrote are its own reflex, not something
                # the run learned: counting them as progress would reset the very
                # streak that made the loop act, and the next branch would get a
                # free margin of barren turns. They are unverified, so
                # ``summary`` files them under ``leads``; subtracting here keeps
                # the delta honest (a barrier the model wrote still counts, as
                # the model following the instruction *is* progress).
                remaining = max(0, counts.get("barrier", 0) - len(self.closed_branches))
                if remaining:
                    counts["barrier"] = remaining
                else:
                    counts.pop("barrier", None)
            return counts
        except Exception:  # noqa: BLE001 - telemetry must never abort a run
            return None

    def _turn_was_argument_rejection(self) -> bool:
        """Whether the last turn failed on its arguments, not on the target.

        Measured in HackPark V12 (2026-10-21, iterations 13-15): ``form_url``
        with a query string, a missing ``^PASS^`` and an invalid
        ``failure_string`` -three rejections of the *call*, none of them a
        statement about the login page- raised ``consecutive_no_progress`` to 5,
        fired ``react.stuck_detected`` and pushed the run to RDP. The target had
        not been tested even once.
        """
        observation = getattr(self, "observation", None)
        if not isinstance(observation, dict) or observation.get("success"):
            return False
        if observation.get("input_rejected"):
            return True
        outcome = str(observation.get("outcome") or "").strip().lower()
        if outcome.startswith("invalid_"):
            return True
        return str(observation.get("failure_kind") or "") == "input"

    def _track_no_progress(self) -> None:
        """Count turns without a new verified fact and signal a stuck loop.

        Measured in run_abe04509c5064c6e8e475f46ba8f8c60: 10 consecutive turns
        with ``blackboard_delta = 0`` went unnoticed and the model kept proposing
        the same enumeration until its profile budget killed the run. The signal
        is informational -it never stops the run nor changes the phase by
        itself-; what asks for a pivot is the line injected into the next system
        prompt (see ``ContextBuilder.render``). Emitted at the threshold and then
        once per further threshold, so the log records a long stall without one
        event per turn.
        """
        delta = self.telemetry.current_delta()
        if delta is None:
            return
        # R7: an argument rejection is friction (it already carries its own
        # telemetry flag), never a reason to abandon the branch. The first two
        # consecutive ones leave the pivot counter untouched; from the third the
        # model is guessing, and the turn counts like any other barren one so a
        # run cannot loop on malformed calls until the budget dies.
        if self._turn_was_argument_rejection():
            self.argument_rejections += 1
            if self.argument_rejections <= MAX_FREE_ARGUMENT_REJECTIONS:
                self.telemetry.note_no_progress(consecutive=self.consecutive_no_progress)
                self._track_repeated_tool(delta)
                return
        else:
            self.argument_rejections = 0
        self.consecutive_no_progress = self.consecutive_no_progress + 1 if delta <= 0 else 0
        self.telemetry.note_no_progress(consecutive=self.consecutive_no_progress)
        self._track_repeated_tool(delta)
        threshold = self.stuck_threshold
        if threshold <= 0 or self.consecutive_no_progress < threshold:
            return
        # The first threshold is the advisory line; from the second one the loop
        # stops asking and closes the branch itself, because the measured stall
        # outlived eight advisory events (see ``_close_stalled_branch``).
        if self.consecutive_no_progress >= threshold * STALL_BARRIER_MULTIPLIER:
            self._close_stalled_branch()
        if self.consecutive_no_progress % threshold:
            return
        self.context.event(
            STUCK_EVENT_TYPE,
            iterations_stuck=self.consecutive_no_progress,
            phase=self.plan.current,
            subagent_id=self.subagent.id,
            last_tools=self._last_tools(),
        )

    def _track_repeated_tool(self, delta: int) -> None:
        """Count turns that repeat one tool without adding a fact (WP4).

        The stuck signal above counts *any* barren turn; this one is narrower:
        a run that keeps asking the same capability is not exploring, it is
        guessing at the same door, and the cheapest way out is the curated
        recipe the skill catalogue already ships. When the streak reaches
        ``SKILL_NUDGE_TURNS`` the next prompt says so and names the loader; the
        signal never stops the run nor changes the phase.
        """
        # A turn that could not be decoded (a parse error) never sets
        # ``self.action``, and its barren turn still has to be counted safely.
        action = getattr(self, "action", None)
        tool_id = str(getattr(action, "tool_id", "") or "")
        if delta <= 0 and tool_id and tool_id == self.last_turn_tool:
            self.same_tool_no_progress += 1
        else:
            self.same_tool_no_progress = 1 if (delta <= 0 and tool_id) else 0
        self.last_turn_tool = tool_id or None
        if self.same_tool_no_progress != SKILL_NUDGE_TURNS:
            return
        self.context.event(
            SKILL_NUDGE_EVENT_TYPE,
            iterations_stuck=self.same_tool_no_progress,
            tool_id=tool_id,
            phase=self.plan.current,
            subagent_id=self.subagent.id,
        )

    def _last_tools(self, limit: int = 5) -> list[str]:
        """Tool ids of the most recent tool calls (payload of the stuck event)."""
        tools: list[str] = []
        for entry in reversed(self.actions):
            tool_id = entry.get("tool_id")
            if tool_id and str(tool_id) not in tools:
                tools.append(str(tool_id))
            if len(tools) >= limit:
                break
        return tools

    def _blackboard_services(self) -> list[str]:
        """Keys of the verified ``service`` facts (never raises).

        The deterministic enumeration→exploit rule needs to know *which* surface
        is on the board; counts alone cannot tell SMB from HTTP.
        """
        if not self.engagement_id or not getattr(self, "store", None):
            return []
        try:
            from nexus_core.kernel.blackboard import Blackboard

            facts = Blackboard(self.store).list_facts(
                self.tenant_id, self.engagement_id, fact_type="service"
            )
            return [str(fact.get("key") or "") for fact in facts if isinstance(fact, dict)]
        except Exception:  # noqa: BLE001 - a missing board must not abort a run
            return []

    def _turn_outcome(self, transition: Transition) -> str:
        """Outcome label of a finished turn (the run status when it stopped)."""
        if transition is Transition.STOP and self.status:
            return self.status
        return "next_turn" if transition is Transition.NEXT_TURN else "completed_turn"

    def _target_margin_spent(self) -> bool:
        """Count a tool call made after the warning; ``True`` when it must be cut.

        The warning turn itself counts as the first tool call, so two more are
        executed and the third is intercepted (``TARGET_REACHED_GRACE_TURNS``).
        """
        if not self.target_reached:
            return False
        self.tool_calls_since_target_reached += 1
        return self.tool_calls_since_target_reached >= TARGET_REACHED_GRACE_TURNS

    def _flag_findings(self) -> list[dict[str, Any]]:
        """One finding per captured flag, citing the evidence that proved it."""
        findings: list[dict[str, Any]] = []
        for flag, source in self.captured_flag_refs.items():
            findings.append(
                {
                    "severity": "critical",
                    "title": f"Flag capturada: {flag}",
                    "invocation_id": str(source.get("invocation_id") or ""),
                    "target": str(source.get("target") or ""),
                    "fact_type": "loot",
                    "value": {"flag": flag},
                    "evidence": (
                        f"la salida de la herramienta devolvió {flag}"
                        if source.get("source") == "observation"
                        else f"hecho loot verificado en el tablero: {flag}"
                    ),
                }
            )
        return findings

    def _force_target_completion(self) -> Transition:
        """Close the run with a synthesized ``task_complete`` (WP5).

        The model ignored the imperative warning for the whole margin, so the
        loop closes on the evidence it already has. The completion is grounded in
        the captured flags themselves (verified loot facts or the successful tool
        output that printed them), which is why it can be marked verified without
        asking the model for anything else.
        """
        self.forced_completion = True
        flags = list(self.captured_flag_refs)
        # The board facts the closure reports, without inventing any: type, key and
        # provenance of what the engagement already proved (capped for the record).
        board_facts = [
            {
                "fact_type": str(fact.get("fact_type") or ""),
                "key": str(fact.get("key") or ""),
                "verified": bool(fact.get("verified")),
                "verification_method": str(fact.get("verification_method") or ""),
            }
            for fact in self._blackboard_facts()[:50]
            if isinstance(fact, dict)
        ]
        self.findings = self._flag_findings()
        self.final_summary = (
            "Cierre forzado por objetivo cumplido: "
            f"{len(flags)} flag(s) capturada(s) - " + ", ".join(flags)
        )
        self.status = STATUS_COMPLETED
        # The evidence is the captured flags, not a model summary: the closure is
        # verified when at least one of them came from a verifier assertion or a
        # successful tool output (both are true by construction of the state).
        self.completion_verified_override = bool(flags)
        self.actions.append(
            _action_entry(
                self.iteration,
                ACTION_TASK_COMPLETE,
                thought="Cierre forzado: el objetivo estaba cumplido y el margen de 3 turnos se agotó.",
                summary=self.final_summary,
                findings=self.findings,
                forced=True,
                flags=flags,
                board_facts=board_facts,
            )
        )
        self.store.append_run_event(
            self.tenant_id,
            self.run_id,
            TARGET_REACHED_FORCED_EVENT_TYPE,
            {
                "iteration": self.iteration,
                "tool_calls": self.tool_calls_since_target_reached,
                "flags": flags,
                "board_facts": board_facts,
                "tool_id": str(getattr(self.action, "tool_id", "") or ""),
                "subagent_id": self.last_subagent_id,
            },
        )
        memory.append_step(
            self.store,
            self.tenant_id,
            self.conversation_id,
            "assistant",
            json.dumps(
                {"summary": self.final_summary, "findings": self.findings},
                ensure_ascii=False,
            ),
            {
                "kind": "react.final",
                "iteration": self.iteration,
                "findings_count": len(self.findings),
                "forced": True,
                "flags": flags,
                "run_id": self.run_id,
            },
        )
        self.audit_step(
            iteration=self.iteration,
            action=ACTION_TASK_COMPLETE,
            decision="allow",
            reason="target_reached_forced",
            forced=True,
            flags=flags,
            findings_count=len(self.findings),
        )
        return Transition.STOP

    def _result(self) -> ReActResult:
        if self.status == STATUS_MAX_ITERATIONS and (not self.final_summary):
            self.final_summary = (
                f"iteration budget exhausted ({self.config.max_iterations}) without task_complete"
            )
        self.context.event(
            "react.finished",
            status=self.status,
            iterations=self.iteration,
            conversation_id=self.conversation_id,
            findings_count=len(self.findings),
            subagent_id=self.last_subagent_id,
        )
        return ReActResult(
            status=self.status,
            iterations=self.iteration,
            final_summary=self.final_summary,
            findings=self.findings,
            conversation_id=self.conversation_id,
            actions=self.actions,
            turns=self.telemetry.as_dicts(),
            question=self.question,
            plan=self.last_plan.to_dict() if self.last_plan is not None else None,
            subagent_id=self.last_subagent_id,
            evidence_stats=self.evidence_stats,
            engagement_plan=(
                self.engagement_plan.to_dict()
                if self.engagement_plan is not None
                else None
            ),
            completion_objections=list(self.completion_objections),
            budget_tokens=int(self.budget or 0),
            budget_used=(
                _budget_used(self.store, self.tenant_id, self.run_id)
                if self.budget
                else 0
            ),
            completion_verified=(
                bool(self.completion_verified_override)
                if self.completion_verified_override is not None
                else (
                    self.status == STATUS_COMPLETED
                    and self.config.enforce_completion_gates
                    and (not self.completion_objections)
                    and bool(self.run_evidence)
                )
            ),
        )

    async def run(self) -> ReActResult:
        await self._initialize()
        while self.iteration < self.iteration_limit:
            if self._guard() is Transition.STOP:
                break
            await self._build_context()
            if await self._select_profile() is Transition.STOP:
                break
            self._advance_phase()
            # The turn is opened only once the phase, the profile and the
            # allowed catalog of this iteration are known, so the record is
            # attributable from the first millisecond.
            self.telemetry.begin_turn(
                iteration=self.iteration,
                phase=self.plan.current,
                subagent_id=self.subagent.id,
                facts_total=self.plan.facts_total,
                counts=self.plan.counts,
            )
            turn_started = time.perf_counter()
            try:
                transition = await self._iteration_body()
            except BaseException:
                # A turn that died mid-way is exactly what the operator needs to
                # see, so the record is published before the exception travels on.
                self.telemetry.finish(
                    outcome=self.status or "exception",
                    turn_ms=_elapsed_ms(turn_started),
                )
                raise
            counts = self._blackboard_counts()
            if counts is not None:
                self.telemetry.note_blackboard(facts_total=sum(counts.values()), counts=counts)
                self._track_no_progress()
            self.telemetry.finish(
                outcome=self._turn_outcome(transition),
                turn_ms=_elapsed_ms(turn_started),
            )
            self._note_completed_turn()
            if transition is Transition.STOP:
                break
        await self.telemetry.flush()
        return self._result()

    async def _iteration_body(self) -> Transition:
        """One model turn and the transition it asked for (the loop's unit)."""
        # ``_request_action`` may also answer ``NEXT_TURN``: a malformed JSON
        # answer is corrected and the turn re-issued instead of decoded.
        request = await self._request_action()
        if request is not Transition.READY:
            return request
        if self._decode_action() is Transition.NEXT_TURN:
            return Transition.NEXT_TURN
        if isinstance(self.action, TaskComplete):
            return await self._complete()
        if isinstance(self.action, RequestClarification):
            return self._clarify()
        # WP5: once the objective is reached the model gets an imperative warning
        # and a fixed margin of tool calls. When it spends them without closing,
        # the next call is intercepted: the run ends with a synthesized
        # ``task_complete`` instead of dying at the budget with the work done.
        if self._target_margin_spent():
            # PLAN-FIRST: a capture is not the engagement while the plan still
            # promises a flag (run v8 closed on the first one). The margin is
            # reset instead of forcing the closure, so the model keeps working
            # on the open TODO; without a plan the old WP5 behavior stands.
            if self._flag_todos_pending():
                self.tool_calls_since_target_reached = 0
                self.store.append_run_event(
                    self.tenant_id,
                    self.run_id,
                    "orchestrator.plan_open_at_target",
                    {
                        "iteration": self.iteration,
                        "pending": [
                            todo.id for todo in (self.engagement_plan.flags_pending if self.engagement_plan else ())
                        ],
                    },
                )
            else:
                return self._force_target_completion()
        if isinstance(self.action, ToolCallBatch):
            return await self._batch_turn()
        return await self._tool_turn()

    async def _tool_turn(self) -> Transition:
        self._tool_entry()
        transition = self._check_tool()
        if transition is not Transition.READY:
            return transition
        transition = self._approve_tool()
        if transition is not Transition.READY:
            return transition
        return await self._execute_tool()
