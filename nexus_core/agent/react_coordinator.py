"""Explicit ReAct transitions with per-run state and injected boundary services."""

from __future__ import annotations

import asyncio
import json
import os
import time
from typing import Any

from nexus_core.kernel.audit import AuditWriter
from nexus_core.llm.abstraction import LLMMessage
from nexus_core.scope import ScopeViolation

from . import memory
from nexus_core.kernel.errors import ApprovalRequired, ProviderFailure
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

from .react_types import (
    BUDGET_EXEMPT_EVENT_TYPE,
    BUDGET_GRACE_EVENT_TYPE,
    DEFAULT_AGENT_ID,
    OBJECTIVE_GRACE_EVENT_TYPE,
    OBJECTIVE_GRACE_TURNS,
    SUBAGENT_SOFT_LIMIT_EVENT_TYPE,
    OBJECTIVE_COMPLETE_EVENT_TYPE,
    MAX_CONSECUTIVE_TOOL_FAILURES,
    MAX_TOOL_FAILURES_BEFORE_UNAVAILABLE,
    TOOL_UNAVAILABLE_EVENT_TYPE,
    PHASE_TIMEOUT_EVENT_TYPE,
    STUCK_EVENT_TYPE,
    PREMATURE_COMPLETION_EVENT_TYPE,
    MAX_PREMATURE_COMPLETIONS,
    RUN_EVIDENCE_MAX_OBSERVATIONS,
    STATUS_COMPLETED,
    STATUS_MAX_ITERATIONS,
    STATUS_CLARIFICATION,
    STATUS_FAILED,
    STATUS_PREMATURE_COMPLETION,
    STATUS_CANCELLED,
    STATUS_SCOPE_VIOLATION,
    STATUS_BUDGET_EXCEEDED,
    STATUS_SUBAGENT_BUDGET,
    SUBAGENT_EVENT_TYPE,
    BUDGET_EVENT_TYPE,
    BUDGET_SUBJECT_ID,
    SKILL_NUDGE_EVENT_TYPE,
    SKILL_NUDGE_TURNS,
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
    repeated_action_correction,
    _invocation_signature,
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
    ENUMERATION_EXHAUSTED_REASON,
    SESSION_ESTABLISHED_REASON,
    CredentialHandover,
    EnumerationEscalation,
    Plan,
    SessionHandover,
    apply_objective_completion,
    credential_handover,
    enumeration_escalation,
    enumeration_still_open,
    escalate_credential,
    escalate_enumeration,
    escalate_session,
    established_msf_session,
    objective_completion,
    session_handover,
    verified_credential,
)
from .subagents import SubAgentDefinition
from .project_context import ProjectInstruction
from .skills import Skill
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from nexus_core.hooks import HookRunner
from nexus_core.kernel.control_store import ControlStore
from nexus_core.scope import EngagementScope
from nexus_core.kernel.domain_dto import Action, ToolCall, TaskComplete, RequestClarification
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
    ) -> None:
        self.context = context
        self.objective = objective
        self.engagement_id = engagement_id
        self.llm_client = llm_client
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
        from nexus_core.kernel.scope_loader import scope_signing_secret

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
        self.budget = _budget_tokens(self.payload, self.budget_tokens)
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
        self.stuck_threshold = stuck_threshold()
        self.same_tool_no_progress = 0
        self.last_turn_tool = None
        self.plan_reason = None
        self.enumeration_escalated = False
        self.session_handed_over = False
        self.credential_handed_over = False
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

    async def _build_context(self) -> Transition:
        self.iteration += 1
        self.snapshot = await self.context_builder.gather(
            store=self.store,
            tenant_id=self.tenant_id,
            run_id=self.run_id,
            conversation_id=self.conversation_id,
            llm_client=self.llm_client,
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
        self._refresh_objective_complete()
        # WP5: the same board (plus the flags this run already saw in a tool
        # output) decides whether the objective's flags are in hand. It is read
        # every turn, so a flag captured after the previous turn is announced on
        # the very next prompt instead of when the budget runs out.
        self._refresh_target_reached()
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

    def _note_observed_flags(self) -> None:
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
        arguments = getattr(self.action, "arguments", None) or {}
        target = str(
            arguments.get("target") or arguments.get("url") or arguments.get("host") or ""
        )
        for token in tokens:
            if token in self.captured_flag_refs:
                continue
            self.captured_flag_refs[token] = {
                "flag": token,
                "ref": str(getattr(self.action, "tool_id", "") or ""),
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
        """Every fact of the engagement (never raises)."""
        if not self.engagement_id or not getattr(self, "store", None):
            return []
        try:
            from nexus_core.kernel.blackboard import Blackboard

            return list(Blackboard(self.store).list_facts(self.tenant_id, self.engagement_id))
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
            store=self.store,
            tenant_id=self.tenant_id,
            no_progress=self.consecutive_no_progress,
            stuck_threshold=self.stuck_threshold,
            same_tool_no_progress=self.same_tool_no_progress,
            target_reached=self.target_reached,
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
            response = await _complete_turn(self.llm_client, self.messages, self.config)
        except ProviderFailure as exc:
            # A provider failure raised directly by the client ends the run with
            # a typed terminal status instead of escaping ``run()`` (B8.2).
            return self._provider_error_stop(
                exc, estimated=estimated, started=reasoning_started, reservation=reservation
            )
        except Exception as exc:
            # The failed turn still carries what it cost (the estimate) and how
            # long the provider took before it died; the run closes with the
            # terminal status instead of propagating ``ProviderFailure`` (B8.2).
            return self._provider_error_stop(
                ProviderFailure(type(exc).__name__),
                estimated=estimated,
                started=reasoning_started,
                reservation=reservation,
            )
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
                f"Tu respuesta anterior no era JSON válido y no se ejecutó nada. Error del parser: {str(exc)[:300]}. Responde de nuevo con UN solo objeto JSON que cumpla el contrato (tool_call, task_complete o request_clarification).",
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
            },
        )
        self.telemetry.note_action(
            action=self.action.action,
            tool_id=getattr(self.action, "tool_id", None),
            arguments=getattr(self.action, "arguments", None),
        )
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

    def _check_tool(self) -> Transition:
        if self.action.tool_id not in self.catalog:
            self.observation = {
                "success": False,
                "error": f"tool '{self.action.tool_id}' does not exist in the catalog",
                "available_tools": sorted(self.catalog),
            }
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
                self.subagent, self.unavailable_tools, self.consecutive_failures
            ):
                self.status = STATUS_FAILED
                self.final_summary = f"aborted after {self.consecutive_failures} consecutive tool failures (last: unknown tool '{self.action.tool_id}'; no usable tools remain for subagent '{self.subagent.id}')"
                return Transition.STOP
            self.consecutive_failures = 0
            return Transition.NEXT_TURN
        if not permits(self.subagent, self.action.tool_id, self.catalog.get(self.action.tool_id)):
            self.observation = {
                "success": False,
                "error": f"tool '{self.action.tool_id}' is outside subagent '{self.subagent.id}' subset",
                "subagent_id": self.subagent.id,
                "available_tools": sorted(self.allowed_catalog),
            }
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
                self.subagent, self.unavailable_tools, self.consecutive_failures
            ):
                self.status = STATUS_FAILED
                self.final_summary = f"aborted after {self.consecutive_failures} consecutive tool failures (last: '{self.action.tool_id}' outside subagent '{self.subagent.id}'; no usable tools remain)"
                return Transition.STOP
            self.consecutive_failures = 0
            return Transition.NEXT_TURN
        if self.action.tool_id in self.unavailable_tools:
            self.observation = {
                "success": False,
                "tool_id": self.action.tool_id,
                "error": f"tool '{self.action.tool_id}' is unavailable after repeated failures; use another tool from the available list",
                "subagent_id": self.subagent.id,
                "available_tools": sorted(self.allowed_catalog),
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
            self.audit_step(
                iteration=self.iteration,
                action=self.action.action,
                decision="deny",
                tool_id=self.action.tool_id,
                reason="tool_unavailable",
            )
            return Transition.NEXT_TURN
        return Transition.READY

    def _approve_tool(self) -> Transition:
        assert isinstance(self.action, ToolCall)
        resolved = self.catalog[self.action.tool_id]
        definition = resolved[0] if isinstance(resolved, tuple) else resolved
        self.tool_payload = {
            "tool_id": self.action.tool_id,
            "arguments": dict(self.action.arguments or {}),
            "identity": self.payload.get("identity") or {},
            "engagement_id": self.engagement_id,
            "permissions": tuple(self.payload.get("permissions") or ()),
            "approval_id": self.payload.get("approval_id"),
            "trace_id": self.run_id,
            "session_id": self.conversation_id,
            "phase": getattr(self.plan, "current", "") or "",
            "objective": self.objective,
        }
        from nexus_core.kernel.job_authority import JobAuthority

        self.tool_payload["job_authority"] = JobAuthority(
            run_id=self.run_id, engagement_id=self.engagement_id or "", profile_id=self.subagent.id,
            tools=tuple(sorted(self.subagent.tools)),
            token_budget=self.subagent.token_budget,
            run_token_budget=max(0, self.budget),
            job_limit=max(0, self.subagent.max_iterations - self.subagent_iterations),
        ).model_dump(mode="json")
        if self.config.on_approval_needed is not None:
            denial = self.approval_coordinator.review(
                config=self.config,
                context=self.context,
                definition=definition,
                tool_payload=self.tool_payload,
            )
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

    def _correct_repeated_action(self, tool_id: str) -> Transition:
        """Answer an identical repeat of a failed action with a correction (V1-26).

        The turn is a normal turn of the loop -it consumes the iteration and the
        tokens of the active subagent- and it never reaches the gateway. The policy
        gate of the turn (``_approve_tool``) already ran; what is avoided here is the
        journal's ``retry:invocation:<id>`` approval for an unknown outcome, which a
        ``--trust-mode`` run cannot grant and which closed the rerun #7 as
        ``blocked``. So no approval is requested or consumed and the run continues:
        the model gets text telling it what to do next, never a silent refusal.
        """
        self.telemetry.flag(FrictionFlag.REPEATED_ACTION)
        correction = repeated_action_correction(tool_id)
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
            reason="repeated_failed_action",
        )
        return Transition.NEXT_TURN

    async def _execute_tool(self) -> Transition:
        repeated_tool = self._repeated_failed_action()
        if repeated_tool is not None:
            return self._correct_repeated_action(repeated_tool)
        tool_started = time.perf_counter()
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
            self.status = STATUS_SCOPE_VIOLATION
            self.final_summary = f"scope violation aborted the loop: {exc}"
            self.observation = {
                "success": False,
                "error_type": type(exc).__name__,
                "error": str(exc)[:500],
                "scope_violation": True,
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
                "react.scope_violation",
                {
                    "iteration": self.iteration,
                    "tool_id": self.action.tool_id,
                    "error": str(exc)[:500],
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
            return Transition.STOP
        except Exception as exc:
            self.telemetry.note_tool(
                duration_ms=_elapsed_ms(tool_started),
                success=False,
                error_type=type(exc).__name__,
            )
            if isinstance(exc, PermissionError):
                self.status = (
                    "blocked" if isinstance(exc, ApprovalRequired) else "governance_denial"
                )
                self.final_summary = str(exc)
                self.observation = {
                    "success": False,
                    "error_type": type(exc).__name__,
                    "error": str(exc),
                    "failure_kind": "governance",
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
                self.audit_step(
                    iteration=self.iteration,
                    action=self.action.action,
                    decision="deny",
                    tool_id=self.action.tool_id,
                    reason=self.status,
                )
                return Transition.STOP
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
                self.consecutive_failures = 0
                self.run_evidence.extend(self.observation.get("assertions") or [])
                del self.run_evidence[:-RUN_EVIDENCE_MAX_OBSERVATIONS]
            else:
                failure_outcome = str(self.observation.get("outcome") or "")
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
            self.subagent, self.unavailable_tools, self.consecutive_failures
        ):
            self.status = STATUS_FAILED
            self.final_summary = f"aborted after {self.consecutive_failures} consecutive tool failures (no usable tools remain for subagent '{self.subagent.id}')"
            return Transition.STOP
        if self.consecutive_failures >= MAX_CONSECUTIVE_TOOL_FAILURES:
            self.consecutive_failures = 0
        return Transition.READY

    def _note_tool_failure(self, tool_id: str) -> int:
        """Count one *tool* failure and retire the tool once it is exhausted (B3).

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
        """
        if not self.engagement_id or not getattr(self, "store", None):
            return None
        try:
            from nexus_core.kernel.blackboard import Blackboard

            summary = Blackboard(self.store).summary(self.tenant_id, self.engagement_id)
            counts = summary.get("counts") if isinstance(summary, dict) else None
            if isinstance(counts, dict):
                return {str(key): int(value or 0) for key, value in counts.items()}
        except Exception:  # noqa: BLE001 - telemetry must never abort a run
            return None
        return None

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
        self.consecutive_no_progress = self.consecutive_no_progress + 1 if delta <= 0 else 0
        self.telemetry.note_no_progress(consecutive=self.consecutive_no_progress)
        self._track_repeated_tool(delta)
        threshold = self.stuck_threshold
        if threshold <= 0 or self.consecutive_no_progress < threshold:
            return
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
            completion_objections=list(self.completion_objections),
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
        if await self._request_action() is Transition.STOP:
            return Transition.STOP
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
            return self._force_target_completion()
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
