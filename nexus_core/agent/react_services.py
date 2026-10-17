"""Independent ReAct services with explicit inputs and no coordinator imports."""

from __future__ import annotations
import asyncio
from dataclasses import dataclass
from typing import Any, TypeVar
from collections.abc import Awaitable, Mapping
from nexus_core.kernel.control_store import ControlStore
from nexus_core.kernel.runtime import ExecutionContext
from nexus_core.kernel.models import ToolDefinition
from nexus_core.scope import EngagementScope
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from nexus_core.hooks import HookRunner
from .planner import Plan
from .subagents import SubAgentDefinition
from .project_context import ProjectInstruction
from .skills import Skill

T = TypeVar("T")
from nexus_core.kernel.domain_dto import Action
from nexus_core.llm.abstraction import LLMMessage
from . import memory
from .parser import parse_react_response
from .react_types import ReActConfig
from .react_support import (
    _run_messages,
    _blackboard_view,
    _playbook_guidance,
    with_kickoff_user_turn,
    _completion_objections,
)
from .observations import bounded_context
from .injection import render_for_model
from .prompts import render_system_prompt, describe_scope
from .react_types import DEFAULT_STUCK_THRESHOLD, STUCK_PROMPT_LINE
from .project_context import render_project_instruction
from .skills import render_skills
from .evidence import annotate_findings


class ActionDecoder:
    def decode(self, text: str) -> Action:
        action: Action = parse_react_response(text)
        return action


class ApprovalCoordinator:
    def review(
        self,
        *,
        config: ReActConfig,
        context: ExecutionContext,
        definition: ToolDefinition,
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
        from nexus_core.kernel.operator_mode import OperatorMode

        decision = OperatorMode(context.store).constrain(run_context, definition, decision)
        if not decision.allowed:
            raise PermissionError(decision.reason)
        if not decision.requires_approval or config.on_approval_needed is None:
            return None

        legacy_answer = config.on_approval_needed(
            tool_id, dict(tool_payload["arguments"]), decision
        )
        answer = legacy_answer.to_dto() if legacy_answer is not None else None
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


class ToolExecutionService:
    async def execute(
        self,
        payload: dict[str, Any],
        context: ExecutionContext,
        *,
        timeout: float,
        cancel_event: asyncio.Event | None,
    ) -> tuple[dict[str, Any] | None, bool]:
        from nexus_core.kernel.runtime import execute_tool

        return await self.await_tool(
            execute_tool(payload, context), timeout=timeout, cancel_event=cancel_event
        )

    async def await_tool(
        self,
        awaitable: Awaitable[T],
        *,
        timeout: float,
        cancel_event: asyncio.Event | None,
    ) -> tuple[T | None, bool]:
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
            if not task.done():
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)
            if not cancel_waiter.done():
                cancel_waiter.cancel()
                await asyncio.gather(cancel_waiter, return_exceptions=True)


@dataclass(frozen=True)
class ContextSnapshot:
    run_history: list[dict[str, Any]]
    history_summary: str
    plan: Plan
    facts_text: str
    run_id: str = ""


class ContextBuilder:
    async def gather(
        self,
        *,
        store: ControlStore,
        tenant_id: str,
        run_id: str,
        conversation_id: str,
        llm_client: Any,
        config: ReActConfig,
        hooks: HookRunner,
        engagement_id: str | None,
        phase_turns: Mapping[str, int] | None = None,
    ) -> ContextSnapshot:
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
                pre_compact=lambda: hooks.emit("pre_compact", conversation_id=conversation_id),
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
            history_summary = f"{base}\n\nObjetivos previos de esta sesión de trabajo:\n{bullets}"

        plan, facts_text = _blackboard_view(
            store, tenant_id, engagement_id, phase_turns=phase_turns
        )
        return ContextSnapshot(run_history, history_summary, plan, facts_text, run_id)

    def render(
        self,
        snapshot: ContextSnapshot,
        *,
        allowed_catalog: dict[str, Any],
        objective: str,
        engagement_id: str | None,
        scope: EngagementScope | None,
        subagent: SubAgentDefinition,
        project_instruction: ProjectInstruction | None,
        active_skills: list[Skill],
        store: ControlStore,
        tenant_id: str,
        no_progress: int = 0,
        stuck_threshold: int = DEFAULT_STUCK_THRESHOLD,
    ) -> list[LLMMessage]:
        history_summary, plan, facts_text = (
            snapshot.history_summary,
            snapshot.plan,
            snapshot.facts_text,
        )
        run_history = snapshot.run_history
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
            playbook_summary=_playbook_guidance(store, tenant_id, engagement_id, run_id=snapshot.run_id),
        )
        # A stalled loop (no new verified fact for N turns) gets one explicit
        # line: measured in run_abe04509c5064c6e8e475f46ba8f8c60, ten such turns
        # went by with the same instruction and no pivot (Fase 3 fixes).
        if stuck_threshold > 0 and no_progress >= stuck_threshold:
            system_prompt = (
                f"{system_prompt}\n\n"
                + STUCK_PROMPT_LINE.format(iterations=int(no_progress))
            )
        messages: list[LLMMessage] = [LLMMessage(role="system", content=system_prompt)]
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

        return messages


@dataclass(frozen=True)
class CompletionAssessment:
    findings: list[dict[str, Any]]
    #: ``annotate_findings`` payload: integer counters plus, since V1-48, the
    #: ``rejected_findings`` detail list (which is why this is not ``dict[str, int]``).
    evidence_stats: dict[str, Any]
    objections: list[str]


class CompletionVerifier:
    async def verify(
        self,
        *,
        findings: list[dict[str, Any]],
        observations: list[dict[str, Any]],
        run_id: str,
        plan: Plan,
        config: ReActConfig,
        engagement_id: str | None,
        store: ControlStore,
        tenant_id: str,
        hooks: HookRunner,
        objective: str,
        require_plan_phase: bool = True,
    ) -> CompletionAssessment:
        from nexus_core.kernel.blackboard import Blackboard, is_verified_fact

        annotated, stats = annotate_findings(findings, observations=observations, run_id=run_id)
        objections = _completion_objections(
            plan,
            enforce_completion_gates=config.enforce_completion_gates,
            evidence_stats=stats,
            engagement_id=engagement_id,
            require_plan_phase=require_plan_phase,
        )
        facts = (
            [
                fact
                for fact in Blackboard(store).list_facts(tenant_id, engagement_id)
                if is_verified_fact(fact)
            ]
            if engagement_id
            else []
        )
        objections.extend(
            await hooks.verify_stop(
                findings=annotated, facts_verified=facts, phase=plan.current, objective=objective
            )
        )
        return CompletionAssessment(annotated, stats, objections)
