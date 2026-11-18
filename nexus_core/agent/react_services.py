"""Independent ReAct services with explicit inputs and no coordinator imports."""

from __future__ import annotations
import asyncio
from dataclasses import dataclass, field
from typing import Any, TypeVar
from collections.abc import Awaitable, Mapping, Set
from nexus_core.kernel.control_store import ControlStore
from nexus_core.kernel.credentials import available_credentials_for
from nexus_core.kernel.runtime import ExecutionContext
from nexus_core.kernel.models import ToolDefinition
from nexus_core.scope import EngagementScope
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from nexus_core.hooks import HookRunner
from .coverage import (
    Coverage,
    load_graph_context,
    parse_directive,
    render_coverage,
)
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
from .prompts import (
    CATALOG_REFRESH_TURNS,
    describe_scope,
    render_available_credentials,
    render_system_prompt,
)
from .react_types import (
    DEFAULT_STUCK_THRESHOLD,
    SKILL_NUDGE_PROMPT,
    SKILL_NUDGE_TURNS,
    STUCK_PROMPT_LINE,
    TARGET_REACHED_PROMPT,
    WRAP_UP_PROMPT,
)
from .project_context import render_project_instruction
from .skills import default_skills_root, discover_skills, render_skill_index, render_skills
from .evidence import annotate_findings


def _skills_root() -> str:
    """Catalogue directory shared by the prompt index and ``nexus.skill.*``."""
    return str(default_skills_root())


def _skills_secret() -> str | None:
    """Shared HMAC secret used to verify signed skills (``None`` when absent).

    Imported lazily: the kernel loader pulls the scope layer, and the ReAct
    services must stay importable without a store.
    """
    from nexus_core.kernel.scope_loader import scope_signing_secret

    return scope_signing_secret()


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
    #: Deterministic ledger of the discovered services (``coverage.py``). It is
    #: carried with the snapshot so the prompt and the loop's pivot rule read
    #: the *same* board image of this turn, and so a caller without a store (a
    #: test, the CLI) gets an empty ledger instead of an error.
    coverage: Coverage = field(default_factory=Coverage)
    #: Bounded view of ``kernel_fact_edges``: which services hang from a host and
    #: where a credential came from (Fase 3). Empty when the engagement has no
    #: edges yet, so a pre-graph board pays nothing.
    asset_graph: str = ""


class ContextBuilder:
    def __init__(self) -> None:
        #: Last subagent the catalog was rendered for. A phase change swaps the
        #: allowed tools, so the full catalog is re-sent once instead of leaving
        #: the model without the argument contract of the new set.
        self._last_subagent_id: str | None = None

    def full_catalog_for(self, *, iteration: int, subagent: SubAgentDefinition) -> bool:
        """Whether this turn gets the full tool catalog (see prompts.py).

        Four turns out of five carry the abbreviated catalog; the first turn,
        every ``CATALOG_REFRESH_TURNS`` and any subagent change carry the full
        one. Measured on the 72-tool catalog: 15 780 chars full vs 7 774
        compact, i.e. ~2 000 tokens per turn of the ~10 600 Simple CTF paid.
        """
        subagent_id = str(getattr(subagent, "id", "") or "")
        changed = self._last_subagent_id is not None and subagent_id != self._last_subagent_id
        self._last_subagent_id = subagent_id
        return iteration <= 1 or changed or iteration % CATALOG_REFRESH_TURNS == 0

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
        # One board read feeds both the ledger and the graph view, so the prompt
        # and the pivot rule see the same image of the turn.
        coverage, asset_graph = load_graph_context(store, tenant_id, engagement_id)
        return ContextSnapshot(
            run_history,
            history_summary,
            plan,
            facts_text,
            run_id,
            coverage=coverage,
            asset_graph=asset_graph,
        )

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
        #: Skills whose body must travel this turn (R2). ``None`` renders every
        #: body, which is the historical behaviour; the loop passes only the
        #: skills it has not delivered yet.
        skill_bodies: Set[str] | None = None,
        store: ControlStore,
        tenant_id: str,
        no_progress: int = 0,
        stuck_threshold: int = DEFAULT_STUCK_THRESHOLD,
        same_tool_no_progress: int = 0,
        target_reached: bool = False,
        iteration: int = 0,
        budget_hint: str = "",
        webshell_hint: str = "",
        coverage_hint: str = "",
        robots_hint: str = "",
        login_hint: str = "",
        reflection_hint: str = "",
        pivot_hint: str = "",
        engagement_plan_summary: str = "",
        #: Work-time budget: inside the wrap-up window the prompt orders the
        #: closure and names the remaining minutes. ``False`` keeps the historical
        #: prompt byte-for-byte (the budget is opt-in).
        wrap_up: bool = False,
        wrap_up_seconds: int = 0,
    ) -> list[LLMMessage]:
        full_catalog = self.full_catalog_for(iteration=iteration, subagent=subagent)
        history_summary, plan, facts_text = (
            snapshot.history_summary,
            snapshot.plan,
            snapshot.facts_text,
        )
        run_history = snapshot.run_history
        # Fix 2.3: the handles the engine could inject, as data the model can
        # copy into `credential_ref` instead of retyping a secret. Three per
        # host, newest first; empty when the board has none (so a run without
        # credentials pays nothing).
        credential_hint = render_available_credentials(
            available_credentials_for(store, tenant_id, str(engagement_id or ""))
        )
        # Tool hiding: el modelo solo ve el perfil por defecto (shell.exec,
        # execute_and_parse, workspace.read, skill.load, create_plan) más lo que
        # este run haya activado descubriendo un grupo o cargando una skill. El
        # catálogo durable sigue siendo la autoridad del gateway y la auditoría.
        from nexus_core.tools.profiles import visible_catalog

        prompt_catalog = visible_catalog(allowed_catalog, run_id=snapshot.run_id)
        system_prompt = render_system_prompt(
            catalog=prompt_catalog,
            objective=objective,
            engagement_id=engagement_id,
            scope_summary=describe_scope(scope),
            history_summary=history_summary or "(sin historial previo)",
            facts_summary=facts_text,
            available_credentials=credential_hint,
            plan_summary=plan.render(),
            # The engagement's own TODO contract (``loot/ENGAGEMENT_PLAN.md``),
            # reconciled against the board before this turn: every profile sees
            # the same checklist, so a subagent knows what the run still owes.
            engagement_plan_summary=engagement_plan_summary,
            # The operator's objective outranks the ledger: the frontier may only
            # suggest a branch the objective allows (V15 obeyed the pivot into a
            # service the same objective had excluded).
            coverage_summary="\n\n".join(
                block
                for block in (
                    render_coverage(
                        snapshot.coverage, directive=parse_directive(objective)
                    ),
                    snapshot.asset_graph,
                )
                if block
            ),
            subagent_summary=subagent.describe(),
            # WP2: the single ``omni`` profile is unrestricted, and the system
            # message must not claim a per-phase subset it does not enforce.
            subagent_unrestricted=bool(getattr(subagent, "unrestricted", False)),
            project_summary=render_project_instruction(project_instruction),
            skills_summary=render_skills(active_skills, bodies=skill_bodies),
            # The catalogue is read on every turn, so a skill created during the
            # engagement is loadable without restarting the run (WP4).
            # One resolution for the prompt and for ``nexus.skill.load``: the
            # installation's catalogue (or ``NEXUS_SKILLS_ROOT``), never the
            # engagement workspace the CLI happens to run from. The index names
            # the directory it read when it is empty, so "no skills" is never
            # confused with "wrong root".
            skill_index=render_skill_index(
                discover_skills(secret=_skills_secret()), catalogue=_skills_root()
            ),
            playbook_summary=_playbook_guidance(store, tenant_id, engagement_id, run_id=snapshot.run_id),
            full_catalog=full_catalog,
        )
        # A stalled loop (no new verified fact for N turns) gets one explicit
        # line: measured in run_abe04509c5064c6e8e475f46ba8f8c60, ten such turns
        # went by with the same instruction and no pivot (Fase 3 fixes).
        if stuck_threshold > 0 and no_progress >= stuck_threshold:
            system_prompt = (
                f"{system_prompt}\n\n"
                + STUCK_PROMPT_LINE.format(iterations=int(no_progress))
            )
        # A model repeating one tool with no new fact is the concrete stall a
        # skill can break (WP4): telling it *that* it is stuck is not enough, it
        # needs the way out (the index) and the recipe behind it.
        if same_tool_no_progress >= SKILL_NUDGE_TURNS:
            system_prompt = f"{system_prompt}\n\n{SKILL_NUDGE_PROMPT}"
        # Smart budget (Simple CTF 2026-10-18): a wide, still-unexploited surface
        # after ten turns is the measured token sink. The rule lives in the
        # planner (deterministic, unit-tested); the loop only injects its text.
        if budget_hint:
            system_prompt = f"{system_prompt}\n\n{budget_hint}"
        # A build/transfer loop pushed through a webshell is the measured
        # Vulnversity stall (35 turns compiling `pwnkit` via curl): the rule lives
        # in the planner and the prompt carries the interactive way out.
        if webshell_hint:
            system_prompt = f"{system_prompt}\n\n{webshell_hint}"
        # The surface ledger's correction: a run that keeps attacking a service
        # already documented as a dead end, or that burns turns while another
        # service is still unexplored, gets one explicit order to switch branch
        # (``coverage.pivot_hint``, deterministic and unit-tested).
        if coverage_hint:
            system_prompt = f"{system_prompt}\n\n{coverage_hint}"
        # Reading ``robots.txt``/``sitemap.xml`` is not following them. The rule
        # lives in the planner (``robots_paths_hint``, deterministic and tested);
        # the loop only injects the order naming the routes still unvisited, so
        # the branch cannot be closed with the index half-read.
        if robots_hint:
            system_prompt = f"{system_prompt}\n\n{robots_hint}"
        # A login form read but never probed: enumerating the directory tree
        # first is the documented order, and it was measured to burn 5 and 30
        # minutes on wordlists while the form accepted `admin'-- -`. The rule
        # lives in the planner (``login_probe_hint``, deterministic).
        if login_hint:
            system_prompt = f"{system_prompt}\n\n{login_hint}"
        # B3: the run is stalled and the board holds verified facts its actions
        # never touched (a credential, a confirmed account, a proven path). The
        # rule lives in ``agent/reflection.py`` (deterministic substring over the
        # action history); the loop only injects the text.
        if reflection_hint:
            system_prompt = f"{system_prompt}\n\n{reflection_hint}"
        # The board proves access on one host and the run aims at another
        # network: the order names the tunnel command, because a local tool has
        # no route and its "filtered" is noise (DeadDrop P8, 19 iterations).
        if pivot_hint:
            system_prompt = f"{system_prompt}\n\n{pivot_hint}"
        # WP5: the objective's flags are in hand. The model still decides how to
        # close -the loop only forbids more exploration and orders the closure-;
        # if it ignores the order for the whole margin, the loop closes itself.
        if target_reached:
            system_prompt = f"{system_prompt}\n\n{TARGET_REACHED_PROMPT}"
        # Work-time budget: the last minutes are for the deliverable. The rule is
        # injected last so it outranks every hint that asks for more exploration.
        if wrap_up:
            minutes = max(1, int(round(wrap_up_seconds / 60)))
            system_prompt = f"{system_prompt}\n\n{WRAP_UP_PROMPT.format(minutes=minutes)}"
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
        engagement_plan: Any = None,
        require_plan_first: bool = False,
        micro_task: bool = False,
        background_tasks: list[dict[str, Any]] | None = None,
    ) -> CompletionAssessment:
        from nexus_core.kernel.blackboard import Blackboard, is_verified_fact

        annotated, stats = annotate_findings(findings, observations=observations, run_id=run_id)
        objections = _completion_objections(
            plan,
            enforce_completion_gates=config.enforce_completion_gates,
            evidence_stats=stats,
            engagement_id=engagement_id,
            require_plan_phase=require_plan_phase,
            engagement_plan=engagement_plan,
            require_plan_first=require_plan_first,
            # Fase 1: una micro-tarea ("solo escanea puertos") cierra cuando su
            # acción está hecha; el plan global del engagement es contexto.
            micro_task=micro_task,
            # Tarea 1: un cierre con un job en vuelo mataba el escaneo al salir
            # del proceso; la objeción lo rechaza y nombra la entrega automática.
            background_tasks=background_tasks,
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
