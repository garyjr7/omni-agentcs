"""Public ReAct entry point; implementation lives in services and coordinator."""

from __future__ import annotations
import asyncio
import os
from typing import Any
from . import memory
from .preflight import unavailable_tools_from_env as unavailable_tools_from_env
from .react_coordinator import ReActCoordinator as ReActCoordinator
from .react_types import (
    DEFAULT_AGENT_ID as DEFAULT_AGENT_ID,
    MAX_CONSECUTIVE_TOOL_FAILURES as MAX_CONSECUTIVE_TOOL_FAILURES,
    CANCEL_EVENT_TYPE as CANCEL_EVENT_TYPE,
    MAX_TOOL_FAILURES_BEFORE_UNAVAILABLE as MAX_TOOL_FAILURES_BEFORE_UNAVAILABLE,
    TOOL_UNAVAILABLE_EVENT_TYPE as TOOL_UNAVAILABLE_EVENT_TYPE,
    PHASE_TIMEOUT_EVENT_TYPE as PHASE_TIMEOUT_EVENT_TYPE,
    PHASE_TIMEOUT_ENV as PHASE_TIMEOUT_ENV,
    STUCK_EVENT_TYPE as STUCK_EVENT_TYPE,
    STUCK_THRESHOLD_ENV as STUCK_THRESHOLD_ENV,
    DEFAULT_STUCK_THRESHOLD as DEFAULT_STUCK_THRESHOLD,
    STUCK_PROMPT_LINE as STUCK_PROMPT_LINE,
    REACT_MAX_TOKENS_ENV as REACT_MAX_TOKENS_ENV,
    REACT_DEFAULT_MAX_TOKENS as REACT_DEFAULT_MAX_TOKENS,
    REACT_MIN_MAX_TOKENS as REACT_MIN_MAX_TOKENS,
    KICKOFF_USER_PROMPT as KICKOFF_USER_PROMPT,
    FINAL_PHASE_ID as FINAL_PHASE_ID,
    PREMATURE_COMPLETION_EVENT_TYPE as PREMATURE_COMPLETION_EVENT_TYPE,
    MAX_PREMATURE_COMPLETIONS as MAX_PREMATURE_COMPLETIONS,
    RUN_EVIDENCE_MAX_OBSERVATIONS as RUN_EVIDENCE_MAX_OBSERVATIONS,
    STATUS_COMPLETED as STATUS_COMPLETED,
    STATUS_MAX_ITERATIONS as STATUS_MAX_ITERATIONS,
    STATUS_CLARIFICATION as STATUS_CLARIFICATION,
    STATUS_FAILED as STATUS_FAILED,
    STATUS_PREMATURE_COMPLETION as STATUS_PREMATURE_COMPLETION,
    STATUS_CANCELLED as STATUS_CANCELLED,
    STATUS_SCOPE_VIOLATION as STATUS_SCOPE_VIOLATION,
    STATUS_BLOCKED as STATUS_BLOCKED,
    STATUS_BUDGET_EXCEEDED as STATUS_BUDGET_EXCEEDED,
    STATUS_SUBAGENT_BUDGET as STATUS_SUBAGENT_BUDGET,
    SUBAGENT_EVENT_TYPE as SUBAGENT_EVENT_TYPE,
    BUDGET_EVENT_TYPE as BUDGET_EVENT_TYPE,
    BUDGET_SUBJECT_TYPE as BUDGET_SUBJECT_TYPE,
    BUDGET_SUBJECT_ID as BUDGET_SUBJECT_ID,
    BUDGET_METRIC as BUDGET_METRIC,
    OBJECTIVE_GRACE_EVENT_TYPE as OBJECTIVE_GRACE_EVENT_TYPE,
    BUDGET_GRACE_EVENT_TYPE as BUDGET_GRACE_EVENT_TYPE,
    OBJECTIVE_GRACE_TURNS as OBJECTIVE_GRACE_TURNS,
    SUBAGENT_SOFT_LIMIT_EVENT_TYPE as SUBAGENT_SOFT_LIMIT_EVENT_TYPE,
    TARGET_REACHED_EVENT_TYPE as TARGET_REACHED_EVENT_TYPE,
    TARGET_REACHED_FORCED_EVENT_TYPE as TARGET_REACHED_FORCED_EVENT_TYPE,
    TARGET_REACHED_GRACE_TURNS as TARGET_REACHED_GRACE_TURNS,
    TARGET_REACHED_PROMPT as TARGET_REACHED_PROMPT,
    ApprovalDecision as ApprovalDecision,
    ReActConfig as ReActConfig,
    ReActResult as ReActResult,
)
from .react_support import (
    _task_payload as _task_payload,
    stuck_threshold as stuck_threshold,
    _cancellation_requested as _cancellation_requested,
    _blackboard_facts as _blackboard_facts,
    _blackboard_view as _blackboard_view,
    _playbook_guidance as _playbook_guidance,
    _audit_step as _audit_step,
    _failure_kind as _failure_kind,
    _phase_timeout_seconds as _phase_timeout_seconds,
    react_max_tokens as react_max_tokens,
    _usable_tool_count as _usable_tool_count,
    _keep_going_after_failures as _keep_going_after_failures,
    _remaining_tools as _remaining_tools,
    _run_messages as _run_messages,
    _completion_objections as _completion_objections,
    missing_evidence as missing_evidence,
    DEFAULT_RUN_BUDGET_TOKENS as DEFAULT_RUN_BUDGET_TOKENS,
    with_kickoff_user_turn as with_kickoff_user_turn,
    _premature_completion_message as _premature_completion_message,
    _persisted_actions as _persisted_actions,
    _last_persisted_iteration as _last_persisted_iteration,
    _action_entry as _action_entry,
    _operator_approval_gate as _operator_approval_gate,
    _observation_payload as _observation_payload,
    _budget_tokens as _budget_tokens,
    _budget_used as _budget_used,
    subagent_budget_subject as subagent_budget_subject,
    extract_partial_thought as extract_partial_thought,
    _notify as _notify,
    _complete_turn as _complete_turn,
    _record_response_tokens as _record_response_tokens,
    _await_tool as _await_tool,
    _estimate_request_tokens as _estimate_request_tokens,
    _inject_observation as _inject_observation,
    _maybe_autospawn as _maybe_autospawn,
)
from .parser import ReActAction as ReActAction


async def _run_react_loop_impl(
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
) -> ReActResult:
    return await ReActCoordinator(
        context=context,
        objective=objective,
        engagement_id=engagement_id,
        llm_client=llm_client,
        config=config,
        tool_catalog=tool_catalog,
        conversation_id=conversation_id,
        budget_tokens=budget_tokens,
        cancel_event=cancel_event,
        isolated_child=isolated_child,
        phase_timeout_seconds=_phase_timeout_seconds(),
        initial_unavailable_tools=unavailable_tools_from_env(),
    ).run()


async def _reap_pty_sessions(context: Any) -> None:
    """Close this run's tmux sessions before ``session_end`` (P0.5).

    A PTY survives the call that created it by design; it must not survive the
    run. Cleanup is best-effort: no tmux, an already-dead server or a sandbox
    that cannot spawn must never turn a finished run into an exception.
    """
    try:
        from nexus_core.kernel.pty_sessions import PtySessionManager

        workspace = (
            str(getattr(context, "project_root", "") or "")
            or os.getenv("NEXUS_WORKSPACE_ROOT")
            or os.getcwd()
        )
        await PtySessionManager(workspace, str(getattr(context, "run_id", ""))).reap()
    except BaseException:  # noqa: BLE001 - teardown must not mask the run result
        return


async def _reap_stale_process_groups() -> None:
    """Kill the sandbox groups a previous run left behind (P0.5, orphan wall).

    A run killed by an external signal never reaches the kernel's cleanup, so
    its children keep their own session and stay alive. Measured in the DeadDrop
    campaign (2026-10-22): two ``nmap -p-`` sweeps kept attacking the target for
    over an hour after their runs were stopped. The registry verifies pid *and*
    start time before signalling, so a recycled pid is never touched.
    """
    try:
        from nexus_core.kernel.process_registry import reap_stale

        await asyncio.to_thread(reap_stale)
    except BaseException:  # noqa: BLE001 - reaping must never block a run
        return


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
    isolated_child: bool = False,
) -> ReActResult:
    """Public entry point: the engine plus a guaranteed ``session_end``.

    ``_run_react_loop_impl`` owns the ReAct mechanics. This thin wrapper adds the
    lifecycle guarantee the operator extensions depend on: ``session_end`` is
    emitted exactly once, whether the engine returns normally (``status`` is the
    terminal status) or raises (``reason="exception"``). The hook can never
    swallow the engine error: the exception is always re-raised after the audit.
    """
    from nexus_core.kernel import runtime as runtime_module
    from nexus_core.hooks import HookRunner

    payload = _task_payload(context)
    project_root = None if isolated_child else (payload.get("project_root") or None)
    hook_context = None
    try:
        # Resolve the *same* deterministic conversation the engine will use, so
        # ``session_start``/``session_end`` share a session id and building the
        # hook context never has the side effect of opening a work session.
        session_id = conversation_id or memory.ensure_conversation(
            context.store,
            context.tenant_id,
            context.run_id,
            str(payload.get("agent_id") or DEFAULT_AGENT_ID),
        )
        hook_context = runtime_module._build_run_context(
            {**payload, "engagement_id": engagement_id, "session_id": session_id},
            context,
        )
    except Exception:  # noqa: BLE001 - lifecycle telemetry must never block the engine
        hook_context = None
    hooks = (
        HookRunner(
            hook_context,
            project_root=project_root,
            engagement_id=engagement_id,
            workspace=project_root or os.getenv("NEXUS_WORKSPACE_ROOT") or os.getcwd(),
        )
        if hook_context is not None
        else None
    )
    # Before the first tool: whatever an earlier run left running is no longer
    # part of this engagement.
    await _reap_stale_process_groups()
    try:
        result = await _run_react_loop_impl(
            context=context,
            objective=objective,
            engagement_id=engagement_id,
            llm_client=llm_client,
            config=config,
            tool_catalog=tool_catalog,
            conversation_id=conversation_id,
            budget_tokens=budget_tokens,
            cancel_event=cancel_event,
            isolated_child=isolated_child,
        )
    except BaseException:
        await _reap_pty_sessions(context)
        if hooks is not None:
            await hooks.emit("session_end", status="exception", reason="exception")
        raise
    await _reap_pty_sessions(context)
    if hooks is not None:
        await hooks.emit(
            "session_end",
            status=result.status,
            iterations=result.iterations,
            reason=result.status,
        )
    return result
