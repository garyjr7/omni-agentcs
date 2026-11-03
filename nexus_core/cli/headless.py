"""Headless runner: one objective, machine-readable output, never a TUI.

``omni run "<objetivo>" --json`` prints one JSON object at the end;
``--stream-json`` prints NDJSON, one event per line, while the run happens. Both
go through the *same* durable ReAct loop as the interactive REPL — the only
differences are presentation and approvals:

* the TUI is never started (no ``prompt_toolkit`` application, no alt-screen);
* rendering is suppressed, so stdout carries only JSON/NDJSON and stays pipeable;
* approval-required tools are **denied** rather than prompted, because there is
  no human at the terminal. ``--trust-mode`` re-enables the audited auto-approval
  of high-risk (never destructive) tools.

Every emitted line carries the active ``subagent_id`` when the producer knows it,
so a CI consumer can attribute each step to the phase that proposed it.
"""

from __future__ import annotations

import asyncio
from contextlib import contextmanager
from datetime import datetime, timezone
import json
import sys
import threading
import time
from typing import Any, Iterator, TextIO

import os
from types import SimpleNamespace

from nexus_core.agent import memory
from nexus_core.agent.preflight import (
    PREFLIGHT_ENV,
    PreflightVerdict,
    env_flag,
    preflight_binaries,
)
from nexus_core.agent.react import ReActConfig, run_react_loop
from nexus_core.kernel.audit import AuditWriter
from nexus_core.kernel.runtime import ExecutionContext

#: Poll interval of the NDJSON emitter.
STREAM_INTERVAL = 0.1
#: Audit actions that are worth streaming (everything else is noise).
STREAMED_AUDIT_ACTIONS = frozenset(
    {"react.step", "tool.invoke", "tool.complete", "tool.failed", "mcp.tool_denied",
     "mcp.timeout", "mcp.unavailable", "scope.denied", "roe.denied"}
)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def write_line(stream: TextIO, payload: dict[str, Any]) -> None:
    """Write one NDJSON line (never pretty-printed, always flushed)."""
    payload.setdefault("ts", _now())
    stream.write(json.dumps(payload, ensure_ascii=False, default=str) + "\n")
    stream.flush()


EXIT_CODE_VERSION = 1


from nexus_core.kernel.errors import ApprovalRequired as ApprovalPending, ProviderFailure


def exit_code_for(status, completion_verified=False):
    if status == "completed" and completion_verified:
        return 0
    if status == "blocked":
        return 2
    if status == "provider_error":
        return 3
    if status in {"governance_denial", "scope_violation_aborted"}:
        return 4
    if status in {"cancelled", "interrupted"}:
        return 130
    return 1


def token_accounting(result: Any) -> dict[str, int]:
    """Per-turn cost and how many turns the ceiling really buys (R1).

    ``run.complete`` used to publish only ``iterations``, so an operator could not
    tell a run that spent its budget from one that spent its iterations. The
    number is measured from this run's own telemetry (never a global constant),
    and ``budget_turns`` is what the ceiling bought at that price.
    """
    turns = [turn for turn in (getattr(result, "turns", None) or []) if isinstance(turn, dict)]
    spent = sum(int(turn.get("total_tokens") or 0) for turn in turns)
    per_turn = int(round(spent / len(turns))) if turns and spent else 0
    budget = int(getattr(result, "budget_tokens", 0) or 0)
    return {
        "tokens_per_turn": per_turn,
        "tokens_spent": int(getattr(result, "budget_used", 0) or spent),
        "budget_tokens": budget,
        "budget_turns": (budget // per_turn) if (budget and per_turn) else 0,
    }


def result_payload(result: Any, run_id: str) -> dict[str, Any]:
    """The final ``run.complete`` object (also used by ``--json``)."""
    return {
        "type": "run.complete",
        "run_id": run_id,
        "status": getattr(result, "status", "unknown"),
        "termination_reason": getattr(result, "termination_reason", None) or getattr(result, "status", "unknown"),
        "completion_verified": getattr(result, "status", None) == "completed" and bool(getattr(result, "completion_verified", False)),
        "exit_code": exit_code_for(getattr(result, "status", "unknown"), bool(getattr(result, "completion_verified", False))),
        "exit_code_version": EXIT_CODE_VERSION,
        "iterations": getattr(result, "iterations", 0),
        "summary": getattr(result, "final_summary", ""),
        "findings": getattr(result, "findings", []),
        "subagent_id": getattr(result, "subagent_id", None),
        "conversation_id": getattr(result, "conversation_id", ""),
        "plan": getattr(result, "plan", None),
        **token_accounting(result),
    }


def llm_identity(session: Any) -> dict[str, str | None]:
    """Provider/model actually used, for the ``run.complete`` record (Fase 4.0).

    The run report needs to know which model produced a trace; the NDJSON did
    not carry it. Defensive: an unbuildable client reports ``None``, never raises.
    """
    client = getattr(session, "llm_client", None)
    config = getattr(client, "config", None) or getattr(
        getattr(client, "primary", None), "config", None
    )
    provider = getattr(getattr(config, "provider", None), "value", None)
    return {"provider": provider, "model": getattr(config, "model", None)}


class _EventEmitter(threading.Thread):
    """Polls the durable run events and audit trail, emitting new NDJSON lines."""

    def __init__(self, session: Any, stop: threading.Event, stream: TextIO):
        super().__init__(name="omni-ndjson", daemon=True)
        self.session = session
        self.stop = stop
        self.stream = stream
        self.state: dict[str, Any] = {"run_id": None, "events": 0, "audit": 0}
        self.error: str | None = None

    def run(self) -> None:  # pragma: no cover - exercised through emit_new
        while True:
            self.emit_new()
            if self.stop.wait(STREAM_INTERVAL):
                break
        self.emit_new()

    def emit_new(self) -> None:
        """Emit every event/audit row not yet streamed (never raises)."""
        try:
            self._emit_new()
        except Exception as exc:  # noqa: BLE001 - streaming must not break the run
            self.error = f"{type(exc).__name__}: {exc}"

    def _emit_new(self) -> None:
        run_id = getattr(self.session, "run_id", None)
        if not run_id:
            return
        if run_id != self.state["run_id"]:
            self.state.update(run_id=run_id, events=0, audit=0)
            return
        store = self.session.store
        tenant = self.session.tenant_id
        events = store.list_run_events(tenant, run_id, after=self.state["events"])
        for event in events:
            sequence = int(event.get("sequence") or 0)
            self.state["events"] = max(self.state["events"], sequence)
            payload = event.get("payload") or {}
            write_line(
                self.stream,
                {
                    "type": str(event.get("event_type") or ""),
                    "run_id": run_id,
                    "sequence": sequence,
                    "subagent_id": payload.get("subagent_id"),
                    "payload": payload,
                },
            )
        rows = [
            row
            for row in AuditWriter(store).export(tenant, trace_id=run_id)
            if str(row.get("action") or "") in STREAMED_AUDIT_ACTIONS
        ]
        for row in rows[self.state["audit"] :]:
            payload = row.get("payload") or {}
            write_line(
                self.stream,
                {
                    "type": str(row.get("action") or ""),
                    "run_id": run_id,
                    "sequence": int(row.get("sequence") or 0),
                    "decision": row.get("decision"),
                    # The loop tags every react.step with the active subagent.
                    "subagent_id": payload.get("subagent_id"),
                    "payload": payload,
                },
            )
        self.state["audit"] = len(rows)


def _run_preflight() -> PreflightVerdict | None:
    """Binaries preflight; ``NEXUS_PREFLIGHT_BINARIES=0`` disables it."""
    if not env_flag(os.environ, PREFLIGHT_ENV, default=True):
        return None
    return preflight_binaries()


#: Machine stream owned by the outermost guard (empty when it is not active).
#: The run record must keep writing to the stdout that existed *before* human
#: output was re-routed; that is why it is remembered here instead of being
#: looked up at each write.
_MACHINE_STREAM: dict[str, TextIO] = {}


@contextmanager
def human_output_on_stderr() -> Iterator[None]:
    """Keep stdout machine-readable: every human line goes to stderr (P14/P17).

    Two leaks were measured in rerun 8's NDJSON stream: the trust-mode banner
    (21 non-JSON lines in three blocks, plus three blank lines) and its ANSI
    escapes. Under ``--json``/``--stream-json`` the run record owns stdout, so
    renderers are re-routed to stderr and colour is switched off for the
    duration; the previous colour setting is restored afterwards.

    Reentrant: the CLI enters it once for the whole dispatch (so an error raised
    before the run starts also lands on stderr) and :func:`run_headless` enters
    it again. Only the outermost guard redirects, and it publishes the machine
    stream :func:`machine_stream` hands back.
    """
    from contextlib import redirect_stdout

    from .render import color_enabled, set_color_enabled
    from .tui.output import StderrOutput, route_output

    if _MACHINE_STREAM:
        yield
        return
    previous_color = color_enabled()
    set_color_enabled(False)
    _MACHINE_STREAM["stream"] = sys.stdout
    try:
        with route_output(StderrOutput()), redirect_stdout(sys.stderr):
            yield
    finally:
        _MACHINE_STREAM.clear()
        set_color_enabled(previous_color)


def machine_stream(default: TextIO | None = None) -> TextIO | None:
    """The stream that carries the run record: the pre-guard stdout when active."""
    return _MACHINE_STREAM.get("stream", default)


def run_headless(
    session: Any,
    objective: str,
    *,
    mode: str = "json",
    stream: TextIO | None = None,
    max_iterations: int | None = None,
    budget_tokens: int | None = None,
    preflight: PreflightVerdict | None = None,
) -> int:
    """Run one objective headlessly; return the process exit code.

    ``mode`` is ``"json"`` (one object at the end) or ``"stream"`` (NDJSON plus a
    final ``run.complete`` line). Only verified completion exits 0;
    ``max_iterations`` and ``clarification`` exit 1 under contract v1.

    In both headless modes stdout carries the run record and nothing else (P17);
    the body runs with human output re-routed to stderr.

    The machine stream is resolved **before** the human output is re-routed: the
    CLI calls this function without an explicit stream, so looking ``sys.stdout``
    up inside the guard would hand the run record the stderr that the guard just
    installed -NDJSON on fd 2 and an empty stdout for the consumer.
    """
    if mode in {"json", "stream"}:
        with human_output_on_stderr():
            return _run_headless(
                session,
                objective,
                mode=mode,
                stream=stream if stream is not None else machine_stream(),
                max_iterations=max_iterations,
                budget_tokens=budget_tokens,
                preflight=preflight,
            )
    return _run_headless(
        session,
        objective,
        mode=mode,
        stream=stream,
        max_iterations=max_iterations,
        budget_tokens=budget_tokens,
        preflight=preflight,
    )


def _run_headless(
    session: Any,
    objective: str,
    *,
    mode: str = "json",
    stream: TextIO | None = None,
    max_iterations: int | None = None,
    budget_tokens: int | None = None,
    preflight: PreflightVerdict | None = None,
) -> int:
    """Body of :func:`run_headless` (already inside the stdout guard)."""
    out = stream if stream is not None else sys.stdout
    objective = str(objective or "").strip()
    if not objective:
        payload = result_payload(SimpleNamespace(status="incomplete", termination_reason="invalid_objective"), "")
        write_line(out, payload)
        return payload["exit_code"]

    # Refuse to start against a wrong binary: it burns tokens and then fails
    # with an opaque post-condition error (B1). The operator can opt into a
    # degraded run with NEXUS_ALLOW_DEGRADED_TOOLS=1.
    from nexus_core.kernel.sandbox_modes import SandboxPolicy, UnknownSandboxMode, SandboxModeMismatch, SandboxModeNotImplemented
    try:
        SandboxPolicy.resolve()
        verdict = preflight if preflight is not None else _run_preflight()
    except (UnknownSandboxMode, SandboxModeMismatch, SandboxModeNotImplemented) as exc:
        payload = result_payload(SimpleNamespace(status="governance_denial", final_summary=str(exc)), "")
        write_line(out, payload)
        return payload["exit_code"]
    if verdict is not None and not verdict.ok:
        payload = result_payload(SimpleNamespace(status="incomplete", termination_reason="preflight_failed",
                                                final_summary=verdict.message()), "")
        write_line(out, payload)
        return payload["exit_code"]
    if verdict is not None and verdict.problems and verdict.degraded:
        write_line(
            out,
            {
                "type": "run.preflight_degraded",
                "problems": [problem.to_dict() for problem in verdict.problems],
            },
        )

    raw_iterations: Any = max_iterations or getattr(session, "max_iterations", 20)
    iterations = int(raw_iterations)

    run_id = str(
        session.store.create_run(
            session.tenant_id,
            {"source": "omni-headless", "objective": objective,
             "engagement_id": session.engagement_id},
        )["id"]
    )
    session.run_id = run_id
    session.conversation_id = session._ensure_work_session() or memory.ensure_conversation(
        session.store, session.tenant_id, run_id, session.agent_id
    )

    task = {
        "id": f"headless-{run_id}",
        "tenant_id": session.tenant_id,
        "run_id": run_id,
        "task_type": "react.run",
        "payload": {
            "objective": objective,
            "session_id": session.conversation_id,
            "engagement_id": session.engagement_id,
            "max_iterations": iterations,
            # R1: the explicit ceiling (``--budget-tokens``). Absent, the loop
            # derives it from ``max_iterations`` so the two ceilings agree.
            **(
                {"budget_tokens": int(budget_tokens)}
                if budget_tokens is not None
                else {}
            ),
            "agent_id": session.agent_id,
            "identity": session.agent_identity_payload,
            "permissions": list(session.permissions),
            "active_skills": list(getattr(session, "active_skills", []) or []),
            # P2 (Fase 3.7): the operator pin from ``--subagent``; ``None`` lets
            # the planner choose.
            "subagent": getattr(session, "subagent_override", None),
            # P2-A2: the engagement workspace, explicit so headless hooks see the
            # same directory as REPL and worker regardless of cwd.
            "project_root": os.getenv("NEXUS_WORKSPACE_ROOT", os.getcwd()),
        },
    }
    context = ExecutionContext(session.store, task, session.worker_id)
    config = ReActConfig(
        max_iterations=iterations,
        # No human at the terminal: approvals are denied unless trust mode asked
        # for the audited auto-approval of high-risk (never destructive) tools.
        on_approval_needed=_trust_approval(session),
        # ``--resume-policy``: only a trust-mode run may replay an ``unknown``
        # invocation without asking; anything else keeps the fail-closed block.
        resume_policy=getattr(session, "effective_resume_policy", ""),
        # PLAN-FIRST: an engagement does not start by attacking. The planning
        # turn below writes the contract; this flag makes the loop hold the run
        # to it (and refuse a closure with TODOs still open).
        require_plan_first=True,
    )

    stop = threading.Event()
    emitter: _EventEmitter | None = None
    if mode == "stream":
        emitter = _EventEmitter(session, stop, out)
        emitter.start()
    started = time.monotonic()
    result: Any = None
    async def _plan_then_run() -> Any:
        """PLAN MODE (iteration 0) and then the ACT loop.

        The planning call is one extra model turn *before* any tool can touch the
        target; if it fails, the deterministic seed is written, so a headless run
        never starts without a contract (run v8 closed on the first flag).
        """
        from nexus_core.agent.engagement_plan import is_engagement_objective
        from nexus_core.agent.planning import draft_engagement_plan
        from nexus_core.llm.dynamic_selector import build_model_selector, routed_for_task

        # ``[model_routing]``, resolved once: ``None`` when the operator never
        # pinned a profile, so the run keeps the client it was given.
        try:
            selector = build_model_selector(session.llm_client)
        except Exception:  # noqa: BLE001 - routing must never block a run
            selector = None

        # Only an engagement is planned: a bare objective has no signed scope to
        # attack, so there is nothing to contract. This also keeps the extra model
        # call out of runs that are not engagements.
        if session.engagement_id and is_engagement_objective(objective):
            try:
                plan = await draft_engagement_plan(
                    llm_client=routed_for_task("planner", base=session.llm_client),
                    objective=objective,
                    engagement_id=session.engagement_id,
                    workspace=os.getenv("NEXUS_WORKSPACE_ROOT", os.getcwd()),
                )
                if plan is not None:
                    write_line(out, {
                        "event": "plan_created",
                        "todos": len(plan.todos),
                        "source": plan.source,
                        "path": "loot/ENGAGEMENT_PLAN.md",
                    })
            except Exception:  # noqa: BLE001 - planning must never block the run
                pass
        return await run_react_loop(
            context=context,
            objective=objective,
            engagement_id=session.engagement_id,
            llm_client=session.llm_client,
            model_selector=selector,
            config=config,
            conversation_id=session.conversation_id,
        )

    try:
        result = asyncio.run(_plan_then_run())
    except ApprovalPending:
        result = SimpleNamespace(status="blocked", completion_verified=False)
    except PermissionError:
        result = SimpleNamespace(status="governance_denial", completion_verified=False)
    except KeyboardInterrupt:  # pragma: no cover - interactive interruption
        session.store.append_run_event(
            session.tenant_id, run_id, "react.cancel_requested", {"source": "headless-sigint"}
        )
        result = SimpleNamespace(status="cancelled", completion_verified=False)
    except Exception as exc:
        from nexus_core.scope import ScopeViolation
        from nexus_core.kernel.sandbox_modes import SandboxModeMismatch, SandboxModeNotImplemented, UnknownSandboxMode
        status = "failed"
        if isinstance(exc, (ScopeViolation, SandboxModeMismatch, SandboxModeNotImplemented, UnknownSandboxMode)):
            status = "governance_denial"
        elif isinstance(exc, (ProviderFailure, TimeoutError, ConnectionError)):
            status = "provider_error"
        result = SimpleNamespace(status=status,
                                 completion_verified=False, final_summary=type(exc).__name__)
    finally:
        stop.set()
        if emitter is not None:
            emitter.join(timeout=2.0)

    payload = result_payload(result, run_id)
    payload["duration_seconds"] = round(time.monotonic() - started, 3)
    payload.update(llm_identity(session))
    write_line(out, payload)
    return payload["exit_code"]


def _trust_approval(session: Any):
    """Approval hook for headless runs (``--trust-mode`` only; else deny)."""
    if not getattr(session, "trust_mode", False):
        def pending(tool_id, arguments, decision):
            AuditWriter(session.store).append(
                tenant_id=session.tenant_id, trace_id=session.run_id,
                actor_id=session.agent_identity_payload.get("subject_id", "headless"),
                action="approval.pending", resource_type="tool", resource_id=tool_id,
                payload={"reason": "headless_requires_human"}, decision="deny")
            raise ApprovalPending("durable human approval required")
        return pending
    from .approval import make_approval_callback

    return make_approval_callback(
        session, session.store, session.tenant_id, session.run_id, trust_mode=True
    )


__all__ = [
    "STREAMED_AUDIT_ACTIONS",
    "STREAM_INTERVAL",
    "human_output_on_stderr",
    "llm_identity",
    "machine_stream",
    "result_payload",
    "run_headless",
    "token_accounting",
    "write_line",
]
