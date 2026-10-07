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
from datetime import datetime, timezone
import json
import sys
import threading
import time
from typing import Any, TextIO

import os

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


def result_payload(result: Any, run_id: str) -> dict[str, Any]:
    """The final ``run.complete`` object (also used by ``--json``)."""
    return {
        "type": "run.complete",
        "run_id": run_id,
        "status": getattr(result, "status", "unknown"),
        "iterations": getattr(result, "iterations", 0),
        "summary": getattr(result, "final_summary", ""),
        "findings": getattr(result, "findings", []),
        "subagent_id": getattr(result, "subagent_id", None),
        "conversation_id": getattr(result, "conversation_id", ""),
        "plan": getattr(result, "plan", None),
    }


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


def run_headless(
    session: Any,
    objective: str,
    *,
    mode: str = "json",
    stream: TextIO | None = None,
    max_iterations: int | None = None,
    preflight: PreflightVerdict | None = None,
) -> int:
    """Run one objective headlessly; return the process exit code.

    ``mode`` is ``"json"`` (one object at the end) or ``"stream"`` (NDJSON plus a
    final ``run.complete`` line). A non-``completed``/``max_iterations``/
    ``clarification`` status is a failure for automation.
    """
    out = stream if stream is not None else sys.stdout
    objective = str(objective or "").strip()
    if not objective:
        write_line(out, {"type": "run.error", "error": "el objetivo no puede estar vacío"})
        return 2

    # Refuse to start against a wrong binary: it burns tokens and then fails
    # with an opaque post-condition error (B1). The operator can opt into a
    # degraded run with NEXUS_ALLOW_DEGRADED_TOOLS=1.
    verdict = preflight if preflight is not None else _run_preflight()
    if verdict is not None and not verdict.ok:
        write_line(out, {"type": "run.error", "error": verdict.message()})
        return 2
    if verdict is not None and verdict.problems and verdict.degraded:
        write_line(
            out,
            {
                "type": "run.preflight_degraded",
                "problems": [problem.to_dict() for problem in verdict.problems],
            },
        )

    raw_iterations: Any = max_iterations or getattr(session, "max_iterations", 12)
    iterations = int(raw_iterations)

    run_id = str(
        session.store.create_run(
            session.tenant_id, {"source": "omni-headless", "objective": objective}
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
            "engagement_id": session.engagement_id,
            "max_iterations": iterations,
            "agent_id": session.agent_id,
            "identity": session.agent_identity_payload,
            "permissions": list(session.permissions),
            "active_skills": list(getattr(session, "active_skills", []) or []),
        },
    }
    context = ExecutionContext(session.store, task, session.worker_id)
    config = ReActConfig(
        max_iterations=iterations,
        # No human at the terminal: approvals are denied unless trust mode asked
        # for the audited auto-approval of high-risk (never destructive) tools.
        on_approval_needed=_trust_approval(session),
    )

    stop = threading.Event()
    emitter: _EventEmitter | None = None
    if mode == "stream":
        emitter = _EventEmitter(session, stop, out)
        emitter.start()
    started = time.monotonic()
    try:
        result = asyncio.run(
            run_react_loop(
                context=context,
                objective=objective,
                engagement_id=session.engagement_id,
                llm_client=session.llm_client,
                config=config,
                conversation_id=session.conversation_id,
            )
        )
    except KeyboardInterrupt:  # pragma: no cover - interactive interruption
        session.store.append_run_event(
            session.tenant_id, run_id, "react.cancel_requested", {"source": "headless-sigint"}
        )
        write_line(out, {"type": "run.error", "run_id": run_id, "error": "interrupted"})
        return 130
    finally:
        stop.set()
        if emitter is not None:
            emitter.join(timeout=2.0)

    payload = result_payload(result, run_id)
    payload["duration_seconds"] = round(time.monotonic() - started, 3)
    write_line(out, payload)
    return 0 if payload["status"] in {"completed", "max_iterations", "clarification"} else 1


def _trust_approval(session: Any):
    """Approval hook for headless runs (``--trust-mode`` only; else deny)."""
    if not getattr(session, "trust_mode", False):
        return None
    from .approval import make_approval_callback

    return make_approval_callback(
        session, session.store, session.tenant_id, session.run_id, trust_mode=True
    )


__all__ = [
    "STREAMED_AUDIT_ACTIONS",
    "STREAM_INTERVAL",
    "result_payload",
    "run_headless",
    "write_line",
]
