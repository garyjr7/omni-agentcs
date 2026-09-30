"""Interactive ``omni`` session: REPL, live event stream and run orchestration.

The session never executes a tool by itself. Every objective is handed to
``run_react_loop``, which routes each model-requested call through
``execute_tool`` (policy, scope, approval, sandbox and audit). The session only
displays what the durable record already contains.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from nexus_core.agent import memory
from nexus_core.agent.react import ReActConfig, _operator_approval_gate, run_react_loop
from nexus_core.kernel.audit import AuditWriter
from nexus_core.kernel.models import Identity, RunContext
from nexus_core.kernel.runtime import ExecutionContext, select_llm_client

from . import commands as commands_module
from . import render
from .approval import default_operator_id, make_approval_callback

DEFAULT_TENANT = "system"
DEFAULT_AGENT_ID = "omni"
DEFAULT_MAX_ITERATIONS = 12
STREAM_INTERVAL_SECONDS = 0.5
STREAM_MESSAGE_WINDOW = 500

#: Tool that sends one command into an open session.
SESSION_INTERACT_TOOL = "nexus.session.interact"
#: Tool that terminates one session.
SESSION_KILL_TOOL = "nexus.session.kill"
SESSION_COMMAND_AUDIT_ACTION = "session.command"


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def fetch_sessions() -> dict | None:
    """Read ``session.list`` directly; ``None`` when the daemon cannot answer.

    Listing sessions is a read of the daemon's own state, not a command sent to
    a session, so it does not need to go through the tool gateway. Returns
    ``None`` (unknown) instead of ``{}`` so callers never mistake an unreachable
    daemon for "no sessions".
    """
    from nexus_core.integrations.metasploit.client import (
        MetasploitClient,
        MetasploitConfig,
    )

    try:
        config = MetasploitConfig.from_env()
        if not config.password:
            return None

        async def _list() -> dict:
            async with MetasploitClient(config) as client:
                return await client.list_sessions()

        return asyncio.run(_list())
    except Exception:  # noqa: BLE001 - the REPL must survive an absent daemon
        return None


def find_session(sessions: dict | None, session_uuid: str) -> dict | None:
    """Return the session record matching ``session_uuid``, if any."""
    for record in (sessions or {}).values():
        if isinstance(record, dict) and str(record.get("uuid") or "") == session_uuid:
            return record
    return None


def build_llm_client() -> Any:
    """Resolve the provider used by the interactive loop (real providers first)."""
    return select_llm_client()


def _install_readline() -> Path | None:
    """Enable line editing/history when ``readline`` exists (POSIX builds)."""
    try:
        import readline  # noqa: PLC0415 - optional, platform dependent
    except ImportError:  # pragma: no cover - Windows without pyreadline
        return None
    try:
        from nexus_core.config.xdg import resolve_xdg_paths
        paths = resolve_xdg_paths()
        paths.state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        history_path = paths.state_dir / "history"
        if history_path.exists():
            readline.read_history_file(str(history_path))
        readline.set_history_length(1000)
        return history_path
    except OSError:  # pragma: no cover - unwritable home directory
        return None


def _save_readline_history(history_path: Path | None) -> None:
    if history_path is None:
        return
    try:
        import readline  # noqa: PLC0415 - optional, platform dependent
    except ImportError:  # pragma: no cover
        return
    try:
        readline.write_history_file(str(history_path))
        history_path.chmod(0o600)
    except OSError:  # pragma: no cover - unwritable home directory
        pass


class OmniSession:
    """State of one interactive session (engagement, run and local thread)."""

    def __init__(
        self,
        store: Any,
        tenant_id: str = DEFAULT_TENANT,
        engagement: Any = None,
        llm_client: Any = None,
        max_iterations: int = DEFAULT_MAX_ITERATIONS,
        *,
        agent_id: str = DEFAULT_AGENT_ID,
        operator_id: str | None = None,
        input_reader: Callable[[str], str] | None = None,
        stream_interval: float = STREAM_INTERVAL_SECONDS,
        export_dir: Any = None,
        run_id: str | None = None,
        trust_mode: bool = False,
    ) -> None:
        self.store = store
        self.tenant_id = tenant_id
        self.engagement = engagement
        self.llm_client = llm_client
        try:
            self.max_iterations = max(1, int(max_iterations))
        except (TypeError, ValueError):
            self.max_iterations = DEFAULT_MAX_ITERATIONS
        self.agent_id = agent_id
        self.operator_id = operator_id or default_operator_id()
        self.input_reader = input_reader
        self.stream_interval = max(0.05, float(stream_interval))
        self.export_dir = Path(export_dir) if export_dir else None
        #: ``--trust-mode``: auto-authorize high-risk (never destructive) tools.
        self.trust_mode = bool(trust_mode)
        self.worker_id = f"cli:{self.operator_id}"
        self.history: list[str] = []
        self.run_id = run_id
        self.resume_run_id = run_id
        self.conversation_id: str | None = None
        self.should_exit = False
        self.last_result: Any = None
        self.last_question: str | None = None
        #: Session-mode state (attach does not touch the engagement scope).
        self.active_session_uuid: str | None = None
        self.active_session_info: dict | None = None
        self.session_commands_sent: int = 0
        self.session_started_at: str | None = None
        #: Report-mode state: where the last deliverable was written.
        self.last_report_directory: str | None = None
        self.last_report_sha256: str | None = None
        if run_id:
            # Resuming: recover the durable conversation of that run.
            self.conversation_id = memory.ensure_conversation(
                store, tenant_id, run_id, self.agent_id
            )

    # ------------------------------------------------------------- identities
    @property
    def engagement_id(self) -> str | None:
        return getattr(self.engagement, "engagement_id", None)

    @property
    def agent_subject_id(self) -> str:
        """Subject of the agent (never equal to the human operator)."""
        return f"agent:{self.agent_id}"

    @property
    def agent_identity(self) -> Identity:
        return Identity(
            subject_id=self.agent_subject_id,
            tenant_id=self.tenant_id,
            kind="agent",
            roles=("operator",),
        )

    @property
    def agent_identity_payload(self) -> dict[str, Any]:
        return {"subject_id": self.agent_subject_id, "kind": "agent", "roles": ["operator"]}

    @property
    def permissions(self) -> tuple[str, ...]:
        """Role-based authorization: the operator role carries the tool grants."""
        return ()

    def build_run_context(self, run_id: str | None = None) -> RunContext:
        """RunContext of the session's agent (same identity/scope as execute_tool)."""
        resolved = str(run_id or self.run_id or "")
        return RunContext(
            tenant_id=self.tenant_id,
            identity=self.agent_identity,
            run_id=resolved,
            trace_id=resolved,
            scope=self.engagement,
            store=self.store,
            worker_id=self.worker_id,
        )

    def reset_context(self) -> None:
        """Forget the local thread; durable history and audit are untouched."""
        self.run_id = None
        self.conversation_id = None
        self.resume_run_id = None
        self.last_result = None
        self.last_question = None

    @property
    def prompt(self) -> str:
        name = getattr(self.engagement, "name", None) or "(sin engagement)"
        trust = "─[TRUST MODE]" if self.trust_mode else ""
        session = ""
        if self.active_session_uuid:
            info = self.active_session_info or {}
            kind = str(info.get("type") or "session")
            session = f"─[session {self.active_session_uuid}/{kind}]"
        report = ""
        if self.last_report_directory:
            # Short marker only: the full path is printed by ``/report``.
            report = f"─[report {Path(self.last_report_directory).name}]"
        return f"┌──(OmniAgentCS)─[{name}]{trust}{session}{report}\n└─$ "

    # --------------------------------------------------------------- sessions
    def fetch_sessions(self) -> dict | None:
        """Read the daemon's session list; ``None`` when it cannot answer."""
        return fetch_sessions()

    def refresh_active_session(self) -> dict | None:
        """Look the active session up; ``None`` when it is gone or unknown."""
        if not self.active_session_uuid:
            return None
        sessions = self.fetch_sessions()
        if sessions is None:
            return None
        return find_session(sessions, self.active_session_uuid)

    def attach_session(self, session_uuid: str) -> bool:
        """Attach to an existing session by uuid; the scope is left untouched."""
        sessions = self.fetch_sessions()
        if sessions is None:
            render.render_error("no se pudo consultar msfrpcd (¿está vivo?)")
            return False
        record = find_session(sessions, str(session_uuid or ""))
        if record is None:
            render.render_error(f"sesión no encontrada: {session_uuid}")
            return False
        self.active_session_uuid = str(record.get("uuid") or session_uuid)
        self.active_session_info = dict(record)
        self.session_started_at = _utc_now()
        render.render_session_attached(self.active_session_info)
        return True

    def detach_session(self, *, notify: bool = True) -> str | None:
        """Leave session mode (the session itself keeps running)."""
        previous = self.active_session_uuid
        self.active_session_uuid = None
        self.active_session_info = None
        self.session_started_at = None
        if notify and previous:
            print(f"Detached from session {previous}. Session remains active.")
        return previous

    def check_active_session(self) -> bool:
        """Detect a dead session on prompt return; detach and warn when so."""
        if not self.active_session_uuid:
            return True
        if self.refresh_active_session() is None:
            uuid = self.active_session_uuid
            self.detach_session(notify=False)
            render.render_session_died(uuid)
            return False
        return True

    # ---------------------------------------------------------------- governed
    def ensure_run(self, objective: str) -> str:
        """Reuse the current run or create one, so audit always has a run id."""
        if self.run_id:
            return self.run_id
        run = self.store.create_run(
            self.tenant_id, {"source": "omni-cli", "objective": objective}
        )
        self.run_id = str(run["id"])
        return self.run_id

    def invoke_tool(self, tool_id: str, arguments: dict[str, Any]) -> dict[str, Any] | None:
        """Run one tool through ``execute_tool`` (policy, scope, approval, audit).

        The approval handshake reuses the very same gate the ReAct loop uses, so
        an unattended operator gets the identical trust-mode behaviour.
        """
        from nexus_core.kernel.runtime import execute_tool
        from nexus_core.tools.registry import durable_tool_definitions

        entry = durable_tool_definitions(self.tenant_id).get(tool_id)
        if entry is None:
            render.render_error(f"tool desconocida: {tool_id}")
            return None
        definition = entry[0] if isinstance(entry, tuple) else entry
        run_id = self.ensure_run(f"{tool_id} desde el REPL")
        payload = {
            "tool_id": tool_id,
            "arguments": dict(arguments or {}),
            "identity": self.agent_identity_payload,
            "engagement_id": self.engagement_id,
            "permissions": list(self.permissions),
            "trace_id": run_id,
        }
        task = {
            "id": f"cli-{run_id}",
            "tenant_id": self.tenant_id,
            "run_id": run_id,
            "task_type": "tool.invoke",
            "payload": payload,
        }
        context = ExecutionContext(self.store, task, self.worker_id)
        config = ReActConfig(
            on_approval_needed=make_approval_callback(
                self, self.store, self.tenant_id, run_id, trust_mode=self.trust_mode
            )
        )
        denial = _operator_approval_gate(
            config=config, context=context, definition=definition, tool_payload=payload
        )
        if denial is not None:
            render.render_error(
                f"denegado por el operador: {denial.get('reason') or denial.get('status')}"
            )
            return None
        try:
            result = asyncio.run(execute_tool(payload, context))
        except (PermissionError, ValueError, RuntimeError, KeyError, TypeError) as exc:
            render.render_error(f"{tool_id} falló: {type(exc).__name__}: {exc}")
            return None
        self.record_tool_result(run_id, tool_id, dict(arguments or {}), result)
        return result

    def record_tool_result(
        self,
        run_id: str,
        tool_id: str,
        arguments: dict[str, Any],
        result: dict[str, Any],
    ) -> None:
        """Persist a REPL-invoked ToolResult exactly like the ReAct loop does.

        The audit trail keeps the decision and the completion, but deliberately
        trims the output; the report layer reads the ToolResult from the durable
        conversation, so a tool run from the REPL has to leave the same record a
        model-driven call would. Failure here never breaks the command.
        """
        output = result.get("output") if isinstance(result, dict) else None
        if not isinstance(output, dict):
            return
        try:
            conversation_id = memory.ensure_conversation(
                self.store, self.tenant_id, run_id, self.agent_id
            )
            observation = {
                "success": bool(output.get("success")),
                "verification_method": output.get("verification_method"),
                "evidence": output.get("evidence"),
                "output": output.get("output"),
            }
            memory.append_step(
                self.store,
                self.tenant_id,
                conversation_id,
                "user",
                json.dumps({"tool_id": tool_id, **observation}, default=str),
                {
                    "kind": "react.observation",
                    "source": "cli",
                    "tool_id": tool_id,
                    "arguments": arguments,
                    "success": observation["success"],
                    "tool_result": {
                        key: value
                        for key, value in observation.items()
                        if key not in {"evidence", "output"}
                    },
                    "run_id": run_id,
                },
            )
        except Exception:  # noqa: BLE001 - persistence must never break a command
            return

    def audit_session_command(
        self, session_uuid: str, command: str, run_id: str, outcome: str
    ) -> None:
        """Record every command sent into a session, with the current engagement."""
        AuditWriter(self.store).append(
            tenant_id=self.tenant_id,
            trace_id=run_id,
            actor_id=self.agent_subject_id,
            action=SESSION_COMMAND_AUDIT_ACTION,
            resource_type="session",
            resource_id=session_uuid,
            payload={
                "tool_id": SESSION_INTERACT_TOOL,
                "session_uuid": session_uuid,
                "command": str(command)[:500],
                "command_sha256": hashlib.sha256(str(command).encode("utf-8")).hexdigest(),
                "engagement_id": self.engagement_id,
                "run_id": run_id,
                "outcome": outcome,
            },
            decision="deny" if outcome == "denied" else "allow",
        )

    def run_session_command(self, command: str) -> bool:
        """Send one line to the attached session and render its output."""
        session_uuid = self.active_session_uuid
        if not session_uuid:
            return False
        run_id = self.ensure_run(f"comando a la sesión {session_uuid}")
        result = self.invoke_tool(
            SESSION_INTERACT_TOOL, {"session_uuid": session_uuid, "command": command}
        )
        if result is None:
            self.audit_session_command(session_uuid, command, run_id, "denied")
            return True
        output = result.get("output") or {}
        status = str(output.get("status") or "")
        self.audit_session_command(session_uuid, command, run_id, status or "unknown")
        if not output.get("success"):
            render.render_error(
                f"el comando no se verificó: {output.get('verification_method') or 'error'}"
            )
        render.render_session_output(str(output.get("output") or ""))
        self.session_commands_sent += 1
        if status == "session_dead":
            self.detach_session(notify=False)
            render.render_session_died(session_uuid)
        return True

    # ------------------------------------------------------------------ run
    def run_objective(self, objective: str) -> Any:
        """Run one objective through the durable ReAct loop, streaming events."""
        objective = str(objective or "").strip()
        if not objective:
            render.render_error("el objetivo no puede estar vacío")
            return None
        if self.resume_run_id:
            run_id = self.resume_run_id
            self.resume_run_id = None
        else:
            run_id = str(
                self.store.create_run(
                    self.tenant_id, {"source": "omni-cli", "objective": objective}
                )["id"]
            )
        self.run_id = run_id
        self.conversation_id = memory.ensure_conversation(
            self.store, self.tenant_id, run_id, self.agent_id
        )
        payload = {
            "objective": objective,
            "engagement_id": self.engagement_id,
            "max_iterations": self.max_iterations,
            "agent_id": self.agent_id,
            "identity": self.agent_identity_payload,
            "permissions": list(self.permissions),
        }
        task = {
            "id": f"cli-{run_id}",
            "tenant_id": self.tenant_id,
            "run_id": run_id,
            "task_type": "react.run",
            "payload": payload,
        }
        context = ExecutionContext(self.store, task, self.worker_id)
        config = ReActConfig(
            max_iterations=self.max_iterations,
            on_approval_needed=make_approval_callback(
                self, self.store, self.tenant_id, run_id, trust_mode=self.trust_mode
            ),
        )
        stop_event = threading.Event()
        streamer = threading.Thread(
            target=_stream_run_events,
            args=(self, stop_event),
            name="omni-event-stream",
            daemon=True,
        )
        render.render_status(
            f"run={run_id} engagement={self.engagement_id or '(ninguno)'} "
            f"max_iterations={self.max_iterations}"
        )
        streamer.start()
        try:
            result = asyncio.run(
                run_react_loop(
                    context=context,
                    objective=objective,
                    engagement_id=self.engagement_id,
                    llm_client=self.llm_client,
                    config=config,
                )
            )
        except KeyboardInterrupt:
            self.store.append_run_event(
                self.tenant_id, run_id, "react.cancel_requested", {"source": "cli-sigint"}
            )
            render.render_error(
                "run interrumpido: pedí cancelación cooperativa. "
                f"Reanúdalo con: omni --resume {run_id}"
            )
            return None
        finally:
            stop_event.set()
            streamer.join(timeout=2.0)
        self.last_result = result
        self.history.append(f"[{result.status}] {result.final_summary}")
        if result.status == "clarification" and result.question:
            self.last_question = result.question
        render.render_summary(
            result.final_summary or f"(sin resumen · estado={result.status})", result.findings
        )
        if result.question and result.status == "clarification":
            render.render_clarification(result.question)
        render.render_status(
            f"estado={result.status} iteraciones={result.iterations} "
            f"conversación={result.conversation_id}"
        )
        return result

    # ----------------------------------------------------------------- repl
    def run_repl(self) -> None:
        """Main loop: prompt → input → meta command or objective."""
        history_path = _install_readline()
        render.render_status(
            f"omni listo · tenant={self.tenant_id} · "
            f"engagement={self.engagement_id or '(ninguno)'} · /help para comandos"
        )
        while not self.should_exit:
            self.check_active_session()
            try:
                line = (self.input_reader or input)(self.prompt)
            except KeyboardInterrupt:
                print()
                render.render_status("Ctrl+C interrumpe la entrada, no la sesión. /exit para salir.")
                continue
            except EOFError:
                print()
                break
            text = str(line or "").strip()
            if not text:
                continue
            self.history.append(f"└─$ {text}")
            if text.startswith("/"):
                commands_module.run_command(self, text)
                continue
            if self.active_session_uuid:
                # Session mode: everything without a leading ``/`` goes to the
                # session, through the tool gateway, never straight to the RPC.
                self.run_session_command(text)
                continue
            self.run_objective(text)
        _save_readline_history(history_path)
        render.render_status("sesión terminada")


# --------------------------------------------------------------- live stream
def _stream_run_events(session: OmniSession, stop_event: threading.Event) -> None:
    """Poll the durable run events and messages until the loop finishes.

    Runs in a background thread while ``run_react_loop`` owns the main thread,
    so the human approval prompt always reads from a real terminal.
    """
    state: dict[str, Any] = {"run_id": None, "sequence": 0, "messages": 0}
    while True:
        _drain_stream(session, state)
        if stop_event.wait(session.stream_interval):
            break
    _drain_stream(session, state)


def _drain_stream(session: OmniSession, state: dict[str, Any]) -> None:
    run_id = session.run_id
    if run_id != state["run_id"]:
        state.update(run_id=run_id, sequence=0, messages=0)
        return
    if not run_id:
        return
    try:
        events = session.store.list_run_events(session.tenant_id, run_id, after=state["sequence"])
    except Exception:  # noqa: BLE001 - the stream must never break the run
        return
    for event in events:
        state["sequence"] = max(state["sequence"], int(event.get("sequence") or 0))
        _render_run_event(session, event)

    conversation_id = session.conversation_id
    if not conversation_id:
        return
    try:
        messages = session.store.list_messages(
            session.tenant_id, conversation_id, limit=STREAM_MESSAGE_WINDOW
        )
    except Exception:  # noqa: BLE001
        return
    for message in messages[state["messages"] :]:
        _render_message(message)
    state["messages"] = len(messages)


def _render_run_event(session: OmniSession, event: dict[str, Any]) -> None:
    event_type = str(event.get("event_type") or "")
    payload = event.get("payload") or {}
    if event_type == "react.parse_error":
        render.render_error(f"respuesta no parseable del LLM: {payload.get('error')}")
    elif event_type == "react.scope_violation":
        render.render_error(
            f"SCOPE VIOLATION · tool={payload.get('tool_id')} · {payload.get('error')}"
        )
    elif event_type == "react.clarification_requested":
        session.last_question = str(payload.get("question") or "")
    elif event_type == "react.cancelled":
        render.render_status("cancelación solicitada: el bucle se detiene de forma cooperativa")


def _tool_risk(tool_id: str | None) -> str:
    """Declared risk of a tool, used as its static noise label."""
    if not tool_id:
        return ""
    try:
        from nexus_core.tools.registry import durable_tool_definitions

        entry = durable_tool_definitions().get(tool_id)
    except Exception:  # noqa: BLE001 - cosmetic only
        return ""
    if entry is None:
        return ""
    definition = entry[0] if isinstance(entry, tuple) else entry
    return str(getattr(definition.risk, "value", getattr(definition, "risk", "")) or "")


def _render_message(message: dict[str, Any]) -> None:
    metadata = message.get("metadata") or {}
    kind = str(metadata.get("kind") or "")
    if kind == "react.action":
        action = str(metadata.get("action") or "")
        if action == "tool_call":
            render.render_thought(str(metadata.get("thought") or ""))
            render.render_tool_call(
                str(metadata.get("tool_id") or "?"),
                metadata.get("arguments") or {},
                _tool_risk(metadata.get("tool_id")),
            )
        return
    if kind == "react.observation":
        _render_observation(message)
    return


def _render_observation(message: dict[str, Any]) -> None:
    metadata = message.get("metadata") or {}
    tool_id = str(metadata.get("tool_id") or "?")
    observation = metadata.get("tool_result")
    try:
        parsed = json.loads(str(message.get("content") or ""))
    except (TypeError, ValueError):
        parsed = None
    if isinstance(parsed, dict):
        # The message body keeps the full evidence the metadata trims.
        observation = {**parsed, **(observation or {})}
    if not isinstance(observation, dict):
        observation = {"success": bool(metadata.get("success"))}
    render.render_tool_result(tool_id, observation)


__all__ = ["OmniSession", "build_llm_client"]
