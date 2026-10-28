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
import os
import sys
import threading
from contextlib import contextmanager, nullcontext
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterator

from nexus_core.agent import memory
from nexus_core.agent.react import ReActConfig, _operator_approval_gate, run_react_loop
from nexus_core.kernel.audit import AuditWriter
from nexus_core.kernel.models import Identity, RunContext
from nexus_core.kernel.runtime import ExecutionContext, select_llm_client
from nexus_core.scope import ScopeViolation

from . import commands as commands_module
from . import render
from .approval import default_operator_id, make_approval_callback
from .tool_result import tool_method, tool_payload, tool_success
from .tui.history import history_path as tui_history_path
from .tui.output import PlainOutput, TuiOutput, routed
from .tui.session import PROMPT_PREFIX, TuiSession, should_use_tui
from .tui.status import load_status_preference

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

#: Session backends the REPL can attach to.
SESSION_BACKEND_MSF = "msf"
SESSION_BACKEND_SLIVER = "sliver"

#: Sliver durable tools used by the REPL session mode and meta commands.
SLIVER_SERVER_TOOL = "nexus.c2.sliver_server"
SLIVER_IMPLANTS_TOOL = "nexus.c2.sliver_implants"
SLIVER_SESSIONS_TOOL = "nexus.c2.sliver_sessions"
SLIVER_EXEC_TOOL = "nexus.c2.sliver_exec"


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def fetch_sessions() -> dict[str, Any] | None:
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

        async def _list() -> dict[str, Any]:
            async with MetasploitClient(config) as client:
                return dict(await client.list_sessions())

        return asyncio.run(_list())
    except Exception:  # noqa: BLE001 - the REPL must survive an absent daemon
        return None


def find_session(sessions: dict[str, Any] | None, session_uuid: str) -> dict[str, Any] | None:
    """Return the session record matching ``session_uuid``, if any."""
    for record in (sessions or {}).values():
        if isinstance(record, dict) and str(record.get("uuid") or "") == session_uuid:
            return record
    return None


def _normalize_sliver_session(record: dict[str, Any]) -> dict[str, Any]:
    """Present a Sliver session in the shape the REPL already renders."""
    session_id = str(record.get("session_id") or "")
    return {
        **record,
        "uuid": session_id,
        "type": str(record.get("kind") or "session"),
        "target_host": record.get("remote_address") or record.get("hostname") or "",
    }


def build_llm_client() -> Any:
    """Resolve the provider used by the interactive loop (real providers first)."""
    return select_llm_client()


def _stdout_is_tty() -> bool:
    """True only when stdout is a real terminal (banner/spinner gate)."""
    try:
        return bool(sys.stdout.isatty())
    except Exception:  # noqa: BLE001 - detached stdout counts as "not a tty"
        return False


def _detect_msfrpcd_version(timeout_seconds: float = 2.0) -> str | None:
    """Version of a running msfrpcd, or ``None`` when it cannot be reached.

    Reads ``core.version`` through the existing MSF client (no subprocess) with
    a hard timeout: a dead daemon must never delay the REPL banner.
    """
    from nexus_core.integrations.metasploit.client import (
        MetasploitClient,
        MetasploitConfig,
    )

    try:
        config = MetasploitConfig.from_env()
        if not config.password:
            return None
    except Exception:  # noqa: BLE001 - unconfigured MSF is simply "n/a"
        return None

    async def _fetch() -> str | None:
        async with MetasploitClient(config) as client:
            data = await client._rpc("core.version", [])  # noqa: SLF001 - read-only probe
        if isinstance(data, dict):
            version = str(data.get("version") or "").strip()
            if version:
                return version
        return None

    try:
        return asyncio.run(asyncio.wait_for(_fetch(), timeout_seconds))
    except Exception:  # noqa: BLE001 - absent daemon is the normal case
        return None


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
        from .tui.history import file_history
        readline.clear_history()
        for entry in reversed(list(file_history(history_path).load_history_strings())):
            readline.add_history(entry)
        readline.set_history_length(1000)
        return Path(history_path)
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
        from .tui.history import file_history, history_lock
        history = file_history(history_path)
        entries = [readline.get_history_item(i) for i in range(1, readline.get_current_history_length()+1)]
        with history_lock(history_path):
            history._write([entry for entry in entries if entry is not None])
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
        budget_tokens: int | None = None,
        agent_id: str = DEFAULT_AGENT_ID,
        operator_id: str | None = None,
        input_reader: Callable[[str], str] | None = None,
        stream_interval: float = STREAM_INTERVAL_SECONDS,
        export_dir: Any = None,
        run_id: str | None = None,
        trust_mode: bool = False,
        resume_policy: str = "",
        no_color: bool = False,
        use_tui: bool | None = None,
        status_bar_enabled: bool = True,
        output: Any=None,
        engagement_names: list[str] | None = None,
        fullscreen: bool = True,
        show_art_banner: bool = False,
        subagent: str | None = None,
    ) -> None:
        self.store = store
        self.tenant_id = tenant_id
        self.autospawn: bool = False
        self.supervisor_budget: int = 0
        self.engagement = engagement
        from .workspace import workspace_root
        self.workspace_root = workspace_root(engagement)
        self.llm_client = llm_client
        try:
            self.max_iterations = max(1, int(max_iterations))
        except (TypeError, ValueError):
            self.max_iterations = DEFAULT_MAX_ITERATIONS
        #: R1: ``--budget-tokens``. ``None`` derives the ceiling from
        #: ``max_iterations``; ``0`` keeps its documented "unlimited" meaning.
        self.budget_tokens = None if budget_tokens is None else int(budget_tokens)
        self.agent_id = agent_id
        self.operator_id = operator_id or default_operator_id()
        self.input_reader = input_reader
        self.stream_interval = max(0.05, float(stream_interval))
        self.export_dir = Path(export_dir) if export_dir else None
        #: ``--trust-mode``: auto-authorize high-risk (never destructive) tools.
        self.trust_mode = bool(trust_mode)
        #: ``--resume-policy``: what a retry of an invocation the journal holds
        #: ``unknown`` may do without a human. Only trusted with ``--trust-mode``
        #: (see :attr:`effective_resume_policy`); empty means fail closed.
        self.resume_policy = str(resume_policy or "")
        #: ``--no-color``: the banner still renders, only plain ASCII.
        self.no_color = bool(no_color)
        #: ``--about``/``--banner``: show the big ASCII art instead of the
        #: compact three-line header at startup.
        self.show_art_banner = bool(show_art_banner)
        self.worker_id = f"cli:{self.operator_id}"
        self.history: list[str] = []
        #: Skills the operator explicitly activated for this session (opt-in).
        self.active_skills: list[str] = []
        #: ``/interview`` engagement brief (objectives, targets, restrictions).
        #: It is also persisted as a durable blackboard ``hint`` fact; this copy
        #: is what the running session renders without re-reading the store.
        self.engagement_brief: dict[str, Any] = {}
        #: ``--subagent``/``/subagent``: an operator pin for the profile of the
        #: next run (P2, Fase 3.7). ``None`` means "the planner decides"; an
        #: unknown id is rejected by ``subagents.select_subagent``, fail-closed.
        self.subagent_override: str | None = str(subagent) if subagent else None
        self.run_id = run_id
        self.resume_run_id = run_id
        self.conversation_id: str | None = None
        #: Durable work session of the active engagement (shared by runs and /ask).
        self._work_session_id: str | None = None
        self.should_exit = False
        self.last_result: Any = None
        self.last_question: str | None = None
        #: Session-mode state (attach does not touch the engagement scope).
        self.active_session_uuid: str | None = None
        self.active_session_info: dict[str, Any] | None = None
        #: Which C2 backend the attached session belongs to (msf | sliver).
        self.active_session_backend: str = SESSION_BACKEND_MSF
        self.session_commands_sent: int = 0
        self.session_started_at: str | None = None
        #: Report-mode state: where the last deliverable was written.
        self.last_report_directory: str | None = None
        self.last_report_sha256: str | None = None
        tui_enabled = should_use_tui() if use_tui is None else use_tui
        self._tui = TuiSession(
            use_tui=tui_enabled,
            history_path=tui_history_path(), no_color=no_color,
            status_bar_enabled=status_bar_enabled and load_status_preference(),
            tools=commands_module._tool_catalog(self) if tui_enabled else {},
            engagements=engagement_names or ([self.engagement.name] if self.engagement else []),
            full_screen=fullscreen,
        )
        # The badge pulls the engagement from this session on every frame: it is
        # right on the first frame and after any ``set_engagement``, not only
        # after a status-bar push.
        self._tui.bind_engagement_source(
            lambda: getattr(self.engagement, "name", None) or self.engagement_id
        )
        self._tui.set_status(
            workspace_path=str(self.workspace_root),
            engagement_name=getattr(self.engagement, "name", None),
            provider_model=self._llm_summary(),
        )
        self._output = output or (TuiOutput(self._tui) if self._tui.use_tui else PlainOutput())
        self._usage_by_run: dict[str, tuple[int, int, float]] = {}
        self._usage_local = [0, 0, 0.0]
        self._cost_known = False
        self._has_usage = False
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
    def effective_resume_policy(self) -> str:
        """``--resume-policy`` when the run is trusted, else the fail-closed ``""``.

        A headless bench acknowledges that an ``unknown`` invocation may be
        replayed only because the operator handed the run ``--trust-mode``: the
        engine never auto-approves a replay for a run that has no human at the
        terminal *and* no trust delegation (V1-54).
        """
        return self.resume_policy if self.trust_mode else ""

    @property
    def _llm(self) -> Any:
        """The LLM client of this session, resolved lazily if it was not given.

        ``/ask`` is conversational and must not fail just because the caller
        built the session without a client, so it resolves on first use through
        the same ``select_llm_client`` the agentic path uses.
        """
        if self.llm_client is None:
            self.llm_client = build_llm_client()
        return self.llm_client

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
            session_id=self._ensure_work_session() or self.conversation_id or "",
        )

    def reset_context(self) -> None:
        """Forget the local thread; durable history and audit are untouched."""
        self.run_id = None
        self.conversation_id = None
        self.resume_run_id = None
        self.last_result = None
        self.last_question = None

    def set_engagement(self, scope: Any) -> None:
        """Switch the active engagement in place (no REPL restart).

        The durable work session is per engagement, so the local run/thread is
        dropped: the next objective opens the new engagement's context instead
        of mixing scopes. The prompt, the status bar and the ``@`` completion
        follow immediately.
        """
        from .workspace import workspace_root
        self.workspace_root = workspace_root(scope)
        self.engagement = scope
        self._work_session_id = None
        self.reset_context()
        self.reload_engagement_names()
        self._update_status_bar(force=True)
        self._tui.invalidate()

    def reload_engagement_names(self) -> None:
        """Refresh the ``@engagement`` completion list from the store."""
        if self.store is None:
            return
        try:
            from nexus_core.scope import EngagementStore

            names = [
                scope.name for scope in EngagementStore(self.store).list_for_tenant(self.tenant_id)
            ]
        except Exception:  # noqa: BLE001 - listing must never break the REPL
            return
        self._tui.update_engagement_names(names)

    # ------------------------------------------------------------ work session
    def _ensure_work_session(self) -> str | None:
        """Conversation of the engagement's persistent work session.

        The durable conversation is created once per engagement and reused by
        every run and by ``/ask``, so the model sees the whole engagement
        context instead of a single objective. It survives individual runs and
        CLI restarts (looked up by title ``work:<engagement_id>``).
        """
        if self.store is None:
            return None
        if self._work_session_id:
            return self._work_session_id
        self._work_session_id = memory.ensure_work_conversation(
            self.store, self.tenant_id, self.agent_id, self.engagement_id
        )
        return self._work_session_id

    def rotate_work_session(self) -> str | None:
        """Start a new work session (``/clear``); the previous one is archived."""
        if self.store is None:
            return None
        self._work_session_id = memory.start_work_conversation(
            self.store, self.tenant_id, self.agent_id, self.engagement_id
        )
        return self._work_session_id

    @property
    def prompt(self) -> str:
        """Minimal prompt with contextual chips only when they apply.

        The engagement (and the model) live in the compact header, shown once,
        so the prompt stays a bare ``> `` chevron. Transient state that changes
        during the session (trust, attached session, last report) appears as
        chips on a line above it, and only when present. Colour is applied
        *around* each token, never inside it, so the plain substrings
        (``[TRUST MODE]``, ``[session <uuid>/<type>]``) stay intact and remain
        greppable.
        """
        trust = "─" + render.paint("[TRUST MODE]", render.RED, render.BOLD) if self.trust_mode else ""
        session = ""
        if self.active_session_uuid:
            info = self.active_session_info or {}
            kind = str(info.get("type") or info.get("kind") or "session")
            if self.active_session_backend == SESSION_BACKEND_SLIVER:
                token = f"[sliver:{self.active_session_uuid}/{kind}]"
            else:
                token = f"[session {self.active_session_uuid}/{kind}]"
            session = "─" + render.paint(token, render.MAGENTA)
        report = ""
        if self.last_report_directory:
            # Short marker only: the full path is printed by ``/report``.
            report = "─" + render.paint(
                f"[report {Path(self.last_report_directory).name}]", render.BLUE
            )
        chips = f"{trust}{session}{report}".lstrip("─")
        return f"{chips}\n{PROMPT_PREFIX}" if chips else PROMPT_PREFIX

    # ------------------------------------------------------------ presentation
    def _verify_audit_chain(self) -> bool:
        """True when the durable audit chain validates. Fail-safe: ``False``."""
        try:
            valid, _ = AuditWriter(self.store).verify_chain()
            return bool(valid)
        except Exception:  # noqa: BLE001 - an unreadable chain is not "valid"
            return False

    def _llm_stats(self) -> tuple[str, int]:
        """``(summary, real_provider_count)`` via the canonical resolution.

        Delegates to :mod:`nexus_core.cli.llm_env` so the banner cannot drift
        from what ``select_llm_client`` (and therefore ``execute_react``) will
        actually use. No client is constructed: nothing is logged.
        """
        from .llm_env import provider_summary

        provider, limit = provider_summary()
        return str(provider), int(limit)

    def _llm_summary(self) -> str:
        """Human label of the resolved provider, e.g. ``groq/openai/gpt-oss-20b``."""
        return self._llm_stats()[0]

    def _count_providers(self) -> int:
        """Number of configured *real* LLM providers (the fake fallback excluded)."""
        return self._llm_stats()[1]

    def _supports_unicode(self) -> bool:
        """True when stdout can encode the braille spinner frames."""
        encoding = getattr(sys.stdout, "encoding", None) or ""
        return "utf" in str(encoding).lower()

    def _show_banner(self) -> None:
        """Print the welcome banner once, only for a real interactive terminal."""
        if os.getenv("NEXUS_NO_BANNER"):
            return
        if not _stdout_is_tty():
            return
        if self._tui.use_tui:
            from .main import PROGRAM_VERSION
            from .tui.presentation import startup_banner

            try:
                width = int(self._tui._session.output.get_size().columns)
            except (AttributeError, TypeError, ValueError):
                width = 80
            banner = startup_banner(
                str(getattr(self.engagement, "name", None) or self.engagement_id or "workspace"),
                PROGRAM_VERSION,
                width=width,
                no_color=self.no_color,
            )
            self._output.write(banner, end="")
            self._tui.mark_startup_banner()
            self._announce_update_in_background()
            return
        from .banner import build_banner, render_banner
        from .main import PROGRAM_VERSION

        try:
            from nexus_core.tools.registry import durable_tool_definitions

            tools_count = len(durable_tool_definitions(self.tenant_id))
        except Exception:  # noqa: BLE001 - a broken catalog must not hide the banner
            tools_count = 0
        from .banner import describe_scope

        llm_summary, providers_count = self._llm_stats()
        banner_text = build_banner(
                version=PROGRAM_VERSION,
                tools_count=tools_count,
                providers_count=providers_count,
                engagement_name=getattr(self.engagement, "name", None),
                scope_summary=describe_scope(self.engagement),
                valid_until=getattr(self.engagement, "valid_until", None),
                audit_chain_valid=self._verify_audit_chain(),
                msfrpcd_version=_detect_msfrpcd_version(),
                llm_summary=llm_summary,
                no_color=self.no_color,
                compact=not self.show_art_banner,
        )
        if self._tui.use_tui:
            self._output.write(banner_text, end="")
        else:
            render_banner(banner_text, no_color=self.no_color)

    def _announce_update_in_background(self) -> None:
        """Check GitHub off the UI thread and print the notice when it lands.

        Two seconds is a *cap*, not a delay: the banner and the prompt are
        already on screen when this returns, and the thread simply gives up when
        the API does not answer. ``OMNI_NO_UPDATE_CHECK=1`` opts out (offline
        box, CI, air-gapped lab). The write goes through the same locked
        scrollback the streaming output uses, so it cannot interleave with a
        tool's output.
        """
        from .update import DISABLE_ENV, check_for_update, update_notice

        if os.getenv(DISABLE_ENV, "").strip().lower() in {"1", "true", "yes"}:
            return

        def worker() -> None:
            try:
                release = check_for_update()
            except Exception:  # noqa: BLE001 - a version check never breaks a run
                return
            if release is None:
                return
            try:
                self._output.write(render.paint(update_notice(release), render.YELLOW, render.BOLD))
            except Exception:  # noqa: BLE001 - the UI may already be closing
                pass

        threading.Thread(target=worker, name="omni-update-check", daemon=True).start()

    def _describe_tool_call(self, tool_id: str, arguments: dict[str, Any]) -> str:
        """One-line description of a running tool, shown by the spinner."""
        arguments = arguments or {}
        target = next(
            (
                str(arguments[key])
                for key in ("target", "targets", "domain", "url", "host")
                if arguments.get(key)
            ),
            "",
        )
        if tool_id == "nexus.recon.nmap":
            return f"Ejecutando nmap contra {target or 'el objetivo'}"
        if tool_id == "nexus.exploit.msf_exploit":
            module = str(arguments.get("module") or "exploit").split("/")[-1]
            return f"Ejecutando {module} contra {target or 'el objetivo'} (esperando sesión)"
        if tool_id == SESSION_INTERACT_TOOL:
            uuid = str(arguments.get("session_uuid") or self.active_session_uuid or "")
            return f"Enviando comando a sesión {uuid[:8] or '?'}"
        if tool_id == "nexus.report.generate":
            return "Generando reporte del engagement"
        return f"Ejecutando {tool_id}"

    def _spinner_enabled(self) -> bool:
        """Spinner gate: interactive terminal, colour allowed, not opted out."""
        from .spinner import spinner_enabled

        return (not self._tui.use_tui and spinner_enabled() and not os.getenv("NEXUS_NO_SPINNER")
                and os.getenv("CI", "").strip().lower() not in {"1", "true", "yes"})

    @contextmanager
    def _busy(self, message: Any) -> Iterator[Any]:
        self._tui.set_busy(message)
        try:
            yield
        finally:
            self._tui.clear_busy()

    def _metered_client(self, client: Any, *, durable: Any=True) -> Any:
        if not self._tui.use_tui:
            return client
        from .tui.usage import MeteredClient

        return MeteredClient(client, lambda response: self._record_usage(response, durable=durable),
                             context_callback=lambda state: self._tui.set_status(**state))

    async def _with_cancel(self, operation: Any, run_id: Any, *, cooperative: Any=True, cancel_event: Any=None) -> Any:
        """Consume UI cancellation on the work loop, never writing DB on the UI thread."""
        if not self._tui.use_tui:
            return await operation
        task = asyncio.create_task(operation)
        try:
            while not task.done():
                if self._tui._cancel_event.is_set():
                    self._tui._cancel_event.clear()
                    if cancel_event is not None:
                        # Signal the executor so it can kill in-flight tools.
                        cancel_event.set()
                    if run_id:
                        self.store.append_run_event(
                            self.tenant_id, run_id, "react.cancel_requested", {"source": "cli-escape"}
                        )
                    self._output.write("• Cancelación solicitada; esperando el punto seguro de la operación.")
                    if not cooperative:
                        task.cancel()
                    # Exactly one request for this operation.
                    return await task
                await asyncio.wait({task}, timeout=0.05)
            return await task
        finally:
            if not task.done():
                task.cancel()
            await asyncio.gather(task, return_exceptions=True)

    def _record_usage(self, response: Any, *, durable: Any=True) -> None:
        from .tui.usage import response_usage

        incoming, outgoing, cost = response_usage(response)
        self._cost_known = (self._cost_known if self._has_usage else True) and cost is not None
        self._has_usage = True
        amounts = (incoming, outgoing, cost or 0.0)
        if durable and self.run_id:
            previous = self._usage_by_run.get(self.run_id, (0, 0, 0.0))
            self._usage_by_run[self.run_id] = tuple(a + b for a, b in zip(previous, amounts))
            try:
                for metric, amount in zip(("tokens_input", "tokens_output", "cost_usd"), amounts):
                    self.store.record_usage(
                        self.tenant_id, self.run_id, "cli_model", "all", metric, amount,
                        {"source": "tui", "cost_known": cost is not None},
                    )
            except Exception:  # presentation must not fail an otherwise successful call
                pass
        else:
            self._usage_local = [a + b for a, b in zip(self._usage_local, amounts)]
        self._update_status_bar()

    def _blackboard_status(self) -> Any:
        """``(facts_count, plan)`` for the active engagement (best effort)."""
        if self.engagement is None:
            return None, None
        try:
            from nexus_core.agent.planner import plan_from_summary
            from nexus_core.kernel.blackboard import Blackboard

            summary = Blackboard(self.store).summary(self.tenant_id, self.engagement_id)
        except Exception:  # presentation must not fail
            return None, None
        plan = plan_from_summary(summary, engagement_id=self.engagement_id)
        return int(summary.get("total") or 0), plan

    def _facts_count(self) -> int | None:
        """Distinct blackboard facts for the active engagement (best effort)."""
        count = self._blackboard_status()[0]
        return int(count) if count is not None else None

    def _update_status_bar(self, *, force: Any=False) -> None:
        if not self._tui.use_tui and not force:
            return
        totals = list(self._usage_local)
        for run_id, cached in self._usage_by_run.items():
            try:
                recorded = tuple(self.store.usage_total(
                    self.tenant_id, run_id, "cli_model", "all", metric,
                ) for metric in ("tokens_input", "tokens_output", "cost_usd"))
                amounts = tuple(max(a, b) for a, b in zip(cached, recorded))
            except Exception:
                amounts = cached
            totals = [a + b for a, b in zip(totals, amounts)]
        fields = dict(
            workspace_path=str(self.workspace_root),
            engagement_name=getattr(self.engagement, "name", None),
            session_uuid=self.active_session_uuid,
            session_type=(self.active_session_info or {}).get("type"),
            trust_mode=self.trust_mode, provider_model=self._llm_summary(),
            tokens_input=int(totals[0]), tokens_output=int(totals[1]),
            cost_usd=totals[2], cost_known=self._cost_known,
            audit_chain_valid=self._verify_audit_chain(),
            scope_targets=len({str(item) for field in ("cidrs", "domains", "urls")
                               for item in (getattr(self.engagement, field, ()) or ())}) if self.engagement else None,
            budget_usd=getattr(self, "budget_usd", None),
        )
        facts_count, plan = self._blackboard_status()
        fields["facts_count"] = facts_count
        if plan is not None:
            done, total = plan.progress
            fields["plan_phase"] = plan.phase.label
            fields["plan_progress"] = f"{done}/{total}"
        if self._tui.use_tui:
            self._tui.set_status(**fields)
            if plan is not None:
                self._tui.set_plan(self._plan_panel_payload(plan))
        else:
            for key, value in fields.items():
                setattr(self._tui._status, key, value)

    def _plan_panel_payload(self, plan: Any) -> dict[str, Any]:
        """Phase plan plus the engagement's TODOs, for the side panel.

        The phase plan is derived from the blackboard; the TODOs come from
        ``loot/ENGAGEMENT_PLAN.md`` and are what the run actually promised. Both
        are shown because they answer different questions ("where is the kill
        chain" vs "what did this engagement contract to prove").
        """
        payload = plan.to_dict()
        try:
            from nexus_core.agent.engagement_plan import load_plan_for, panel_todos

            contract = load_plan_for(self.engagement_id, str(self.workspace_root))
        except Exception:  # noqa: BLE001 - presentation must not fail
            return payload
        if contract is not None:
            counts = contract.counts()
            payload["todos"] = panel_todos(contract)
            payload["todos_done"] = counts.get("done", 0)
            payload["todos_total"] = len(contract.todos)
        return payload

    # --------------------------------------------------------------- sessions
    def fetch_sessions(self) -> dict[str, Any] | None:
        """Read the daemon's session list; ``None`` when it cannot answer."""
        from nexus_core.kernel.models import Identity, RunContext
        from nexus_core.kernel.sessions import SessionRegistry, validate_session_scope

        context = RunContext(self.tenant_id, Identity("cli-session-list", self.tenant_id),
                             scope=self.engagement, store=self.store)
        try:
            validate_session_scope(context)
            raw = fetch_sessions()
            if raw is None:
                return None
            return dict(SessionRegistry(self.store).filter_owned(context, raw))
        except PermissionError:
            return {}

    def fetch_sliver_sessions(self) -> dict[str, Any] | None:
        """Read Sliver sessions/beacons through the governed tool.

        Returns ``None`` when the tool cannot answer so callers never mistake an
        unreachable team server for "no sessions".
        """
        result = self.invoke_tool(SLIVER_SESSIONS_TOOL, {"kind": "both"})
        if not tool_success(result):
            return None
        payload = tool_payload(result)
        records: dict[str, dict[str, Any]] = {}
        for item in list(payload.get("sessions") or []) + list(payload.get("beacons") or []):
            if isinstance(item, dict) and item.get("session_id"):
                records[str(item["session_id"])] = _normalize_sliver_session(item)
        return records

    def refresh_active_session(self) -> dict[str, Any] | None:
        """Look the active session up; ``None`` when it is gone or unknown."""
        if not self.active_session_uuid:
            return None
        if self.active_session_backend == SESSION_BACKEND_SLIVER:
            sessions = self.fetch_sliver_sessions()
            if sessions is None:
                return None
            return sessions.get(self.active_session_uuid)
        sessions = self.fetch_sessions()
        if sessions is None:
            return None
        return find_session(sessions, self.active_session_uuid)

    @routed
    def attach_sliver_session(self, session_uuid: str) -> bool:
        """Attach to a Sliver session/beacon; the scope is left untouched."""
        sessions = self.fetch_sliver_sessions()
        if sessions is None:
            render.render_error("no se pudo consultar el team server de Sliver (¿está vivo?)")
            return False
        record = sessions.get(str(session_uuid or ""))
        if record is None:
            render.render_error(f"sesión Sliver no encontrada: {session_uuid}")
            return False
        self.active_session_uuid = str(record.get("uuid") or session_uuid)
        self.active_session_info = dict(record)
        self.active_session_backend = SESSION_BACKEND_SLIVER
        self.session_started_at = _utc_now()
        render.render_session_attached(self.active_session_info)
        return True

    @routed
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

    @routed
    def detach_session(self, *, notify: bool = True) -> str | None:
        """Leave session mode (the session itself keeps running)."""
        previous = self.active_session_uuid
        self.active_session_uuid = None
        self.active_session_info = None
        self.active_session_backend = SESSION_BACKEND_MSF
        self.session_started_at = None
        if notify and previous:
            self._output.write(f"Detached from session {previous}. Session remains active.")
        return previous

    @routed
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
            self.tenant_id,
            {"source": "omni-cli", "objective": objective, "engagement_id": self.engagement_id, "project_root": str(self.workspace_root)},
        )
        self.run_id = str(run["id"])
        return self.run_id

    @routed
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
            "project_root": str(self.workspace_root),
            "engagement_id": self.engagement_id,
            "permissions": list(self.permissions),
            "trace_id": run_id,
            "session_id": self._ensure_work_session() or self.conversation_id,
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
        try:
            denial = _operator_approval_gate(
                config=config, context=context, definition=definition, tool_payload=payload
            )
        except PermissionError as exc:
            render.render_error(str(exc))
            return None
        if denial is not None:
            render.render_error(
                f"denegado por el operador: {denial.get('reason') or denial.get('status')}"
            )
            return None
        from .spinner import Spinner

        try:
            if self._tui.use_tui:
                from .tui.stream import format_tool_invocation
                self._output.write(format_tool_invocation(tool_id, arguments))
            with self._busy(self._describe_tool_call(tool_id, arguments)), Spinner(
                self._describe_tool_call(tool_id, dict(arguments or {})),
                enabled=self._spinner_enabled(),
                use_ascii=not self._supports_unicode(),
            ):
                result = asyncio.run(self._with_cancel(execute_tool(payload, context), run_id, cooperative=False))
        except asyncio.CancelledError:
            render.render_status("operación cancelada")
            return None
        except ScopeViolation as exc:
            # Fail-closed: the target was refused before anything ran. Render a
            # clean, actionable message instead of a raw traceback (H7).
            detail = getattr(exc, "reason", "") or str(exc)
            target = getattr(exc, "target", "") or "n/d"
            render.render_error(
                f"{tool_id} bloqueado por scope: {detail} (target: {target})"
            )
            return None
        except (PermissionError, ValueError, RuntimeError, KeyError, TypeError) as exc:
            from .tui.stream import render_tool_result
            self._output.write(render_tool_result(
                {"success": False, "tool_id": tool_id, "error": f"{type(exc).__name__}: {exc}"},
                no_color=self.no_color or not self._tui.use_tui))
            return None
        self.record_tool_result(run_id, tool_id, dict(arguments or {}), result)
        if self._tui.use_tui:
            # Per-block accordion: the card remembers its own state and can be
            # expanded by clicking its footer.
            self._tui.append_card(result.get("output") or {})
        return dict(result) if result is not None else None

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
            conversation_id = self._ensure_work_session() or memory.ensure_conversation(
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
        self,
        session_uuid: str,
        command: str,
        run_id: str,
        outcome: str,
        *,
        tool_id: str = SESSION_INTERACT_TOOL,
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
                "tool_id": tool_id,
                "session_uuid": session_uuid,
                "command": str(command)[:500],
                "command_sha256": hashlib.sha256(str(command).encode("utf-8")).hexdigest(),
                "engagement_id": self.engagement_id,
                "run_id": run_id,
                "outcome": outcome,
            },
            decision="deny" if outcome == "denied" else "allow",
        )

    @routed
    def run_session_command(self, command: str) -> bool:
        """Send one line to the attached session and render its output."""
        session_uuid = self.active_session_uuid
        if not session_uuid:
            return False
        run_id = self.ensure_run(f"comando a la sesión {session_uuid}")
        if self.active_session_backend == SESSION_BACKEND_SLIVER:
            return self._run_sliver_command(session_uuid, command, run_id)
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

    def _run_sliver_command(self, session_uuid: str, command: str, run_id: str) -> bool:
        """Send one line to a Sliver session/beacon via ``nexus.c2.sliver_exec``."""
        kind = str((self.active_session_info or {}).get("kind") or "session")
        result = self.invoke_tool(
            SLIVER_EXEC_TOOL,
            {"session_id": session_uuid, "command": command, "kind": kind},
        )
        if result is None:
            self.audit_session_command(
                session_uuid, command, run_id, "denied", tool_id=SLIVER_EXEC_TOOL
            )
            return True
        payload = tool_payload(result)
        status = str(payload.get("status") or "")
        self.audit_session_command(
            session_uuid, command, run_id, status or "unknown", tool_id=SLIVER_EXEC_TOOL
        )
        if not tool_success(result):
            render.render_error(
                f"el comando no se verificó: {tool_method(result) or 'error'}"
            )
        text = str(payload.get("stdout") or "")
        if not text and payload.get("stderr"):
            text = str(payload.get("stderr"))
        render.render_session_output(text)
        self.session_commands_sent += 1
        return True

    # ------------------------------------------------------------------ run
    async def _draft_engagement_plan(
        self, llm_client: Any, objective: str, *, workspace: str | None = None
    ) -> Any:
        """PLAN MODE: write ``loot/ENGAGEMENT_PLAN.md`` before the first turn.

        The plan is a property of an engagement instruction, not of every run: a
        question or an objective that only needs reasoning returns ``None`` and
        the loop keeps its old behavior. A planning failure is not fatal -the
        deterministic seed is written instead- so the contract always exists.
        """
        from nexus_core.agent.engagement_plan import is_engagement_objective
        from nexus_core.agent.planning import draft_engagement_plan

        # Only an engagement is planned: without a signed scope there is no target
        # to attack, so there is nothing to contract.
        if not self.engagement_id or not is_engagement_objective(objective):
            return None
        try:
            plan = await draft_engagement_plan(
                llm_client=llm_client,
                objective=objective,
                engagement_id=self.engagement_id,
                workspace=workspace,
            )
        except Exception:  # noqa: BLE001 - planning must never block the run
            return None
        if plan is not None:
            render.render_status(
                f"plan del engagement: {len(plan.todos)} TODOs ({plan.source}) → "
                "loot/ENGAGEMENT_PLAN.md"
            )
            self._update_status_bar()
        return plan

    @routed
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
                    self.tenant_id,
                    {"source": "omni-cli", "objective": objective, "engagement_id": self.engagement_id, "project_root": str(self.workspace_root)},
                )["id"]
            )
        self.run_id = run_id
        # Reuse the engagement's durable work session: a new objective keeps the
        # context of the previous ones instead of opening a fresh conversation.
        self.conversation_id = self._ensure_work_session() or memory.ensure_conversation(
            self.store, self.tenant_id, run_id, self.agent_id
        )
        payload = {
            "objective": objective,
            "engagement_id": self.engagement_id,
            "max_iterations": self.max_iterations,
            **(
                {"budget_tokens": self.budget_tokens}
                if self.budget_tokens is not None
                else {}
            ),
            "agent_id": self.agent_id,
            "identity": self.agent_identity_payload,
            "permissions": list(self.permissions),
            "session_id": self.conversation_id,
            "active_skills": list(self.active_skills),
            "subagent": self.subagent_override,
            # P2-A2: pass the engagement workspace explicitly so lifecycle hooks
            # resolve the same directory in REPL, headless and worker.
            "project_root": str(self.workspace_root),
            # P2-C3: opt-in automatic delegation on a family transition.
            "autospawn": bool(getattr(self, "autospawn", False)),
            "supervisor_budget": int(getattr(self, "supervisor_budget", 0) or 0),
            "resume_policy": self.effective_resume_policy,
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
            resume_policy=self.effective_resume_policy,
            # Stream the model's reasoning into the live overlay (TUI only).
            on_thought=self._tui.set_thought if self._tui.use_tui else None,
            on_thought_done=self._tui.end_thought if self._tui.use_tui else None,
            # PLAN-FIRST: an engagement does not begin by attacking. The plan is
            # drafted below, before the first turn; this flag is what makes the
            # loop hold the run to it.
            require_plan_first=True,
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
            from .spinner import Spinner

            if self._tui.use_tui:
                from .tui.presentation import input_quote, input_chip, render_rich
                visible_objective = render_rich(input_chip(objective), no_color=self.no_color)
                width = int(self._tui._session.output.get_size().columns)
                self._tui.append_scrollback(input_quote(
                    "❯ " + visible_objective, width=max(1, width - 2),
                    no_color=self.no_color,
                ) + "\n\n")
            with self._busy("Working"), Spinner(
                f"Ejecutando objetivo: {objective[:80]}",
                enabled=self._spinner_enabled(),
                use_ascii=not self._supports_unicode(),
            ):
                cancel_event = asyncio.Event()
                llm_client = (
                    self._metered_client(self._llm)
                    if self._tui.use_tui
                    else self.llm_client
                )

                async def _plan_then_run() -> Any:
                    """PLAN MODE (iteration 0) and then the ACT loop."""
                    await self._draft_engagement_plan(
                        llm_client, objective, workspace=str(self.workspace_root)
                    )
                    return await run_react_loop(
                        context=context,
                        objective=objective,
                        engagement_id=self.engagement_id,
                        llm_client=llm_client,
                        config=config,
                        conversation_id=self.conversation_id,
                        cancel_event=cancel_event,
                    )

                result = asyncio.run(
                    self._with_cancel(_plan_then_run(), run_id, cancel_event=cancel_event)
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

    def visible_input(self, prompt: str) -> str:
        """Read a non-secret line mid-command, TUI-safe.

        ``input()`` inside a meta command fights prompt_toolkit for the terminal
        and deadlocks it -- the same reason :meth:`secure_input` exists. This is
        the visible counterpart, used by ``/auth`` to pick a provider from the
        menu before the key itself is read concealed.
        """
        if self.input_reader is not None:
            return str(self.input_reader(prompt))
        if self._tui.use_tui:
            return str(self._tui.prompt(prompt))
        return input(prompt)

    def secure_input(self, prompt: str) -> str:
        """Read a secret: masked, never echoed, never written to history.

        Routes through, in order: the operator-injected ``input_reader`` (tests
        and embedded clients), the TUI's own masked prompt, and finally
        ``getpass`` for a bare ``--no-tui`` REPL. Centralising it here keeps
        ``getpass`` -- which fights the TUI for the terminal -- out of the meta
        commands.
        """
        if self.input_reader is not None:
            return str(self.input_reader(prompt))
        if self._tui.use_tui:
            return str(self._tui.prompt_secret(prompt))
        import getpass

        return getpass.getpass(prompt)

    def fan_out_tool(
        self,
        tool_id: str,
        targets: list[str],
        *,
        subagent_id: str | None = None,
        concurrency: int | None = None,
    ) -> list[Any]:
        """Run one read-only tool across many targets, concurrently and bounded.

        The classic case is a CIDR: the same enumeration across every host, at
        once, instead of one turn per host. Fail-closed by construction —
        :func:`gather_readonly` refuses any profile that is not ``parallel_safe``
        *before* scheduling a single call, so an active phase can never be
        parallelised by accident.

        Every call still goes through the governed gateway (``execute_tool``), so
        policy, the signed scope, the RoE gate and the audit chain apply to each
        target independently. Results come back in the caller's order; a failing
        target yields its exception in place instead of discarding the others.
        """
        from nexus_core.agent import subagents
        from nexus_core.kernel import runtime as runtime_module

        profile = (
            subagents.SUBAGENTS_BY_ID[subagent_id]
            if subagent_id
            else subagents.select_subagent(None)
        )
        ordered = [str(target) for target in (targets or [])]
        run_id = str(
            self.store.create_run(
                self.tenant_id,
                {"source": "omni-fanout", "tool_id": tool_id, "engagement_id": self.engagement_id},
            )["id"]
        )
        AuditWriter(self.store).append(
            tenant_id=self.tenant_id,
            trace_id=run_id,
            actor_id=self.agent_id,
            action="fanout.started",
            resource_type="tool",
            resource_id=str(tool_id),
            payload={
                "subagent_id": profile.id,
                "read_only": profile.read_only,
                "targets": ordered,
                "concurrency": concurrency or subagents.DEFAULT_MAX_PARALLEL,
            },
            decision="allow",
        )
        task = {
            "id": f"fanout-{run_id}",
            "tenant_id": self.tenant_id,
            "run_id": run_id,
            "task_type": "tool.fanout",
            "payload": {"engagement_id": self.engagement_id, "session_id": self._ensure_work_session()},
        }
        context = ExecutionContext(self.store, task, self.worker_id)

        def emit(kind: Any, task_id: Any, target: Any, status: Any='running') -> None:
            data = {'task_id': task_id, 'subagent_id': profile.id, 'target': target, 'status': status}
            self.store.append_run_event(self.tenant_id, run_id, kind, data)
            self._tui.task_event({'event_type':kind,'run_id':run_id,'payload':data})

        def make_call(index: Any, target: str) -> Any:
            async def call() -> Any:
                task_id = str(index)
                emit('fanout.task.started',task_id,target)
                loop, current = asyncio.get_running_loop(), asyncio.current_task()
                assert current is not None  # we are inside the task being cancelled
                self._tui.bind_task_cancel(run_id+':'+task_id,lambda: loop.call_soon_threadsafe(current.cancel))
                status = 'ok'
                try:
                    return await runtime_module.execute_tool(
                        {'tool_id': str(tool_id), 'arguments': {'target':target},
                         'identity':self.agent_identity_payload, 'permissions':list(self.permissions),
                         'engagement_id':self.engagement_id, 'trace_id':run_id}, context)
                except asyncio.CancelledError:
                    status = 'cancelled'
                    raise
                except Exception:
                    status = 'failed'
                    raise
                finally:
                    self._tui.bind_task_cancel(run_id+':'+task_id,None)
                    emit('fanout.task.ended',task_id,target,status)
            return call

        calls = [make_call(index,target) for index,target in enumerate(ordered)]
        return asyncio.run(
            subagents.gather_readonly(
                calls,
                subagent=profile,
                limit=concurrency or subagents.DEFAULT_MAX_PARALLEL,
            )
        )

    # ----------------------------------------------------------------- repl
    @routed
    def run_repl(self) -> None:
        """Main loop: prompt → input → meta command or objective."""
        history_path = None if self._tui.use_tui else _install_readline()
        stdout_patch: Any = nullcontext()
        if self._tui.use_tui:
            from .tui.output import capture_output

            stdout_patch = capture_output(self._tui)
        try:
            with stdout_patch:
                self._show_banner()
                if not self._tui.use_tui:
                    # On the dedicated screen the banner and the status bar
                    # already carry the tenant, engagement, provider and cost:
                    # no second "ready" line.
                    render.render_status(
                        f"omni listo · tenant={self.tenant_id} · "
                        f"engagement={self.engagement_id or '(ninguno)'} · /help para comandos"
                    )
                self._update_status_bar()
                while not self.should_exit:
                    self.check_active_session()
                    try:
                        line = (self.input_reader or self._tui.prompt)(self.prompt)
                    except KeyboardInterrupt:
                        self._output.write("")
                        render.render_status("Ctrl+C interrumpe la entrada, no la sesión. /exit para salir.")
                        continue
                    except EOFError:
                        self._output.write("")
                        break
                    text = str(line or "").strip()
                    if not text:
                        continue
                    self.history.append(f"{PROMPT_PREFIX}{text}")
                    if text.startswith("/"):
                        commands_module.run_command(self, text)
                    elif self.active_session_uuid:
                        self.run_session_command(text)
                    else:
                        self.run_objective(text)
                    self._update_status_bar()
                    self._tui.invalidate()
                render.render_status("sesión terminada")
        finally:
            _save_readline_history(history_path)
            self._tui.close()


# --------------------------------------------------------------- live stream
@routed
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
        # A shared work session already holds the previous runs' messages; skip
        # them and stream only what this run appends.
        existing = 0
        if session.conversation_id:
            try:
                existing = len(
                    session.store.list_messages(
                        session.tenant_id, session.conversation_id,
                        limit=STREAM_MESSAGE_WINDOW,
                    )
                )
            except Exception:  # noqa: BLE001 - the stream must never break the run
                existing = 0
        state.update(run_id=run_id, sequence=0, messages=existing)
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
        if session._tui.use_tui:
            from .tui.stream import observation, render_message
            if (message.get("metadata") or {}).get("kind") == "react.observation":
                session._tui.append_card(observation(message))
            else:
                meta = message.get("metadata") or {}
                if meta.get("kind") == "react.action" and meta.get("thought"):
                    session._tui.append_card({}, thought=str(meta["thought"]))
                    message = {**message, "metadata": {**meta, "thought": ""}}
                text = render_message(message, expanded=session._tui.expand_cards)
                if text:
                    session._output.write(text)
        else:
            _render_message(message)
    state["messages"] = len(messages)


def _render_run_event(session: OmniSession, event: dict[str, Any]) -> None:
    event_type = str(event.get("event_type") or event.get("action") or "")
    payload = event.get("payload") or {}
    session._tui.task_event({**event, 'run_id': event.get('run_id') or session.run_id})
    if session._tui.use_tui:
        if event_type in {"tool.invoke", "react.tool_started"} or (event_type == "react.action" and payload.get("tool_id")):
            session._tui.set_status(busy_message=f"Executing {payload.get('tool_id', 'tool')}")
        elif event_type in {"tool.complete", "tool.failed", "react.turn_telemetry"}:
            session._tui.set_status(busy_message="Working")
        from .tui.stream import format_tool_invocation

        if event_type == "react.action" and "arguments" in payload:
            session._output.write(format_tool_invocation(payload.get("tool_id", "?"), payload["arguments"]))
        elif event_type in {"tool.complete", "tool.failed"}:
            result = payload.get("tool_result") or payload
            if event_type == "tool.failed":
                result = {**result, "success": False}
            # Same per-block card the observation path uses (click to expand).
            session._tui.append_card({**result, "tool_id": result.get("tool_id") or payload.get("tool_id", "tool")})
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
            from .tui.presentation import render_rich, thinking
            render.write(render_rich(thinking(str(metadata.get("thought") or "")), no_color=True))
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
    if observation.get("stdout") or observation.get("stderr") or not observation.get("success"):
        from .tui.stream import render_tool_result
        render.write(render_tool_result({**observation, "tool_id": tool_id}, no_color=True))
    else:
        render.render_tool_result(tool_id, observation)


__all__ = ["OmniSession", "build_llm_client"]
