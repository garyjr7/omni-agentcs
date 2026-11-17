"""Persistent prompt_toolkit application with a synchronous readline facade."""

from __future__ import annotations

import asyncio
import importlib
import logging
import os
import sys
import threading
import time
from contextvars import copy_context
from pathlib import Path
from queue import Queue
from typing import TYPE_CHECKING, Any, Callable

from .fallback import fallback_prompt
from .status import StatusState, render_status_bar

if TYPE_CHECKING:
    from prompt_toolkit.buffer import Buffer
    from prompt_toolkit.formatted_text import StyleAndTextTuples
    from prompt_toolkit.layout import Window

#: Prefix that marks a user turn, both in the live editor and in the echoed
#: transcript line: Codex-style single chevron, so the transcript reads as
#: ``> objective`` / result instead of hiding the operator's words.
PROMPT_PREFIX = "> "

#: Internal trace. Subagent lifecycle is bookkeeping, not conversation: it goes
#: to the log instead of the transcript.
log = logging.getLogger("omni.tui")

#: The visual transcript is a bounded view over the durable conversation. These
#: caps keep a long session's memory flat; the Store remains the full history.
TRANSCRIPT_MAX_SEGMENTS = 50
TRANSCRIPT_MAX_LINES = 1000


def alt_screen_enabled() -> bool:
    """False when ``NEXUS_NO_ALT_SCREEN`` opts out of the dedicated screen."""
    return os.getenv("NEXUS_NO_ALT_SCREEN", "").strip().lower() not in {"1", "true", "yes"}


def should_use_tui() -> bool:
    if os.getenv("CI", "").strip().lower() in {"1", "true", "yes"}:
        return False
    if os.getenv("NEXUS_NO_TUI", "").strip().lower() in {"1", "true", "yes"}:
        return False
    try:
        if not sys.stdin.isatty() or not sys.stdout.isatty():
            return False
        importlib.import_module("prompt_toolkit")
    except (ImportError, OSError, AttributeError, ValueError):
        return False
    return True


class TuiSession:
    """Keep the UI loop in its own thread while governed work runs synchronously.

    Explicit use_tui is injectable for pipe-input tests. Automatic selection
    belongs to should_use_tui; fallback never imports prompt_toolkit.
    """

    _input: Buffer
    _scrollback: Buffer
    _scrollback_window: Window
    _app: Any

    def __init__(
        self, *, use_tui: bool, history_path: Path | None = None,
        status_bar_enabled: bool = True, no_color: bool = False,
        prompt_style: dict[str, Any] | None = None,
        enable_completion: bool = True,
        commands: dict[str, Any] | None = None, tools: dict[str, Any] | None = None,
        engagements: list[str] | None = None,
        input: Any=None, output: Any=None, full_screen: bool = True,
    ) -> None:
        self.use_tui = bool(use_tui)
        #: Own the terminal's alternate screen by default, like the top coding
        #: CLIs: ``omni`` opens on a clean dedicated screen and the shell prompt
        #: is restored on exit. ``--no-fullscreen`` (or
        #: ``NEXUS_NO_ALT_SCREEN``) keeps the inline layout so the terminal
        #: scrollback stays visible.
        self.full_screen = bool(full_screen) and alt_screen_enabled()
        self.status_bar_enabled = status_bar_enabled
        self.no_color = no_color or "NO_COLOR" in os.environ
        self.prompt_text = PROMPT_PREFIX
        #: Live source of the active engagement's display name. The compact
        #: header badge reads it on every frame, so it follows the session
        #: instead of a push that may not have happened yet.
        self._engagement_source: Callable[[], str | None] | None = None
        from .status import load_status_fields
        self._status = StatusState(cost_known=False, fields=load_status_fields())
        self._completion_context = (commands, tools or {}, engagements or [])
        self._enable_completion = enable_completion
        self._completer: Any = None
        self._lock = threading.RLock()
        self._closed = False
        self._session: Any = None
        self._thread: threading.Thread | None = None
        self._loop: Any = None
        self._context: Any = None
        self._ready = threading.Event()
        self._answers: Queue[str | BaseException] = Queue()
        self._accepting = False
        #: While True the input buffer is masked and its content is never echoed
        #: to the transcript (secure secret entry).
        self._secret_mode = False
        self._lines: list[str] = []
        self._styled_lines: list[list[Any]] = [[]]
        #: Ordered transcript segments (text or tool card) for in-place redraw.
        self._segments: list[dict[str, Any]] = []
        self._write_queue: list[dict[str, Any]] = []
        self._flush_scheduled = False
        #: Typewriter reveal. Blocks waiting to be printed, the task pacing
        #: them, the committed text the partial block is drawn over and whether
        #: a flush arrived while it was typing. The pulse is a fixed row of the
        #: layout, so none of this touches a row height.
        self._typing_queue: list[dict[str, Any]] = []
        self._typing_task: Any = None
        self._typing_active = False
        self._typing_deferred = False
        self._typed_base: str | None = None
        #: Per-block accordion: card state, toggle-line index and id counter.
        self._cards: dict[int, dict[str, Any]] = {}
        self._toggle_rows: dict[int, int] = {}
        self._next_card_id = 1
        #: Calls already opened for each subagent in the current operator turn:
        #: the first card is ``OMNI · Recon``, the next ``OMNI · Recon (2)``.
        self._identity_seq: dict[str, int] = {}
        #: Last tool that produced a block in this session. It only feeds the
        #: subagent label of the next answer/result panel; it never changes
        #: dispatch, scope or policy.
        self._last_tool_id: str | None = None
        #: Width the transcript was last rendered at. A resize is handled once
        #: per width change, so reflowing the log cannot loop with invalidate.
        self._last_render_width: int | None = None
        #: A resize arrived while a typewriter reveal owned the document.
        self._resize_pending = False
        #: Live ReAct "thinking" text shown while the model streams a turn.
        self._thought_text: str | None = None
        #: Provider's native reasoning, attached to the next thought card.
        self._pending_reasoning: str | None = None
        from .presentation import WorkingIndicator
        self._working_indicator = WorkingIndicator()
        self._auto_scroll = True
        #: Mirror of ``_auto_scroll`` for the rest of the UI. ``True`` means the
        #: operator moved the viewport up and new output must not drag the view
        #: back to the tail until PageDown (or a new command) resumes it.
        self._is_scrolling = False
        #: The dedicated screen is cleared exactly once, before its first frame.
        self._screen_cleared = False
        self._cancel_event = threading.Event()
        self._error: BaseException | None = None
        from .tasks import TaskPanel
        self.task_panel = TaskPanel()
        self._task_cancellers: dict[str, Callable[[], None]] = {}
        self._plan: dict[str, Any] | None = None
        self.panel_enabled = False
        #: Collapse tool cards to 5 lines by default; the footer click (or
        #: ``/expand``) shows the full output.
        self.expand_cards = False
        self._approval: dict[str, Any] | None = None
        self._approval_selected = 0
        #: First Enter selects the option, the second one submits it. Nothing
        #: is authorized until the operator confirms the highlighted row.
        self._approval_armed = False
        self._banner_end_line: int | None = None
        self._completion_status: str | None = None
        #: Accumulated text of an answer streaming into the live overlay.
        self._answer_text: str | None = None
        self._answer_cache: tuple[Any, list[str]] | None = None
        from uuid import uuid4

        from .paste import InputDocument, prune_drafts
        draft = None
        if history_path and self.use_tui:
            directory = history_path.parent / 'drafts'
            directory.mkdir(parents=True, exist_ok=True, mode=0o700)
            prune_drafts(directory)
            draft = directory / (uuid4().hex + '.draft.json')
        self.input_document = InputDocument(path=draft)
        self._syncing_input = False
        if self.use_tui:
            self._build(history_path, prompt_style, input, output)

    def _build(self, history_path: Any, prompt_style: Any, input: Any, output: Any) -> None:
        from prompt_toolkit.filters import Condition
        from prompt_toolkit.key_binding import KeyBindings
        from prompt_toolkit.keys import Keys

        from ..commands import COMMANDS
        from .completion import OmniCompleter
        from .history import file_history
        from .layout import build_layout

        commands, tools, engagements = self._completion_context
        if self._enable_completion:
            self._completer = OmniCompleter(
                commands=COMMANDS if commands is None else commands,
                tools=tools, engagements=engagements,
            )
        keys = KeyBindings()

        @keys.add("left", filter=Condition(lambda: self._can_edit and not self._input.text and not self._secret_mode))
        def previous_input(event: Any) -> None:
            self._input.history_backward()

        @keys.add("?", filter=Condition(lambda: self._can_edit and not self._input.text
                                        and not self._secret_mode and not self.approval_active))
        def help_input(event: Any) -> None:
            self._input.insert_text('/help')
            self._input.validate_and_handle()

        @keys.add(Keys.BracketedPaste, eager=True)
        def paste(event: Any) -> None:
            if self._can_edit:
                self.paste_text(event.data)

        @keys.add('f5', eager=True)
        def restore_paste(event: Any) -> None:
            if self._can_edit and not self._secret_mode:
                self.restore_paste_draft()

        @keys.add('f3', eager=True)
        def expand_paste(event: Any) -> None:
            if self._can_edit:
                self.expand_paste()

        @keys.add('f4', eager=True)
        def delete_paste(event: Any) -> None:
            if self._can_edit:
                self.delete_paste()

        @keys.add("tab", eager=True)
        def complete(event: Any) -> None:
            if not self._can_edit or self._completer is None:
                return
            from prompt_toolkit.completion import CompleteEvent

            buffer = event.current_buffer
            if buffer.complete_state:
                buffer.complete_next()
                return
            candidates = list(self._completer.get_completions(
                buffer.document, CompleteEvent(completion_requested=True),
            ))
            # A rapid Tab can arrive while automatic async completion is still
            # pending. Apply the unique candidate immediately in that case.
            if len(candidates) == 1:
                buffer.apply_completion(candidates[0])
            elif candidates:
                buffer.start_completion(insert_common_part=True)

        @keys.add("escape", "enter", eager=True)
        def newline(event: Any) -> None:
            if self._can_edit:
                event.current_buffer.insert_text("\n")

        @keys.add("enter", eager=True)
        def submit(event: Any) -> None:
            if not self._can_edit:
                return
            if self.approval_active and not event.current_buffer.text:
                from .frame import APPROVAL_TOKENS
                # Two-step confirmation: the first Enter only *selects* the
                # highlighted option (the row already carries the red
                # background), so one stray Enter cannot authorize a command.
                if not self._arm_approval():
                    return
                event.current_buffer.insert_text(APPROVAL_TOKENS[self._approval_selected])
            event.current_buffer.validate_and_handle()

        @keys.add("up", filter=Condition(lambda: self.approval_active))
        def approval_previous(event: Any) -> None:
            from .frame import APPROVAL_TOKENS
            self._approval_selected = (self._approval_selected - 1) % len(APPROVAL_TOKENS)
            # Changing the choice withdraws the previous selection: Submit must
            # always describe the option that is highlighted now.
            self._approval_armed = False
            self.invalidate()

        @keys.add("down", filter=Condition(lambda: self.approval_active))
        def approval_next(event: Any) -> None:
            from .frame import APPROVAL_TOKENS
            self._approval_selected = (self._approval_selected + 1) % len(APPROVAL_TOKENS)
            self._approval_armed = False
            self.invalidate()

        @keys.add("escape", filter=Condition(lambda: self.approval_active))
        def approval_cancel(event: Any) -> None:
            # Leaving the menu is a refusal, never the highlighted answer: no
            # option is authorized by default.
            self._cancel_approval()

        @keys.add("c-d", eager=True)
        def eof(event: Any) -> None:
            buffer = event.current_buffer
            if buffer.text:
                if self._can_edit:
                    buffer.delete()
                return
            # While the reader is paused above the live tail, Ctrl+D walks the
            # history forward instead of closing the session: the same key that
            # resumes follow must not swallow the pending work.
            if self._is_scrolling:
                self.scroll_transcript(self._page_lines())
                return
            if self._can_edit:
                self._answer(EOFError())

        @keys.add("c-u", eager=True)
        def scroll_up(event: Any) -> None:
            buffer = event.current_buffer
            if buffer.text:
                # With text in the editor the emacs meaning wins: kill back to
                # the start of the line. The transcript only takes the key when
                # there is nothing to edit (the editor is read-only while busy).
                if not self._can_edit:
                    return
                from prompt_toolkit.key_binding.bindings.named_commands import get_by_name

                get_by_name("unix-line-discard").call(event)
                return
            self.scroll_transcript(-self._page_lines())

        @keys.add("c-c", eager=True)
        def interrupt(event: Any) -> None:
            if self._can_edit:
                event.current_buffer.reset()
                self._answer(KeyboardInterrupt())
            else:
                # The main thread owns the governed call and its cancellation.
                import _thread

                _thread.interrupt_main()

        @keys.add("escape", filter=Condition(lambda: self._status.busy and not self._accepting))
        def cancel(event: Any) -> None:
            self._cancel_event.set()

        @keys.add("pageup", eager=True)
        def page_up(event: Any) -> None:
            self.scroll_transcript(-self._page_lines())

        @keys.add("pagedown", eager=True)
        def page_down(event: Any) -> None:
            self.scroll_transcript(self._page_lines())

        @keys.add(Keys.ScrollUp, eager=True)
        def wheel_up(event: Any) -> None:
            self.scroll_transcript(-3)

        @keys.add(Keys.ScrollDown, eager=True)
        def wheel_down(event: Any) -> None:
            self.scroll_transcript(3)

        @keys.add('f6', eager=True)
        def next_task(event: Any) -> None:
            self.task_panel.select_next()
            self.invalidate()

        @keys.add('f7', eager=True)
        def cancel_task(event: Any) -> None:
            with self._lock:
                callback = self._task_cancellers.get(self.task_panel.selected)
            if callback:
                callback()

        @keys.add("f2", eager=True)
        def toggle_panel(event: Any) -> None:
            self.set_panel(not self.panel_enabled)

        @keys.add("c-t", eager=True)
        def toggle_thoughts(event: Any) -> None:
            self.toggle_thoughts()

        @keys.add("c-o", eager=True)
        def toggle_last_card(event: Any) -> None:
            self.toggle_last_card()

        build_layout(self, keys, file_history(history_path) if history_path else None,
                     prompt_style, input, output, full_screen=self.full_screen)

    def _input_height(self) -> Any:
        """Editor rows, footer and breathing room in its panel.

        The panel reserves one blank row above the editor, one between the
        editor and the model/folder footer, and one below it.
        """
        from prompt_toolkit.utils import get_cwidth

        size = self._session.output.get_size()
        # Two cells of left inset and two for the ``> `` prefix.
        columns = max(1, size.columns - 4)
        rows = sum(max(1, (get_cwidth(line) + columns - 1) // columns)
                   for line in self.input_document.render().split("\n"))
        return 4 + min(5, rows)

    @property
    def _can_edit(self) -> bool:
        # Preserve typeahead between prompts. While working, only an explicit
        # prompt (e.g. operator approval) may unlock the input region.
        return self._accepting or not self._status.busy

    @property
    def transcript(self) -> str:
        """What the operator can read right now, including a block mid-reveal."""
        with self._lock:
            return "".join(self._segment_text(segment) for segment in self._segments)

    @property
    def is_scrolling(self) -> bool:
        """True while the viewport is paused above the live tail."""
        return self._is_scrolling

    def _formatted(self, text: str) -> StyleAndTextTuples:
        from prompt_toolkit.formatted_text import ANSI, to_formatted_text

        fragments = to_formatted_text(ANSI(text))
        return [("", part[1]) for part in fragments] if self.no_color else fragments

    def bind_engagement_source(self, source: Callable[[], str | None]) -> None:
        """Read the active engagement from the session state on every frame.

        The CLI binds ``lambda: self.engagement_id``: the badge names the id and
        is correct as soon as an engagement is initialized or loaded, without
        waiting for a status push (and without a stale copy after a switch).
        """
        self._engagement_source = source
        self.invalidate()

    def _engagement_label(self) -> str:
        """Active engagement *id* for the compact header badge.

        The badge names the engagement the run is bound to (``eng-...``), never
        the descriptive name and never the working directory: the footer below
        the input already shows the folder, so the header answers a different
        question. With no engagement bound, it keeps a clear workspace label
        instead of borrowing a name from the status bar.
        """
        from .frame import DEFAULT_ENGAGEMENT
        from .presentation import clean_text
        value: Any = None
        if self._engagement_source is not None:
            try:
                value = self._engagement_source()
            except Exception:  # noqa: BLE001 - a frame must never fail to render
                value = None
        label = ' '.join(clean_text(value or '').split())
        return label or DEFAULT_ENGAGEMENT

    def _header_badge(self) -> StyleAndTextTuples:
        """Fixed top row: brand, engagement and -only while working- a timer.

        The row is always reserved (see ``layout``); it stays empty while the
        startup masthead is still on screen, so the brand is never painted over
        the banner.
        """
        from ..theme import THEME
        from .frame import header_text

        if not self._show_engagement_badge():
            return []
        elapsed = (
            time.monotonic() - self._status.busy_started_at
            if self._status.busy
            else None
        )
        try:
            width = self._session.output.get_size().columns
        except Exception:  # noqa: BLE001 - cosmetic sizing only
            width = None
        return [("" if self.no_color else THEME.primary,
                 header_text(self._engagement_label(), elapsed_seconds=elapsed,
                             width=width))]

    def mark_startup_banner(self) -> None:
        """Record the banner's last transcript row for scroll-aware branding."""
        self._banner_end_line = max(0, self._scrollback.document.line_count - 1)
        self.invalidate()

    def _show_engagement_badge(self) -> bool:
        """The header is fixed while working; idle keeps the masthead rule.

        During a run the timer in the header is the operator's anchor, so it
        cannot wait for the startup banner to scroll away. Idle behaviour is
        unchanged: no duplicate brand while the masthead is still on screen.
        """
        if self._status.busy:
            return True
        return (self._banner_end_line is not None
                and self._scrollback_window.vertical_scroll > self._banner_end_line)

    def _completion_formatted(self) -> StyleAndTextTuples:
        if not self._completion_status:
            return []
        # A finished run is information, not an accent: dim like the rest of
        # the chrome. The accent stays on the header, the operator's rail and
        # the work pulse.
        from .presentation import SECONDARY_STYLE

        return [("" if self.no_color else SECONDARY_STYLE, self._completion_status)]

    def _workspace_footer(self) -> StyleAndTextTuples:
        """``model · ~/cwd`` in the bottom-left corner of the input panel.

        The panel footer is the single line that names the agent and the
        directory the session is bound to; ``Build`` is never rendered.
        """
        from .status import workspace_line
        with self._lock:
            from dataclasses import replace
            text = workspace_line(replace(self._status))
        from .presentation import SECONDARY_STYLE

        return [("" if self.no_color else SECONDARY_STYLE, text)]

    def _toolbar(self) -> StyleAndTextTuples:
        if not self.status_bar_enabled:
            return []
        with self._lock:
            from dataclasses import replace
            fragments = render_status_bar(replace(self._status), width=self._session.output.get_size().columns)
        parts: StyleAndTextTuples = [("", part[1]) for part in fragments] if self.no_color else list(fragments)
        if not self._auto_scroll:
            # Visible affordance: the transcript is paused above the live tail.
            parts[0:0] = [("class:scroll", "▲ historial · PgDn/Fin"), ("class:scroll", " · ")]
        return parts

    def update_engagement_names(self, names: list[str]) -> None:
        """Refresh the ``@engagement`` completion candidates in place."""
        if self._completer is not None:
            self._completer.engagements = tuple(sorted(set(names)))

    def task_event(self, event: Any) -> None:
        self.task_panel.consume(event)
        if self.use_tui:
            kind = str(event.get("event_type") or event.get("action") or "") if isinstance(event, dict) else ""
            raw_payload = event.get("payload") if isinstance(event, dict) else None
            payload = raw_payload if isinstance(raw_payload, dict) else {}
            if kind in {"orchestrator.subagent", "subagent.started", "subagent.ended",
                        "fanout.task.started", "fanout.task.ended"}:
                from .presentation import clean_text
                label = " ".join(clean_text(
                    str(payload.get("subagent_id") or payload.get("task_id") or "subagent")
                ).splitlines())
                status = " ".join(clean_text(str(
                    payload.get("status") or ("running" if kind.endswith("started") else "finished")
                )).splitlines())
                log.debug("[omni.tui] subagent %s · %s (%s)", label, status, kind)
            self._dispatch(self._session.app.refresh_wake.set)
        self.invalidate()

    def bind_task_cancel(self, key: Any, callback: Any) -> None:
        with self._lock:
            if callback is None:
                self._task_cancellers.pop(key, None)
            else:
                self._task_cancellers[key] = callback

    def set_plan(self, plan: dict[str, Any] | None) -> None:
        """Store the latest engagement plan for the side panel."""
        self._plan = plan if isinstance(plan, dict) else None
        self.invalidate()

    def set_panel(self, enabled: bool) -> bool:
        """Show/hide the plan side panel; returns the new state."""
        self.panel_enabled = bool(enabled)
        self.invalidate()
        return self.panel_enabled

    def _panel_formatted(self) -> StyleAndTextTuples:
        from .panels import panel_lines

        return [(style, text) for style, text in panel_lines(self._plan, width=44)]

    @property
    def answer_active(self) -> bool:
        """True while an answer is streaming into the live overlay."""
        return self._answer_text is not None

    def begin_answer(self) -> None:
        """Open the live answer overlay (streaming starts)."""
        self._answer_text = ""
        self._answer_cache = None
        self.invalidate()

    def append_answer(self, chunk: str) -> None:
        """Append a streamed chunk; the overlay re-renders the whole answer."""
        if self._answer_text is None:
            self._answer_text = ""
        self._answer_text += str(chunk)
        self._answer_cache = None
        self.invalidate()

    def set_answer(self, text: str) -> None:
        """Replace the live answer with a cumulative streaming snapshot.

        ReAct extracts the ``summary`` field from a partial JSON object, so the
        same prefix is re-sent on every chunk; replacing avoids duplicating it.
        """
        value = str(text or "")
        if not value:
            return
        with self._lock:
            self._answer_text = value
            self._answer_cache = None
        self.invalidate()

    def end_answer(self) -> str:
        """Close the overlay and return the accumulated answer."""
        text = self._answer_text or ""
        self._answer_text = None
        self._answer_cache = None
        self.invalidate()
        return text

    def _answer_lines(self) -> list[str]:
        """Markdown-rendered lines of the in-progress answer (cached per width)."""
        if self._answer_text is None:
            return []
        from .markdown import render_markdown

        # The live overlay uses the same content width as the committed panel:
        # one geometry for both, with no 100-column cap on wide terminals.
        width = max(20, self.text_width - 6)
        key = (self._answer_text, width)
        if self._answer_cache is not None and self._answer_cache[0] == key:
            return self._answer_cache[1]
        body = render_markdown(self._answer_text, no_color=self.no_color, max_width=width)
        lines = [("  " + line) if line.strip() else "" for line in body.splitlines()]
        self._answer_cache = (key, lines)
        return lines

    def answer_height(self) -> int:
        """Height of the live overlay: the tail of the answer, capped to the screen."""
        if not self.answer_active:
            return 0
        rows = self._session.output.get_size().rows
        return int(max(1, min(len(self._answer_lines()), max(1, rows - 6))))

    def _answer_formatted(self) -> StyleAndTextTuples:
        lines = self._answer_lines()
        limit = self.answer_height()
        if limit and len(lines) > limit:
            lines = lines[-limit:]
        return self._formatted("\n".join(lines))

    @property
    def thought_active(self) -> bool:
        """True while the model's reasoning is streaming into the live overlay."""
        return self._thought_text is not None

    def set_thought(self, text: str) -> None:
        """Show the partial ``thought`` of the current ReAct turn (streaming)."""
        with self._lock:
            self._thought_text = str(text or "…")
        self.invalidate()

    def end_thought(self) -> None:
        """Close the live reasoning overlay (iteración terminada)."""
        with self._lock:
            self._thought_text = None
        self.invalidate()

    def _thought_width(self) -> int:
        try:
            columns = self._session.output.get_size().columns
        except Exception:  # noqa: BLE001 - cosmetic sizing only
            columns = 80
        return max(20, int(columns) - 4)

    def thought_height(self) -> int:
        """Rows of the live reasoning row: one to five, never more."""
        with self._lock:
            text = self._thought_text or ""
        from .presentation import LIVE_THOUGHT_LINES, live_thought
        lines = live_thought(text, width=self._thought_width()).plain.splitlines()
        return max(1, min(LIVE_THOUGHT_LINES, len(lines)))

    def _thought_formatted(self) -> StyleAndTextTuples:
        with self._lock:
            text = self._thought_text or ""
        from .presentation import live_thought, render_rich
        return self._formatted(
            render_rich(live_thought(text, width=self._thought_width()),
                        width=self._thought_width(), no_color=self.no_color)
        )

    def toggle_thoughts(self) -> bool:
        """Expand/collapse every reasoning card (ctrl+t); returns the new state."""
        with self._lock:
            cards = [card for card in self._cards.values() if card.get("thought") is not None]
            if not cards:
                return False
            enabled = not all(bool(card.get("expanded")) for card in cards)
            for card in cards:
                card["expanded"] = enabled
            plain = self._rebuild_state_locked()
            cursor = len(plain) if self._auto_scroll else min(
                self._scrollback.cursor_position, len(plain)
            )
        self._dispatch(lambda: self._commit_transcript(plain, cursor))
        return enabled

    def toggle_last_card(self) -> bool:
        """Expand/collapse the last foldable card (ctrl+o)."""
        with self._lock:
            cards = [card for card in self._cards.values() if self._has_toggle(card)]
            if not cards:
                return False
            card = max(cards, key=lambda item: int(item.get("id") or 0))
            card["expanded"] = not bool(card.get("expanded"))
            plain = self._rebuild_state_locked()
            cursor = len(plain) if self._auto_scroll else min(
                self._scrollback.cursor_position, len(plain)
            )
        self._dispatch(lambda: self._commit_transcript(plain, cursor))
        return bool(card.get("expanded"))

    def set_expand(self, enabled: bool) -> bool:
        """Expand/collapse every tool card; returns the new state.

        Also sets the default for cards created afterwards. Individual cards are
        toggled by clicking their "mostrar más/menos" footer through
        :meth:`toggle_card_at_line`.
        """
        self.expand_cards = bool(enabled)
        self.invalidate()
        return self.expand_cards

    @property
    def approval_active(self) -> bool:
        return self._approval is not None

    def set_approval(self, payload: dict[str, Any] | None) -> bool:
        """Open the permission menu for ``payload``; returns whether it is shown."""
        from .frame import APPROVAL_DEFAULT

        self._approval = dict(payload) if isinstance(payload, dict) else None
        # Enter must authorize once, not for the whole engagement.
        self._approval_selected = APPROVAL_DEFAULT
        self._approval_armed = False
        self.invalidate()
        return self.approval_active

    def clear_approval(self) -> None:
        """Hide the approval modal (called once the operator decided)."""
        self._approval = None
        self._approval_armed = False
        self.invalidate()

    def _arm_approval(self) -> bool:
        """Select the highlighted option; ``True`` once Enter may submit it.

        The two-step answer is what keeps a reflexive Enter from authorizing a
        call: the first one only asks for confirmation and the dock says which
        option would be sent.
        """
        if self._approval_armed:
            return True
        self._approval_armed = True
        self.invalidate()
        return False

    def _cancel_approval(self) -> None:
        """Esc closes the menu as an explicit refusal (nothing is granted)."""
        from .frame import APPROVAL_TOKENS

        self._approval_armed = False
        self._input.reset()
        self._answer(APPROVAL_TOKENS[APPROVAL_TOKENS.index("n")])

    def _approval_width(self) -> int:
        """Menu width: 62 cells, shrunk to fit an 80-column terminal."""
        try:
            columns = int(self._session.output.get_size().columns)
        except Exception:  # noqa: BLE001 - cosmetic sizing only
            columns = 80
        return max(32, min(62, columns - 4))

    def _approval_capacity(self) -> int:
        """Rows the dock can give the menu without pushing the editor away."""
        try:
            rows = int(self._session.output.get_size().rows)
        except Exception:  # noqa: BLE001 - cosmetic sizing only
            rows = 24
        return max(6, min(12, rows - 10))

    def _approval_lines(self) -> list[tuple[str, str]]:
        """One ``(style, text)`` row of the permission menu, in reading order."""
        from .panels import approval_lines

        return approval_lines(
            self._approval, width=self._approval_width(),
            selected=self._approval_selected, armed=self._approval_armed,
            max_rows=self._approval_capacity(),
        )

    def _approval_formatted(self) -> StyleAndTextTuples:
        """The menu rows, separated by newlines.

        ``FormattedTextControl`` concatenates its fragments, so without the
        separator every row would render as one glued paragraph (``tool:``
        followed by ``riesgo:`` on the same wrapped line) and the panel height
        would not match what is actually drawn.
        """
        fragments: StyleAndTextTuples = []
        for index, (style, text) in enumerate(self._approval_lines()):
            if index:
                fragments.append(("", "\n"))
            fragments.append((style, text))
        return fragments

    def set_status_bar_enabled(self, enabled: bool) -> None:
        self.status_bar_enabled = bool(enabled)
        if self.use_tui:
            def update() -> None:
                self._session.bottom_toolbar = self._toolbar if enabled else None
                self.invalidate()
            self._dispatch(update)

    def _answer(self, value: Any) -> None:
        self._accepting = False
        self._answers.put(value)
        self.invalidate()

    def _accept(self, buffer: Buffer) -> bool:
        if self._can_edit:
            text = buffer.text if self._secret_mode else self.input_document.reconstruct()
            from .. import commands as commands_module
            from .presentation import input_chip, render_rich
            visible = render_rich(input_chip(text), no_color=self.no_color) if len(text) > 500 else self.input_document.render()
            # A state-changing slash command prints nothing, so neither its
            # command nor a response belongs in the transcript. The decision is
            # made before the echo: suppressing it afterwards left the rail in
            # the transcript forever.
            silent_command = not self._secret_mode and commands_module.is_silent_command(text)
            # A secret is never echoed to the transcript: show a fixed mask so
            # the operator still sees that the input was taken.
            if silent_command:
                pass
            elif not self._secret_mode and len(text) > 500:
                self.append_card({}, pasted_input=text, input_prefix=self._input_prefix(), expanded=False)
            else:
                value = "••••••" if self._secret_mode else visible
                self._echo_turn(value)
            self._answer(text)
        return False

    def _echo_turn(self, value: str) -> None:
        """Echo one submitted turn exactly once: rail, stamp and the task.

        ``run_objective`` used to echo the same objective again with a second
        chevron, so every run showed the task twice. The editor is the only
        writer of this block.
        """
        self.append_user_turn(value)

    def _input_prefix(self) -> str:
        """The chevron that opens the echoed user turn.

        Only the last line of the prompt is echoed: the contextual chips
        (trust/session/report) belong to the header row, not to every turn of
        the transcript, so the history stays clean.
        """
        lines = self.prompt_text.splitlines()
        return (lines[-1] if lines else "") or PROMPT_PREFIX

    def _input_changed(self, buffer: Any) -> None:
        if self._secret_mode or self._syncing_input:
            return
        try:
            from .paste import InputDocument, paste_threshold
            if paste_threshold(buffer.text) and buffer.text in buffer.history.get_strings():
                recalled = InputDocument(path=self.input_document.path)
                recalled.text, recalled.refs = '', {}
                recalled.insert_paste(0, buffer.text)
                self.input_document = recalled
                self._set_input_document(1)
                return
            self.input_document.synchronize(buffer.text)
        except (ValueError, OSError) as exc:
            self._syncing_input = True
            try:
                buffer.text = self.input_document.text
            finally:
                self._syncing_input = False
            self.print(f"Entrada conservada: {exc}")

    def paste_text(self, content: Any) -> None:
        from .paste import paste_threshold
        if self._secret_mode or not paste_threshold(content):
            self._input.insert_text(content)
            return
        pos = self._input.cursor_position
        self._input.save_to_undo_stack()
        try:
            self.input_document.insert_paste(pos, content)
        except (ValueError, OSError) as exc:
            self.print(f"Pegado rechazado, entrada conservada: {exc}")
            return
        self._set_input_document(pos+1)

    def restore_paste_draft(self) -> bool:
        from .paste import InputDocument
        path = self.input_document.path
        if self._secret_mode or self._input.text or not path:
            return False
        candidates = sorted(path.parent.glob('*.draft.json'), key=lambda p:p.stat().st_mtime, reverse=True)
        for candidate in candidates:
            if candidate == path:
                continue
            restored = InputDocument(path=candidate)
            if restored.text:
                self._input.save_to_undo_stack()
                self.input_document._commit(restored.text, restored.refs)
                self.input_document.next_id = restored.next_id
                self._set_input_document(len(restored.text))
                return True
        return False

    def _set_input_document(self, cursor: Any) -> None:
        from prompt_toolkit.document import Document
        self._syncing_input = True
        try:
            self._input.set_document(Document(self.input_document.text, cursor))
        finally:
            self._syncing_input = False

    def _selected_paste(self) -> int | None:
        cursor = self._input.cursor_position
        return next((p for p in (cursor, cursor-1) if p in self.input_document.refs), None)

    def expand_paste(self) -> None:
        pos = self._selected_paste()
        if pos is not None:
            self._input.save_to_undo_stack()
            self._set_input_document(self.input_document.replace_ref(pos, expand=True))

    def delete_paste(self) -> None:
        pos = self._selected_paste()
        if pos is not None:
            self._input.save_to_undo_stack()
            self._set_input_document(self.input_document.replace_ref(pos, expand=False))

    def _clear_screen_once(self) -> None:
        """Erase whatever the terminal had before the first frame.

        The transcript paints its own solid background, but a terminal that
        still holds the shell's previous output (or an inline banner) shows it
        through any cell prompt_toolkit has not touched yet. Clearing here, in
        the UI thread before the event loop starts, leaves a clean canvas.
        """
        if self._screen_cleared:
            return
        self._screen_cleared = True
        output = getattr(self._session, "output", None)
        if output is None:
            return
        try:
            output.erase_screen()
            output.cursor_goto(0, 0)
            output.flush()
        except Exception:  # noqa: BLE001 - clearing is best-effort
            pass

    def _run(self) -> None:
        self._clear_screen_once()

        async def run() -> None:
            def ready() -> None:
                self._loop = asyncio.get_running_loop()
                self._context = copy_context()
                self._ready.set()
            await self._session.app.run_async(pre_run=ready, handle_sigint=False)
        try:
            asyncio.run(run())
        except BaseException as exc:
            self._error = exc
            self._answers.put(exc)
        finally:
            self._ready.set()
            self._answers.put(EOFError())

    def _start(self) -> None:
        if self._thread is None:
            context = copy_context()
            self._thread = threading.Thread(
                target=context.run, args=(self._run,), name="omni-tui", daemon=True,
            )
            self._thread.start()
            self._ready.wait()
        if self._error:
            raise self._error

    def _dispatch(self, callback: Any) -> None:
        if self._loop is not None and self._loop.is_running():
            # All Buffer mutations belong to the UI loop and its app context.
            self._loop.call_soon_threadsafe(self._context.copy().run, callback)
        else:
            callback()

    def prompt(self, prompt_text: str | None = None) -> str:
        """Read one line; Ctrl+D raises EOFError and Ctrl+C KeyboardInterrupt."""
        if self._closed:
            raise EOFError
        if prompt_text is not None:
            self.prompt_text = prompt_text
        if not self.use_tui:
            return str(fallback_prompt(self.prompt_text))
        self._accepting = True
        self._start()
        self.invalidate()
        result = self._answers.get()
        self._accepting = False
        if isinstance(result, BaseException):
            raise result
        return str(result)

    def prompt_secret(self, prompt_text: str = PROMPT_PREFIX + "🔒 valor oculto: ") -> str:
        """Read one line masked: never echoed, never kept in any history.

        Uses the session's own input buffer so it cannot fight the running TUI
        application the way a bare ``getpass`` would (``getpass`` writes straight
        to the terminal while ``prompt_toolkit`` owns it, which is what froze
        ``/secrets``). For the duration of the read the persistent history is
        swapped for an empty in-memory one, so the secret never reaches the
        on-disk history file, and the prompt is restored afterwards.
        """
        if not self.use_tui:
            import getpass

            return getpass.getpass(prompt_text)
        from prompt_toolkit.history import InMemoryHistory

        previous_history = self._input.history
        previous_prompt = self.prompt_text
        self._input.history = InMemoryHistory()
        self._secret_mode = True
        try:
            return str(self.prompt(prompt_text))
        finally:
            self._secret_mode = False
            self._input.history = previous_history
            self.prompt_text = previous_prompt
            self.invalidate()

    def print(self, text: str, *, end: str = "\n") -> None:
        if not self.use_tui:
            print(text, end=end)
            return
        self.append_scrollback(str(text) + end)

    def _block_break(self) -> str:
        """One blank line before a new block, never two.

        The transcript is a concatenation of segments, so a block that starts
        right after a line ending in ``\n`` used to be glued to it (the tool
        invocation and the following thought read as one paragraph). Reading
        the previous segment instead of the rendered buffer keeps this correct
        while a typewriter reveal is still drawing.
        """
        with self._lock:
            if not self._segments:
                return ""
            last = self._segments[-1]
            tail = str(last.get("_type_full") or self._segment_text(last))
        if not tail:
            return ""
        if tail.endswith("\n\n"):
            return ""
        return "\n" if tail.endswith("\n") else "\n\n"

    def append_execution_block(self, text: str) -> None:
        """Append a tool invocation as its own paragraph.

        ``· fase · [tool]`` opens an execution block: one blank line separates
        it from the previous block, and the result card renders on the next
        line under it. The spacing is stored in the segment text, so rebuilding
        the transcript (a card toggle) reproduces it exactly.
        """
        body = str(text or "").rstrip("\n")
        if not body:
            return
        self.append_scrollback(self._block_break() + body + "\n")

    def append_result_block(self, markdown: str, *, title: str | None = None) -> None:
        """Append the final result as a framed panel with air above and below.

        The raw Markdown is stored, not a painted box: :meth:`_segment_text`
        re-renders it at the current width, so a resize or a reflow redraws the
        border instead of cutting it. Execution blocks already contribute their
        separating blank line; the result is terminal and owns the trailing gap.
        """
        body = str(markdown or "").rstrip("\n")
        if not body:
            return
        if not self.use_tui:
            print(body)
            return
        lead = self._block_break()
        self._enqueue_segment({
            "kind": "result", "markdown": body, "title": title,
            "lead": lead, "trail": "\n\n",
        })

    def append_answer_block(self, markdown: str, *, title: str | None = None) -> None:
        """Append a conversational answer as a reflowable framed block."""
        body = str(markdown or "").rstrip("\n")
        if not body:
            return
        if not self.use_tui:
            print(body)
            return
        lead = self._block_break()
        self._enqueue_segment({
            "kind": "answer", "markdown": body, "title": title,
            "lead": lead, "trail": "\n\n",
        })

    def append_user_turn(self, value: str) -> None:
        """Append one operator turn as a reflowable framed block.

        A turn opens a new identity context: the next block is titled by the
        tools *this* turn runs, never by a subagent left over from the previous
        one. The timestamp is captured here so a redraw keeps the original time.
        """
        from datetime import datetime

        text = str(value or "")
        if not text:
            return
        if not self.use_tui:
            print(text)
            return
        lead = self._block_break()
        self._last_tool_id = None
        # A new turn starts a fresh identity context: the first Recon card is
        # ``OMNI · Recon`` again, not ``(3)`` from the previous question.
        with self._lock:
            self._identity_seq.clear()
        self._enqueue_segment({
            "kind": "user", "text": text, "lead": lead, "trail": "\n\n",
            "now": datetime.now(),
        })
        # Submitting a question resumes the live tail: the operator sees the new
        # turn, while the previous work stays above and remains scrollable.
        if not self._auto_scroll:
            self._follow_tail()

    def append_scrollback(self, text: str, *, typed: bool = False) -> None:
        if not self.use_tui:
            print(text, end="")
            return
        self._enqueue_segment({"kind": "text", "text": str(text)}, typed=typed)

    def _enqueue_segment(self, segment: dict[str, Any], *, typed: bool = False) -> None:
        """Queue one transcript segment, typed or whole, in program order."""
        schedule = False
        typed_block = False
        with self._lock:
            text = self._segment_text(segment)
            self._lines.append(text)
            self._segments.append(segment)
            typed_block = bool(typed) and self._typewriter_enabled()
            if typed_block:
                segment["_type_full"] = text
                segment["text"] = ""
                # Visible to ``flush``/``close`` at once: a block waiting for
                # its dispatch can never be lost.
                self._typing_queue.append(segment)
                self._typing_active = True
            else:
                self._write_queue.append(segment)
                schedule = not self._flush_scheduled
                self._flush_scheduled = True
        if typed_block:
            self._dispatch(self._start_typing)
        elif schedule:
            self._schedule_flush()

    def _schedule_flush(self) -> None:
        if self._loop is not None and self._loop.is_running():
            self._dispatch(lambda: self._loop.call_later(0.05, self._flush_scrollback))
        else:
            self._flush_scrollback()

    # -- transcript typewriter --------------------------------------------
    def _typewriter_enabled(self) -> bool:
        """True when a reveal can be paced: a running UI loop on a real session.

        ``NEXUS_TUI_TYPEWRITER=0`` turns it off for dumps and recordings; without
        a running loop (pipe capture, headless render) every block is written
        whole, so nothing is ever left invisible.
        """
        if not self.use_tui:
            return False
        if os.getenv("NEXUS_TUI_TYPEWRITER", "").strip().lower() in {"0", "false", "no"}:
            return False
        return self._loop is not None and self._loop.is_running()

    def _start_typing(self) -> None:
        """Start the reveal pump (runs on the UI loop).

        Anything older than the queued block is written first, so the log keeps
        the order the agent produced.
        """
        self._append_pending()
        if self._typing_task is None or self._typing_task.done():
            self._typing_task = asyncio.ensure_future(self._type_pending())

    async def _type_pending(self) -> None:
        from .presentation import (
            TYPEWRITER_INTERVAL,
            TYPEWRITER_MAX_BACKLOG,
            typewriter_steps,
        )

        try:
            while self._typing_queue:
                # The agent can produce faster than the reveal. An older block
                # is committed whole rather than letting the log lag behind.
                while len(self._typing_queue) > TYPEWRITER_MAX_BACKLOG:
                    self._commit_typed_block(self._typing_queue.pop(0))
                segment = self._typing_queue[0]
                full = str(segment.get("_type_full") or "")
                if not full:
                    self._typing_queue.pop(0)
                    self._commit_typed_block(segment)
                    continue
                base = self._scrollback.text
                revealed = ""
                for chunk in typewriter_steps(full):
                    revealed += chunk
                    with self._lock:
                        segment["text"] = revealed
                    self._commit_partial(base, revealed)
                    await asyncio.sleep(TYPEWRITER_INTERVAL)
                self._typing_queue.pop(0)
                with self._lock:
                    segment["text"] = full
                self._commit_typed_block(segment, base=base)
        finally:
            self._typing_active = False
            if self._typing_deferred:
                self._typing_deferred = False
                self._append_pending()
            if self._typing_queue:
                # A block arrived while the reveal was closing: keep the pump
                # running instead of leaving it queued forever.
                self._typing_active = True
                self._typing_task = asyncio.ensure_future(self._type_pending())
            else:
                self._typing_task = None
                # The reveal held the trim so it could never resurrect a
                # dropped block; now the bounded view can be compacted.
                self._dispatch(self._compact_transcript)
                if self._resize_pending:
                    self._resize_pending = False
                    self._dispatch(self.handle_resize)

    def _commit_partial(self, base: str, revealed: str) -> None:
        """Draw the block being typed over the committed transcript.

        The partial text lives only in the document: the ``_write_queue`` keeps
        receiving whole segments meanwhile, and none of them can be appended
        while a reveal is open (that would duplicate the tail).
        """
        from prompt_toolkit.document import Document

        from .presentation import wrap_terminal_text

        self._typed_base = base
        tail = (wrap_terminal_text(revealed, width=self._scrollback_width(),
                                  no_color=self.no_color) if revealed else "")
        plain = base + tail
        # A reveal must not yank the operator back to the tail: if they scrolled
        # up to read earlier work, the growing block keeps arriving below,
        # outside the viewport, until they return to the bottom.
        cursor = len(plain) if self._auto_scroll else min(
            self._scrollback.cursor_position, len(plain)
        )
        self._scrollback.set_document(Document(plain, cursor), bypass_readonly=True)

    def _commit_typed_block(self, segment: dict[str, Any], *, base: str | None = None) -> None:
        """Close a reveal: the block becomes an ordinary transcript segment."""
        from prompt_toolkit.document import Document

        committed = self._typed_base if base is None else base
        if committed is not None and self._scrollback.text != committed:
            self._scrollback.set_document(Document(committed, len(committed)),
                                          bypass_readonly=True)
        self._typed_base = None
        with self._lock:
            segment.pop("_type_full", None)
            segment["text"] = str(segment.get("text") or "")
            self._write_queue.append(segment)
            self._flush_scheduled = True
            self._append_pending()

    def _reveal_typed_now(self) -> None:
        """Commit every block still being typed (``flush`` never splits a block)."""
        from prompt_toolkit.document import Document

        task, pending = self._typing_task, self._typing_queue
        self._typing_queue = []
        if self._typed_base is not None:
            self._scrollback.set_document(Document(self._typed_base, len(self._typed_base)),
                                          bypass_readonly=True)
            self._typed_base = None
        with self._lock:
            for segment in pending:
                full = segment.pop("_type_full", None)
                if full is not None:
                    segment["text"] = str(full)
                self._write_queue.append(segment)
            self._flush_scheduled = True
        self._typing_active = False
        self._typing_deferred = False
        if task is not None and not task.done():
            task.cancel()
        if self._resize_pending:
            self._resize_pending = False
            self._dispatch(self.handle_resize)

    def _next_identity(self, base: str | None) -> int:
        """The call number of ``base`` inside the current operator turn."""
        key = str(base or 'Resultado')
        index = int(self._identity_seq.get(key, 0)) + 1
        self._identity_seq[key] = index
        return index

    def _new_tool_card(self, tool_id: str | None, arguments: Any,
                       result: dict[str, Any] | None, *,
                       expanded: bool | None, typed: bool | None) -> dict[str, Any]:
        """Build one subagent card holding its invocation (and result, if any)."""
        from .presentation import subagent_title

        base = subagent_title(tool_id) or 'Resultado'
        card: dict[str, Any] = {
            "kind": "card",
            "thought": None,
            "reasoning": None,
            "pasted_input": None,
            "input_prefix": None,
            "id": self._next_card_id,
            "tool_id": str(tool_id or ''),
            "arguments": arguments,
            "title_base": base,
            "identity_index": self._next_identity(base),
            "result": result,
            "expanded": bool(self.expand_cards if expanded is None else expanded),
        }
        self._next_card_id += 1
        if tool_id:
            self._last_tool_id = str(tool_id)
        return card

    def begin_tool(self, tool_id: str, arguments: Any) -> int | None:
        """Open the subagent card for a call that is about to run.

        The invocation is painted *inside* the identity that owns it, so the
        operator never sees ``• nexus.recon.nmap`` floating above a result box.
        :meth:`complete_tool` fills the result into this same card; a second
        call of the same subagent opens a new card (``OMNI · Recon (2)``).
        """
        if not self.use_tui:
            return None
        with self._lock:
            card = self._new_tool_card(tool_id, arguments, None, expanded=None, typed=False)
            # A pending call is not a typewriter block: its result must be able
            # to land in the same segment as soon as the tool returns.
            card["lead"] = self._block_break()
            self._cards[card["id"]] = card
            self._lines.append(self._card_text(card))
            self._segments.append(card)
            self._write_queue.append(card)
            schedule = not self._flush_scheduled
            self._flush_scheduled = True
        if schedule:
            self._schedule_flush()
        return int(card["id"])

    def complete_tool(self, result: dict[str, Any]) -> bool:
        """Attach a result to the pending card of the same tool, if any.

        Returns ``False`` when there is no open card (a resumed session or a
        result rendered on its own); the caller then appends an ordinary card.
        """
        if not self.use_tui:
            return False
        value = dict(result) if isinstance(result, dict) else {}
        tool_id = str(value.get("tool_id") or '')
        with self._lock:
            card: dict[str, Any] | None = None
            for segment in reversed(self._segments):
                if segment.get("kind") != 'card':
                    continue
                if segment.get("thought") is not None or segment.get("pasted_input") is not None:
                    continue
                if segment.get("result") is not None:
                    continue
                other = str(segment.get('tool_id') or '')
                if other and tool_id and other != tool_id:
                    continue
                card = segment
                break
            if card is None:
                return False
            card["result"] = value
            if tool_id:
                card["tool_id"] = tool_id
                self._last_tool_id = tool_id
            queued = card in self._write_queue or card in self._typing_queue
            if queued:
                return True
            plain = self._rebuild_state_locked()
            cursor = len(plain) if self._auto_scroll else min(
                self._scrollback.cursor_position, len(plain)
            )
        self._dispatch(lambda: self._commit_transcript(plain, cursor))
        return True

    def append_card(self, result: dict[str, Any], *, expanded: bool | None = None,
                    thought: str | None = None, pasted_input: str | None = None,
                    input_prefix: str | None = None, typed: bool | None = None,
                    reasoning: str | None = None, tool_id: str | None = None,
                    arguments: Any = None) -> None:
        """Append a tool-result card that expands/collapses on its own (click).

        ``arguments`` turns it into a combined subagent card: the invocation and
        the result share one box. Without arguments it keeps the historical
        result-only card (used by resumed sessions and standalone renderers).
        """
        value = dict(result) if isinstance(result, dict) else {}
        schedule = False
        typed_block = False
        with self._lock:
            if thought is None and pasted_input is None and tool_id is None:
                tool_id = str(value.get("tool_id") or '') or None
            if thought is None and pasted_input is None and tool_id:
                card = self._new_tool_card(tool_id, arguments, value,
                                           expanded=expanded, typed=typed)
            else:
                card = {
                    "kind": "card",
                    "thought": thought,
                    "reasoning": reasoning,
                    "pasted_input": pasted_input,
                    "input_prefix": input_prefix,
                    "id": self._next_card_id,
                    "result": value,
                    "expanded": bool(self.expand_cards if expanded is None else expanded),
                }
                self._next_card_id += 1
            # The card is a block of its own: keep it off the previous line.
            card["lead"] = self._block_break()
            self._cards[card["id"]] = card
            text = self._card_text(card)
            self._lines.append(text)
            self._segments.append(card)
            # A combined call is only revealed while it is a plain result card;
            # the pending segment must stay updatable in place.
            typed_block = (
                arguments is None
                and (self._typewriter_enabled() if typed is None
                     else bool(typed) and self._typewriter_enabled())
            )
            if typed_block:
                card["_type_full"] = text
                card["text"] = ""
                self._typing_queue.append(card)
                self._typing_active = True
            else:
                self._write_queue.append(card)
                schedule = not self._flush_scheduled
                self._flush_scheduled = True
        if typed_block:
            self._dispatch(self._start_typing)
        elif schedule:
            self._schedule_flush()

    def _card_text(self, card: dict[str, Any]) -> str:
        from .stream import format_tool_card, render_tool_result

        lead = str(card.get("lead") or "")
        if card.get("pasted_input") is not None:
            from .strings import HIDE_REASONING, SHOW_PASTED_INPUT
            from rich.text import Text
            from .presentation import clean_text, input_chip, input_quote, render_rich
            value = str(card['pasted_input'])
            expanded = bool(card.get('expanded'))
            visible = clean_text(value) if expanded else input_chip(value).plain
            prefix = clean_text(str(card.get('input_prefix') or self._input_prefix()))
            width = self.text_width
            quote = input_quote(prefix + visible, width=width, no_color=self.no_color)
            footer = render_rich(Text(HIDE_REASONING if expanded else SHOW_PASTED_INPUT, style='dim'),
                                 width=width, no_color=self.no_color)
            return lead + quote + '\n  ' + footer + '\n\n'
        if card.get("thought") is not None:
            from .presentation import thinking_block
            expanded = bool(card.get("expanded"))
            rendered = thinking_block(
                str(card["thought"]), expanded=expanded,
                width=self.text_width, reasoning=card.get("reasoning"),
                no_color=self.no_color,
            )
            return lead + rendered + "\n\n"
        tool_id = str(card.get("tool_id") or (card.get("result") or {}).get("tool_id") or '')
        if card.get("arguments") is not None:
            from .presentation import numbered_title
            title = numbered_title(
                str(card.get("title_base") or 'Resultado'),
                int(card.get("identity_index") or 1),
            )
            return lead + format_tool_card(
                tool_id, card.get("arguments"), card.get("result"),
                expanded=bool(card.get("expanded")), max_lines=6,
                width=self.text_width, no_color=self.no_color, title=title,
            ) + "\n\n"
        from .presentation import numbered_title
        card_title: str | None = None
        if card.get("title_base"):
            card_title = numbered_title(
                str(card.get("title_base")), int(card.get("identity_index") or 1)
            )
        return lead + render_tool_result(
            card.get("result") or {}, expanded=bool(card.get("expanded")),
            max_lines=4, width=self.text_width, no_color=self.no_color,
            title=card_title,
        ) + "\n\n"

    def _segment_text(self, segment: dict[str, Any]) -> str:
        """Render one segment at the *current* transcript width.

        Pre-rendered text is fine for incidental output, but every framed block
        is stored as data (kind + payload) and redrawn here. That is what lets a
        terminal resize repaint the borders instead of wrapping and cutting a
        panel that was frozen at the old width.
        """
        # A block being revealed shows what has been typed so far, not its full
        # rendering; once committed it is rebuilt from its payload again.
        if segment.get("_type_full") is not None:
            return str(segment.get("text") or "")
        kind = segment.get("kind")
        if kind == "card":
            return self._card_text(segment)
        if kind == "user":
            from .presentation import user_message

            return (
                str(segment.get("lead") or "")
                + user_message(
                    str(segment.get("text") or ""),
                    width=self.text_width,
                    no_color=self.no_color,
                    now=segment.get("now"),
                )
                + str(segment.get("trail") or "\n\n")
            )
        if kind in {"answer", "result"}:
            from .markdown import render_markdown
            from .presentation import ADVISOR_TITLE, answer_panel, result_panel

            width = self.text_width
            body = render_markdown(
                str(segment.get("markdown") or ""),
                no_color=self.no_color,
                max_width=max(20, width - 6),
            )
            title = str(segment.get("title") or "")
            if kind == "answer":
                panel = answer_panel(
                    body, width=width, title=title or ADVISOR_TITLE,
                    no_color=self.no_color,
                )
            else:
                panel = result_panel(
                    body, width=width, title=title or ADVISOR_TITLE,
                    no_color=self.no_color,
                )
            return (
                str(segment.get("lead") or "")
                + panel
                + str(segment.get("trail") or "\n\n")
            )
        return str(segment.get("text") or "")

    @staticmethod
    def _has_toggle(card: dict[str, Any]) -> bool:
        from .presentation import clean_text
        from .stream import structured_detail, trace_text
        if card.get("thought") is not None or card.get("pasted_input") is not None:
            return True
        result = card.get("result") or {}
        if structured_detail(result):
            # Its pretty JSON is the detail: collapsed it only shows a summary,
            # so the toggle has to be reachable even for a two-line body.
            return True
        value, _ = trace_text(result)
        return len(clean_text(value).splitlines()) > 4

    @staticmethod
    def _footer_line_index(styled: list[list[Any]]) -> int | None:
        """Last physical content line, including footers wrapped on narrow screens.

        Framed blocks put the bottom border after the actual footer. Walking
        back from the bottom, a border-only row is not an affordance: the click
        target is the last row that still carries text (``Ver X líneas más``,
        ``▸ Razonamiento``, ``ctrl+t colapsar``).
        """
        from prompt_toolkit.formatted_text import fragment_list_to_text
        frame = set("╭╮╰╯─│┌┐└┘ ")
        for index in range(len(styled) - 1, -1, -1):
            text = fragment_list_to_text(styled[index]).strip()
            if text and any(char not in frame for char in text):
                return index
        return None

    def toggle_card_at_line(self, line: int) -> bool:
        """Expand/collapse the card whose toggle footer is ``line`` (click/Enter)."""
        with self._lock:
            card_id = self._toggle_rows.get(int(line))
            card = self._cards.get(card_id) if card_id is not None else None
            if card is None:
                return False
            card["expanded"] = not bool(card["expanded"])
            plain = self._rebuild_state_locked()
            cursor = len(plain) if self._auto_scroll else min(
                self._scrollback.cursor_position, len(plain)
            )
        self._dispatch(lambda: self._commit_transcript(plain, cursor))
        return True

    def _commit_transcript(self, plain: str, cursor: int) -> None:
        from prompt_toolkit.document import Document

        self._scrollback.set_document(Document(plain, cursor), bypass_readonly=True)
        if self._auto_scroll:
            self._scrollback_window.vertical_scroll = max(0, len(self._styled_lines) - 1)
        else:
            # Old blocks may have been dropped while the operator was reading:
            # never leave the viewport pointing past the remaining document.
            self._scrollback_window.vertical_scroll = min(
                self._scrollback_window.vertical_scroll,
                max(0, len(self._styled_lines) - 1),
            )
        self.invalidate()

    def _trim_transcript_locked(self) -> bool:
        """Drop the oldest visual blocks when the bounded view is exceeded.

        Durable messages stay in the Store; only the in-memory segments, cards
        and toggle targets are released. The newest block is always kept, even
        when a single tool output is larger than the line cap.
        """
        if self._typing_active or self._typing_queue or self._write_queue:
            return False
        segments = self._segments
        total = sum(int(segment.get("_line_count") or 0) for segment in segments)
        if len(segments) <= TRANSCRIPT_MAX_SEGMENTS and total <= TRANSCRIPT_MAX_LINES:
            return False
        drop = 0
        while drop < len(segments) - 1 and (
            len(segments) - drop > TRANSCRIPT_MAX_SEGMENTS
            or total > TRANSCRIPT_MAX_LINES
        ):
            total -= int(segments[drop].get("_line_count") or 0)
            drop += 1
        if not drop:
            return False
        dropped, self._segments = segments[:drop], segments[drop:]
        for segment in dropped:
            card_id = segment.get("id")
            if card_id is not None:
                self._cards.pop(card_id, None)
        self._lines = [self._segment_text(segment) for segment in self._segments]
        return True

    def _compact_transcript(self) -> None:
        """Apply retention after a typewriter reveal has fully drained."""
        with self._lock:
            if not self._trim_transcript_locked():
                return
            plain = self._rebuild_state_locked()
            cursor = len(plain) if self._auto_scroll else min(
                self._scrollback.cursor_position, len(plain)
            )
        self._commit_transcript(plain, cursor)

    def _rebuild_state_locked(self) -> str:
        """Recompute styled lines, toggle rows and plain text from the segments.

        Called while holding ``_lock``; the buffer commit happens on the UI loop
        through :meth:`_commit_transcript`.
        """
        from prompt_toolkit.formatted_text import fragment_list_to_text
        from prompt_toolkit.formatted_text.utils import split_lines
        from .presentation import wrap_terminal_text

        styled: list[list[Any]] = [[]]
        toggle: dict[int, int] = {}
        raw_lines: list[str] = []
        for segment in self._segments:
            text = self._segment_text(segment)
            raw_lines.append(text)
            if not text:
                continue
            wrapped = wrap_terminal_text(text, width=self._scrollback_width(), no_color=self.no_color)
            lines = list(split_lines(self._formatted(wrapped)))
            if not lines:
                continue
            segment["_line_count"] = len(lines)
            styled[-1].extend(lines[0])
            styled.extend(lines[1:])
            if segment.get("kind") == "card" and self._has_toggle(segment):
                index = self._footer_line_index(styled)
                if index is not None:
                    toggle[index] = segment["id"]
        plain = "\n".join(fragment_list_to_text(row) for row in styled)
        self._styled_lines = styled
        self._toggle_rows = toggle
        self._lines = raw_lines
        self._last_render_width = self._scrollback_width()
        return plain

    def _flush_scrollback(self) -> None:
        """Append queued segments, unless a typewriter reveal is open."""
        if self._typing_active:
            # Appending now would duplicate the partial block that only lives in
            # the document; the reveal flushes the queue when it closes.
            self._typing_deferred = True
            return
        self._append_pending()

    def _append_pending(self) -> None:
        from prompt_toolkit.document import Document
        from prompt_toolkit.formatted_text import fragment_list_to_text
        from prompt_toolkit.formatted_text.utils import split_lines
        from .presentation import wrap_terminal_text

        with self._lock:
            pending = self._write_queue
            self._write_queue = []
            self._flush_scheduled = False
        if not pending:
            return
        plain_add: list[str] = []
        for segment in pending:
            text = self._segment_text(segment)
            if not text:
                continue
            wrapped = wrap_terminal_text(text, width=self._scrollback_width(), no_color=self.no_color)
            fragments = self._formatted(wrapped)
            lines = list(split_lines(fragments))
            if not lines:
                continue
            self._styled_lines[-1].extend(lines[0])
            self._styled_lines.extend(lines[1:])
            segment["_line_count"] = len(lines)
            if segment.get("kind") == "card" and self._has_toggle(segment):
                # The footer is the click target for expanding just this card.
                index = self._footer_line_index(self._styled_lines)
                if index is not None:
                    self._toggle_rows[index] = segment["id"]
            plain_add.append(fragment_list_to_text(fragments))
        if not plain_add:
            return
        compacted: tuple[str, int] | None = None
        with self._lock:
            if self._trim_transcript_locked():
                plain = self._rebuild_state_locked()
                cursor = len(plain) if self._auto_scroll else min(
                    self._scrollback.cursor_position, len(plain)
                )
                compacted = (plain, cursor)
        if compacted is not None:
            self._commit_transcript(*compacted)
            return
        plain = self._scrollback.text + "".join(plain_add)
        cursor = len(plain) if self._auto_scroll else self._scrollback.cursor_position
        self._scrollback.set_document(Document(plain, cursor), bypass_readonly=True)
        # BufferControl observes the document change; no explicit invalidation.

    def _page_lines(self) -> int:
        """Logical lines moved by PageUp/PageDown, sized to the visible region.

        The transcript does not own the whole terminal: the badge, the prompt
        dock (five rows), the helper hints and the operational bar keep their
        own rows. Subtracting them from ``rows`` makes one PageUp move one
        *visible* page instead of overshooting the whole history.
        """
        try:
            rows = int(self._session.output.get_size().rows)
        except Exception:  # noqa: BLE001 - cosmetic sizing only
            rows = 24
        return max(1, rows - 10)

    def _scrollback_width(self) -> int:
        """Usable text width after the console's two-cell left inset."""
        try:
            columns = int(self._session.output.get_size().columns)
        except Exception:  # noqa: BLE001 - keep render fallback resilient
            columns = 80
        return max(1, columns - 2)

    def block_width(self) -> int:
        """The one geometry of the transcript: every framed block uses it.

        The scrollback owns two inset cells (``left=2``/``right=2``), so a block
        painted at ``columns - 2`` fills the region exactly. Renderers call
        :attr:`text_width`; keeping the arithmetic here means a future inset
        change touches one place instead of every panel.
        """
        return self._scrollback_width()

    @property
    def text_width(self) -> int:
        """Usable transcript width, for renderers that pre-wrap a block."""
        return self.block_width()

    def note_tool(self, tool_id: str | None) -> None:
        """Remember the last tool that ran, for the next block's identity.

        This is a label only. Scope, approvals, risk and the audit chain keep
        using the real tool id through the gateway.
        """
        value = str(tool_id or "").strip()
        if value:
            self._last_tool_id = value

    def last_subagent_title(self) -> str | None:
        """``OMNI · Recon`` for the last tool of this turn, or ``None``."""
        from .presentation import subagent_title

        return subagent_title(self._last_tool_id)

    def copy_candidates(self) -> list[dict[str, str]]:
        """Assistant blocks that ``/copy`` can deliver, newest first.

        Only content the model produced counts: a conversational answer, a
        final result or a tool body. Operator turns are context, not an answer,
        and thinking cards are excluded because reasoning is not evidence. The
        stored payload is rendered again as plain text, so the clipboard never
        receives ANSI codes or half a frame.
        """
        from .markdown import render_markdown
        from .presentation import ADVISOR_TITLE, clean_text, subagent_title
        from .stream import plain_result_text

        with self._lock:
            segments = list(self._segments)
        items: list[dict[str, str]] = []
        for segment in reversed(segments):
            kind = segment.get("kind")
            if kind in {"answer", "result"}:
                markdown = str(segment.get("markdown") or "").strip()
                if not markdown:
                    continue
                default = ADVISOR_TITLE if kind == "answer" else "Resultado final"
                items.append({
                    "kind": str(kind),
                    "title": str(segment.get("title") or default),
                    "text": clean_text(
                        render_markdown(markdown, no_color=True)
                    ).strip(),
                })
                continue
            if kind == "card" and segment.get("thought") is None:
                result = segment.get("result") or {}
                text = plain_result_text(result).strip()
                if not text:
                    continue
                items.append({
                    "kind": "tool",
                    "title": subagent_title(result.get("tool_id")) or "Resultado",
                    "text": text,
                })
        return items

    def plain_transcript(self) -> str:
        """The whole conversation as unframed plain text, for ``/copy all``."""
        from .markdown import render_markdown
        from .presentation import clean_text
        from .stream import plain_result_text

        with self._lock:
            segments = list(self._segments)
        blocks: list[str] = []
        for segment in segments:
            kind = segment.get("kind")
            if kind == "user":
                blocks.append(clean_text(str(segment.get("text") or "")).strip())
            elif kind in {"answer", "result"}:
                blocks.append(clean_text(render_markdown(
                    str(segment.get("markdown") or ""), no_color=True,
                )).strip())
            elif kind == "card":
                if segment.get("thought") is not None:
                    thought = clean_text(str(segment.get("thought") or "")).strip()
                    if thought:
                        blocks.append(f"▸ Razonamiento\n{thought}")
                else:
                    blocks.append(plain_result_text(segment.get("result") or {}).strip())
            else:
                blocks.append(clean_text(str(segment.get("text") or "")).strip())
        return "\n\n".join(block for block in blocks if block)

    def handle_resize(self) -> None:
        """Redraw every framed block at the new terminal width.

        A box painted at the old width is text, so prompt_toolkit would merely
        wrap it and cut the border. Rebuilding from the stored payload is the
        only way to keep the geometry honest after a resize.
        """
        if not self.use_tui:
            return
        if self._typing_active:
            # The reveal owns the document; reflow once it closes.
            self._resize_pending = True
            return
        width = self._scrollback_width()
        with self._lock:
            if width == self._last_render_width:
                return
            self._last_render_width = width
            plain = self._rebuild_state_locked()
            cursor = len(plain) if self._auto_scroll else min(
                self._scrollback.cursor_position, len(plain)
            )
        self._commit_transcript(plain, cursor)

    def _scroll_to(self, line: int) -> None:
        """Put logical line ``line`` at the top of the transcript region."""
        document = self._scrollback.document
        line = max(0, min(int(line), max(0, document.line_count - 1)))
        self._scrollback.cursor_position = document.translate_row_col_to_index(line, 0)
        self._scrollback_window.vertical_scroll = line
        self.invalidate()

    def _follow_tail(self) -> None:
        """Resume following new output (the view returns to the live tail)."""
        self._auto_scroll = True
        self._is_scrolling = False
        self._scrollback.cursor_position = len(self._scrollback.text)
        self._scrollback_window.vertical_scroll = max(
            0, self._scrollback.document.line_count - 1
        )
        self.invalidate()

    def _visible_height(self) -> int:
        """Rows the transcript actually paints, including wrapped lines.

        ``render_info`` is the honest source once the first frame is on screen;
        before that (and in headless tests) the row estimate is used.
        """
        info = getattr(self._scrollback_window, "render_info", None)
        if info is not None:
            try:
                height = int(info.window_height)
                if height > 0:
                    return height
            except (AttributeError, TypeError, ValueError):
                pass
        return self._page_lines()

    def _max_vertical_scroll(self) -> int:
        """Top line that still leaves the tail visible.

        A logical line may occupy several rows, so ``line_count - height``
        overshoots on a wrapped transcript. Walking up from the last line with
        the renderer's own wrapped heights keeps the anchor exact and makes
        PageDown return to the live tail on the first press that reaches it.
        """
        document = self._scrollback.document
        last = max(0, document.line_count - 1)
        height = max(1, self._visible_height())
        info = getattr(self._scrollback_window, "render_info", None)
        if info is None or not getattr(info, "wrap_lines", True):
            return max(0, document.line_count - height)
        used = 0
        for lineno in range(last, -1, -1):
            try:
                used += max(1, int(info.get_height_for_line(lineno)))
            except Exception:  # noqa: BLE001 - cosmetic anchor only
                used += 1
            if used >= height:
                return lineno
        return 0

    def scroll_transcript(self, lines: int) -> None:
        """Scroll the transcript by ``lines`` (negative scrolls up).

        Moving the view directly (not just the buffer cursor) removes the
        one-page lag of the old handler: the first PageUp already shows the
        previous page. Reaching the bottom resumes automatic follow.
        """
        if lines < 0:
            self._auto_scroll = False
            self._is_scrolling = True
            self._scroll_to(self._scrollback_window.vertical_scroll + lines)
            return
        target = self._scrollback_window.vertical_scroll + max(0, int(lines))
        if target >= self._max_vertical_scroll():
            self._follow_tail()
        else:
            self._scroll_to(target)

    def _render_busy(self) -> StyleAndTextTuples:
        if not self._status.busy:
            return []
        elapsed = max(0, int(time.monotonic() - self._status.busy_started_at))
        # The row is drawn inside the console's two-cell inset: sizing it to the
        # usable width keeps ``esc interrupt`` whole on a 60-column terminal
        # instead of losing its last cell to the margin.
        text = self._working_indicator.frame(
            self._status.busy_message, now=time.monotonic(), elapsed=elapsed,
            width=self._scrollback_width(), no_color=self.no_color)
        return self._formatted(text)

    def set_busy(self, message: str = "") -> None:
        """Start the fixed work row: the pulse replaces the completion line.

        Nothing is written to the transcript, so the pulse cannot scroll away
        while the chat advances.
        """
        self._cancel_event.clear()
        self._completion_status = None
        self.set_status(busy=True, busy_message=message)

    def clear_busy(self) -> None:
        """Stop the pulse; the same row now shows ``Worked for Xs • hh:mm``."""
        self.flush()
        with self._lock:
            was_busy = self._status.busy
            elapsed = max(0, int(time.monotonic() - self._status.busy_started_at))
        if was_busy and self.use_tui:
            from .frame import completion_text
            self._completion_status = completion_text(elapsed)
            self.set_status(busy=False)
            self.invalidate()
        else:
            self.set_status(busy=False)


    def clear_screen(self) -> None:
        """Clear the TUI terminal before its first frame; fallback is untouched."""
        if not self.use_tui:
            return
        def clear() -> None:
            self._session.output.erase_screen()
            self._session.output.cursor_goto(0, 0)
            self._session.output.flush()
            self.invalidate()
        self._dispatch(clear)

    def flush(self) -> None:
        if not self.use_tui or self._loop is None or not self._loop.is_running():
            return
        if threading.current_thread() is self._thread:
            return
        done = threading.Event()

        def drain() -> None:
            try:
                self._reveal_typed_now()
                self._append_pending()
            finally:
                done.set()

        self._dispatch(drain)
        if not done.wait(5):
            raise RuntimeError("TUI output did not drain")

    def set_status(self, **fields: Any) -> None:
        if not self.use_tui:
            return
        aliases = {
            "engagement": "engagement_name", "session": "session_uuid",
            "trust": "trust_mode", "provider": "provider_model",
            "cost": "cost_usd", "audit_chain": "audit_chain_valid",
            "msfrpcd": "msfrpcd_version", "time": "started_at",
        }
        with self._lock:
            if fields.get("busy") and not self._status.busy:
                self._status.busy_started_at = time.monotonic()
            tokens = fields.pop("tokens", None)
            if tokens is not None:
                fields["tokens_input"], fields["tokens_output"] = (
                    tokens if isinstance(tokens, tuple) else (tokens, 0)
                )
            for key, value in fields.items():
                setattr(self._status, aliases.get(key, key), value)
        self._session.app.min_redraw_interval = 0.1
        self._session.app.refresh_interval = 0.1 if self._status.busy or self.task_panel.running else None
        self._dispatch(self._session.app.refresh_wake.set)
        self.invalidate()

    def invalidate(self) -> None:
        if self.use_tui and not self._closed:
            self._session.app.invalidate()

    def close(self) -> None:
        if self._closed:
            return
        try:
            self.flush()
        finally:
            self._closed = True
            if self._thread and self._thread.is_alive():
                def stop() -> None:
                    app = self._session.app
                    if app.is_running and not app.future.done():
                        app.exit()
                self._dispatch(stop)
                self._thread.join(timeout=5)
                if self._thread.is_alive():
                    raise RuntimeError("TUI thread did not stop")
