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
        #: Live ReAct "thinking" text shown while the model streams a turn.
        self._thought_text: str | None = None
        from .presentation import WorkingIndicator
        self._working_indicator = WorkingIndicator()
        self._auto_scroll = True
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
            if self._can_edit and not event.current_buffer.text:
                self._answer(EOFError())
            elif self._can_edit:
                event.current_buffer.delete()

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
        """Editor rows, footer and three lines of breathing room in its panel."""
        from prompt_toolkit.utils import get_cwidth

        size = self._session.output.get_size()
        # The panel loses one column to the red bar and two to the ``> `` prefix.
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
        """Fixed top row: brand, engagement and -only while working- a timer."""
        from .frame import header_text

        elapsed = (
            time.monotonic() - self._status.busy_started_at
            if self._status.busy
            else None
        )
        try:
            width = self._session.output.get_size().columns
        except Exception:  # noqa: BLE001 - cosmetic sizing only
            width = None
        return [("" if self.no_color else "#ff0055",
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
        return [("#ff0055 bold" if not self.no_color else "", self._completion_status)]

    def _workspace_footer(self) -> StyleAndTextTuples:
        """``model · ~/cwd`` in the bottom-left corner of the input panel.

        The panel footer is the single line that names the agent and the
        directory the session is bound to; ``Build`` is never rendered.
        """
        from .status import workspace_line
        with self._lock:
            from dataclasses import replace
            text = workspace_line(replace(self._status))
        return [("" if self.no_color else "#00d7ff", text)]

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
        from .markdown import DEFAULT_READING_WIDTH, render_markdown

        columns = self._session.output.get_size().columns
        width = max(20, min(DEFAULT_READING_WIDTH, columns - 4))
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
        """Rows of the live reasoning row: 1..3, never more."""
        with self._lock:
            text = self._thought_text or ""
        from .presentation import live_thought
        lines = live_thought(text, width=self._thought_width()).plain.splitlines()
        return max(1, min(3, len(lines)))

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
            from .presentation import input_chip, render_rich
            visible = render_rich(input_chip(text), no_color=self.no_color) if len(text) > 500 else self.input_document.render()
            # A secret is never echoed to the transcript: show a fixed mask so
            # the operator still sees that the input was taken.
            if not self._secret_mode and len(text) > 500:
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
        from .presentation import user_message

        width = int(self._session.output.get_size().columns) if self.use_tui else 100
        self.append_scrollback(user_message(
            value, width=max(8, width - 2), no_color=self.no_color,
        ) + "\n\n")

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

    def _run(self) -> None:
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

    def append_scrollback(self, text: str, *, typed: bool = False) -> None:
        if not self.use_tui:
            print(text, end="")
            return
        segment = {"kind": "text", "text": str(text)}
        schedule = False
        typed_block = False
        with self._lock:
            self._lines.append(segment["text"])
            self._segments.append(segment)
            typed_block = bool(typed) and self._typewriter_enabled()
            if typed_block:
                segment["_type_full"] = segment["text"]
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
        self._scrollback.set_document(Document(plain, len(plain)), bypass_readonly=True)

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

    def append_card(self, result: dict[str, Any], *, expanded: bool | None = None,
                    thought: str | None = None, pasted_input: str | None = None,
                    input_prefix: str | None = None, typed: bool | None = None,
                    reasoning: str | None = None) -> None:
        """Append a tool-result card that expands/collapses on its own (click)."""
        card: dict[str, Any] = {
            "kind": "card",
            "thought": thought,
            "reasoning": reasoning,
            "pasted_input": pasted_input,
            "input_prefix": input_prefix,
            "id": self._next_card_id,
            "result": result if isinstance(result, dict) else {},
            "expanded": bool(self.expand_cards if expanded is None else expanded),
        }
        schedule = False
        typed_block = False
        with self._lock:
            # The card is a block of its own: keep it off the previous line.
            card["lead"] = self._block_break()
            self._next_card_id += 1
            self._cards[card["id"]] = card
            text = self._card_text(card)
            self._lines.append(text)
            self._segments.append(card)
            typed_block = (self._typewriter_enabled() if typed is None
                           else bool(typed) and self._typewriter_enabled())
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
        from .stream import render_tool_result

        lead = str(card.get("lead") or "")
        if card.get("pasted_input") is not None:
            from .strings import HIDE_REASONING, SHOW_PASTED_INPUT
            from rich.text import Text
            from .presentation import clean_text, input_chip, input_quote, render_rich
            value = str(card['pasted_input'])
            expanded = bool(card.get('expanded'))
            visible = clean_text(value) if expanded else input_chip(value).plain
            prefix = clean_text(str(card.get('input_prefix') or self._input_prefix()))
            width = max(1, int(self._session.output.get_size().columns) - 2)
            quote = input_quote(prefix + visible, width=width, no_color=self.no_color)
            footer = render_rich(Text(HIDE_REASONING if expanded else SHOW_PASTED_INPUT, style='dim'),
                                 width=width, no_color=self.no_color)
            return lead + quote + '\n  ' + footer + '\n\n'
        if card.get("thought") is not None:
            from .presentation import render_rich, thinking
            expanded = bool(card.get("expanded"))
            width = int(self._session.output.get_size().columns) if self.use_tui else 100
            rendered = thinking(str(card["thought"]), expanded=expanded,
                                width=max(20, width - 2), reasoning=card.get("reasoning"))
            return lead + render_rich(rendered, width=max(20, width - 2),
                                      no_color=self.no_color) + "\n\n"
        width = int(self._session.output.get_size().columns) if self.use_tui else 100
        return lead + render_tool_result(card.get("result") or {}, expanded=bool(card.get("expanded")),
                                         max_lines=4, width=max(20, width - 2),
                                         no_color=self.no_color) + "\n\n"

    def _segment_text(self, segment: dict[str, Any]) -> str:
        # A card being revealed shows what has been typed so far, not its full
        # rendering; once committed it is rebuilt from its result again.
        if segment.get("_type_full") is not None:
            return str(segment.get("text") or "")
        if segment.get("kind") == "card":
            return self._card_text(segment)
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
        """Last physical footer line, including footers wrapped on narrow screens."""
        from prompt_toolkit.formatted_text import fragment_list_to_text
        for index in range(len(styled) - 1, -1, -1):
            if fragment_list_to_text(styled[index]).strip():
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
        self.invalidate()

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
            if segment.get("kind") == "card" and self._has_toggle(segment):
                # The footer is the click target for expanding just this card.
                index = self._footer_line_index(self._styled_lines)
                if index is not None:
                    self._toggle_rows[index] = segment["id"]
            plain_add.append(fragment_list_to_text(fragments))
        if not plain_add:
            return
        plain = self._scrollback.text + "".join(plain_add)
        cursor = len(plain) if self._auto_scroll else self._scrollback.cursor_position
        self._scrollback.set_document(Document(plain, cursor), bypass_readonly=True)
        # BufferControl observes the document change; no explicit invalidation.

    def _page_lines(self) -> int:
        """Logical lines moved by PageUp/PageDown, sized to the visible region."""
        try:
            rows = int(self._session.output.get_size().rows)
        except Exception:  # noqa: BLE001 - cosmetic sizing only
            rows = 24
        return max(1, rows - 5)

    def _scrollback_width(self) -> int:
        """Usable text width after the console's two-cell left inset."""
        try:
            columns = int(self._session.output.get_size().columns)
        except Exception:  # noqa: BLE001 - keep render fallback resilient
            columns = 80
        return max(1, columns - 2)

    @property
    def text_width(self) -> int:
        """Usable transcript width, for renderers that pre-wrap a block."""
        return self._scrollback_width()

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
        self._scrollback.cursor_position = len(self._scrollback.text)
        self._scrollback_window.vertical_scroll = max(
            0, self._scrollback.document.line_count - 1
        )
        self.invalidate()

    def scroll_transcript(self, lines: int) -> None:
        """Scroll the transcript by ``lines`` (negative scrolls up).

        Moving the view directly (not just the buffer cursor) removes the
        one-page lag of the old handler: the first PageUp already shows the
        previous page. Reaching the bottom resumes automatic follow.
        """
        if lines < 0:
            self._auto_scroll = False
            self._scroll_to(self._scrollback_window.vertical_scroll + lines)
            return
        document = self._scrollback.document
        target = self._scrollback_window.vertical_scroll + max(0, int(lines))
        if target >= max(0, document.line_count - self._page_lines()):
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
