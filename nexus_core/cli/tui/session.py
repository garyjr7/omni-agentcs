"""Persistent prompt_toolkit application with a synchronous readline facade."""

from __future__ import annotations

import asyncio
from contextvars import copy_context
import importlib
import os
from pathlib import Path
from queue import Queue
import sys
import threading
import time
from typing import Any

from .fallback import fallback_prompt
from .status import StatusState, render_status_bar


def alt_screen_enabled() -> bool:
    """False when ``NEXUS_NO_ALT_SCREEN`` opts out of the dedicated screen."""
    return os.getenv("NEXUS_NO_ALT_SCREEN", "").strip().lower() not in {"1", "true", "yes"}


def should_use_tui() -> bool:
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

    def __init__(
        self, *, use_tui: bool, history_path: Path | None = None,
        status_bar_enabled: bool = True, no_color: bool = False,
        prompt_style: dict[str, Any] | None = None,
        enable_completion: bool = True,
        commands: dict | None = None, tools: dict | None = None,
        engagements: list[str] | None = None,
        input=None, output=None, full_screen: bool = True,
    ):
        self.use_tui = bool(use_tui)
        #: Own the terminal's alternate screen by default, like the top coding
        #: CLIs: ``omni`` opens on a clean dedicated screen and the shell prompt
        #: is restored on exit. ``--no-fullscreen`` (or
        #: ``NEXUS_NO_ALT_SCREEN``) keeps the inline layout so the terminal
        #: scrollback stays visible.
        self.full_screen = bool(full_screen) and alt_screen_enabled()
        self.status_bar_enabled = status_bar_enabled
        self.no_color = no_color or "NO_COLOR" in os.environ
        self.prompt_text = "└─$ "
        from .status import load_status_fields
        self._status = StatusState(cost_known=False, fields=load_status_fields())
        self._completion_context = (commands, tools or {}, engagements or [])
        self._enable_completion = enable_completion
        self._completer = None
        self._lock = threading.RLock()
        self._closed = False
        self._session = None
        self._thread = None
        self._loop = None
        self._context = None
        self._ready = threading.Event()
        self._answers: Queue = Queue()
        self._accepting = False
        #: While True the input buffer is masked and its content is never echoed
        #: to the transcript (secure secret entry).
        self._secret_mode = False
        self._lines: list[str] = []
        self._styled_lines = [[]]
        #: Ordered transcript segments (text or tool card) for in-place redraw.
        self._segments: list[dict[str, Any]] = []
        self._write_queue: list[dict[str, Any]] = []
        self._flush_scheduled = False
        #: Per-block accordion: card state, toggle-line index and id counter.
        self._cards: dict[int, dict[str, Any]] = {}
        self._toggle_rows: dict[int, int] = {}
        self._next_card_id = 1
        #: Live ReAct "thinking" text shown while the model streams a turn.
        self._thought_text: str | None = None
        self._auto_scroll = True
        self._cancel_event = threading.Event()
        self._error = None
        from .tasks import TaskPanel
        self.task_panel = TaskPanel()
        self._task_cancellers = {}
        self._plan: dict[str, Any] | None = None
        self.panel_enabled = False
        #: Collapse tool cards to 5 lines by default; the footer click (or
        #: ``/expand``) shows the full output.
        self.expand_cards = False
        self._approval: dict[str, Any] | None = None
        #: Accumulated text of an answer streaming into the live overlay.
        self._answer_text: str | None = None
        self._answer_cache: tuple[Any, list[str]] | None = None
        from .paste import InputDocument, prune_drafts
        from uuid import uuid4
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

    def _build(self, history_path, prompt_style, input, output):
        from prompt_toolkit.key_binding import KeyBindings
        from prompt_toolkit.filters import Condition
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

        @keys.add(Keys.BracketedPaste, eager=True)
        def paste(event):
            if self._can_edit:
                self.paste_text(event.data)

        @keys.add('f3', eager=True)
        def expand_paste(event):
            if self._can_edit:
                self.expand_paste()

        @keys.add('f4', eager=True)
        def delete_paste(event):
            if self._can_edit:
                self.delete_paste()

        @keys.add("tab", eager=True)
        def complete(event):
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
        def newline(event):
            if self._can_edit:
                event.current_buffer.insert_text("\n")

        @keys.add("enter", eager=True)
        def submit(event):
            if self._can_edit:
                event.current_buffer.validate_and_handle()

        @keys.add("c-d", eager=True)
        def eof(event):
            if self._can_edit and not event.current_buffer.text:
                self._answer(EOFError())
            elif self._can_edit:
                event.current_buffer.delete()

        @keys.add("c-c", eager=True)
        def interrupt(event):
            if self._can_edit:
                event.current_buffer.reset()
                self._answer(KeyboardInterrupt())
            else:
                # The main thread owns the governed call and its cancellation.
                import _thread

                _thread.interrupt_main()

        @keys.add("escape", filter=Condition(lambda: self._status.busy and not self._accepting))
        def cancel(event):
            self._cancel_event.set()

        @keys.add("pageup", eager=True)
        def page_up(event):
            self.scroll_transcript(-self._page_lines())

        @keys.add("pagedown", eager=True)
        def page_down(event):
            self.scroll_transcript(self._page_lines())

        @keys.add(Keys.ScrollUp, eager=True)
        def wheel_up(event):
            self.scroll_transcript(-3)

        @keys.add(Keys.ScrollDown, eager=True)
        def wheel_down(event):
            self.scroll_transcript(3)

        @keys.add('f6', eager=True)
        def next_task(event):
            self.task_panel.select_next()
            self.invalidate()

        @keys.add('f7', eager=True)
        def cancel_task(event):
            with self._lock:
                callback = self._task_cancellers.get(self.task_panel.selected)
            if callback:
                callback()

        @keys.add("f2", eager=True)
        def toggle_panel(event):
            self.set_panel(not self.panel_enabled)

        build_layout(self, keys, file_history(history_path) if history_path else None,
                     prompt_style, input, output, full_screen=self.full_screen)

    def _input_height(self):
        from prompt_toolkit.utils import get_cwidth

        size = self._session.output.get_size()
        columns = max(1, size.columns - 4)
        rows = sum(max(1, (get_cwidth(line) + columns - 1) // columns)
                   for line in self.input_document.render().split("\n"))
        return max(0, len(self.prompt_text.splitlines()) - 1) + min(5, rows) + bool(self.input_document.refs)

    @property
    def _can_edit(self):
        # Preserve typeahead between prompts. While working, only an explicit
        # prompt (e.g. operator approval) may unlock the input region.
        return self._accepting or not self._status.busy

    @property
    def transcript(self) -> str:
        with self._lock:
            return "".join(self._lines)

    def _formatted(self, text):
        from prompt_toolkit.formatted_text import ANSI, to_formatted_text

        fragments = to_formatted_text(ANSI(text))
        return [("", part[1]) for part in fragments] if self.no_color else fragments

    def _toolbar(self):
        if not self.status_bar_enabled:
            return []
        with self._lock:
            from dataclasses import replace
            fragments = render_status_bar(replace(self._status, busy=False), width=self._session.output.get_size().columns)
        parts = [("", text) for _, text in fragments] if self.no_color else list(fragments)
        if not self._auto_scroll:
            # Visible affordance: the transcript is paused above the live tail.
            parts = [("class:scroll", "▲ historial · PgDn/Fin"), ("class:scroll", " · ")] + parts
        return parts

    def update_engagement_names(self, names: list[str]) -> None:
        """Refresh the ``@engagement`` completion candidates in place."""
        if self._completer is not None:
            self._completer.engagements = tuple(sorted(set(names)))

    def task_event(self, event):
        self.task_panel.consume(event)
        if self.use_tui:
            self._session.app.refresh_interval = 0.25 if self.task_panel.running or self._status.busy else None
            self._dispatch(self._session.app.refresh_wake.set)
        self.invalidate()

    def bind_task_cancel(self, key, callback):
        with self._lock:
            if callback is None:
                self._task_cancellers.pop(key, None)
            else:
                self._task_cancellers[key] = callback

    def set_plan(self, plan: dict | None) -> None:
        """Store the latest engagement plan for the side panel."""
        self._plan = plan if isinstance(plan, dict) else None
        self.invalidate()

    def set_panel(self, enabled: bool) -> bool:
        """Show/hide the plan side panel; returns the new state."""
        self.panel_enabled = bool(enabled)
        self.invalidate()
        return self.panel_enabled

    def _panel_formatted(self):
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
        lines = ["OmniAgent ·"]
        lines += [("  " + line) if line.strip() else "" for line in body.splitlines()]
        self._answer_cache = (key, lines)
        return lines

    def answer_height(self) -> int:
        """Height of the live overlay: the tail of the answer, capped to the screen."""
        if not self.answer_active:
            return 0
        rows = self._session.output.get_size().rows
        return max(1, min(len(self._answer_lines()), max(1, rows - 6)))

    def _answer_formatted(self):
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

    def _thought_formatted(self):
        from prompt_toolkit.utils import get_cwidth

        with self._lock:
            text = self._thought_text or ""
        try:
            columns = self._session.output.get_size().columns
        except Exception:  # noqa: BLE001 - cosmetic sizing only
            columns = 80
        prefix = "💭 "
        width = max(10, columns - get_cwidth(prefix) - 2)
        line = " ".join(text.split())
        if get_cwidth(line) > width:
            # Show the tail: what the model is reasoning about *now*.
            line = line[-width:]
        return self._formatted(prefix + line)

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

    def set_approval(self, payload: dict | None) -> bool:
        """Show the approval modal for ``payload``; returns whether it is shown."""
        self._approval = dict(payload) if isinstance(payload, dict) else None
        self.invalidate()
        return self.approval_active

    def clear_approval(self) -> None:
        """Hide the approval modal (called once the operator decided)."""
        self._approval = None
        self.invalidate()

    def _approval_formatted(self):
        from .panels import approval_lines

        return [(style, text) for style, text in approval_lines(self._approval, width=62)]

    def set_status_bar_enabled(self, enabled: bool):
        self.status_bar_enabled = bool(enabled)
        if self.use_tui:
            def update():
                self._session.bottom_toolbar = self._toolbar if enabled else None
                self.invalidate()
            self._dispatch(update)

    def _answer(self, value):
        self._accepting = False
        self._answers.put(value)
        self.invalidate()

    def _accept(self, buffer):
        if self._can_edit:
            text = buffer.text if self._secret_mode else self.input_document.reconstruct()
            visible = self.input_document.render()
            # A secret is never echoed to the transcript: show a fixed mask so
            # the operator still sees that the input was taken.
            self.print(self.prompt_text + ("••••••" if self._secret_mode else visible))
            self._answer(text)
        return False

    def _input_changed(self, buffer):
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

    def paste_text(self, content):
        from .paste import paste_threshold
        if self._secret_mode or not paste_threshold(content):
            self._input.insert_text(content)
            return
        pos = self._input.cursor_position
        try:
            self.input_document.insert_paste(pos, content)
        except (ValueError, OSError) as exc:
            self.print(f"Pegado rechazado, entrada conservada: {exc}")
            return
        self._set_input_document(pos+1)

    def _set_input_document(self, cursor):
        from prompt_toolkit.document import Document
        self._syncing_input = True
        try:
            self._input.set_document(Document(self.input_document.text, cursor))
        finally:
            self._syncing_input = False

    def _selected_paste(self):
        cursor = self._input.cursor_position
        return next((p for p in (cursor, cursor-1) if p in self.input_document.refs), None)

    def expand_paste(self):
        pos = self._selected_paste()
        if pos is not None:
            self._set_input_document(self.input_document.replace_ref(pos, expand=True))

    def delete_paste(self):
        pos = self._selected_paste()
        if pos is not None:
            self._set_input_document(self.input_document.replace_ref(pos, expand=False))

    def _run(self):
        async def run():
            def ready():
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

    def _start(self):
        if self._thread is None:
            context = copy_context()
            self._thread = threading.Thread(
                target=context.run, args=(self._run,), name="omni-tui", daemon=True,
            )
            self._thread.start()
            self._ready.wait()
        if self._error:
            raise self._error

    def _dispatch(self, callback):
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
            return fallback_prompt(self.prompt_text)
        self._accepting = True
        self._start()
        self.invalidate()
        result = self._answers.get()
        self._accepting = False
        if isinstance(result, BaseException):
            raise result
        return result

    def prompt_secret(self, prompt_text: str = "└─🔒 valor oculto: ") -> str:
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

    def append_scrollback(self, text: str) -> None:
        if not self.use_tui:
            print(text, end="")
            return
        segment = {"kind": "text", "text": str(text)}
        with self._lock:
            self._lines.append(segment["text"])
            self._segments.append(segment)
            self._write_queue.append(segment)
            if self._flush_scheduled:
                return
            self._flush_scheduled = True
        if self._loop is not None and self._loop.is_running():
            self._dispatch(lambda: self._loop.call_later(0.05, self._flush_scrollback))
        else:
            self._flush_scrollback()

    def append_card(self, result: dict, *, expanded: bool | None = None) -> None:
        """Append a tool-result card that expands/collapses on its own (click)."""
        card = {
            "kind": "card",
            "id": self._next_card_id,
            "result": result if isinstance(result, dict) else {},
            "expanded": bool(self.expand_cards if expanded is None else expanded),
        }
        with self._lock:
            self._next_card_id += 1
            self._cards[card["id"]] = card
            text = self._card_text(card)
            self._lines.append(text)
            self._segments.append(card)
            self._write_queue.append(card)
            if self._flush_scheduled:
                return
            self._flush_scheduled = True
        if self._loop is not None and self._loop.is_running():
            self._dispatch(lambda: self._loop.call_later(0.05, self._flush_scrollback))
        else:
            self._flush_scrollback()

    def _card_text(self, card: dict[str, Any]) -> str:
        from .stream import render_tool_result

        # A trailing blank line gives each result room to breathe, so turns are
        # visually separated instead of a flat wall of output.
        return render_tool_result(card.get("result") or {}, expanded=bool(card.get("expanded"))) + "\n\n"

    def _segment_text(self, segment: dict[str, Any]) -> str:
        if segment.get("kind") == "card":
            return self._card_text(segment)
        return str(segment.get("text") or "")

    @staticmethod
    def _footer_line_index(styled: list[list]) -> int | None:
        """Index of a card's toggle footer, or ``None`` when it has none.

        The footer is the card's last non-empty logical line; a trailing newline
        leaves an empty line after it, so scanning from the end is required.
        """
        from prompt_toolkit.formatted_text import fragment_list_to_text

        for index in range(len(styled) - 1, -1, -1):
            text = fragment_list_to_text(styled[index]).strip()
            if not text:
                continue
            return index if "mostrar" in text else None
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

        styled: list[list] = [[]]
        toggle: dict[int, int] = {}
        raw_lines: list[str] = []
        for segment in self._segments:
            text = self._segment_text(segment)
            raw_lines.append(text)
            if not text:
                continue
            lines = list(split_lines(self._formatted(text)))
            if not lines:
                continue
            styled[-1].extend(lines[0])
            styled.extend(lines[1:])
            if segment.get("kind") == "card":
                index = self._footer_line_index(styled)
                if index is not None:
                    toggle[index] = segment["id"]
        plain = "\n".join(fragment_list_to_text(row) for row in styled)
        self._styled_lines = styled
        self._toggle_rows = toggle
        self._lines = raw_lines
        return plain

    def _flush_scrollback(self):
        from prompt_toolkit.document import Document
        from prompt_toolkit.formatted_text import fragment_list_to_text
        from prompt_toolkit.formatted_text.utils import split_lines

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
            fragments = self._formatted(text)
            lines = list(split_lines(fragments))
            if not lines:
                continue
            self._styled_lines[-1].extend(lines[0])
            self._styled_lines.extend(lines[1:])
            if segment.get("kind") == "card":
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

    def _render_busy(self):
        if not self._status.busy:
            return []
        elapsed = max(0, int(time.monotonic() - self._status.busy_started_at))
        frame = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"[int(time.monotonic() * 4) % 10]
        message = self._status.busy_message or "Working"
        text = f" {frame} {message}... ({elapsed}s · esc to interrupt)"
        return [("" if self.no_color else "class:busy", text)]

    def set_busy(self, message: str = ""):
        self._cancel_event.clear()
        self.set_status(busy=True, busy_message=message)

    def clear_busy(self):
        self.set_status(busy=False)

    def clear_screen(self) -> None:
        """Clear the TUI terminal before its first frame; fallback is untouched."""
        if not self.use_tui:
            return
        def clear():
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

        def drain():
            try:
                self._flush_scrollback()
            finally:
                done.set()

        self._dispatch(drain)
        if not done.wait(5):
            raise RuntimeError("TUI output did not drain")

    def set_status(self, **fields) -> None:
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
        self._session.app.refresh_interval = 0.25 if self._status.busy or self.task_panel.running else None
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
                def stop():
                    app = self._session.app
                    if app.is_running and not app.future.done():
                        app.exit()
                self._dispatch(stop)
                self._thread.join(timeout=5)
                if self._thread.is_alive():
                    raise RuntimeError("TUI thread did not stop")
