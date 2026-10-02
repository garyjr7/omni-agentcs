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
        input=None, output=None,
    ):
        self.use_tui = bool(use_tui)
        self.status_bar_enabled = status_bar_enabled
        self.no_color = no_color or "NO_COLOR" in os.environ
        self.prompt_text = "└─$ "
        self._status = StatusState(cost_known=False)
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
        self._lines: list[str] = []
        self._styled_lines = [[]]
        self._write_queue: list[str] = []
        self._flush_scheduled = False
        self._auto_scroll = True
        self._cancel_event = threading.Event()
        self._error = None
        self._plan: dict[str, Any] | None = None
        self.panel_enabled = False
        if self.use_tui:
            self._build(history_path, prompt_style, input, output)

    def _build(self, history_path, prompt_style, input, output):
        from prompt_toolkit.key_binding import KeyBindings
        from prompt_toolkit.filters import Condition
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

        @keys.add("pageup")
        def page_up(event):
            self._auto_scroll = False
            self._scrollback.cursor_up(count=max(1, self._session.output.get_size().rows - 5))

        @keys.add("f2", eager=True)
        def toggle_panel(event):
            self.set_panel(not self.panel_enabled)

        @keys.add("pagedown")
        def page_down(event):
            self._scrollback.cursor_down(count=max(1, self._session.output.get_size().rows - 5))
            if self._scrollback.document.is_cursor_at_the_end:
                self._auto_scroll = True

        build_layout(self, keys, file_history(history_path) if history_path else None,
                     prompt_style, input, output)

    def _input_height(self):
        from prompt_toolkit.utils import get_cwidth

        size = self._session.output.get_size()
        columns = max(1, size.columns - 4)
        rows = sum(max(1, (get_cwidth(line) + columns - 1) // columns)
                   for line in self._session.default_buffer.document.lines)
        return max(0, len(self.prompt_text.splitlines()) - 1) + min(5, rows)

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
        return [("", text) for _, text in fragments] if self.no_color else fragments

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
            text = buffer.text
            self.print(self.prompt_text + text)
            self._answer(text)
        return False

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

    def print(self, text: str, *, end: str = "\n") -> None:
        if not self.use_tui:
            print(text, end=end)
            return
        self.append_scrollback(str(text) + end)

    def append_scrollback(self, text: str) -> None:
        if not self.use_tui:
            print(text, end="")
            return
        with self._lock:
            self._lines.append(str(text))
            self._write_queue.append(str(text))
            if self._flush_scheduled:
                return
            self._flush_scheduled = True
        if self._loop is not None and self._loop.is_running():
            self._dispatch(lambda: self._loop.call_later(0.05, self._flush_scrollback))
        else:
            self._flush_scrollback()

    def _flush_scrollback(self):
        from prompt_toolkit.document import Document
        from prompt_toolkit.formatted_text import fragment_list_to_text
        from prompt_toolkit.formatted_text.utils import split_lines

        with self._lock:
            text = "".join(self._write_queue)
            self._write_queue.clear()
            self._flush_scheduled = False
        if not text:
            return
        fragments = self._formatted(text)
        lines = list(split_lines(fragments))
        self._styled_lines[-1].extend(lines[0])
        self._styled_lines.extend(lines[1:])
        plain = self._scrollback.text + fragment_list_to_text(fragments)
        cursor = len(plain) if self._auto_scroll else self._scrollback.cursor_position
        self._scrollback.set_document(Document(plain, cursor), bypass_readonly=True)
        # BufferControl observes the document change; no explicit invalidation.

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
        self._session.app.refresh_interval = 0.25 if self._status.busy else None
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
