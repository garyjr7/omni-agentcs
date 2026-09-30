"""Persistent prompt_toolkit application with a synchronous readline facade."""

from __future__ import annotations

import asyncio
from collections import deque
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
        input=None, output=None,
    ):
        self.use_tui = bool(use_tui)
        self.status_bar_enabled = status_bar_enabled
        self.no_color = no_color or "NO_COLOR" in os.environ
        self.prompt_text = "└─$ "
        self._status = StatusState()
        self._lock = threading.RLock()
        self._closed = False
        self._session = None
        self._thread = None
        self._loop = None
        self._context = None
        self._ready = threading.Event()
        self._answers: Queue = Queue()
        self._accepting = False
        self._lines: deque[str] = deque(maxlen=2000)
        self._pending: set = set()
        self._error = None
        if self.use_tui:
            self._build(history_path, prompt_style, input, output)

    def _build(self, history_path, prompt_style, input, output):
        from prompt_toolkit import PromptSession
        from prompt_toolkit.completion import WordCompleter
        from prompt_toolkit.data_structures import Point
        from prompt_toolkit.filters import Condition
        from prompt_toolkit.key_binding import KeyBindings
        from prompt_toolkit.layout import HSplit, Window
        from prompt_toolkit.layout.controls import FormattedTextControl
        from prompt_toolkit.output import ColorDepth
        from prompt_toolkit.shortcuts import CompleteStyle
        from prompt_toolkit.styles import Style

        from ..commands import command_names
        from .history import file_history

        keys = KeyBindings()

        @keys.add("c-d", eager=True)
        def eof(event):
            if self._accepting and not event.current_buffer.text:
                self._answer(EOFError())
            elif self._accepting:
                event.current_buffer.delete()

        @keys.add("c-c", eager=True)
        def interrupt(event):
            if self._accepting:
                event.current_buffer.reset()
                self._answer(KeyboardInterrupt())
            else:
                # The main thread owns the governed call and its cancellation.
                import _thread

                _thread.interrupt_main()

        self._session = PromptSession(
            message=lambda: self._formatted(self.prompt_text),
            history=file_history(history_path) if history_path else None,
            bottom_toolbar=self._toolbar if self.status_bar_enabled else None,
            refresh_interval=2.0, enable_open_in_editor=True, enable_suspend=True,
            multiline=False, complete_style=CompleteStyle.MULTI_COLUMN,
            completer=WordCompleter(command_names(), sentence=True),
            complete_while_typing=False, reserve_space_for_menu=0,
            style=Style.from_dict(prompt_style or {}),
            color_depth=ColorDepth.DEPTH_1_BIT if self.no_color else None,
            key_bindings=keys, input=input, output=output,
        )
        self._session.default_buffer.accept_handler = self._accept
        self._session.default_buffer.read_only = Condition(lambda: not self._accepting)
        app = self._session.app
        prompt_container = app.layout.container
        prompt_container.height = lambda: len(self.prompt_text.splitlines()) + int(self.status_bar_enabled)
        log = FormattedTextControl(
            lambda: self._formatted(self.transcript),
            get_cursor_position=lambda: Point(0, max(0, len(self.transcript.splitlines()) - 1)),
        )
        app.layout.container = HSplit([
            Window(log, wrap_lines=True, always_hide_cursor=True), prompt_container,
        ])
        app.full_screen = True

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
            fragments = render_status_bar(self._status, width=self._session.output.get_size().columns)
        return [("", text) for _, text in fragments] if self.no_color else fragments

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
        if self._accepting:
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
            # run_in_terminal creates asyncio tasks: marshal onto the UI loop
            # with its application context, just like StdoutProxy does.
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
        if isinstance(result, BaseException):
            raise result
        return result

    def print(self, text: str, *, end: str = "\n") -> None:
        if not self.use_tui:
            print(text, end=end)
            return
        from prompt_toolkit.application import run_in_terminal

        def append():
            with self._lock:
                self._lines.extend((str(text) + end).splitlines(keepends=True))
            self.invalidate()

        def schedule():
            # The full-screen panel owns these lines. Printing to the physical
            # terminal too would duplicate them when the renderer resumes.
            future = run_in_terminal(append)
            self._pending.add(future)
            future.add_done_callback(self._pending.discard)

        if self._loop is not None and self._loop.is_running():
            self._dispatch(schedule)
        else:
            append()
        # Before the first prompt, the transcript is the sole destination.
        # Emitting it now would show the banner again when the panel paints.
        self.invalidate()

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

        async def drain():
            try:
                if self._pending:
                    await asyncio.gather(*tuple(self._pending))
            finally:
                done.set()

        self._dispatch(lambda: self._loop.create_task(drain()))
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
