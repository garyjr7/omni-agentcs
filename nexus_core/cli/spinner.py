"""Spinner for long operations (an exploit can wait 30-120s for a session).

It writes to stderr, never stdout, so it cannot corrupt the REPL's readline
buffer or any machine-readable output. The thread is a daemon and ``stop()`` is
idempotent, so no orphan thread survives a tool call or a Ctrl+C.
"""

from __future__ import annotations

import sys
import threading
import time
from typing import Any

SPINNER_FRAMES = ("⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏")
SPINNER_FRAMES_ASCII = ("|", "/", "-", "\\")

CLEAR_LINE = "\r\033[K"
#: Elapsed seconds are shown as ``[Ns]``; the tick interval keeps this simple.
DEFAULT_INTERVAL_SECONDS = 0.1


def _as_float(value: Any, default: float) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _is_tty(stream: Any) -> bool:
    try:
        return bool(stream.isatty())
    except Exception:  # noqa: BLE001 - detached/closed stream counts as "not a tty"
        return False


def spinner_enabled() -> bool:
    """True only when both streams are terminals and ANSI colour is allowed."""
    from . import render

    if not _is_tty(sys.stdout) or not _is_tty(sys.stderr):
        return False
    return bool(render.color_enabled())


class Spinner:
    """Spinner with elapsed time, rendered on stderr.

    ``with Spinner("Esperando callback en 10.0.0.1:4444"): ...`` shows
    ``⠋ Esperando callback en 10.0.0.1:4444  [12s]`` and, on exit,
    ``✓ Esperando callback en 10.0.0.1:4444  [27s]`` (or ``✗`` on failure).
    """

    def __init__(
        self,
        message: str,
        *,
        enabled: bool = True,
        interval_seconds: float = DEFAULT_INTERVAL_SECONDS,
        stream: Any = None,
        use_ascii: bool = False,
    ) -> None:
        self.message = str(message or "")
        self.enabled = bool(enabled)
        self.interval_seconds = max(0.01, _as_float(interval_seconds, DEFAULT_INTERVAL_SECONDS))
        self.stream = stream if stream is not None else sys.stderr
        self.frames = SPINNER_FRAMES_ASCII if use_ascii else SPINNER_FRAMES
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._started_at: float | None = None
        self._final_message: str | None = None

    # ------------------------------------------------------------------ control
    def start(self) -> None:
        """Start the animation thread (no-op when disabled or already running)."""
        if not self.enabled or self._thread is not None:
            return
        self._started_at = time.monotonic()
        self._thread = threading.Thread(
            target=self._spin, name="omni-spinner", daemon=True
        )
        self._thread.start()

    def stop(self, *, success: bool = True) -> None:
        """Stop the thread, clear the line and print the final status line."""
        if not self.enabled:
            return
        self._stop_event.set()
        thread, self._thread = self._thread, None
        if thread is not None and thread.is_alive():
            thread.join(timeout=1.0)
        message = self._final_message if self._final_message is not None else self.message
        marker = "✓" if success else "✗"
        line = f"{marker} {message}  [{self.elapsed_seconds()}s]\n"
        self._write(CLEAR_LINE + line)

    def update_message(self, message: str) -> None:
        """Replace the displayed message at runtime (thread-safe)."""
        with self._lock:
            self._final_message = None
            self.message = str(message or "")

    def elapsed_seconds(self) -> int:
        """Whole seconds since ``start()`` (0 when never started)."""
        if self._started_at is None:
            return 0
        return max(0, int(time.monotonic() - self._started_at))

    # --------------------------------------------------------------- internals
    def _write(self, text: str) -> None:
        try:
            self.stream.write(text)
            self.stream.flush()
        except (ValueError, OSError):  # pragma: no cover - closed stream
            pass

    def _current_message(self) -> str:
        with self._lock:
            return self.message

    def _spin(self) -> None:
        index = 0
        while not self._stop_event.is_set():
            frame = self.frames[index % len(self.frames)]
            index += 1
            self._write(f"{CLEAR_LINE}{frame} {self._current_message()}  [{self.elapsed_seconds()}s]")
            self._stop_event.wait(self.interval_seconds)

    # --------------------------------------------------------------- protocol
    def __enter__(self) -> "Spinner":
        self.start()
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> bool:
        self.stop(success=exc_type is None)
        return False


__all__ = [
    "SPINNER_FRAMES",
    "SPINNER_FRAMES_ASCII",
    "Spinner",
    "spinner_enabled",
]