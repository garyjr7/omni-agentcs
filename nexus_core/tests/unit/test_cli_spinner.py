"""Spinner: stderr-only output, clean shutdown and KeyboardInterrupt safety."""

from __future__ import annotations

import io
import sys
import threading
import time

import pytest

from nexus_core.cli import render
from nexus_core.cli.spinner import SPINNER_FRAMES_ASCII, Spinner, spinner_enabled


def _run(spinner: Spinner, seconds: float = 0.12) -> str:
    with spinner:
        time.sleep(seconds)
    return spinner.stream.getvalue()


def test_spinner_disabled_writes_nothing():
    stream = io.StringIO()
    spinner = Spinner("callando", enabled=False, interval_seconds=0.01, stream=stream)
    with spinner:
        time.sleep(0.05)
    assert stream.getvalue() == ""
    assert spinner._thread is None


def test_spinner_start_stop_thread_lifecycle():
    stream = io.StringIO()
    spinner = Spinner("nmap", interval_seconds=0.01, stream=stream)
    spinner.start()
    assert spinner._thread is not None and spinner._thread.is_alive()
    spinner.stop()
    assert spinner._thread is None
    # No orphan thread survives the call.
    assert not any(thread.name == "omni-spinner" for thread in threading.enumerate())
    # stop() is idempotent.
    spinner.stop()


def test_spinner_writes_to_stderr_not_stdout(capsys):
    spinner = Spinner("ejecutando nmap", interval_seconds=0.01)
    with spinner:
        time.sleep(0.05)
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "ejecutando nmap" in captured.err
    assert captured.err.endswith("\n")


def test_spinner_default_stream_is_stderr():
    assert Spinner("x").stream is sys.stderr


def test_spinner_clears_line_on_stop():
    stream = io.StringIO()
    _run(Spinner("limpiando", interval_seconds=0.01, stream=stream))
    assert stream.getvalue().startswith("\r\033[K")
    assert "\r\033[K✓ limpiando" in stream.getvalue()


def test_spinner_shows_success_marker():
    stream = io.StringIO()
    _run(Spinner("éxito", interval_seconds=0.01, stream=stream))
    assert stream.getvalue().rstrip().endswith("]")
    assert "✓ éxito" in stream.getvalue()


def test_spinner_shows_failure_marker():
    stream = io.StringIO()
    spinner = Spinner("fallo", interval_seconds=0.01, stream=stream)
    spinner.start()
    spinner.stop(success=False)
    assert "✗ fallo" in stream.getvalue()


def test_spinner_handles_keyboard_interrupt():
    stream = io.StringIO()
    spinner = Spinner("interrumpido", interval_seconds=0.01, stream=stream)
    with pytest.raises(KeyboardInterrupt):
        with spinner:
            raise KeyboardInterrupt
    assert "✗ interrumpido" in stream.getvalue()
    assert spinner._thread is None
    assert not any(thread.name == "omni-spinner" for thread in threading.enumerate())


def test_spinner_update_message_thread_safe():
    stream = io.StringIO()
    spinner = Spinner("inicial", interval_seconds=0.01, stream=stream)
    with spinner:
        spinner.update_message("segundo mensaje")
        time.sleep(0.05)
    assert "✓ segundo mensaje" in stream.getvalue()


def test_spinner_ascii_fallback_when_no_unicode():
    stream = io.StringIO()
    spinner = Spinner("ascii", interval_seconds=0.01, stream=stream, use_ascii=True)
    assert spinner.frames == SPINNER_FRAMES_ASCII
    with spinner:
        time.sleep(0.05)
    assert "ascii" in stream.getvalue()
    assert "⠋" not in stream.getvalue()


def test_spinner_uses_monotonic_time(monkeypatch):
    ticks = iter([100.0, 100.0, 127.0])
    monkeypatch.setattr(time, "monotonic", lambda: next(ticks, 127.0))
    spinner = Spinner("cronometrado", interval_seconds=0.01, stream=io.StringIO())
    spinner.start()
    spinner.stop()
    assert "cronometrado  [27s]" in spinner.stream.getvalue()


def test_spinner_enabled_requires_both_ttys(monkeypatch):
    render.configure_color(no_color=False)

    class _Tty(io.StringIO):
        def isatty(self) -> bool:
            return True

    monkeypatch.setattr(sys, "stdout", _Tty())
    monkeypatch.setattr(sys, "stderr", _Tty())
    assert spinner_enabled() is True
    monkeypatch.setattr(sys, "stderr", io.StringIO())
    assert spinner_enabled() is False


def test_spinner_enabled_false_when_color_disabled(monkeypatch):
    render.configure_color(no_color=True)

    class _Tty(io.StringIO):
        def isatty(self) -> bool:
            return True

    monkeypatch.setattr(sys, "stdout", _Tty())
    monkeypatch.setattr(sys, "stderr", _Tty())
    assert spinner_enabled() is False
    render.configure_color(no_color=False)