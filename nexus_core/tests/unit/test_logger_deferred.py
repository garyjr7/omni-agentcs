"""The console handler must resolve its stream at emit time.

A handler built with ``StreamHandler(sys.stdout)`` keeps writing to the stdout
that existed before the TUI replaced it, which moves the cursor behind the
renderer's back. These tests lock the single-writer boundary down.
"""

from __future__ import annotations

import io
import logging
import sys
import time

import pytest

from nexus_core.cli.tui.output import TuiStreamProxy, capture_exceptions, capture_output
from nexus_core.utils import logger as logger_module
from nexus_core.utils.logger import DeferredStreamHandler


class _FakeTui:
    """Minimal TuiSession stand-in: the two methods the proxy calls."""

    def __init__(self):
        self.parts: list[str] = []

    def append_scrollback(self, text: str) -> None:
        self.parts.append(text)

    def flush(self) -> None:
        pass


class _BoomStream:
    def write(self, text: str):  # noqa: D401 - deliberately broken
        raise OSError("stream unavailable")

    def flush(self):
        pass


def _name() -> str:
    return f"deferred-{time.time_ns()}"


def _isolated_logger(name: str, handler: logging.Handler) -> logging.Logger:
    logger = logging.getLogger(name)
    logger.handlers[:] = [handler]
    logger.setLevel(logging.INFO)
    logger.propagate = False
    return logger


def _swap(monkeypatch, attr: str, stream):
    """Swap ``sys.<attr>`` and return a callable that restores it."""
    original = getattr(sys, attr)
    setattr(sys, attr, stream)
    return lambda: setattr(sys, attr, original)


def test_handler_resolves_stream_at_emit_time(monkeypatch):
    """The mission's core regression: write to the stream that is current now."""
    handler = DeferredStreamHandler(stream_name="stdout")
    handler.setFormatter(logging.Formatter("%(message)s"))
    logger = _isolated_logger(_name(), handler)

    restore = _swap(monkeypatch, "stdout", original := sys.stdout)
    captured = io.StringIO()
    sys.stdout = captured
    try:
        logger.info("hello")
    finally:
        restore()

    assert "hello" in captured.getvalue()
    assert sys.stdout is original


def test_handler_is_not_a_stream_handler():
    handler = DeferredStreamHandler()
    assert isinstance(handler, logging.Handler)
    assert not isinstance(handler, logging.StreamHandler)


def test_handler_does_not_store_the_construction_time_stream():
    """There must be no bound ``stream`` attribute to go stale."""
    assert getattr(DeferredStreamHandler(), "stream", None) is None


def test_handler_appends_exactly_one_terminator(monkeypatch):
    handler = DeferredStreamHandler()
    handler.setFormatter(logging.Formatter("%(message)s"))
    logger = _isolated_logger(_name(), handler)
    captured = io.StringIO()
    restore = _swap(monkeypatch, "stdout", captured)
    try:
        logger.info("line")
    finally:
        restore()
    assert captured.getvalue() == "line\n"


def test_handler_can_target_stderr(monkeypatch):
    handler = DeferredStreamHandler(stream_name="stderr")
    handler.setFormatter(logging.Formatter("%(message)s"))
    logger = _isolated_logger(_name(), handler)
    captured = io.StringIO()
    restore = _swap(monkeypatch, "stderr", captured)
    try:
        logger.info("por stderr")
    finally:
        restore()
    assert "por stderr" in captured.getvalue()


def test_handler_tolerates_a_broken_stream(monkeypatch):
    monkeypatch.setattr(logging, "raiseExceptions", False)
    handler = DeferredStreamHandler()
    handler.setFormatter(logging.Formatter("%(message)s"))
    logger = _isolated_logger(_name(), handler)
    restore = _swap(monkeypatch, "stdout", _BoomStream())
    try:
        logger.info("no debe propagar")  # must not raise
    finally:
        restore()


def test_nexus_logger_installs_the_deferred_handler():
    nexus = logger_module.get_logger(_name())
    console = [h for h in nexus.logger.handlers if getattr(h, "_nexus_console", False)]
    assert len(console) == 1
    assert isinstance(console[0], DeferredStreamHandler)


def test_nexus_logger_does_not_stack_deferred_handlers():
    name = _name()
    logger_module.get_logger(name)
    logger_module.get_logger(name)
    console = [h for h in logging.getLogger(name).handlers if getattr(h, "_nexus_console", False)]
    assert len(console) == 1


def test_tui_stream_proxy_routes_writes_to_scrollback():
    fake = _FakeTui()
    original = io.StringIO()
    proxy = TuiStreamProxy(fake, "stdout", original)
    assert proxy.write("uno") == 3
    assert proxy.write("") == 0
    assert fake.parts == ["uno"]
    assert proxy.isatty() is False


def test_capture_output_routes_logger_into_the_scrollback(monkeypatch, capsys):
    """A log emitted during the REPL lands in the buffer, not on the terminal."""
    monkeypatch.setenv("NEXUS_LOG_LEVEL", "info")
    nexus = logger_module.get_logger(_name())
    fake = _FakeTui()
    with capture_output(fake):
        nexus.info("routed-by-the-tui")
    assert any("routed-by-the-tui" in part for part in fake.parts)
    assert "routed-by-the-tui" not in capsys.readouterr().out


def test_capture_output_restores_both_streams():
    out, err = sys.stdout, sys.stderr
    with capture_output(_FakeTui()):
        assert sys.stdout is not out
        assert sys.stderr is not err
    assert sys.stdout is out
    assert sys.stderr is err


def test_capture_output_restores_streams_after_an_exception():
    out, err = sys.stdout, sys.stderr
    with pytest.raises(RuntimeError):
        with capture_output(_FakeTui()):
            raise RuntimeError("boom")
    assert sys.stdout is out and sys.stderr is err


def test_capture_exceptions_restores_the_original_hook():
    original = sys.excepthook
    with capture_exceptions():
        assert sys.excepthook is not original
    assert sys.excepthook is original


def test_capture_exceptions_routes_tracebacks_through_stderr(monkeypatch):
    captured = io.StringIO()
    restore = _swap(monkeypatch, "stderr", captured)
    try:
        with capture_exceptions():
            try:
                raise ValueError("fallo de prueba")
            except ValueError:
                sys.excepthook(*sys.exc_info())
    finally:
        restore()
    assert "Excepción no capturada" in captured.getvalue()
    assert "ValueError" in captured.getvalue()
