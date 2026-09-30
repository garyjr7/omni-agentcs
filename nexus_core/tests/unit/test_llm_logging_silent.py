"""Logging is silent by default and never duplicates handlers.

The internal LLM loggers used to print one INFO line per provider and per call
straight to stdout, which landed in the middle of the banner and spinner.
"""

from __future__ import annotations

import io
import logging
import time

import pytest

from nexus_core.cli import llm_env
from nexus_core.cli.spinner import Spinner
from nexus_core.utils import logger as logger_module


@pytest.fixture(autouse=True)
def _restore_loggers():
    """Give every test a pristine logger state and restore it afterwards."""
    saved = {name: logging.getLogger(name) for name in llm_env.NOISY_LOGGERS}
    levels = {name: saved[name].level for name in saved}
    handlers = {name: list(saved[name].handlers) for name in saved}
    yield
    for name, value in saved.items():
        value.setLevel(levels[name])
        value.handlers[:] = handlers[name]


def _client_name() -> str:
    return f"logging-silent-{time.time_ns()}"


def test_logger_default_level_warning(monkeypatch):
    """Without ``NEXUS_LOG_LEVEL`` a new logger speaks at WARNING."""
    monkeypatch.delenv("NEXUS_LOG_LEVEL", raising=False)
    assert logger_module._default_level() == logging.WARNING
    assert logger_module.get_logger(_client_name()).logger.level == logging.WARNING


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("debug", logging.DEBUG),
        ("info", logging.INFO),
        ("warning", logging.WARNING),
        ("error", logging.ERROR),
        ("critical", logging.CRITICAL),
        ("INFO", logging.INFO),
        ("nonsense", logging.WARNING),
    ],
)
def test_logger_level_follows_env(monkeypatch, value, expected):
    monkeypatch.setenv("NEXUS_LOG_LEVEL", value)
    assert logger_module._default_level() == expected


def test_nexus_llm_logger_warning_when_env_warning(monkeypatch):
    monkeypatch.setenv("NEXUS_LOG_LEVEL", "warning")
    assert llm_env.configure_logging() == logging.WARNING
    assert logging.getLogger("NexusLLM").level == logging.WARNING
    assert llm_env.verbose_logging() is False


def test_nexus_llm_logger_info_when_env_info(monkeypatch):
    monkeypatch.setenv("NEXUS_LOG_LEVEL", "info")
    assert llm_env.configure_logging() == logging.INFO
    assert logging.getLogger("NexusLLM").level == logging.INFO
    assert logging.getLogger("LLMFactory").level == logging.INFO
    assert llm_env.verbose_logging() is True


def test_configure_logging_defaults_to_warning(monkeypatch):
    monkeypatch.delenv("NEXUS_LOG_LEVEL", raising=False)
    assert llm_env.configure_logging() == logging.WARNING
    assert llm_env.resolve_log_level() == logging.WARNING


def test_default_log_level_is_warning():
    """The shipped ``.env.example`` must not turn INFO chatter back on."""
    from pathlib import Path

    example = Path(__file__).resolve().parents[3] / ".env.example"
    lines = [line.strip() for line in example.read_text(encoding="utf-8").splitlines()]
    assert "NEXUS_LOG_LEVEL=warning" in lines
    assert llm_env.DEFAULT_LOG_LEVEL == "warning"


def test_llm_factory_does_not_add_duplicate_handlers(monkeypatch):
    """Instantiating the same logger twice must not stack console handlers."""
    monkeypatch.setenv("NEXUS_LOG_LEVEL", "warning")
    name = _client_name()
    logger_module.get_logger(name)
    logger_module.get_logger(name)
    logger_module.get_logger(name)
    console = [h for h in logging.getLogger(name).handlers if getattr(h, "_nexus_console", False)]
    assert len(console) == 1


def test_logger_emits_nothing_below_warning_by_default(monkeypatch, capsys):
    monkeypatch.delenv("NEXUS_LOG_LEVEL", raising=False)
    logger = logger_module.get_logger(_client_name())
    logger.info("this must not be printed")
    logger.debug("nor this")
    assert capsys.readouterr().out == ""


def test_logger_still_emits_at_info_when_asked(monkeypatch, capsys):
    monkeypatch.setenv("NEXUS_LOG_LEVEL", "info")
    logger = logger_module.get_logger(_client_name())
    logger.info("visible on demand")
    assert "visible on demand" in capsys.readouterr().out


def test_spinner_clears_line_before_each_frame():
    stream = io.StringIO()
    spinner = Spinner("limpiando", interval_seconds=0.01, stream=stream)
    with spinner:
        time.sleep(0.08)
    # Every frame is preceded by \r\033[K so a longer previous frame cannot
    # leave stale characters behind.
    frames = [line for line in stream.getvalue().split("\r") if line]
    assert len(frames) >= 2
    assert all(frame.startswith("\033[K") for frame in frames[:-1])


def test_spinner_not_interrupted_by_info_log_at_warning_level(monkeypatch, capsys):
    """With logs at WARNING, an INFO line never reaches stdout mid-spin."""
    monkeypatch.setenv("NEXUS_LOG_LEVEL", "warning")
    llm_env.configure_logging()
    logger = logger_module.get_logger(_client_name())
    with Spinner("ejecutando nmap", interval_seconds=0.01):
        logger.info("LLM call successful via groq")
        time.sleep(0.05)
    captured = capsys.readouterr()
    assert "LLM call successful" not in captured.out
    assert "ejecutando nmap" in captured.err


def test_noisy_logger_names_cover_the_llm_clients():
    for name in ("LLMFactory", "NexusLLM", "LLMClient.groq", "LLMClient.openai"):
        assert name in llm_env.NOISY_LOGGERS