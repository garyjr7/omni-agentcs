"""Regressions found by running the shell-polish build against a real ``.env``.

The banner and the ReAct loop were both reporting/using ``fake`` while a working
Groq key sat in ``.env``, and the LLM INFO logs corrupted the spinner line.
"""

from __future__ import annotations

import io
import sys
import time
from unittest import mock

import pytest

from nexus_core.cli import llm_env
from nexus_core.cli import render, session as session_module
from nexus_core.cli.session import OmniSession
from nexus_core.utils import logger as logger_module

TENANT = "system"


@pytest.fixture()
def clean_env(monkeypatch):
    for key in llm_env.PROVIDER_KEY_ENVS.values():
        monkeypatch.delenv(key, raising=False)
    monkeypatch.delenv(llm_env.DEFAULT_PROVIDER_ENV, raising=False)
    monkeypatch.delenv(llm_env.LEGACY_PROVIDER_ENV, raising=False)
    return monkeypatch


@pytest.fixture()
def groq_env(clean_env):
    """The user's real situation: a working Groq key and a stale fake alias."""
    clean_env.setenv("GROQ_API_KEY", "gsk_fixture")
    clean_env.setenv("GROQ_MODEL", "openai/gpt-oss-120b")
    clean_env.setenv(llm_env.LEGACY_PROVIDER_ENV, "fake")
    return clean_env


class _Tty(io.StringIO):
    def isatty(self) -> bool:
        return True


def _session() -> OmniSession:
    return OmniSession(store=None, engagement=None, operator_id="operator:tester")


def test_banner_shows_real_provider_when_groq_configured(groq_env):
    groq_env.setenv(llm_env.DEFAULT_PROVIDER_ENV, "groq")
    summary, count = _session()._llm_stats()
    assert summary == "groq/openai/gpt-oss-120b"
    assert count == 1


def test_banner_does_not_show_fake_when_real_available(groq_env):
    groq_env.setenv(llm_env.DEFAULT_PROVIDER_ENV, "groq")
    render.configure_color(no_color=True)
    buffer = _Tty()
    session = _session()
    session.no_color = True
    with (
        mock.patch.object(sys, "stdout", buffer),
        mock.patch.object(session_module, "_detect_msfrpcd_version", return_value="6.5.3"),
        mock.patch.object(OmniSession, "_verify_audit_chain", return_value=True),
    ):
        session._show_banner()
    output = buffer.getvalue()
    # The model moved to the status bar, so the compact header must not
    # advertise the stale fake provider anywhere.
    assert "fake" not in output


def test_repl_objective_uses_real_llm_not_fake(groq_env):
    """The end-to-end regression: what ``execute_react`` will actually run on."""
    groq_env.setenv(llm_env.DEFAULT_PROVIDER_ENV, "groq")
    from nexus_core.kernel.runtime import select_llm_client

    assert select_llm_client().primary.config.provider.value == "groq"


def test_llm_stats_and_kernel_agree(groq_env):
    """Banner label and the kernel's client come from the same resolution."""
    groq_env.setenv(llm_env.DEFAULT_PROVIDER_ENV, "groq")
    from nexus_core.kernel.runtime import select_llm_client

    summary, _ = _session()._llm_stats()
    client = select_llm_client()
    assert summary.split("/")[0] == client.primary.config.provider.value
    assert summary.split("/", 1)[1] == client.primary.config.model


def test_logs_do_not_interfere_with_spinner(groq_env, capsys):
    """stdout stays clean while an INFO-level LLM log is emitted at WARNING."""
    groq_env.setenv("NEXUS_LOG_LEVEL", "warning")
    llm_env.configure_logging()
    from nexus_core.cli.spinner import Spinner

    logger = logger_module.get_logger(f"regression-{time.time_ns()}")
    with Spinner("Consultando al modelo", interval_seconds=0.01):
        logger.info("LLM call successful via groq. Tokens: 42.")
        time.sleep(0.05)
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "Consultando al modelo" in captured.err
    assert "LLM call successful" not in captured.out


def test_verbose_logging_restores_the_llm_lines(groq_env, capsys):
    groq_env.setenv("NEXUS_LOG_LEVEL", "info")
    llm_env.configure_logging()
    logger = logger_module.get_logger(f"regression-{time.time_ns()}")
    logger.info("visible with NEXUS_LOG_LEVEL=info")
    assert "visible with NEXUS_LOG_LEVEL=info" in capsys.readouterr().out