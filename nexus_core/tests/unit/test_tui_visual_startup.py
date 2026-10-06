"""Regressions for duplicate banner output, early logs and intense ASCII art."""

from contextlib import contextmanager
import logging
import sys
from types import SimpleNamespace
from unittest.mock import patch

import omni
from nexus_core.cli import banner, render
from nexus_core.cli.session import OmniSession


def test_banner_is_buffered_once_until_first_prompt(tui_factory):
    ui = tui_factory()
    with patch("prompt_toolkit.print_formatted_text") as terminal_print:
        ui.session.print("BANNER", end="\n")
        # The full-screen renderer will paint this buffer; do not also print
        # the same banner onto the primary terminal before entering the UI.
        assert ui.session.transcript.count("BANNER") == 1
        terminal_print.assert_not_called()


def test_startup_capture_banner_status_prompt_order(monkeypatch):
    events = []
    session = OmniSession(store=None, use_tui=False)
    def eof(prompt):
        events.append("prompt")
        raise EOFError
    session._tui = SimpleNamespace(
        use_tui=True, clear_screen=lambda: events.append("clear"), prompt=eof,
        close=lambda: None,
    )
    @contextmanager
    def patched_stdout(*args, **kwargs):
        events.append("patch")
        yield
    monkeypatch.setattr("nexus_core.cli.tui.output.capture_output", patched_stdout)
    monkeypatch.setattr(session, "_show_banner", lambda: events.append("banner"))
    monkeypatch.setattr(session, "_update_status_bar", lambda: events.append("status"))
    session.run_repl()
    assert events == ["patch", "banner", "status", "prompt"]


def test_no_info_logs_before_banner_on_startup(onboarding_env, monkeypatch, capsys):
    monkeypatch.setenv("NEXUS_LOG_LEVEL", "warning")
    logger = logging.getLogger("LLMFactory")
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
    monkeypatch.setattr(logger, "handlers", [handler])
    monkeypatch.setattr(logger, "propagate", False)
    monkeypatch.setattr(logger, "level", logging.INFO)
    logger.manager._clear_cache()
    monkeypatch.setattr(omni, "load_dotenv", lambda *a, **k: logger.info("Groq client created"))
    monkeypatch.setattr("nexus_core.cli.wizard.should_run_wizard", lambda *a, **k: False)
    def repl(*args, **kwargs):
        print("BANNER")
        return 0
    with patch("nexus_core.cli.main.main", repl):
        assert omni.main(["--no-wizard"]) == 0
    out = capsys.readouterr().out
    assert out.splitlines()[0] == "BANNER"
    assert "[INFO]" not in out


def test_ascii_art_uses_terminal_default_color():
    original = render.color_enabled()
    render.set_color_enabled(True)
    try:
        text = banner.build_banner(
            version="test", tools_count=16, providers_count=1,
            engagement_name="lab", audit_chain_valid=True, msfrpcd_version=None,
            llm_summary="fake/model", width=120, no_color=False, include_tip=False,
            compact=False,
        )
    finally:
        render.set_color_enabled(original)
    art = text.splitlines()[:7]
    assert "██████╗" in art[0]
    assert all("\x1b[" not in line for line in art)


def test_stats_never_construct_provider_clients(monkeypatch):
    session = OmniSession(store=None, use_tui=False)
    with patch("nexus_core.llm.abstraction.LLMFactory.create_from_env", side_effect=AssertionError("client created")):
        summary, count = session._llm_stats()
    assert isinstance(summary, str) and isinstance(count, int)


def test_clear_screen_is_noop_in_fallback(capsys):
    from nexus_core.cli.tui.session import TuiSession

    session = TuiSession(use_tui=False)
    session.clear_screen()
    assert capsys.readouterr().out == ""


def test_clear_screen_uses_terminal_output(tui_factory):
    ui = tui_factory()
    with patch.object(ui.output, "erase_screen") as erase, patch.object(ui.output, "cursor_goto") as move:
        ui.session.clear_screen()
    erase.assert_called_once()
    move.assert_called_once_with(0, 0)


def test_running_tui_does_not_duplicate_output_outside_panel(tui_factory):
    ui = tui_factory()
    ui.pipe.send_text("/status\n")
    ui.session.prompt()
    ui.session.flush()
    with patch("prompt_toolkit.print_formatted_text") as terminal_print:
        ui.session.print("status bar: ON")
        ui.session.flush()
        assert ui.session.transcript.count("status bar: ON") == 1
        terminal_print.assert_not_called()
