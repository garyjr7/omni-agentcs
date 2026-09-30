"""Unknown cost uses a placeholder rather than an invented zero."""

from types import SimpleNamespace

from nexus_core.cli.session import OmniSession
from nexus_core.cli.tui.status import render_status_plain


def test_initial_cost_is_unknown(tui_factory):
    ui = tui_factory()
    ui.pipe.send_text("/status\r")
    ui.session.prompt()
    assert "$—" in render_status_plain(ui.session._status)


def test_unknown_provider_cost_remains_placeholder(tui_factory, monkeypatch):
    monkeypatch.delenv("NEXUS_TUI_INPUT_USD_PER_MTOK", raising=False)
    monkeypatch.delenv("NEXUS_TUI_OUTPUT_USD_PER_MTOK", raising=False)
    ui = tui_factory()
    session = OmniSession(store=None, use_tui=False)
    session._tui = ui.session
    session._record_usage(SimpleNamespace(tokens_input=6000, tokens_output=100, provider="groq"), durable=False)
    text = render_status_plain(ui.session._status)
    assert "6.1k tok" in text and "$—" in text


def test_configured_cost_estimate_is_preserved(tui_factory, monkeypatch):
    monkeypatch.setenv("NEXUS_TUI_INPUT_USD_PER_MTOK", "1")
    monkeypatch.setenv("NEXUS_TUI_OUTPUT_USD_PER_MTOK", "2")
    ui = tui_factory()
    session = OmniSession(store=None, use_tui=False)
    session._tui = ui.session
    session._record_usage(SimpleNamespace(tokens_input=1000, tokens_output=500, provider="openai"), durable=False)
    assert "~$0.0020" in render_status_plain(ui.session._status)
