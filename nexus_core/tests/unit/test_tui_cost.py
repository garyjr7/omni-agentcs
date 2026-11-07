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
    # A provider the reference table does not know stays unknown (no invented
    # number). groq *is* known now, so this uses a genuinely unknown one.
    monkeypatch.delenv("NEXUS_TUI_INPUT_USD_PER_MTOK", raising=False)
    monkeypatch.delenv("NEXUS_TUI_OUTPUT_USD_PER_MTOK", raising=False)
    ui = tui_factory()
    session = OmniSession(store=None, use_tui=False)
    session._tui = ui.session
    session._record_usage(
        SimpleNamespace(tokens_input=6000, tokens_output=100, provider="mystery"),
        durable=False,
    )
    text = render_status_plain(ui.session._status)
    assert "Tokens: 6,100" in text and "coste $—" in text


def test_known_provider_cost_is_registered_by_default(tui_factory, monkeypatch):
    # Regression (P1): groq/gpt-oss-120b now has a reference rate, so the status
    # shows a real estimate without any env override.
    monkeypatch.delenv("NEXUS_TUI_INPUT_USD_PER_MTOK", raising=False)
    monkeypatch.delenv("NEXUS_TUI_OUTPUT_USD_PER_MTOK", raising=False)
    ui = tui_factory()
    session = OmniSession(store=None, use_tui=False)
    session._tui = ui.session
    session._record_usage(
        SimpleNamespace(
            tokens_input=6000,
            tokens_output=100,
            provider="groq",
            model="openai/gpt-oss-120b",
        ),
        durable=False,
    )
    text = render_status_plain(ui.session._status)
    assert "~$" in text and ui.session._status.cost_known
    assert "Presupuesto: $—" in text  # known spend does not imply a configured budget


def test_configured_cost_estimate_is_preserved(tui_factory, monkeypatch):
    monkeypatch.setenv("NEXUS_TUI_INPUT_USD_PER_MTOK", "1")
    monkeypatch.setenv("NEXUS_TUI_OUTPUT_USD_PER_MTOK", "2")
    ui = tui_factory()
    session = OmniSession(store=None, use_tui=False)
    session._tui = ui.session
    session._record_usage(SimpleNamespace(tokens_input=1000, tokens_output=500, provider="openai"), durable=False)
    assert "~$0.0020" in render_status_plain(ui.session._status)
