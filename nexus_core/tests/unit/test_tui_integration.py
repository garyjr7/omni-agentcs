"""The real REPL and event daemon sharing a pipe-driven prompt_toolkit UI."""

import asyncio
import threading
from types import SimpleNamespace
from unittest.mock import patch

from prompt_toolkit.application import create_app_session

from nexus_core.cli import session as module
from nexus_core.cli import render
from nexus_core.cli.session import OmniSession, _stream_run_events
from nexus_core.cli.spinner import spinner_enabled
from nexus_core.cli.tui.output import TuiOutput
from nexus_core.kernel.control_store import ControlStore


def make_session(tui_factory, monkeypatch, **kwargs):
    ui = tui_factory(**kwargs)
    session = OmniSession(store=None, use_tui=False)
    session._tui = ui.session
    session._output = TuiOutput(ui.session)
    monkeypatch.setattr(session, "_llm_summary", lambda: "fake/model")
    monkeypatch.setattr(session, "_verify_audit_chain", lambda: True)
    monkeypatch.setattr(session, "_show_banner", lambda: None)
    return session, ui


def feed(session, ui, lines):
    iterator = iter(lines)
    def reader(prompt):
        try:
            ui.pipe.send_text(next(iterator) + "\n")
        except StopIteration:
            ui.pipe.send_bytes(b"\x04")
        return ui.session.prompt(prompt)
    session.input_reader = reader


def test_repl_uses_tui_when_tty_available(tui_factory, monkeypatch):
    ui = tui_factory()
    with create_app_session(input=ui.pipe, output=ui.output):
        monkeypatch.setattr(module, "should_use_tui", lambda: True)
        session = OmniSession(store=None)
    try:
        assert session._tui.use_tui
        assert isinstance(session._output, TuiOutput)
    finally:
        session._tui.close()


def test_repl_falls_back_to_readline_when_no_tty(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))
    monkeypatch.setattr(module, "should_use_tui", lambda: False)
    session = OmniSession(store=None, input_reader=lambda _: "/exit")
    session.run_repl()
    assert not session._tui.use_tui
    assert "sesión terminada" in capsys.readouterr().out


def test_repl_banner_shown_before_first_prompt(tui_factory, monkeypatch):
    session, ui = make_session(tui_factory, monkeypatch)
    monkeypatch.setattr(session, "_show_banner", lambda: OmniSession._show_banner(session))
    monkeypatch.setattr(module, "_stdout_is_tty", lambda: True)
    monkeypatch.setattr(module, "_detect_msfrpcd_version", lambda: None)
    monkeypatch.setattr(session, "_llm_stats", lambda: ("fake/model", 0))
    monkeypatch.delenv("NEXUS_NO_BANNER", raising=False)
    feed(session, ui, ["/exit"])
    session.run_repl()
    assert ui.session.transcript.index("OmniAgentCS v") < ui.session.transcript.index("└─$")


def test_repl_output_routed_through_tui_output(tui_factory, monkeypatch):
    session, ui = make_session(tui_factory, monkeypatch)
    feed(session, ui, ["/help", "/exit"])
    session.run_repl()
    assert "Comandos disponibles" in ui.session.transcript
    assert "sesión terminada" in ui.session.transcript


def test_stream_events_do_not_break_prompt(tui_factory, monkeypatch):
    session, ui = make_session(tui_factory, monkeypatch)
    session.run_id = "r1"
    read_event = threading.Event()
    def events(*args, after):
        read_event.set()
        return [] if after else [dict(sequence=1, event_type="react.parse_error", payload={"error": "event-marker"})]
    session.store = SimpleNamespace(list_run_events=events)
    session.stream_interval = 0.05
    ui.pipe.send_text("start\n")
    ui.session.prompt()
    stop = threading.Event()
    thread = threading.Thread(target=_stream_run_events, args=(session, stop))
    thread.start()
    try:
        assert read_event.wait(2)
        ui.pipe.send_text("preserved\n")
        assert ui.session.prompt() == "preserved"
    finally:
        stop.set()
        thread.join(2)
    ui.session.flush()
    assert not thread.is_alive()
    assert "event-marker" in ui.session.transcript


def test_spinner_disabled_in_tui_mode(monkeypatch):
    monkeypatch.setattr("nexus_core.cli.tui.session.should_use_tui", lambda: True)
    assert not spinner_enabled()


def test_status_bar_updated_after_each_command(tui_factory, monkeypatch):
    session, ui = make_session(tui_factory, monkeypatch)
    feed(session, ui, ["/trust on", "/exit"])
    with patch.object(session, "_update_status_bar", wraps=session._update_status_bar) as update:
        session.run_repl()
    assert update.call_count == 3
    assert ui.session._status.trust_mode


def test_status_bar_not_shown_when_disabled(tui_factory, monkeypatch):
    session, ui = make_session(tui_factory, monkeypatch, status_bar_enabled=False)
    feed(session, ui, ["/help", "/exit"])
    session.run_repl()
    assert ui.session._session.bottom_toolbar is None


def test_status_live_toggle_and_fixed_input(tui_factory, monkeypatch):
    session, ui = make_session(tui_factory, monkeypatch)
    ui.pipe.send_text("begin\n")
    ui.session.prompt()
    from nexus_core.cli.commands import cmd_status

    cmd_status(session, ["off"])
    ui.session.flush()
    assert ui.session._session.bottom_toolbar is None
    cmd_status(session, ["on"])
    ui.session.flush()
    assert callable(ui.session._session.bottom_toolbar)
    assert not ui.session._session.app.full_screen
    assert len(ui.session._session.app.layout.container.content.children) == 4


def test_llm_usage_accumulates_without_double_counting(tui_factory, monkeypatch, tmp_path):
    session, ui = make_session(tui_factory, monkeypatch)
    session.store = ControlStore(tmp_path / "usage.db")
    session.store.initialize()
    session.run_id = session.store.create_run("system", {})["id"]
    response = SimpleNamespace(tokens_input=20, tokens_output=5, provider="fake")
    session._record_usage(response)
    session._update_status_bar()
    session._update_status_bar()
    assert ui.session._status.tokens_input == 20
    assert ui.session._status.tokens_output == 5
    session.run_id = session.store.create_run("system", {})["id"]
    session._record_usage(response)
    assert ui.session._status.tokens_input == 40
    assert session.store.usage_total("system", session.run_id, "cli_model", "all", "tokens_input") == 20


def test_ask_usage_stays_local(tui_factory, monkeypatch):
    session, ui = make_session(tui_factory, monkeypatch)
    class Client:
        async def complete(self, *args):
            return SimpleNamespace(tokens_input=4, tokens_output=2, provider="fake")
    asyncio.run(session._metered_client(Client(), durable=False).complete([]))
    assert session.run_id is None
    assert ui.session._status.tokens_input == 4


def test_router_restored_after_repl(tui_factory, monkeypatch, capsys):
    session, ui = make_session(tui_factory, monkeypatch)
    feed(session, ui, ["/exit"])
    session.run_repl()
    render.render_status("outside")
    assert "outside" in capsys.readouterr().out
    assert "outside" not in ui.session.transcript
