"""Exercise the persistent UI with pipe input and DummyOutput."""

import threading
from unittest.mock import patch

import pytest
from prompt_toolkit.formatted_text import fragment_list_to_text

from nexus_core.cli.tui.history import history_path
from nexus_core.cli.tui.session import TuiSession


def test_prompt_reads_one_line_in_tui_mode(tui_factory):
    ui = tui_factory()
    ui.pipe.send_text("hello\n")
    assert ui.session.prompt() == "hello"
    assert ui.session._session.app.is_running


def test_prompt_raises_on_eof(tui_factory):
    ui = tui_factory()
    ui.pipe.send_bytes(b"\x04")
    with pytest.raises(EOFError):
        ui.session.prompt()


def test_prompt_raises_keyboard_interrupt(tui_factory):
    ui = tui_factory()
    ui.pipe.send_bytes(b"\x03")
    with pytest.raises(KeyboardInterrupt):
        ui.session.prompt()


def test_print_updates_buffer_without_terminal_suspension(tui_factory):
    ui = tui_factory()
    ui.pipe.send_text("start\n")
    ui.session.prompt()
    ui.session.flush()
    with patch("prompt_toolkit.application.run_in_terminal", side_effect=AssertionError("external terminal write")) as route:
        ui.session.print("event")
        ui.session.flush()
    assert route.call_count == 0
    assert "event" in ui.session._scrollback.text


def test_set_status_updates_fields(tui_factory):
    ui = tui_factory()
    ui.session.set_status(engagement="lab", trust=True, tokens=(7, 8), cost=0.2)
    state = ui.session._status
    assert (state.engagement_name, state.trust_mode, state.tokens_output, state.cost_usd) == (
        "lab", True, 8, 0.2,
    )


def test_invalidate_noop_in_fallback():
    session = TuiSession(use_tui=False)
    session.invalidate()
    assert session._session is None


def test_close_idempotent(tui_factory):
    ui = tui_factory()
    ui.pipe.send_text("line\n")
    ui.session.prompt()
    ui.session.close()
    ui.session.close()
    assert not ui.session._thread.is_alive()


def test_history_file_created_on_first_prompt(tui_factory, tmp_path):
    path = tmp_path / "history"
    ui = tui_factory(history_path=path)
    ui.pipe.send_text("/help\n")
    ui.session.prompt()
    ui.session.flush()
    from nexus_core.cli.tui.history import file_history
    assert list(file_history(path).load_history_strings()) == ["/help"]
    assert path.stat().st_mode & 0o777 == 0o600


def test_history_persisted_across_sessions(tui_factory, tmp_path):
    path = tmp_path / "history"
    first = tui_factory(history_path=path)
    first.pipe.send_text("previous\n")
    first.session.prompt()
    first.session.close()
    second = tui_factory(history_path=path)
    second.pipe.send_bytes(b"\x1b[A\r")
    assert second.session.prompt() == "previous"


def test_history_respects_xdg_state_home(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))
    assert history_path() == tmp_path / "omni/history"


def test_bottom_toolbar_renders_status(tui_factory):
    ui = tui_factory()
    ui.session.set_status(engagement="lab", scope_targets=2)
    assert "Alcance: 2 objetivos" in fragment_list_to_text(ui.session._toolbar())


def test_bottom_toolbar_empty_when_disabled(tui_factory):
    ui = tui_factory(status_bar_enabled=False)
    assert ui.session._toolbar() == []
    assert ui.session._session.bottom_toolbar is None


def test_print_from_background_thread_does_not_block(tui_factory):
    ui = tui_factory()
    ui.pipe.send_text("begin\n")
    ui.session.prompt()
    done = threading.Event()
    def worker():
        for i in range(10):
            ui.session.print(f"msg {i}")
        done.set()
    thread = threading.Thread(target=worker)
    thread.start()
    assert done.wait(timeout=2)
    thread.join(timeout=2)
    ui.session.flush()
    assert all(f"msg {i}\n" in ui.session.transcript for i in range(10))


def test_blank_line_is_not_eof(tui_factory):
    ui = tui_factory()
    ui.pipe.send_text("\n")
    assert ui.session.prompt() == ""
    ui.pipe.send_text("next\n")
    assert ui.session.prompt() == "next"


def test_no_color_removes_fragment_styles(tui_factory):
    ui = tui_factory(no_color=True)
    ui.session.set_status(trust=True)
    assert all(style == "" for style, _ in ui.session._toolbar())
    assert all(style == "" for style, _ in ui.session._formatted("\x1b[31mred\x1b[0m"))


def test_busy_keeps_application_alive(tui_factory):
    ui = tui_factory()
    ui.pipe.send_text("work\n")
    ui.session.prompt()
    ui.session.set_status(busy=True, busy_message="nmap")
    assert ui.session._session.app.is_running
    # DummyOutput is 80 columns; inspect the untruncated state too.
    assert ui.session._status.busy_message == "nmap"
    assert ui.session._status.busy


def test_history_loads_existing_readline_file(tui_factory, tmp_path):
    path = tmp_path / "history"
    path.write_text("legacy\n")
    ui = tui_factory(history_path=path)
    ui.pipe.send_bytes(b"\x1b[A\r")
    assert ui.session.prompt() == "legacy"
