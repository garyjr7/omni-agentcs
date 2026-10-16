import asyncio
import time
from types import SimpleNamespace
from unittest.mock import patch

from prompt_toolkit.formatted_text import fragment_list_to_text


def test_busy_window_height_zero_when_idle(tui_factory):
    assert tui_factory().session._busy_window.height() == 0


def test_busy_window_height_one_when_busy(tui_factory):
    ui = tui_factory()
    ui.session.set_busy()
    assert ui.session._busy_window.height() == 1


def test_busy_shows_pulsing_block_indicator(tui_factory):
    ui = tui_factory()
    ui.session.set_busy()
    text = fragment_list_to_text(ui.session._render_busy())
    assert "[+][+][+][+][+] · esc interrupt" in text
    assert ui.session._busy_line is not None
    lexer = ui.session._scrollback_window.content.lexer
    active_line = lexer.lex_document(ui.session._scrollback.document)(ui.session._busy_line)
    assert fragment_list_to_text(active_line) == "[+][+][+][+][+] · esc interrupt"


def test_busy_completion_logs_worked_for_duration(tui_factory):
    ui = tui_factory()
    ui.session.set_busy()
    ui.session._status.busy_started_at = time.monotonic() - 3
    # The active indicator carries no elapsed time...
    assert "esc interrupt" in fragment_list_to_text(ui.session._render_busy())
    # ...the duration is recorded once the turn completes.
    ui.session.clear_busy()
    assert ui.session._completion_status is not None
    assert ui.session._completion_status.startswith("Worked for 0m 3s ·")
    assert ui.session._completion_window.height() == 1
    assert "Worked for" in ui.session.transcript
    assert "[+][+][+][+][+] · esc interrupt" not in ui.session.transcript


def test_busy_shows_custom_message(tui_factory):
    ui = tui_factory()
    ui.session.set_busy("Ejecutando nmap")
    assert fragment_list_to_text(ui.session._render_busy()).endswith(" · esc interrupt")


def test_busy_clears_after_tool(tui_factory):
    from nexus_core.cli.session import OmniSession
    ui = tui_factory()
    session = OmniSession(store=None, use_tui=False)
    session._tui = ui.session
    try:
        with session._busy("test"):
            raise ValueError("tool failed")
    except ValueError:
        pass
    assert not ui.session._status.busy and ui.session._render_busy() == []


def test_busy_refresh_interval_is_live(tui_factory):
    ui = tui_factory()
    ui.session.set_busy()
    # The pulse is driven by the existing refresh loop, not a second writer.
    assert ui.session._app.refresh_interval == 0.1


def test_escape_during_busy_emits_cancel(tui_factory):
    from nexus_core.cli.session import OmniSession
    ui = tui_factory()
    ui.pipe.send_text("start\r")
    ui.session.prompt()
    events = []
    session = OmniSession(store=None, use_tui=False)
    session._tui = ui.session
    session.store = SimpleNamespace(append_run_event=lambda *args: events.append(args))
    async def operation():
        for _ in range(100):
            if events:
                return "cancelled"
            await asyncio.sleep(.02)
        return "missed"
    with session._busy("Working"):
        ui.pipe.send_bytes(b"\x1b")
        assert asyncio.run(session._with_cancel(operation(), "run1")) == "cancelled"
    assert len(events) == 1 and events[0][2] == "react.cancel_requested"
    assert events[0][3]["source"] == "cli-escape"


def test_busy_does_not_flicker(tui_factory):
    ui = tui_factory()
    ui.pipe.send_text("start\r")
    ui.session.prompt()
    with patch.object(ui.output, "erase_screen") as erase:
        ui.session.set_busy()
        ui.session.print("tool line")
        ui.session.flush()
        ui.session.clear_busy()
    erase.assert_not_called()


def test_busy_visible_above_input(tui_factory):
    ui = tui_factory()
    ui.session.set_busy()
    assert "[+][+][+][+][+] · esc interrupt" in ui.session.transcript
    assert ui.session._busy_window not in ui.session._rows


def test_direct_operation_cancel_without_run_does_not_write_audit(tui_factory):
    from nexus_core.cli.session import OmniSession
    ui = tui_factory()
    session = OmniSession(store=None, use_tui=False)
    session._tui = ui.session
    ui.session.set_busy()
    ui.session._cancel_event.set()
    async def operation():
        await asyncio.sleep(10)
    try:
        asyncio.run(session._with_cancel(operation(), None, cooperative=False))
    except asyncio.CancelledError:
        pass
    else:
        raise AssertionError("operation not cancelled")
