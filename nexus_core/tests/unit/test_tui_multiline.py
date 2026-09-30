"""Alt+Enter edits; Enter submits the entire buffer without changing routing."""

from unittest.mock import patch
import threading
from prompt_toolkit.document import Document

from nexus_core.cli.session import OmniSession


def test_alt_enter_inserts_newline(tui_factory):
    ui = tui_factory()
    ui.pipe.send_text("first\x1b\rsecond\r")
    assert ui.session.prompt() == "first\nsecond"


def test_enter_submits_multiline(tui_factory):
    ui = tui_factory()
    # Bracketed paste preserves embedded newlines; the final Enter submits.
    ui.pipe.send_text("\x1b[200~first\nsecond\x1b[201~\r")
    assert ui.session.prompt() == "first\nsecond"


def test_multiline_visual_continuation(tui_factory):
    ui = tui_factory()
    session = ui.session._session
    assert "·" in session.prompt_continuation(4, 1, False)
    ui.pipe.send_text("start\r")
    ui.session.prompt()
    before = ui.session._input_height()
    changed = threading.Event()
    def change():
        session.default_buffer.set_document(Document("first\nsecond"), bypass_readonly=True)
        changed.set()
    ui.session._dispatch(change)
    assert changed.wait(2)
    assert ui.session._input_height() == before + 1


def test_empty_multiline_not_submitted(tui_factory):
    ui = tui_factory()
    session = OmniSession(store=None, use_tui=False)
    session._tui = ui.session
    lines = iter([" \x1b\r \r", "/exit\r"])
    def reader(prompt):
        ui.pipe.send_text(next(lines))
        return ui.session.prompt(prompt)
    session.input_reader = reader
    with patch.object(session, "run_objective") as objective:
        session.run_repl()
    objective.assert_not_called()
