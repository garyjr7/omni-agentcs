"""Automatic TUI gates and the complete optional-dependency fallback."""

import builtins
import io
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from nexus_core.cli.tui import session as module
from nexus_core.cli.tui.fallback import fallback_prompt
from nexus_core.cli.tui.output import PlainOutput


class Tty(io.StringIO):
    def isatty(self):
        return True


@pytest.fixture
def terminal(monkeypatch):
    monkeypatch.delenv("NEXUS_NO_TUI", raising=False)
    # GitHub sets CI=true and should_use_tui() short-circuits on it before it
    # looks at the streams. The CI gate has its own test in
    # test_tui_rich_presentation.py; here the TTY path is what is under test.
    monkeypatch.delenv("CI", raising=False)
    # Pytest replaces global stdout between fixture setup and the test call.
    # Isolate the module's stream references instead of fighting capture.
    streams = SimpleNamespace(stdin=Tty(), stdout=Tty())
    monkeypatch.setattr(module, "sys", streams)
    return streams


def test_should_use_tui_false_when_stdin_not_tty(terminal, monkeypatch):
    monkeypatch.setattr(terminal, "stdin", io.StringIO())
    assert not module.should_use_tui()


def test_should_use_tui_false_when_stdout_not_tty(terminal, monkeypatch):
    monkeypatch.setattr(terminal, "stdout", io.StringIO())
    assert not module.should_use_tui()


@pytest.mark.parametrize("value", ["1", "true", "yes", "TRUE"])
def test_should_use_tui_false_when_env_var_set(terminal, monkeypatch, value):
    monkeypatch.setenv("NEXUS_NO_TUI", value)
    assert not module.should_use_tui()


def test_should_use_tui_false_when_ptk_unavailable(terminal):
    with patch.object(module.importlib, "import_module", side_effect=ImportError):
        assert not module.should_use_tui()


def test_should_use_tui_true_in_tty_with_ptk(terminal):
    assert module.should_use_tui()


def test_fallback_prompt_reads_line(monkeypatch):
    monkeypatch.setattr(builtins, "input", lambda text: "literal line")
    assert fallback_prompt("$ ") == "literal line"


def test_fallback_prompt_raises_on_eof():
    with patch("builtins.input", side_effect=EOFError), pytest.raises(EOFError):
        fallback_prompt("$ ")


def test_fallback_prompt_raises_keyboard_interrupt():
    with patch("builtins.input", side_effect=KeyboardInterrupt), pytest.raises(KeyboardInterrupt):
        fallback_prompt("$ ")


def test_plain_output_uses_print(capsys):
    PlainOutput().write("line", end="!")
    assert capsys.readouterr().out == "line!"


def test_tui_session_print_in_fallback_writes_to_stdout(capsys):
    session = module.TuiSession(use_tui=False)
    session.print("plain")
    assert capsys.readouterr().out == "plain\n"
