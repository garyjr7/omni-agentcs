"""Status preference persistence without changing the main config schema."""

import pytest

from nexus_core.cli.commands import cmd_help, cmd_status
from nexus_core.cli.session import OmniSession
from nexus_core.cli.tui.status import load_status_preference, preferences_path


@pytest.fixture
def session(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    value = OmniSession(store=None, use_tui=False)
    monkeypatch.setattr(value, "_llm_summary", lambda: "fake/model")
    return value


def test_cmd_status_show_prints_plain(session, capsys):
    cmd_status(session, ["show"])
    text = capsys.readouterr().out
    assert "fake/model" in text and "tok" in text and "\x1b" not in text


def test_cmd_status_off_persists(session):
    cmd_status(session, ["off"])
    assert not load_status_preference()
    assert not OmniSession(store=None, use_tui=False)._tui.status_bar_enabled
    assert preferences_path().stat().st_mode & 0o777 == 0o600


def test_cmd_status_on_persists(session):
    cmd_status(session, ["off"])
    cmd_status(session, ["on"])
    assert load_status_preference()
    assert OmniSession(store=None, use_tui=False)._tui.status_bar_enabled


def test_cmd_status_help_lists_it(session, capsys):
    cmd_help(session, [])
    assert "/status" in capsys.readouterr().out


def test_cmd_status_no_arg_shows_state(session, capsys):
    cmd_status(session, [])
    assert "status bar: ON" in capsys.readouterr().out


def test_cmd_status_invalid_does_not_persist(session, capsys):
    cmd_status(session, ["invalid"])
    assert "uso:" in capsys.readouterr().out
    assert not preferences_path().exists()
