"""Prompt polish: the four states (normal, session, trust, both) and colour.

The input line always opens with the Codex-style ``> `` chevron; contextual
chips (trust/session/report) are the only thing that can precede it.
"""

from __future__ import annotations

import pytest

from nexus_core.cli import render
from nexus_core.cli.session import OmniSession


class _Engagement:
    def __init__(self, name: str = "scanme-lab") -> None:
        self.name = name
        self.engagement_id = "eng-scanme"


def _session(engagement=None) -> OmniSession:
    return OmniSession(store=None, engagement=engagement, operator_id="operator:tester")


@pytest.fixture(autouse=True)
def _plain():
    render.configure_color(no_color=True)
    yield
    render.configure_color(no_color=False)


def test_prompt_normal_no_session_no_trust():
    prompt = _session().prompt
    assert prompt == "> "


def test_prompt_is_minimal_even_with_engagement():
    # The engagement lives in the compact header, shown once, not in the prompt.
    prompt = _session(_Engagement()).prompt
    assert prompt == "> "
    assert "scanme-lab" not in prompt


def test_prompt_with_session():
    session = _session(_Engagement())
    session.active_session_uuid = "abc12345"
    session.active_session_info = {"type": "meterpreter"}
    assert "[session abc12345/meterpreter]" in session.prompt
    assert "[TRUST MODE]" not in session.prompt


def test_prompt_with_session_defaults_type_when_unknown():
    session = _session(_Engagement())
    session.active_session_uuid = "abc12345"
    session.active_session_info = None
    assert "[session abc12345/session]" in session.prompt


def test_prompt_with_trust():
    session = _session(_Engagement())
    session.trust_mode = True
    assert "[TRUST MODE]" in session.prompt
    assert "[session" not in session.prompt


def test_prompt_with_session_and_trust():
    session = _session(_Engagement())
    session.trust_mode = True
    session.active_session_uuid = "abc12345"
    session.active_session_info = {"type": "shell"}
    prompt = session.prompt
    assert "[TRUST MODE]" in prompt
    assert "[session abc12345/shell]" in prompt
    assert prompt.endswith("> ")


def test_prompt_ignores_long_engagement_name():
    name = "x" * 60
    prompt = _session(_Engagement(name)).prompt
    assert name not in prompt
    assert prompt == "> "


def test_prompt_no_color_strips_ansi():
    render.configure_color(no_color=False)
    session = _session(_Engagement())
    session.trust_mode = True
    session.active_session_uuid = "abc12345"
    session.active_session_info = {"type": "shell"}
    prompt = session.prompt
    assert "\033[" in prompt
    # Plain tokens survive the colouring (no code inserted inside them).
    assert "[TRUST MODE]" in prompt
    assert "[session abc12345/shell]" in prompt


def test_prompt_without_engagement_shows_only_contextual_chips():
    session = _session()
    session.trust_mode = True
    prompt = session.prompt
    assert "(sin engagement)" not in prompt
    assert "[TRUST MODE]" in prompt
    assert prompt == "[TRUST MODE]\n> "


def test_prompt_shows_report_directory_when_set():
    session = _session(_Engagement())
    session.last_report_directory = "/tmp/scanme-lab-20260929-143012"
    assert "[report scanme-lab-20260929-143012]" in session.prompt


def test_repl_records_each_turn_with_the_chevron(tmp_path, monkeypatch):
    """What the operator reads in the prompt is what the history records."""
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))
    lines = iter(["/help", "/exit"])
    session = OmniSession(store=None, input_reader=lambda _prompt: next(lines))
    session.run_repl()
    assert session.history[0] == "> /help"
    assert session.history[-1] == "> /exit"