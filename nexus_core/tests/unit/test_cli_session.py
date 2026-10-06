"""Unit tests for the REPL loop itself (no real LLM, no real terminal)."""

from __future__ import annotations

import pytest

from nexus_core.cli import render
from nexus_core.cli.session import OmniSession
from nexus_core.kernel.control_store import ControlStore
from nexus_core.scope import EngagementScope, EngagementStore


@pytest.fixture(autouse=True)
def _no_color():
    original = render.color_enabled()
    render.set_color_enabled(False)
    yield
    render.set_color_enabled(original)


@pytest.fixture()
def session(tmp_path) -> OmniSession:
    store = ControlStore(tmp_path / "session.db")
    store.initialize()
    return OmniSession(store=store, tenant_id="system", llm_client=None, max_iterations=2)


class InterruptThen:
    """Reader that raises ``KeyboardInterrupt`` once before its script."""

    def __init__(self, answers: list[str]) -> None:
        self.answers = list(answers)
        self.interrupted = False

    def __call__(self, prompt: str = "") -> str:
        if not self.interrupted:
            self.interrupted = True
            raise KeyboardInterrupt
        return self.answers.pop(0) if self.answers else "/exit"


def test_repl_survives_ctrl_c_and_exits_on_slash_exit(session, capsys):
    session.input_reader = InterruptThen(["/exit"])

    session.run_repl()

    out = capsys.readouterr().out
    assert "Ctrl+C interrumpe la entrada" in out
    assert "sesión terminada" in out
    assert session.should_exit is True


def test_repl_exits_cleanly_on_ctrl_d(session, capsys):
    def reader(prompt: str = "") -> str:
        raise EOFError

    session.input_reader = reader

    session.run_repl()  # must not raise

    out = capsys.readouterr().out
    assert "sesión terminada" in out
    assert session.should_exit is False


def test_repl_sends_plain_lines_to_the_react_loop(session, monkeypatch, capsys):
    calls: list[str] = []
    monkeypatch.setattr(session, "run_objective", lambda objective: calls.append(objective))
    session.input_reader = InterruptThen(["escanea 10.0.0.5", "/scope"])

    session.run_repl()

    assert calls == ["escanea 10.0.0.5"]
    # The meta command was dispatched instead of being sent to the agent.
    assert "(sin engagement activo)" in capsys.readouterr().out


def test_prompt_is_minimal_and_engagement_stays_durable(tmp_path):
    store = ControlStore(tmp_path / "prompt.db")
    store.initialize()
    plain = OmniSession(store=store, tenant_id="system")
    # The engagement lives in the compact header, not the prompt.
    assert plain.prompt == "└─$ "

    scope = EngagementStore(store).create(
        EngagementScope(
            engagement_id="eng-prompt",
            tenant_id="system",
            name="scanme-test",
            client="acme",
            owner_id="owner-1",
            valid_from="2020-01-01T00:00:00+00:00",
            valid_until="2035-01-01T00:00:00+00:00",
            cidrs=(),
            domains=(),
            urls=(),
            exclusions=(),
        )
    )
    named = OmniSession(store=store, tenant_id="system", engagement=scope)
    assert named.prompt == "└─$ "
    assert named.engagement_id == "eng-prompt"
