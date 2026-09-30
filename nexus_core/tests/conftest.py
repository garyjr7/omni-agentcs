"""Shared fixtures for the current CLI test suite."""

import os

import pytest

from nexus_core.tests.onboarding_support import onboarding_env  # noqa: F401 - pytest fixture


@pytest.fixture(autouse=True)
def _neutralize_no_color(request):
    """Isolate inherited color preferences; explicit no_color_env tests own them."""
    if "no_color_env" in request.fixturenames:
        yield
        return
    original = os.environ.pop("NO_COLOR", None)
    try:
        yield
    finally:
        if original is not None:
            os.environ["NO_COLOR"] = original
        else:
            os.environ.pop("NO_COLOR", None)


@pytest.fixture
def tui_factory(tmp_path, monkeypatch):
    """Real prompt_toolkit sessions on pipes; no terminal or user files."""
    from contextlib import ExitStack
    from types import SimpleNamespace

    from prompt_toolkit.input import create_pipe_input
    from prompt_toolkit.output import DummyOutput

    from nexus_core.cli.tui.session import TuiSession

    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    sessions = []
    with ExitStack() as stack:
        def create(**kwargs):
            pipe = stack.enter_context(create_pipe_input())
            output = DummyOutput()
            session = TuiSession(use_tui=True, input=pipe, output=output, **kwargs)
            sessions.append(session)
            return SimpleNamespace(session=session, pipe=pipe, output=output)
        yield create
        for session in sessions:
            session.close()
