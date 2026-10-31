"""Shared fixtures for the test suite."""

import os

import pytest

from nexus_core.tests.onboarding_support import onboarding_env  # noqa: F401 - pytest fixture


@pytest.fixture(autouse=True)
def _hermetic_binary_preflight(monkeypatch):
    """Unit tests must not depend on the host PATH.

    Since B6 the ReAct loop retires a tool whose binary is absent (e.g.
    ``nexus.workspace.search`` without ``rg``), which would make the tool catalog
    of a test depend on the machine running it. The behaviour itself is covered
    by ``test_binaries.py`` (``which``/``run`` injected) and by
    ``test_react_frame.py`` (the preflight helper is monkeypatched), so the loop
    tests stay hermetic.
    """
    monkeypatch.setenv("NEXUS_PREFLIGHT_BINARIES", "0")


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
def no_stored_keys(tmp_path, monkeypatch):
    """Isolate the operator's secret store from a provider-resolution test.

    ``resolve_api_key`` reads the store **before** the environment, by design.
    On a machine where the operator ran ``omni auth login`` that means a test
    exporting only ``GROQ_API_KEY`` still finds a stored OpenAI/DeepSeek key, so
    an unrelated cloud client is built and can win the primary slot. CI has no
    store and never saw it; a developer box lies. The replacement backend is an
    empty ``0600`` file under ``tmp_path``, which cannot fall back to keyring.
    """
    from nexus_core.config import secrets

    empty = secrets.SecretStore(secrets.FileBackend(tmp_path / "secrets.json"))
    monkeypatch.setattr(secrets, "SecretStore", lambda backend=None: empty)
    return empty


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


@pytest.fixture
def lab_scope(monkeypatch):
    """Explicit unsigned fixtures for tests of non-authentication behavior.

    Not autouse: governed stays the default, including all Phase 0 regressions.
    """
    monkeypatch.setenv("NEXUS_SCOPE_MODE", "lab")
