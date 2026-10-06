"""Banner wiring: REPL-only, one-shot/--help/--version/--doctor excluded."""

from __future__ import annotations

import io
import sys
from unittest import mock

import pytest

import omni
from nexus_core.cli import commands as commands_module
from nexus_core.cli import llm_env
from nexus_core.cli import render, session as session_module
from nexus_core.cli.session import OmniSession

pytestmark = pytest.mark.usefixtures("onboarding_env")

MARKER = "BAJIOWARE"


class _Feed:
    """Deterministic ``input()`` replaying ``/exit`` after the scripted lines."""

    def __init__(self, answers: list[str]) -> None:
        self.answers = list(answers)

    def __call__(self, prompt: str = "") -> str:
        if not self.answers:
            raise EOFError
        return self.answers.pop(0)


class _Tty(io.StringIO):
    def isatty(self) -> bool:
        return True


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.delenv("NEXUS_NO_BANNER", raising=False)
    monkeypatch.delenv("NEXUS_NO_SPINNER", raising=False)
    monkeypatch.delenv("NEXUS_TIP_SEED", raising=False)
    render.configure_color(no_color=False)
    yield
    render.configure_color(no_color=False)


@pytest.fixture(autouse=True)
def _offline_llm(monkeypatch, onboarding_env):
    """Pin ``--objective`` runs to the offline provider.

    Without this, ``omni.main`` would publish the real Groq provider found in
    ``.env`` and the one-shot path would call the live API. The explicit
    ``NEXUS_LLM_DEFAULT_PROVIDER`` wins in ``publish_default_provider``.

    ``onboarding_env`` is requested so it is set up *first*: it clears
    ``os.environ``, so pinning before it would be wiped.
    """
    monkeypatch.setenv(llm_env.DEFAULT_PROVIDER_ENV, llm_env.FAKE_PROVIDER)


def _session(**kwargs) -> OmniSession:
    return OmniSession(store=None, engagement=None, operator_id="operator:tester", **kwargs)


def _run_repl(session: OmniSession) -> str:
    """Run the REPL for one ``/exit`` line with stdout mocked as a TTY."""
    session.input_reader = _Feed(["/exit"])
    buffer = _Tty()
    with (
        mock.patch.object(sys, "stdout", buffer),
        mock.patch.object(session_module, "_detect_msfrpcd_version", return_value=None),
        mock.patch.object(
            OmniSession, "_llm_stats", return_value=("fake/nexus-fake-v1", 0)
        ),
        mock.patch.object(OmniSession, "_verify_audit_chain", return_value=True),
        mock.patch.object(commands_module, "run_command"),
    ):
        session.run_repl()
    return buffer.getvalue()


def test_banner_shown_on_repl_start():
    output = _run_repl(_session())
    assert MARKER in output
    assert "OMNIAGENTCS" in output
    assert "audit" in output


def test_banner_not_shown_when_env_flag_set(monkeypatch):
    monkeypatch.setenv("NEXUS_NO_BANNER", "1")
    assert MARKER not in _run_repl(_session())


def test_banner_not_shown_when_not_tty():
    session = _session()
    session.input_reader = _Feed(["/exit"])
    buffer = io.StringIO()  # isatty() is False
    with (
        mock.patch.object(sys, "stdout", buffer),
        mock.patch.object(commands_module, "run_command"),
    ):
        session.run_repl()
    assert MARKER not in buffer.getvalue()


def test_no_color_flag_renders_plain_ascii_banner():
    """``--no-color`` keeps the banner but drops every ANSI sequence."""
    session = _session(no_color=True)
    buffer = _Tty()
    with (
        mock.patch.object(sys, "stdout", buffer),
        mock.patch.object(session_module, "_detect_msfrpcd_version", return_value=None),
        mock.patch.object(
            OmniSession, "_llm_stats", return_value=("fake/nexus-fake-v1", 0)
        ),
        mock.patch.object(OmniSession, "_verify_audit_chain", return_value=True),
    ):
        session._show_banner()
    output = buffer.getvalue()
    assert MARKER in output
    assert "audit ok" in output
    assert "\033[" not in output


def test_banner_survives_broken_tool_catalog():
    session = _session()
    session.input_reader = _Feed(["/exit"])
    buffer = _Tty()
    with (
        mock.patch.object(sys, "stdout", buffer),
        mock.patch("nexus_core.tools.registry.durable_tool_definitions", side_effect=RuntimeError),
        mock.patch.object(commands_module, "run_command"),
    ):
        session.run_repl()
    assert MARKER in buffer.getvalue()


def test_about_and_banner_flags_parse():
    from nexus_core.cli.main import build_parser

    assert build_parser().parse_args(["--about"]).about is True
    assert build_parser().parse_args(["--banner"]).banner is True
    assert build_parser().parse_args([]).about is False
    assert build_parser().parse_args([]).banner is False


def test_render_about_prints_legacy_art(capsys):
    from nexus_core.cli.main import _render_about, build_parser

    args = build_parser().parse_args(["--about", "--no-color"])
    _render_about([], args)
    output = capsys.readouterr().out
    assert "A G E N T C S" in output
    assert "audit-chain ok" in output


def test_no_banner_in_objective_mode():
    """``--objective`` is one-shot: ``run_objective`` never renders a banner."""
    session = _session()
    with (
        mock.patch.object(OmniSession, "run_objective", return_value=None) as objective,
        mock.patch.object(OmniSession, "_show_banner") as banner,
    ):
        result = session.run_objective("escanea el host")
    assert result is None
    objective.assert_called_once()
    banner.assert_not_called()


@pytest.mark.parametrize(
    "argv",
    [
        # --objective is one-shot: no REPL, therefore no banner.
        ["--objective", "escanea scanme.nmap.org", "--no-wizard"],
        ["--version"],
        ["--help"],
        ["--doctor", "--json", "--no-wizard"],
        ["--list-engagements", "--no-wizard"],
    ],
)
def test_banner_not_shown_in_non_repl_modes(argv, capsys):
    """Every non-REPL flag path returns before ``run_repl`` is reached."""
    with mock.patch.object(OmniSession, "run_repl") as run_repl:
        try:
            omni.main(argv)
        except SystemExit:
            pass
    run_repl.assert_not_called()
    assert MARKER not in capsys.readouterr().out


def test_repl_mode_reaches_run_repl_with_color_flag():
    with (
        mock.patch("nexus_core.cli.main.main", return_value=0) as cli_main,
        mock.patch("nexus_core.cli.wizard.should_run_wizard", return_value=False),
    ):
        assert omni.main(["--no-color", "--no-wizard"]) == 0
    assert cli_main.call_args.args[0] == ["--no-color", "--no-wizard"]


def test_spinner_active_during_tool_call(monkeypatch):
    """``invoke_tool`` wraps the governed call in a spinner when enabled."""
    session = _session()
    seen: list[dict] = []

    class _FakeSpinner:
        def __init__(self, message, **kwargs):
            seen.append({"message": message, **kwargs})

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    monkeypatch.setattr(session_module, "_stdout_is_tty", lambda: True, raising=False)
    monkeypatch.setattr(OmniSession, "_spinner_enabled", lambda self: True)
    monkeypatch.setattr(OmniSession, "_describe_tool_call", lambda self, t, a: f"msg {t}")
    monkeypatch.setattr("nexus_core.cli.spinner.Spinner", _FakeSpinner)
    with (
        mock.patch.object(session, "ensure_run", return_value="run-1"),
        mock.patch.object(session_module, "_operator_approval_gate", return_value=None),
        mock.patch.object(session, "record_tool_result"),
        mock.patch(
            "nexus_core.tools.registry.durable_tool_definitions",
            return_value={"nexus.recon.nmap": (object(), object())},
        ),
        mock.patch("nexus_core.kernel.runtime.execute_tool", new=_async_result),
    ):
        session.invoke_tool("nexus.recon.nmap", {"target": "scanme.nmap.org"})
    assert seen and seen[0]["message"] == "msg nexus.recon.nmap"
    assert seen[0]["enabled"] is True


async def _async_result(payload, context):
    return {"output": {"success": True}}