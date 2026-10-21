"""The ``omni run "<objetivo>"`` shim: routes to headless, never to the TUI.

The CLI is argparse-by-flags, so ``run`` is a positional the dispatcher reads
rather than a real subparser (see docs/missions/FASE3B_ECOSYSTEM.md §7). What
must hold: ``run`` selects the headless runner, ``--json``/``--stream-json``
pick the mode, and no path starts the interactive REPL.
"""

from __future__ import annotations

import pytest

import omni
from nexus_core.cli import headless, llm_env
from nexus_core.cli.session import OmniSession

pytestmark = pytest.mark.usefixtures("onboarding_env")


@pytest.fixture(autouse=True)
def _offline_llm(monkeypatch, onboarding_env):
    monkeypatch.setenv(llm_env.DEFAULT_PROVIDER_ENV, llm_env.FAKE_PROVIDER)


@pytest.fixture()
def no_repl(monkeypatch):
    def _fail(self):  # pragma: no cover - the assertion is that it never runs
        raise AssertionError("the REPL/TUI must never start in headless mode")

    monkeypatch.setattr(OmniSession, "run_repl", _fail)
    monkeypatch.setattr(OmniSession, "run_objective", _fail)
    return _fail


def _capture(monkeypatch):
    seen = {}

    def fake_run_headless(
        session, objective, *, mode, max_iterations=None, budget_tokens=None
    ):
        seen["objective"] = objective
        seen["mode"] = mode
        seen["max_iterations"] = max_iterations
        seen["budget_tokens"] = budget_tokens
        seen["use_tui"] = session._tui.use_tui
        seen["active_skills"] = list(session.active_skills)
        return 0

    monkeypatch.setattr(headless, "run_headless", fake_run_headless)
    return seen


@pytest.mark.parametrize(
    ("extra", "expected_mode"),
    [([], "json"), (["--json"], "json"), (["--stream-json"], "stream")],
)
def test_run_shim_selects_the_headless_mode(monkeypatch, no_repl, extra, expected_mode):
    seen = _capture(monkeypatch)
    code = omni.main(["run", "Escanea 10.0.0.5", *extra, "--no-wizard"])
    assert code == 0
    assert seen["objective"] == "Escanea 10.0.0.5"
    assert seen["mode"] == expected_mode
    assert seen["use_tui"] is False  # headless never opens the TUI


def test_run_shim_joins_the_objective_arguments(monkeypatch, no_repl):
    seen = _capture(monkeypatch)
    omni.main(["run", "Escanea", "scanme.nmap.org", "--no-wizard"])
    assert seen["objective"] == "Escanea scanme.nmap.org"


def test_run_shim_forwards_the_active_skills(monkeypatch, no_repl):
    seen = _capture(monkeypatch)
    omni.main(["run", "Escanea x", "--skill", "recon-http", "--no-wizard"])
    assert seen["active_skills"] == ["recon-http"]


def test_stream_json_with_objective_is_headless_too(monkeypatch, no_repl):
    seen = _capture(monkeypatch)
    omni.main(["--objective", "Escanea x", "--stream-json", "--no-wizard"])
    assert seen["mode"] == "stream"


def test_run_shim_forwards_the_explicit_token_budget(monkeypatch, no_repl):
    """R1: ``--budget-tokens`` reaches the loop; absent, the loop derives it."""
    seen = _capture(monkeypatch)
    omni.main(["run", "Escanea x", "--max-iterations", "50", "--no-wizard"])
    assert seen["max_iterations"] == 50
    assert seen["budget_tokens"] is None

    omni.main(["run", "Escanea x", "--budget-tokens", "900", "--no-wizard"])
    assert seen["budget_tokens"] == 900


def test_unknown_subcommand_fails_without_running_anything(monkeypatch, no_repl):
    monkeypatch.setattr(
        headless, "run_headless", lambda *a, **k: pytest.fail("must not run")
    )
    assert omni.main(["frobnicate", "--no-wizard"]) == 2
