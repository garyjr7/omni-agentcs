"""P2-C3 closure: automatic delegation only on a valid phase-family transition.

Auto-spawn is opt-in and deliberately conservative: a refinement inside the same
kill-chain phase (``web`` → ``services``), a short phase, or a disabled flag must
never pay for a child conversation.
"""
from __future__ import annotations

from nexus_core.agent.supervisor import (
    DEFAULT_AUTOSPAWN_MIN_BUDGET,
    DEFAULT_AUTOSPAWN_MIN_ITERATIONS,
    autospawn_min_budget,
    autospawn_min_iterations,
    should_autospawn,
)
from nexus_core.tests.unit.test_agent_supervisor import setup


def test_autospawn_on_phase_family_transition():
    # recon (recon) → exploit (exploitation): a new front, well-funded target.
    assert should_autospawn("recon", "exploit", expected_iterations=8)


def test_no_autospawn_on_web_to_services():
    # Both are "enumeration": a refinement, not a new front.
    assert not should_autospawn("web", "services", expected_iterations=8)


def test_no_autospawn_on_short_phases():
    assert not should_autospawn("recon", "exploit", expected_iterations=1)


def test_autospawn_disabled_by_flag():
    assert not should_autospawn("recon", "exploit", expected_iterations=8, enabled=False)


def test_autospawn_defaults_and_env_override(monkeypatch):
    monkeypatch.delenv("NEXUS_AUTOSPAWN_MIN_BUDGET", raising=False)
    monkeypatch.delenv("NEXUS_AUTOSPAWN_MIN_ITERATIONS", raising=False)
    assert autospawn_min_budget() == DEFAULT_AUTOSPAWN_MIN_BUDGET
    assert autospawn_min_iterations() == DEFAULT_AUTOSPAWN_MIN_ITERATIONS
    monkeypatch.setenv("NEXUS_AUTOSPAWN_MIN_BUDGET", "200000")
    assert not should_autospawn("recon", "exploit")  # 60000 < 200000 threshold
    monkeypatch.delenv("NEXUS_AUTOSPAWN_MIN_BUDGET", raising=False)
    monkeypatch.setenv("NEXUS_AUTOSPAWN_MIN_ITERATIONS", "10")
    assert not should_autospawn("recon", "exploit", expected_iterations=5)


def test_no_autospawn_for_unknown_profile():
    assert not should_autospawn("recon", "does-not-exist", expected_iterations=8)


def test_maybe_spawn_requires_optin(tmp_path, monkeypatch):
    supervisor, _, _ = setup(tmp_path, monkeypatch, global_budget=1_000_000)
    assert supervisor.autospawn is False
    assert supervisor.maybe_spawn("recon", "exploit") is False
    supervisor.autospawn = True
    assert supervisor.maybe_spawn("recon", "exploit") is True
    # Even opted in, a same-family refinement stays local.
    assert supervisor.maybe_spawn("web", "services") is False
