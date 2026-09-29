"""Unit tests for the ANSI renderer of the omni CLI."""

from __future__ import annotations

import pytest

from nexus_core.cli import render
from nexus_core.kernel.models import PolicyDecision


@pytest.fixture(autouse=True)
def _restore_color_state():
    original = render.color_enabled()
    yield
    render.set_color_enabled(original)


def test_render_thought_no_color_when_disabled(capsys):
    render.set_color_enabled(False)
    render.render_thought("exploro el target autorizado")
    out = capsys.readouterr().out
    assert "exploro el target autorizado" in out
    assert "\033[" not in out


def test_render_tool_call_shows_noise_level(capsys):
    render.set_color_enabled(False)
    render.render_tool_call(
        "nexus.recon.nmap", {"target": "10.0.0.5", "flags": ["-Pn", "-p", "22,80"]}, "high"
    )
    out = capsys.readouterr().out
    assert "nexus.recon.nmap" in out
    assert "target: 10.0.0.5" in out
    assert "flags:  ['-Pn', '-p', '22,80']" in out
    assert "noise:" in out and "high" in out


def test_render_tool_call_colorizes_high_risk_red(capsys):
    render.set_color_enabled(True)
    render.render_tool_call("nexus.recon.nmap", {"target": "10.0.0.5"}, "high")
    out = capsys.readouterr().out
    assert render.RED in out
    render.set_color_enabled(False)
    render.render_tool_call("nexus.recon.nmap", {"target": "10.0.0.5"}, "high")
    assert "\033[" not in capsys.readouterr().out


def test_render_tool_result_summarizes_hosts(capsys):
    render.set_color_enabled(False)
    render.render_tool_result(
        "nexus.recon.nmap",
        {
            "success": True,
            "evidence": {
                "host_count": 2,
                "hosts_up": 1,
                "ports_open_total": 3,
                "noise_level": "medium",
            },
            "output": {"findings": [{"severity": "high", "title": "SSH expuesto"}]},
        },
    )
    out = capsys.readouterr().out
    assert "✓ 1 host(s) up" in out
    assert "✗ 1 host(s) down" in out
    assert "3 puerto(s) abierto(s)" in out
    assert "noise: medium" in out
    assert "[high] SSH expuesto" in out

    render.render_tool_result("nexus.recon.nmap", {"success": False, "error": "scope denied"})
    failure = capsys.readouterr().out
    assert "✗ nexus.recon.nmap" in failure
    assert "scope denied" in failure


def test_render_approval_prompt_includes_all_options(capsys):
    render.set_color_enabled(False)
    decision = PolicyDecision(
        True, "allowed after human approval", "risk-approval", requires_approval=True
    )
    answer = render.render_approval_prompt(
        "nexus.recon.nmap", {"target": "10.0.0.5"}, decision, reader=lambda prompt: "y"
    )
    out = capsys.readouterr().out
    assert "[y]" in out and "[n]" in out and "[e]" in out and "[?]" in out
    assert "APROBACIÓN HUMANA REQUERIDA" in out
    assert '"target": "10.0.0.5"' in out
    assert answer == "y"


def test_render_error_uses_red(capsys):
    render.set_color_enabled(True)
    render.render_error("boom")
    out = capsys.readouterr().out
    assert render.RED in out
    assert "boom" in out
    render.set_color_enabled(False)
    render.render_error("boom")
    assert render.RED not in capsys.readouterr().out
