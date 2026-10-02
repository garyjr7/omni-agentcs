"""Unit tests for the plan side panel rendering."""

from __future__ import annotations

import pytest

from nexus_core.agent.planner import build_plan
from nexus_core.cli.tui.panels import panel_lines, panel_style

pytestmark = pytest.mark.unit


def test_panel_without_plan_is_placeholder():
    lines = panel_lines(None)
    assert lines
    assert any("sin plan" in text for _, text in lines)


def test_panel_shows_current_phase_and_progress():
    plan = build_plan(counts={"service": 1}, engagement_id="eng-1").to_dict()
    lines = panel_lines(plan)
    text = "\n".join(text for _, text in lines)
    assert "PLAN DE ENGAGEMENT" in text
    assert "Enumeración (1/6)" in text
    assert "▶ Enumeración" in text


def test_panel_lists_all_phases():
    plan = build_plan().to_dict()
    lines = panel_lines(plan)
    text = "\n".join(text for _, text in lines)
    assert "Reconocimiento" in text
    assert "Reporte" in text
    assert "(opcional)" in text  # lateral movement


def test_panel_shows_blackboard_counts():
    plan = build_plan(counts={"service": 2, "user": 1}).to_dict()
    text = "\n".join(t for _, t in panel_lines(plan))
    assert "BLACKBOARD" in text
    assert "service:2" in text and "user:1" in text


def test_panel_uses_styled_fragments():
    styles = {style for style, _ in panel_lines(build_plan(counts={"service": 1}).to_dict())}
    assert "class:panel-current" in styles


def test_panel_style_defines_every_used_rule():
    defined = set(panel_style())
    used = {style.split("class:", 1)[1] for style, _ in panel_lines(build_plan().to_dict()) if style.startswith("class:")}
    assert used <= defined
