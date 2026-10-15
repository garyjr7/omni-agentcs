"""The ReAct system prompt embeds a compact catalog exactly once (finding #8)."""

from __future__ import annotations

import pytest

from nexus_core.agent.prompts import (
    REACT_SYSTEM_PROMPT,
    render_system_prompt,
    render_tool_catalog,
)
from nexus_core.tools.registry import durable_tool_definitions

pytestmark = pytest.mark.unit


@pytest.fixture()
def catalog():
    return durable_tool_definitions("system")


def _prompt(catalog) -> str:
    return render_system_prompt(
        catalog=catalog,
        objective="escanea el host",
        engagement_id="eng-1",
        scope_summary="engagement=eng-1",
        history_summary="",
    )


def test_prompt_no_catalog_duplication(catalog):
    prompt = _prompt(catalog)
    # The canonical tool id appears once per prompt, never twice.
    assert prompt.count("nexus.recon.nmap") == 1


def test_prompt_includes_blackboard_facts(catalog):
    prompt = render_system_prompt(
        catalog=catalog,
        objective="encadena",
        engagement_id="eng-1",
        scope_summary="s",
        facts_summary="- [service] 10.0.0.5:21/tcp (verificado, via nmap): {}",
    )
    assert "[service] 10.0.0.5:21/tcp" in prompt


def test_prompt_requires_full_tcp_recon(catalog):
    prompt = _prompt(catalog)
    assert "METODOLOGÍA DE RECONOCIMIENTO" in prompt
    assert "full_tcp" in prompt


def test_prompt_template_references_catalog_once():
    # Guard against re-introducing a second ``{...}`` catalog placeholder.
    assert REACT_SYSTEM_PROMPT.count("{tool_catalog}") == 1


def test_prompt_catalog_compact_format(catalog):
    text = render_tool_catalog(catalog)
    line = next(line for line in text.splitlines() if line.startswith("- nexus.recon.nmap:"))
    assert "| args[" in line
    assert "riesgo:" in line
    # The full JSON schema is not embedded anymore.
    assert "properties" not in line
    assert '"type"' not in line


def test_catalog_stays_compact_for_all_tools(catalog):
    # Fase 3 fixes: legal enum values are part of every line that declares them,
    # because three of eleven turns of run_abe04509c5064c6e8e475f46ba8f8c60 were
    # rejected (30,6 % of that run's tokens) by guessing a value the catalog hid.
    # Both bounds moved once, by the measured growth of that data: 14,519 chars at
    # 68 tools (213,5 per tool) against 13,383 / 196,8 before. The ceiling stays a
    # ceiling: it is the enum values that earned the room, not new prose.
    assert len(catalog) == 68
    text = render_tool_catalog(catalog)
    assert len(text) / len(catalog) < 215
    assert len(text) < 14700


def test_prompt_stays_within_the_reviewed_budget(catalog):
    # Reviewed 68-tool prompt: 22,028 characters, with no repeated schemas
    # (20,883 before the enum values were made visible).
    assert len(_prompt(catalog)) < 22400


def test_catalog_lists_every_tool_exactly_once(catalog):
    text = render_tool_catalog(catalog)
    lines = [line for line in text.splitlines() if line.startswith("- ")]
    assert len(lines) == len(catalog)
    for tool_id in catalog:
        assert text.count(f"- {tool_id}:") == 1


def test_prompt_tells_model_about_shared_session(catalog):
    prompt = _prompt(catalog)
    assert "sesión de trabajo" in prompt.lower()
    assert "/ask" in prompt
