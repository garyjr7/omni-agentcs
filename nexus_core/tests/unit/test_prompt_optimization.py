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
    # Fase 3b (V1-15) publishes the values a handler *refuses* the same way
    # (``options ∉ {RHOSTS, LHOST, …}``), because the model could only learn them
    # by being rejected (run_434f5eeadb104b11ba0c80bce16f8d08). Both bounds moved
    # once more, by the measured growth of that data: 14,976 chars at 68 tools
    # (220,2 per tool) against 14,519 / 213,5 before. The total ceiling is also
    # the ticket's stop threshold (15,500): over it, ask before raising anything,
    # and it is constraint data -never prose- what earns the room. WP4 adds the
    # dynamic skill loader (``nexus.skill.list`` + ``nexus.skill.load``): +262
    # chars for two capability lines, measured at 15,762 (218,9 per tool), so the
    # total ceiling moves to 16,000 and the per-tool bound does *not*.
    assert len(catalog) == 72
    text = render_tool_catalog(catalog)
    assert len(text) / len(catalog) < 225
    assert len(text) < 16000


def test_prompt_stays_within_the_reviewed_budget(catalog):
    # Reviewed 68-tool prompt: 22,613 characters after the operator-owned callback
    # was published (22,485 after the forbidden values, 22,028 with the enums only,
    # 20,883 before those). Fase 3d (V1-20) costs 128 characters for the two tools
    # that own a callback: what earns the room is the constraint the ticket asked
    # for -that ``lhost``/``lport`` are the operator's- not prose. WP1 adds the
    # execution substrate (``nexus.shell.exec`` + ``nexus.session.pty``): +306
    # characters, measured at 23,006. WP4 adds the one-line skill index ("SKILLS
    # DISPONIBLES"): +106 characters on a prompt without skills, measured at
    # 23,374, plus the two catalog lines above. The ceiling moves to 23,700; the
    # per-tool catalog bound (225) was not moved and still holds.
    assert len(_prompt(catalog)) < 23_700


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
