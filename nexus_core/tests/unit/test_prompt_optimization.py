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
    # 64 tools after RUN_sala12 (THM Intrusion Detection): nexus.post.ssh_upload
    # and nexus.recon.nikto. The catalog has to grow with the surface, so the
    # guard is a *per-tool* bound (which catches one tool bloating the prompt)
    # plus an absolute ceiling with a small margin.
    # Measured at 64 tools: 12.588 chars of catalog / 196.7 per tool — the
    # per-tool bound is what really protects the prompt, and it barely moves
    # (194.6 at 56 tools, 194.8 at 58, 195.5 at 59, 195.7 at 60, 195.9 at 61,
    # 196.1 at 62). The ceiling moved 12.400 -> 12.800 in the same review that
    # added those two tool lines: both are ordinary 5-argument recon/post lines
    # (201 and 224 chars), i.e. the growth is two reviewed tools, not one fat one.
    assert len(catalog) == 64
    text = render_tool_catalog(catalog)
    assert len(text) / len(catalog) < 200
    assert len(text) < 12800


def test_prompt_stays_within_the_reviewed_budget(catalog):
    # Measured 20.097 chars at 64 tools (19.641 at 62, 19.460 at 61, 19.222 at
    # 60, 19.045 at 59, 18.810 at 58, 18.404 at 56, 18.000 was set at 54).
    # Bumping this ceiling is a conscious review of the system prompt, not a
    # formality: the catalog grew by two reviewed tool lines and nothing else
    # changed. If a future tool pushes *this* number, the review question is
    # whether the catalog still fits one prompt, not which bound to raise.
    assert len(_prompt(catalog)) < 20500


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
