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


# ------------------------------------------- per-turn cost (Simple CTF autopsy)
# Measured 2026-10-17: the run paid ~10 600 prompt tokens per turn and 250 000
# of budget bought only 22 turns, because the full catalog travelled on every
# turn. The abbreviations below are what keeps the average under 6 000.


def _context_messages(tmp_path, *, iteration: int, catalog, subagent_id="exploit"):
    """Render one turn's message list the way the loop does."""
    from nexus_core.agent.planner import Plan
    from nexus_core.agent.react_services import ContextBuilder, ContextSnapshot
    from nexus_core.agent.react_support import _estimate_request_tokens
    from nexus_core.agent.subagents import SUBAGENTS_BY_ID
    from nexus_core.kernel.control_store import ControlStore

    store = ControlStore(tmp_path / "budget.db")
    store.initialize()
    plan = Plan(
        objective="simple ctf", engagement_id="eng-1", facts_total=0, counts={},
        phases=(), current="exploitation", next_hint="usar sqlmap",
    )
    snapshot = ContextSnapshot(
        run_history=[
            {"role": "user", "content": "x" * 2000},
            {"role": "assistant", "content": '{"thought":"x","action":"tool_call"}'},
            {"role": "user", "content": "y" * 3000},
            {"role": "assistant", "content": '{"thought":"y","action":"tool_call"}'},
            {"role": "user", "content": "z" * 3000},
        ],
        history_summary="## Resumen\n" + "s" * 2500,
        plan=plan,
        facts_text="- [service] 10.64.128.102:21/tcp (verificado, via nmap): {}" * 8,
    )
    messages = ContextBuilder().render(
        snapshot,
        allowed_catalog=catalog,
        objective="Resuelve la sala Simple CTF " * 4,
        engagement_id="eng-1",
        scope=None,
        subagent=SUBAGENTS_BY_ID[subagent_id],
        project_instruction=None,
        active_skills=[],
        store=store,
        tenant_id="system",
        iteration=iteration,
    )
    return messages, _estimate_request_tokens(messages)


def test_compact_catalog_is_a_third_of_the_full_one(catalog):
    from nexus_core.agent.prompts import render_tool_catalog

    full = render_tool_catalog(catalog)
    compact = render_tool_catalog(catalog, compact=True)
    assert len(compact) < len(full) / 3


def test_compact_catalog_keeps_every_tool_id_and_its_required_arguments(catalog):
    from nexus_core.agent.prompts import render_tool_catalog

    text = render_tool_catalog(catalog, compact=True)
    assert len(text.splitlines()) == len(catalog)
    for tool_id in catalog:
        assert text.count(f"- {tool_id} ") == 1 and f"- {tool_id} " in text
    nmap = next(line for line in text.splitlines() if line.startswith("- nexus.recon.nmap "))
    # Required names, and the legal values of a required enum, survive the trim.
    assert "req[target:string*]" in nmap
    sqlmap = next(line for line in text.splitlines() if line.startswith("- nexus.web.sqlmap "))
    assert "url:string*" in sqlmap


def test_render_system_prompt_compact_announces_the_missing_details(catalog):
    from nexus_core.agent.prompts import COMPACT_CATALOG_NOTE, render_system_prompt

    compact = render_system_prompt(
        catalog=catalog, objective="x", engagement_id="eng-1", scope_summary="s",
        full_catalog=False,
    )
    assert COMPACT_CATALOG_NOTE in compact
    assert len(compact) < len(
        render_system_prompt(
            catalog=catalog, objective="x", engagement_id="eng-1", scope_summary="s"
        )
    )


def test_the_full_catalog_comes_back_on_the_first_turn_and_every_fifth(catalog):
    from nexus_core.agent.react_services import ContextBuilder
    from nexus_core.agent.subagents import SUBAGENTS_BY_ID

    builder = ContextBuilder()
    recon, exploit = SUBAGENTS_BY_ID["recon"], SUBAGENTS_BY_ID["exploit"]
    assert builder.full_catalog_for(iteration=1, subagent=recon) is True
    assert builder.full_catalog_for(iteration=2, subagent=recon) is False
    assert builder.full_catalog_for(iteration=5, subagent=recon) is True
    assert builder.full_catalog_for(iteration=6, subagent=recon) is False
    # A phase change swaps the allowed tools: the new set arrives complete.
    assert builder.full_catalog_for(iteration=7, subagent=exploit) is True
    assert builder.full_catalog_for(iteration=8, subagent=exploit) is False


def test_a_compact_turn_fits_under_the_6000_token_target(tmp_path, catalog):
    messages, tokens = _context_messages(tmp_path, iteration=2, catalog=catalog)
    assert "catálogo resumido" in messages[0].content
    assert tokens < 6_000


def test_the_average_turn_over_22_iterations_stays_under_6000(tmp_path, catalog):
    totals = [
        _context_messages(tmp_path, iteration=iteration, catalog=catalog)[1]
        for iteration in range(1, 23)
    ]
    assert sum(totals) / len(totals) < 6_000
    # The refresh turn is the expensive one; it must still fit a 250k budget
    # long enough for the ~40 turns Simple CTF needs.
    assert max(totals) < 8_000
