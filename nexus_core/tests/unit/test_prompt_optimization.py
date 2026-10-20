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


def test_prompt_orders_the_web_skill_before_any_web_attack(catalog):
    # Run run_4e8779f4… (2026-10-20): the agent found /admin and went straight to
    # passwords, SQLi and three rockyou sweeps without ever reading robots.txt or
    # the page source. The rule is the order to load the checklist; the checklist
    # itself lives in the skill, so it is not paid for on every turn.
    prompt = _prompt(catalog)
    assert "- WEB (80/443):" in prompt
    # The order names the skill and the loader in the same sentence: the catalog
    # already lists ``nexus.skill.load``, so a bare mention proves nothing.
    assert "web-recon-master (nexus.skill.load)" in prompt
    # And it forbids the reflex the measured run had: password guessing at login.
    assert "un login no es una invitación a probar contraseñas" in prompt


def test_prompt_forces_a_multi_vector_kill_chain_view(catalog):
    # The measured failure: one vector absorbs the run. The rule has to name the
    # facts lookup, the two-attempt limit, the barrier and the pivot order.
    prompt = _prompt(catalog)
    assert "- ENFOQUE MULTI-VECTOR (CYBER KILL CHAIN):" in prompt
    assert "query_facts" in prompt
    assert "no insistas más de 2 veces" in prompt
    assert "registra un barrier para ese vector" in prompt
    assert "PIVOTA al siguiente" in prompt
    # The rule is methodology, so it sits inside the rules block, before the
    # response contract (a rule after the JSON examples would be truncated).
    assert prompt.index("ENFOQUE MULTI-VECTOR") < prompt.index("RESPONDE SIEMPRE")


def test_prompt_forces_hydra_before_manual_sqli_on_a_login_form(catalog):
    # Run run_6fef3c1ba9384ee79acee2bd09e8890c (v4, iterations 7-15): the agent
    # found ``/admin/`` and tried ``admin' or '1'='1`` by hand with
    # ``nexus.web.request`` for nine turns; the web branch closed without ever
    # asking the form module. The rule is an order with its three fields.
    prompt = _prompt(catalog)
    assert "- REGLA DE LOGIN WEB:" in prompt
    assert "TIENES PROHIBIDO intentar inyecciones SQL manuales" in prompt
    assert 'nexus.cred.bruteforce con service="http-post-form"' in prompt
    for field in ("form_url", "form_params", "failure_string"):
        assert field in prompt
    # Hydra is the first attempt; SQLi/backups only come after it fails.
    assert "Solo si Hydra falla o da error" in prompt
    # Methodology again: inside the rules, before the response contract.
    assert prompt.index("REGLA DE LOGIN WEB") < prompt.index("RESPONDE SIEMPRE")


def test_the_login_rule_travels_only_with_the_credential_tool(catalog):
    # The prompt is gated per subagent: a recon prompt must not even name a tool
    # it cannot invoke (``test_subagent_gating``). The rule is therefore
    # rendered with the catalog that offers ``nexus.cred.bruteforce``, not as a
    # permanent line.
    gated = {
        tool_id: entry
        for tool_id, entry in catalog.items()
        if tool_id != "nexus.cred.bruteforce"
    }
    prompt = render_system_prompt(
        catalog=gated, objective="x", engagement_id="eng-1", scope_summary="s"
    )
    assert "REGLA DE LOGIN WEB" not in prompt
    assert "nexus.cred.bruteforce" not in prompt
    # The rest of the methodology is unaffected.
    assert "- BRUTEFORCE = ÚLTIMO RECURSO:" in prompt


def test_prompt_makes_brute_force_the_last_resort(catalog):
    prompt = _prompt(catalog)
    assert "- BRUTEFORCE = ÚLTIMO RECURSO:" in prompt
    # Every bruteforce tool id carries the word: the rule names the capability,
    # not three tool ids (it has to fit the per-turn budget measured below).
    assert "no lo lances" in prompt
    # No hint means a barrier fact and a branch change, not a wordlist sweep.
    assert "registra un barrier" in prompt


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
    # per-tool catalog bound (225) was not moved and still holds. The coverage
    # discipline does **not** earn room here: it travels inside the rendered
    # ledger (``coverage.render_coverage``), which only exists on turns that
    # have a discovered surface, so the static ceiling is unchanged.
    # The web-enumeration and brute-force-last-resort rules (run
    # run_4e8779f4dc6a46fd8f42608056858cfb: 29 turns, three rockyou sweeps, 0
    # findings, never read robots.txt) cost 302 characters, measured at 23,941.
    # They earn the room because they are *orders* -when to load the
    # ``web-recon-master`` skill and when brute force is allowed-, not prose: the
    # checklist itself travels in the skill, which is loaded on demand and is
    # not paid per turn. The ceiling moves to 24_000; the per-tool catalog bound
    # does not move.
    # The multi-vector rule (a run closed its only web branch and never tried
    # the other open service) costs 466 characters, measured at 24,407. It is an
    # *order* -two failures of the same vector mean barrier + pivot-, not prose
    # (the vector checklist lives in ``web-recon-master``). The ceiling moves to
    # 24_500; the per-tool catalog bound does not move.
    # The login rule (run_6fef3c1ba9384ee79acee2bd09e8890c, v4: nine turns of
    # hand-written ``admin' or '1'='1`` on ``/admin/`` with the form module never
    # invoked) costs 493 characters, measured at 24,900. It is an *order* with
    # the three fields a form sweep needs -``form_url``, ``form_params``,
    # ``failure_string``-; the recipe and the argument example stay in
    # ``web-recon-master``, which is loaded on demand. The ceiling moves to
    # 25_000; the per-tool catalog bound does not move.
    assert len(_prompt(catalog)) < 25_000


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
    # The multi-vector rule (+466 chars, ~116 tokens per turn) lands on every
    # turn: measured 6,103 average against the previous 5,987, i.e. 250k still
    # buys ~41 turns. The target moves to 6_150 (the compact turn stays at
    # 5,476, well under 6_000); what the rule buys is the pivot the measured run
    # never made. The login rule adds its ~124 tokens to every turn as well:
    # measured 6,227 average, so the target moves to 6_250 (250k still buys ~40
    # turns; the compact turn stays at 5,600).
    assert sum(totals) / len(totals) < 6_250
    # The refresh turn is the expensive one; it must still fit a 250k budget
    # long enough for the ~40 turns Simple CTF needs: 8 refreshes at 8 113 plus
    # 32 compact turns at 5 361 are 233 456 tokens, inside the budget. The old
    # 8 000 ceiling had 1 token of slack at HEAD (7 999), so the +302 characters
    # of the two rules and the 161-character index line of the new skill land
    # here: measured 8 113, and the ceiling moves to 8 150. The multi-vector rule
    # adds its ~116 tokens to the same refresh turn: measured 8,236, so the
    # ceiling moves to 8_250. The login rule lands there too: measured 8,359,
    # so the refresh ceiling moves to 8_400 (32 compact turns at 5,600 plus 8
    # refreshes at 8,359 are 246,072, inside the 250k budget).
    assert max(totals) < 8_400
