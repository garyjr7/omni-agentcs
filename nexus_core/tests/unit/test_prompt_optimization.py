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


def _prompt(catalog, **kwargs) -> str:
    return render_system_prompt(
        catalog=catalog,
        objective="escanea el host",
        engagement_id="eng-1",
        scope_summary="engagement=eng-1",
        history_summary="",
        **kwargs,
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
    # The one thing Hydra cannot do: refresh hidden tokens per attempt.
    assert "csrf_mode=true" in prompt
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
    # The 73rd tool (``nexus.post.crack_hash``) is one more capability line with
    # its arguments (249 chars: hash/key input, type, owner, wordlist), measured
    # at 16,089 (220,4 per tool). The *per-tool* average stays under 225 -the
    # thing the bound is for- so only the total ceiling moves, to 16,150.
    # PLAN MODE adds the three ``nexus.orchestrator.*`` plan tools (create,
    # update, status): the contract they write is the one the run is held to.
    # Measured at 16,570 chars for 76 tools (218,0 per tool) -the per-tool bound
    # is what the ceiling protects and it did not move-, so only the total does,
    # to 16,900.
    # V9 adds ``nexus.recon.nfs`` (one capability line with four arguments,
    # 216 chars): measured 16,786 for 77 tools (218,0 per tool). The per-tool
    # bound is what this ceiling protects and it did not move, so only the total
    # does, to 17,000.
    # ``nexus.exploit.find_and_prepare`` (the 78th tool) is one more capability
    # line with four arguments; measured 17,035 for 78 tools (218,4 per tool), so
    # the per-tool bound still holds and only the total moves, to 17,100.
    # ``nexus.exploit.compile_and_upload`` (the 79th tool) is capability data
    # too: one line that names the upload entry point. The per-tool bound is the
    # one that matters and it still holds; the total moves with the line.
    # ``nexus.attack.ad_acl`` (the 80th tool) is one capability line whose
    # argument list is the contract (action, target, principal, rights): measured
    # 17,647 for 80 tools (220,6 per tool), so the per-tool bound still holds and
    # only the total moves, to 17,750.
    # ``nexus.post.verify_route`` (the 81st tool) is one capability line with two
    # required arguments (from_host, to_host, method): measured 17,935 for 81
    # tools (221,4 per tool), so the per-tool bound still holds and only the
    # total moves, to 18,050.
    # Tanda E: the catalog line now carries the *contract* of the tools whose
    # schema the model could not see -the nested properties of a required object
    # and the optional arguments of a tool that requires none- plus one clause per
    # measured semantic constraint (relative ``cwd``, the artifact handle...). It
    # is 209 characters for the whole 81-tool catalog, all of it inside the
    # existing per-tool bound (224,0 < 225): capability data, not prose.
    # Tanda G adds ``nexus.post.http_server`` (the 82nd tool): one capability
    # line with its two arguments. Measured 18,301 for 82 tools (223,2 per
    # tool), still inside the per-tool bound, so only the total moves.
    # B1 adds ``nexus.attack.ad_user_enum`` (the 83rd): one line with its three
    # required arguments. Measured 18,519 for 83 tools (223,1 per tool), still
    # inside the per-tool bound; only the total moves.
    assert len(catalog) == 83
    text = render_tool_catalog(catalog)
    assert len(text) / len(catalog) < 225
    assert len(text) < 18_600


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
    # ``nexus.post.crack_hash`` (the 73rd tool) costs its catalog line: measured
    # 25,152. It is capability data, not prose, so the ceiling moves to 25_250.
    # PLAN MODE adds two things: the `PLAN-FIRST` rule (an order: without a plan
    # no attack tool runs) and the `PLAN DEL ENGAGEMENT` section that carries the
    # TODOs. Measured 26,513 with the three catalog lines and an empty plan, so
    # the ceiling moves to 26,700; the plan itself is measured in
    # ``test_prompt_with_a_plan_stays_under_its_ceiling`` below.
    # V9 (Hijack) adds the two orders the measured run lacked: the BLACK-BOX
    # philosophy (the whole kill chain is authorized unless the RoE says
    # otherwise) and the passive-wait ban, plus the install/scope rewrite they
    # forced ("if the binary is missing, install it" instead of "give up").
    # Measured 27,831 (26,513 + 1,102 chars of policy + the nfs catalog line),
    # so the ceiling moves to 28,000; the per-tool catalog bound does not move.
    # V10 adds the CSRF half of the login rule (~190 chars) and the CMS order
    # (~430 chars: the PoC is useless if the run never obtains it), plus the
    # catalog line of ``find_and_prepare``: measured 28,665, ceiling 28_750.
    # V11 adds the PoC handoff to the CMS order (the file type decides the
    # vector: .ascx theme, .py script, .exe upload) and the catalog line of
    # ``compile_and_upload``: measured 29,131, ceiling 29_400.
    # V14 adds the BlogEngine theme endpoint to the same order (the theme
    # manager, its multipart field and the warning about editpost.cshtml): +499
    # characters, measured 29,630, so the ceiling moves to 29_750. It is an
    # *order* with the exact endpoint a measured run guessed wrong, not prose.
    # ``nexus.attack.ad_acl`` adds its catalog line (the DACL primitive the
    # DeadDrop phase 5 lacked): measured 29,982, so the ceiling moves to 30,100.
    # Tanda A costs 458 characters: the 81st catalog line plus the PIVOTE order
    # (the canonical ``ssh -D`` + proxychains4 chain and the ``verify_route``
    # step that proves it). It earns the room because it is what DeadDrop P11
    # lacked: 20 turns of ``ssh -L`` and a wrapper script, 0 findings, no route
    # anybody could prove. Measured 30,558; ceiling 30,650.
    # Tanda B (Fix 3a.4) adds the deny-list block: what is refused, and *where*
    # (the self-destructive list on both sides of the link; sudo/su only on the
    # local channels). It costs 542 characters -measured 31,101- and it buys the
    # two blocked turns the dossier measured: a ``sudo`` typed into the local
    # sandbox, and a model that believed it could not escalate on a target it
    # owned. Ceiling 31_150.
    # Tanda D (run v1 de DeadDrop P12) adds two orders about a result the model
    # already misread: the Node preview semantics (an executed module that
    # exported nothing answers ``{}``) and the credential families (the web
    # app's hardcoded password is not the operating system's). They cost 900
    # characters together -measured 32,001- and they buy the 30 turns the
    # measured run spent on a vector that had already worked. Ceiling 32_060.
    # Tanda E rewrites the PIVOTE order to forbid ``record_fact(route)`` (+33) and
    # compresses the CMS order by 268 characters without dropping a single fact it
    # exists for: the two PoC handoffs and the BlogEngine theme endpoint stay.
    # Measured 32,090; ceiling 32_150.
    # Tanda F adds the AD tunnel order (+285): the DC is reachable only through
    # the pivot, and wrapping ``nxc``/``secretsdump`` in ``shell.exec`` is what
    # made the DeadDrop run close with ``grounded: 0``. Measured 32,375;
    # ceiling 32,450.
    # Tanda G adds the SSRF order (+443: the victim fetches the payload back, so
    # ``127.0.0.1`` never works) and the http_server catalog line. Measured
    # 32,968; ceiling 33_050.
    # B1 adds the ``ad_user_enum`` catalog line (+225: the tool that confirms an
    # account without a password). Measured 33,193; ceiling 33_250.
    # The parallel contract costs 427 characters (the `tool_calls` shape and its
    # two conditions: only independent tools, and a single `results` block). It
    # is an *order with the wire shape*, not prose, and it is the only way the
    # model can learn that a turn may carry several calls -without it the whole
    # feature is invisible. Measured 33,620; ceiling 33_680.
    # The subagent-scope rule of an ``unrestricted`` profile and the
    # install-last-resort order replace the old "si falta el binario, instálalo"
    # bullet: measured 33,821; ceiling 33_900. The install rule is gated on the
    # catalog offering ``nexus.system.install_tool``, so a restricted profile
    # pays nothing for it.
    assert len(_prompt(catalog)) < 33_900


def test_prompt_with_a_plan_stays_under_its_ceiling(catalog):
    """The TODO block is data the run pays for every turn: it has a ceiling.

    A 7-TODO plan (the seed of an engagement) costs 627 characters on top of the
    static prompt: measured 27,140. The block is capped at 40 TODOs by
    ``prompt_block``, so a pathological plan cannot grow without bound.
    """
    from nexus_core.agent.engagement_plan import new_plan, prompt_block, seed_todos

    plan = new_plan("objective", "eng-1", seed_todos("objective"))
    block = prompt_block(plan)
    assert block
    prompt = _prompt(catalog, engagement_plan_summary=block)
    # V9: measured 28,458 (the 743-character 7-TODO block on the 27,831 static
    # prompt), so the ceiling moves with the static one, to 28,700.
    # V10 measured 29,297 (the same block on the 28,665 static prompt), so the
    # ceiling moves with it, to 29_350.
    # V11 measured 29,758 (the same 743-character block on the 29,131 static
    # prompt), so the ceiling moves with it, to 30_000.
    # V14 measured 30,257 (the same block on the 29,630 static prompt), so the
    # ceiling moves to 30_400.
    # The ad_acl catalog line measured 30,609 on the same block: ceiling 30_750.
    # Tanda A adds the same 458 characters on top of the ad_acl measurement:
    # 30,609 + 576 measured 31,185; ceiling 31_300.
    # Tanda B moves with the static prompt (+532): measured 31,728; ceiling 31_780.
    # Tanda D moves with the static prompt (+900): measured 32,628; ceiling
    # 32_700. The block itself is unchanged.
    # Tanda E moves with the static prompt (+30 over Tanda D): measured 32,717;
    # ceiling 32_800. The block itself is unchanged.
    # Tanda F moves with the static prompt (+285): measured 33,002; ceiling
    # 33_100. The block itself is unchanged.
    # Tanda G moves with the static prompt (+596): measured 33,711; ceiling
    # 33_800. The block itself is unchanged.
    # B1 moves with the static prompt (+109): measured 33,820; ceiling 33_880.
    # The block itself is unchanged.
    # The parallel contract moves with the static prompt: measured 34,247;
    # ceiling 34,320. The block itself is unchanged.
    # The scope + install orders move with the static prompt: measured 34,448;
    # ceiling 34_530. The block itself is unchanged.
    assert len(prompt) < 34_530
    assert len(block) < 1_200


def test_catalog_lists_every_tool_exactly_once(catalog):
    text = render_tool_catalog(catalog)
    lines = [line for line in text.splitlines() if line.startswith("- ")]
    assert len(lines) == len(catalog)
    for tool_id in catalog:
        assert text.count(f"- {tool_id}:") == 1


def test_prompt_states_the_black_box_default_and_the_roe_precedence(catalog):
    """V9 (Hijack): the default authorization is the whole kill chain.

    The prompt must say (a) that every phase is authorized by default, (b) that
    only the objective/RoE can restrict a technique, and (c) that the signed
    scope still bounds the targets -so "no limits" is never read as
    "out of scope".
    """
    from nexus_core.agent.prompts import BLACK_BOX_PHILOSOPHY_PROMPT

    prompt = _prompt(catalog)
    assert BLACK_BOX_PHILOSOPHY_PROMPT in prompt
    for phase in ("reconocimiento", "explotación", "persistencia", "C2", "exfiltración"):
        assert phase in BLACK_BOX_PHILOSOPHY_PROMPT
    assert "Solo el objetivo o el RoE" in BLACK_BOX_PHILOSOPHY_PROMPT
    assert "vía libre dentro del scope" in BLACK_BOX_PHILOSOPHY_PROMPT
    assert "limita los TARGETS, nunca las técnicas" in prompt


def test_web_upload_publishes_the_webshell_use_case_in_its_catalog_line(catalog):
    """V9: the admin-panel upload path must be visible *before* truncation.

    The model read ``nexus.web.upload`` as a generic HTTP helper and never
    tried a webshell in the panel it had just opened. The catalog line is cut
    at 64 characters, so the word has to be in the first 64.
    """
    from nexus_core.agent.prompts import CATALOG_DESCRIPTION_CHARS

    line = next(
        line for line in render_tool_catalog(catalog).splitlines()
        if line.startswith("- nexus.web.upload:")
    )
    head = line.split(":", 1)[1].split("|", 1)[0]
    assert "webshell" in head.lower()
    assert len(head.strip()) <= CATALOG_DESCRIPTION_CHARS + 1


def test_prompt_forbids_passive_waits_and_names_the_replacements(catalog):
    prompt = _prompt(catalog)
    assert "SIN ESPERAS PASIVAS" in prompt
    assert "nexus.post.listener" in prompt and "nexus.post.job" in prompt


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
    # Whole-line granularity: a tool adds one short compact line and one much
    # longer full line, so the ratio can sit a few characters above a third
    # without the compact block carrying prose. B1's 83rd tool put it at 6 181
    # against 18 519/3 = 6 173: an 8-character overshoot. The tolerance is
    # stated rather than deleting the invariant; the absolute ceiling below and
    # the per-tool one above still bound the block.
    assert len(compact) < len(full) / 3 + 40


def test_compact_catalog_keeps_every_tool_id_and_its_required_arguments(catalog):
    from nexus_core.agent.prompts import render_tool_catalog

    text = render_tool_catalog(catalog, compact=True)
    assert len(text.splitlines()) == len(catalog)
    # The id is the first token of the line: a tool that declares no argument at
    # all has no `` | `` tail, so the id cannot be keyed on a trailing space.
    listed = [line[2:].split(" ", 1)[0] for line in text.splitlines()]
    assert sorted(listed) == sorted(catalog)
    nmap = next(line for line in text.splitlines() if line.startswith("- nexus.recon.nmap "))
    # Required names, and the legal values of a required enum, survive the trim.
    assert "target:string*" in nmap
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
    # V9: the two policy orders land on the compact turn too: measured 6,150
    # (5,600 + the philosophy, the wait ban and the nfs catalog line), so the
    # target moves to 6,250.
    # V10's CSRF clause and CMS order land here too: measured 6,309, so the
    # target moves to 6,350 (250k still buys ~39 turns).
    # V11's PoC handoff and the ``compile_and_upload`` catalog line land here:
    # measured 6,380, so the target moves to 6_450.
    # V14's BlogEngine endpoint lands here too: measured 6,505, so the target
    # moves to 6_550 (250k still buys ~38 turns).
    # The ad_acl catalog line adds 19 characters: measured 6,569, ceiling 6_600.
    # Tanda A adds one compact catalog line and the PIVOTE order: measured 6,671,
    # ceiling 6_700 (the 6,600 target still holds for every other factor).
    # Tanda B's deny-list block lands on every turn: +136 tokens, measured 6,807;
    # ceiling 6_850 (250k still buys ~36 compact turns).
    # Tanda D's two orders land here too: measured 7,032, so the target moves to
    # 7_080 (250k still buys ~35 compact turns).
    # Tanda E's catalog contract lands here (+~200 tokens on the compact turn) and
    # buys back the four rejected ``web.upload`` turns and the three ``cwd`` ones
    # at ~11 000 tokens each: measured 7,208; ceiling 7_250 (250k buys ~34 turns).
    # Tanda F's AD tunnel order lands here too (+72 tokens): measured 7,280;
    # ceiling 7_330 (250k buys ~34 turns).
    # Tanda G's SSRF order lands here too (+121 tokens): measured 7,401;
    # ceiling 7_450 (250k buys ~33 turns).
    # The parallel contract lands here too (+130 tokens): measured 7,531;
    # ceiling 7_590 (250k buys ~33 turns).
    assert tokens < 7_590


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
    # PLAN MODE is the expensive rule of the set and it is paid every turn: the
    # PLAN-FIRST order (~112 tokens) plus the engagement's TODO checklist (~157
    # tokens for a 7-TODO plan). Measured 6,524 average, so the target moves to
    # 6_600: 250k now buys ~38 turns instead of 40, and what it buys is the
    # contract that stops a run from closing on the first flag (run v8).
    # V9 (Hijack) is the expensive rule of the set because it is policy, not a
    # capability: the black-box philosophy and the passive-wait ban are paid on
    # every turn. Measured 6,819 average, so the target moves to 6_900: 250k now
    # buys ~36 turns instead of 38, and what it buys is a run that keeps going
    # after the first technical wall instead of stopping at it (run V9).
    # V10's two orders are paid on every turn as well: measured 6,989 average,
    # so the target moves to 7_050; what it buys is the CSRF sweep and the PoC
    # retrieval that run V10 never had.
    # V11 adds the file-type routing of a PoC and one catalog line: measured
    # 7,069 average (250k buys ~35 turns), so the target moves to 7_150.
    # V14 adds the BlogEngine theme endpoint to the CMS order: measured 7,195
    # average, so the target moves to 7_250 (250k buys ~34 turns).
    # The ad_acl line measured 7,272 on average (the mean is what grows with a
    # tool whose argument list is long): ceiling 7_350.
    # Tanda A: measured 7,384 over the 22 iterations; ceiling 7_420.
    # Tanda B: the deny-list block is paid every turn: measured 7,520 average;
    # ceiling 7_560 (250k buys ~33 turns).
    # Tanda D measured 7,745 average (the two new orders on every turn), so the
    # ceiling moves to 7_800; 250k still buys ~32 turns.
    # Tanda E measured 7,886 average (its own catalog contract +200/turn on the
    # compact turns, +209 on the full ones); ceiling 7_930, ~31 turns.
    # Tanda F measured 7,958 average (the AD tunnel order on every turn where the
    # catalog offers ``netexec``): ceiling 8_010, ~31 turns.
    # Tanda G measured 8,085 average (the SSRF order and the new catalog line on
    # every turn): ceiling 8_130, ~30 turns.
    # The parallel contract is paid every turn (+137 tokens of average):
    # measured 8,222; ceiling 8_270, ~30 turns.
    # The scope + install orders cost the same on every turn: measured 8,272
    # average; ceiling 8_330, ~30 turns.
    assert sum(totals) / len(totals) < 8_330
    # The refresh turn is the expensive one; it must still fit a 250k budget
    # long enough for the ~40 turns Simple CTF needs: 8 refreshes at 8 113 plus
    # 32 compact turns at 5 361 are 233 456 tokens, inside the budget. The old
    # 8 000 ceiling had 1 token of slack at HEAD (7 999), so the +302 characters
    # of the two rules and the 161-character index line of the new skill land
    # here: measured 8 113, and the ceiling moves to 8 150. The multi-vector rule
    # adds its ~116 tokens to the same refresh turn: measured 8,236, so the
    # ceiling moves to 8_250. The login rule lands there too: measured 8,359,
    # so the refresh ceiling moves to 8_400 (32 compact turns at 5,600 plus 8
    # refreshes at 8,359 are 246,072, inside the 250k budget). The 73rd tool's
    # catalog line lands here too: measured 8,422, so the ceiling moves to 8_450.
    # The three PLAN MODE catalog lines plus the rule and the checklist land on
    # this turn as well: measured 8,765, so the ceiling moves to 8_800.
    # V9 lands on the refresh turn as well: measured 9,094, so the ceiling moves
    # to 9_200 (the budget note above is the price of the policy, stated there).
    # V10 measured 9,302 on the refresh turn (the full catalog plus both new
    # orders), so the ceiling moves to 9_350.
    # V11 measured 9,417 (79 lines + the PoC handoff), so the ceiling moves to
    # 9_450.
    # V14 measured 9,542 on the refresh turn (29,630 static prompt + the full
    # catalog), so the ceiling moves to 9_600.
    # The ad_acl catalog line measured 9,665 on the refresh turn (the static
    # prompt plus all 80 lines), so the ceiling moves to 9_750.
    # Tanda A: the full-catalog turn measured 9,809; ceiling 9_850.
    # Tanda B: the same block on the refresh turn measured 9,944; ceiling 9_990.
    # Tanda D on the refresh turn: measured 10,169; ceiling 10_220.
    # Tanda E on the refresh turn: measured 10,192; ceiling 10_250.
    # Tanda F on the refresh turn: measured 10,263; ceiling 10_330.
    # Tanda G on the refresh turn: measured 10,413; ceiling 10_470.
    # The parallel contract on the refresh turn: measured 10,574; ceiling 10_620
    # (8 refreshes at 10,574 plus 32 compact turns at 7,531 are 325 584 tokens,
    # which is why the run budget is planned by ``budget_tokens_for_iterations``
    # and not by a fixed 250k).
    # The scope + install orders land here too: measured 10,624; ceiling 10_700.
    assert max(totals) < 10_700


def test_the_prompt_names_the_path_field_for_compile_and_upload(catalog):
    """Run V13 (HackPark, 2026-10-21, iteration 52): "46353" is not a path.

    ``find_and_prepare`` answers ``{path, code}``; the model passed the EDB-ID to
    ``compile_and_upload`` and then spent eight turns looking for a file that was
    already in ``loot/exploits/``. The order has to name the field.
    """
    prompt = _prompt(catalog)
    flat = " ".join(prompt.split())
    assert "`{path, code}`" in flat
    assert "pasa ESE `path` como `exploit_path`" in flat
    assert "nunca el ID ni el CVE" in flat


def test_the_prompt_names_the_blogengine_theme_endpoint(catalog):
    """Run V14 (HackPark, 2026-10-21): the theme went to the wrong endpoint.

    The PoC reached the panel but the POST carried no ``session_ref`` cookie and
    the prompt never named the theme manager, so the model guessed an endpoint.
    The order has to name both facts, and the outcome the tool reports.
    """
    prompt = _prompt(catalog)
    flat = " ".join(prompt.split())
    assert "/admin/app_themes.aspx" in flat
    assert "ctl00$MainContent$UploadTheme$fuTheme" in flat
    assert "editpost.cshtml" in flat
    assert "session_ref del panel" in flat
    assert "exploit_upload_rejected" in flat


# ------------------------------- Tanda E: the contract travels in the catalog line
def test_the_compact_catalog_carries_the_nested_upload_contract(catalog):
    """DeadDrop P12 v2, iterations 6-20: four turns lost to one hidden object.

    The line published ``upload:object*`` and nothing else, so the model sent
    ``content`` at the top level, ``field`` next to ``upload``, and later
    ``session_ref`` inside it. A key the model has never seen is a key it does not
    guess: the required inner names have to be on the line, ahead of the cap.
    """
    from nexus_core.agent.prompts import render_tool_catalog

    line = next(
        line
        for line in render_tool_catalog(catalog, compact=True).splitlines()
        if line.startswith("- nexus.web.upload ")
    )
    assert "upload{" in line
    assert "field:string" in line and "path:string" in line
    assert "upload:object" not in line
    # The whole argument is required, so it keeps the mark the trim documents.
    assert "}*" in line


def test_optional_arguments_are_marked_in_the_compact_catalog(catalog):
    """``req[-]`` read as "this tool takes no arguments" for eighteen tools.

    ``nexus.post.privesc_hints`` was called with none and answered "provide at
    least one of sudo_rules, suid or capabilities" -one turn and its retry-.
    """
    from nexus_core.agent.prompts import render_tool_catalog

    text = render_tool_catalog(catalog, compact=True)
    hints = next(
        line for line in text.splitlines() if line.startswith("- nexus.post.privesc_hints ")
    )
    assert "sudo_rules:array?" in hints
    assert "suid:array?" in hints and "capabilities:array?" in hints
    # The old placeholder is gone: no tool reads as "no arguments" any more.
    assert "req[" not in text
    # A tool that really declares nothing still says so, without inventing a list.
    status = next(line for line in text.splitlines() if line.startswith("- nexus.system.status"))
    assert " | " not in status


def test_a_contract_note_names_the_constraints_a_schema_cannot_state(catalog):
    """Each clause here was paid for with a rejected turn in DeadDrop P12 v2.

    An absolute ``cwd`` (3 turns), ``session_ref`` nested inside ``upload``,
    ``post.job`` started with a bare ``command``, ``privesc_hints`` with no
    argument, and an ``artifact_`` handle addressed as a workspace path.
    """
    from nexus_core.agent.prompts import render_tool_catalog

    lines = {
        line.split(" ", 2)[1]: line
        for line in render_tool_catalog(catalog, compact=True).splitlines()
        if line.startswith("- ")
    }
    assert "cwd relativo al workspace" in lines["nexus.shell.exec"]
    assert "session_ref en la raíz" in lines["nexus.web.upload"]
    assert "tool_id + arguments" in lines["nexus.post.job"]
    assert "al menos uno" in lines["nexus.post.privesc_hints"]
    assert "artifact_<id>" in lines["nexus.workspace.read"]
    # The full catalog carries them too: the first turn is when the call is planned.
    full = render_tool_catalog(catalog)
    assert "cwd relativo al workspace" in full
    assert "artifact_<id>" in full


def test_the_compact_catalog_carries_a_hard_ceiling(catalog):
    """The contract is data, so it may not grow with the prose.

    Carrying the nested/optional contract costs ~800 characters on the compact
    block (5 251 -> 6 046) and buys back four rejected ``web.upload`` turns and
    three ``cwd`` ones. A ceiling keeps the next addition from being free.
    """
    from nexus_core.agent.prompts import render_tool_catalog

    compact = render_tool_catalog(catalog, compact=True)
    full = render_tool_catalog(catalog)
    assert len(compact) < 6_300
    # Same whole-line tolerance as ``test_compact_catalog_is_a_third_of_the_full_one``.
    assert len(compact) < len(full) / 3 + 40


#: Ceiling per prompt block, measured, so the next fix cannot eat the headroom in
#: silence. The total ceiling in ``test_prompt_stays_within_the_reviewed_budget``
#: says how big the prompt may be; these say *where* the next 100 characters can
#: come from -and which block would have to give them up-.
PROMPT_BLOCK_CEILINGS = {
    "BLACK_BOX_PHILOSOPHY_PROMPT": 570,
    "PASSIVE_WAIT_RULE_PROMPT": 230,
    "LOGIN_RULE_PROMPT": 740,
    "CMS_EXPLOIT_RULE_PROMPT": 900,
    "SSRF_HTTP_SERVER_RULE_PROMPT": 480,
    "ENGAGEMENT_PLAN_RULE_PROMPT": 730,
    "PIVOT_ROUTE_RULE_PROMPT": 400,
    "PREVIEW_MODULE_RULE_PROMPT": 490,
    "CREDENTIAL_FAMILIES_RULE_PROMPT": 460,
    "COMPACT_CATALOG_NOTE": 180,
}


def test_the_ssrf_order_points_at_the_http_server_and_forbids_localhost(catalog):
    """Tanda G: the target fetches the payload back, so ``127.0.0.1`` is wrong.

    Measured in the run de HackSmarter (2026-10-23): thirteen turns of hand-made
    ``curl`` with ``targetmachine=127.0.0.1`` while no server of ours existed.
    """
    from nexus_core.agent.prompts import SSRF_HTTP_SERVER_RULE_PROMPT

    flat = " ".join(_prompt(catalog).split())
    assert "nexus.post.http_server" in flat
    assert "NO uses 127.0.0.1" in flat
    assert "attacker_ip" in flat
    # Same contract as every other order: a catalog without the tool never names
    # it, so the per-subagent gating cannot be contradicted by the prompt.
    without = {
        tool_id: entry
        for tool_id, entry in catalog.items()
        if tool_id != "nexus.post.http_server"
    }
    gated = render_system_prompt(
        catalog=without, objective="x", engagement_id="eng-1", scope_summary="s"
    )
    assert SSRF_HTTP_SERVER_RULE_PROMPT not in gated
    assert "nexus.post.http_server" not in gated


def test_the_pivot_order_points_at_verify_route_and_forbids_record_fact(catalog):
    """DeadDrop P12 v2, iteration 73: the model registered the route itself.

    ``record_fact(fact_type="route")`` writes a *hypothesis* (asserted_by=agent),
    so it closes no TODO and the pivot gate stays armed
    (``test_a_recorded_route_does_not_unarm_the_gate``). The order has to say so:
    the previous text named ``verify_route`` but never forbade the shortcut, and
    the run took the shortcut.
    """
    from nexus_core.agent.prompts import PIVOT_ROUTE_RULE_PROMPT, render_system_prompt

    flat = " ".join(_prompt(catalog).split())
    assert "nexus.post.verify_route" in flat
    assert 'record_fact(fact_type="route")' in flat
    assert "no cierra el TODO ni desarma el gate" in flat
    # Same contract as every other order: a catalog without the tool never names
    # it, so the per-subagent gating cannot be contradicted by the prompt.
    without = {
        tool_id: entry
        for tool_id, entry in catalog.items()
        if tool_id != "nexus.post.verify_route"
    }
    gated = render_system_prompt(
        catalog=without, objective="x", engagement_id="eng-1", scope_summary="s"
    )
    assert PIVOT_ROUTE_RULE_PROMPT not in gated
    assert "record_fact(fact_type=\"route\")" not in gated


def test_each_prompt_block_stays_under_its_own_ceiling():
    """A block that grows silently consumes the room the next order needs.

    Tanda E had 59 characters of headroom on the total and needed +33 for the
    PIVOTE order, so it compressed the CMS order by 268 characters first. Without
    this test that trade is invisible: the total would have absorbed the growth
    and the next fix would have found nothing left.
    """
    from nexus_core.agent import prompts

    over = {
        name: (len(getattr(prompts, name)), ceiling)
        for name, ceiling in PROMPT_BLOCK_CEILINGS.items()
        if len(getattr(prompts, name)) > ceiling
    }
    assert over == {}
