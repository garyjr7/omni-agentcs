"""Subagent registry: subsets, budgets, deterministic selection and fan-out."""

from __future__ import annotations

import asyncio

import pytest

from nexus_core.agent import subagents
from nexus_core.tools.registry import durable_tool_definitions


# ------------------------------------------------------------- registry shape


def test_registry_is_healthy_against_the_durable_catalog():
    catalog = durable_tool_definitions("system")
    assert subagents.validate_registry(catalog) == []
    # 56 tools after adding the two Windows tools (ntlm_capture, winrm_exec).
    # + nexus.recon.dns, nexus.post.dns_update,
    # nexus.attack.impacket_changepasswd and nexus.attack.nopac (RUN_sala10/Ra 2).
    # + nexus.post.tftp (the synthetic run/the synthetic lab: only UDP/69 was reachable).
    # + nexus.post.dpapi (the synthetic run/the synthetic lab: the KeePass flag behind user DPAPI).
    # + nexus.post.ssh_upload, nexus.recon.nikto (RUN_sala12/Intrusion Detection).
    assert len(catalog) == 68


def test_read_only_profiles_list_no_active_tool():
    for profile in subagents.SUBAGENTS:
        if profile.read_only:
            assert not (profile.tools & subagents.ACTIVE_TOOLS), profile.id
            assert profile.parallel_safe


def test_every_profile_has_a_positive_budget_and_iterations():
    for profile in subagents.SUBAGENTS:
        assert profile.token_budget > 0, profile.id
        assert profile.max_iterations > 0, profile.id


def test_expected_profiles_exist():
    assert subagents.SUBAGENT_IDS == (
        "recon",
        "web",
        "services",
        "cred",
        "exploit",
        "postexploit",
        "privesc",
        "lateral",
        "reporter",
    )


def test_duplicate_ids_are_reported(monkeypatch):
    duplicate = subagents.SUBAGENTS + (subagents.SUBAGENTS[0],)
    monkeypatch.setattr(subagents, "SUBAGENTS", duplicate)
    assert any("duplicate subagent id" in problem for problem in subagents.validate_registry())


def test_unknown_tools_are_reported(monkeypatch):
    bogus = subagents.SubAgentDefinition(
        id="bogus",
        label="bogus",
        phase="recon",
        focus="n/a",
        tools=frozenset({"nexus.does.not_exist"}),
        token_budget=1,
        max_iterations=1,
        read_only=True,
    )
    monkeypatch.setattr(subagents, "SUBAGENTS", subagents.SUBAGENTS + (bogus,))
    problems = subagents.validate_registry({"nexus.recon.nmap": object()})
    assert any("unknown tools" in problem for problem in problems)


def test_read_only_profile_with_active_tool_is_reported(monkeypatch):
    leaky = subagents.SubAgentDefinition(
        id="leaky",
        label="leaky",
        phase="recon",
        focus="n/a",
        tools=frozenset({"nexus.cred.bruteforce"}),
        token_budget=1,
        max_iterations=1,
        read_only=True,
    )
    monkeypatch.setattr(subagents, "SUBAGENTS", subagents.SUBAGENTS + (leaky,))
    problems = subagents.validate_registry()
    assert any("lists active tools" in problem for problem in problems)


# ----------------------------------------------------------- deterministic pick


@pytest.mark.parametrize(
    ("phase", "expected"),
    [
        ("recon", "recon"),
        ("enumeration", "services"),
        ("exploitation", "exploit"),
        ("privilege_escalation", "privesc"),
        ("post_exploitation", "postexploit"),
        ("lateral_movement", "lateral"),
        ("reporting", "reporter"),
    ],
)
def test_selection_follows_the_kill_chain(phase, expected):
    assert subagents.select_subagent(phase).id == expected


def test_selection_refines_to_credential_profile_when_a_user_is_known():
    assert subagents.select_subagent("enumeration", counts={"user": 1}).id == "cred"
    assert subagents.select_subagent("enumeration", counts={"credential": 2}).id == "cred"
    assert subagents.select_subagent("enumeration", counts={"endpoint": 3}).id == "web"


def test_enumeration_with_only_a_service_fact_can_still_enumerate_it():
    """P0 regression (E2E #3): a lone ``service`` fact must not select a subset
    that cannot touch that service. It used to pick ``web`` (no FTP/SMB)."""
    profile = subagents.select_subagent("enumeration", counts={"service": 1})
    assert profile.id == "services"
    assert "nexus.recon.ftp" in profile.tools
    assert "nexus.recon.netexec" in profile.tools
    # The web surface stays reachable from the same profile (no new dead end).
    assert subagents.WEB_ENUM_TOOLS <= profile.tools
    # The refinement still tightens once web-specific evidence exists.
    assert "nexus.recon.ftp" not in subagents.SUBAGENTS_BY_ID["web"].tools


def test_agent_leads_refine_the_profile_without_advancing_the_phase():
    """P0 regression (Bounty Hacker E2E): an agent-recorded ``user`` must reach
    the credential profile.

    The loop used to stay in ``services`` - which has no tool that can test the
    credentials it just found - because only *verified* facts were visible to the
    profile selector, so the chain dead-ended in enumeration until the subagent
    budget blew up. The lead must steer the profile without ever counting as
    evidence (the phase stays where the verified facts put it).
    """
    from nexus_core.agent.planner import build_plan

    facts = [
        dict(fact_type='service', verified=True, asserted_by='verifier',
             verification_method='nmap_xml_parsed', invocation_id='i1'),
        dict(fact_type='user', verified=False, asserted_by='agent'),
    ]
    plan = build_plan(facts=facts)
    assert plan.current == 'enumeration'  # the lead is not evidence
    assert plan.counts == {'service': 1}
    assert plan.leads == {'user': 1}
    selected = subagents.select_for_plan(plan)
    assert selected.id == 'cred'
    assert 'nexus.cred.bruteforce' in selected.tools


def test_phase_grace_inherits_only_read_only_tools_for_two_iterations():
    recon = subagents.SUBAGENTS_BY_ID["recon"]
    cred = subagents.SUBAGENTS_BY_ID["cred"]  # active profile
    graced = subagents.with_phase_grace(cred, recon, iterations=1)
    assert "nexus.recon.ftp" in graced.tools
    assert "nexus.recon.nmap" in graced.tools
    assert not (graced.tools - cred.tools) & subagents.ACTIVE_TOOLS
    assert graced.max_iterations == cred.max_iterations
    # Past the grace window, or within the same profile, nothing changes.
    assert subagents.with_phase_grace(cred, recon, iterations=3) is cred
    assert subagents.with_phase_grace(recon, recon, iterations=1) is recon
    assert subagents.with_phase_grace(recon, None) is recon


def test_phase_grace_never_inherits_active_tools():
    recon = subagents.SUBAGENTS_BY_ID["recon"]
    lateral = subagents.SUBAGENTS_BY_ID["lateral"]
    graced = subagents.with_phase_grace(recon, lateral, iterations=1)
    assert not (graced.tools - recon.tools) & subagents.ACTIVE_TOOLS
    assert "nexus.attack.impacket_psexec" not in graced.tools


def test_unknown_phase_fails_closed_to_the_most_restrictive_profile():
    assert subagents.select_subagent("wormhole").id == subagents.DEFAULT_SUBAGENT_ID
    assert subagents.select_subagent(None).id == subagents.DEFAULT_SUBAGENT_ID


def test_operator_override_wins_and_is_validated():
    assert subagents.select_subagent("recon", override="lateral").id == "lateral"
    with pytest.raises(ValueError):
        subagents.select_subagent("recon", override="omnipotent")


def test_select_for_plan_uses_the_plan_phase_and_counts():
    class _Plan:
        current = "enumeration"
        counts = {"user": 1}

    assert subagents.select_for_plan(_Plan()).id == "cred"


# --------------------------------------------------------------- subset gating


def test_filter_catalog_keeps_only_the_subset():
    catalog = {
        "nexus.recon.nmap": "a",
        "nexus.web.nuclei": "b",
        "nexus.post.ssh_exec": "c",
        "nexus.knowledge.record_fact": "d",
    }
    recon = subagents.SUBAGENTS_BY_ID["recon"]
    filtered = subagents.filter_catalog(recon, catalog)
    assert set(filtered) == {"nexus.recon.nmap", "nexus.knowledge.record_fact"}


def test_filter_catalog_keeps_the_subset_a_strict_subset_of_the_catalog():
    catalog = durable_tool_definitions("system")
    for profile in subagents.SUBAGENTS:
        filtered = subagents.filter_catalog(profile, catalog)
        assert set(filtered) <= set(catalog), profile.id
        assert filtered, profile.id


# ----------------------------------------------------------- read-only fan-out


async def test_gather_readonly_rejects_active_profiles():
    active = subagents.SUBAGENTS_BY_ID["lateral"]
    with pytest.raises(ValueError):
        await subagents.gather_readonly([], subagent=active)


async def test_gather_readonly_returns_all_results():
    recon = subagents.SUBAGENTS_BY_ID["recon"]

    async def make(value):
        async def _call():
            return value

        return _call

    calls = [await make(index) for index in range(3)]
    assert await subagents.gather_readonly(calls, subagent=recon) == [0, 1, 2]


async def test_gather_readonly_bounds_concurrency():
    recon = subagents.SUBAGENTS_BY_ID["recon"]
    active = 0
    peak = 0
    release = asyncio.Event()

    async def probe():
        nonlocal active, peak
        active += 1
        peak = max(peak, active)
        await release.wait()
        active -= 1
        return "ok"

    calls = [probe for _ in range(8)]
    task = asyncio.ensure_future(subagents.gather_readonly(calls, subagent=recon, limit=2))
    await asyncio.sleep(0.05)
    assert peak == 2  # never exceeded the bound
    release.set()
    assert await task == ["ok"] * 8
    assert peak == 2


async def test_gather_readonly_caps_limit_at_the_hard_ceiling():
    recon = subagents.SUBAGENTS_BY_ID["recon"]
    active = 0
    peak = 0
    release = asyncio.Event()

    async def probe():
        nonlocal active, peak
        active += 1
        peak = max(peak, active)
        await release.wait()
        active -= 1

    calls = [probe for _ in range(10)]
    task = asyncio.ensure_future(
        subagents.gather_readonly(calls, subagent=recon, limit=999)
    )
    await asyncio.sleep(0.05)
    assert peak == subagents.DEFAULT_MAX_PARALLEL
    release.set()
    await task


async def test_gather_readonly_cancels_every_call():
    recon = subagents.SUBAGENTS_BY_ID["recon"]
    cancel_event = asyncio.Event()
    started = asyncio.Event()

    async def probe():
        started.set()
        await asyncio.sleep(30)
        return "never"

    task = asyncio.ensure_future(
        subagents.gather_readonly([probe, probe], subagent=recon, cancel_event=cancel_event)
    )
    await started.wait()
    cancel_event.set()
    results = await asyncio.wait_for(task, timeout=2)
    assert all(isinstance(result, asyncio.CancelledError) for result in results)


async def test_gather_readonly_records_exceptions_in_place():
    recon = subagents.SUBAGENTS_BY_ID["recon"]

    async def boom():
        raise RuntimeError("probe failed")

    async def ok():
        return "fine"

    results = await subagents.gather_readonly([boom, ok], subagent=recon)
    assert isinstance(results[0], RuntimeError)
    assert results[1] == "fine"


async def test_gather_readonly_with_no_calls_returns_empty():
    recon = subagents.SUBAGENTS_BY_ID["recon"]
    assert await subagents.gather_readonly([], subagent=recon) == []
