"""Attack chain: the asset graph as the client-facing path in the report."""

from __future__ import annotations

import asyncio
from dataclasses import replace

from nexus_core.report.attack_chain import build_attack_chains
from nexus_core.report.extractor import build_report
from nexus_core.report.markdown import render_markdown
from nexus_core.report.models import AttackChainStep
from nexus_core.tests import report_support as support

ENGAGEMENT = "eng-lab"
HOST = "10.0.0.5"
SERVICE = f"{HOST}:22:tcp"
CRED = f"cred:ssh:lin@{HOST}"


def _fact(fact_type: str, key: str, value: dict) -> dict:
    return {
        "engagement_id": ENGAGEMENT,
        "fact_type": fact_type,
        "key": key,
        "value": value,
    }


def _uri(fact_type: str, key: str) -> str:
    return f"blackboard/{ENGAGEMENT}/{fact_type}/{key}"


def _edge(src: str, dst: str, relation: str) -> dict:
    return {"src_uri": src, "dst_uri": dst, "relation": relation}


def test_the_chain_runs_from_host_to_privilege() -> None:
    facts = [
        _fact("host", HOST, {"state": "up"}),
        _fact("service", SERVICE, {"port": 22, "service": "ssh"}),
        _fact("credential", CRED, {"username": "lin", "service": "ssh"}),
        _fact("privilege", HOST, {"uid": 0, "user": "root"}),
    ]
    edges = [
        _edge(_uri("host", HOST), _uri("service", SERVICE), "host_has_service"),
        _edge(_uri("service", SERVICE), _uri("credential", CRED),
              "service_yields_credential"),
        _edge(_uri("credential", CRED), _uri("privilege", HOST),
              "credential_grants_privilege"),
    ]

    (chain,) = build_attack_chains(facts, edges, engagement_id=ENGAGEMENT)

    assert [step.fact_type for step in chain.steps] == [
        "host", "service", "credential", "privilege"
    ]
    assert [step.label for step in chain.steps] == [
        HOST, "22/tcp ssh", "lin (ssh)", "root"
    ]


def test_a_host_without_edges_is_not_a_chain() -> None:
    facts = [_fact("host", HOST, {"state": "up"})]
    assert build_attack_chains(facts, [], engagement_id=ENGAGEMENT) == ()


def test_markdown_renders_the_attack_chain_section(tmp_path) -> None:
    store, _engagement, _run_id = support.seed_full_engagement(tmp_path)
    report = asyncio.run(build_report(store, support.TENANT, ENGAGEMENT))
    steps = (
        AttackChainStep("host", HOST, HOST),
        AttackChainStep("service", SERVICE, "22/tcp ssh"),
        AttackChainStep("credential", CRED, "lin (ssh)"),
        AttackChainStep("privilege", HOST, "root"),
    )
    chain = build_attack_chains(
        [
            _fact("host", HOST, {}),
            _fact("service", SERVICE, {"service": "ssh"}),
            _fact("credential", CRED, {"username": "lin", "service": "ssh"}),
            _fact("privilege", HOST, {"uid": 0}),
        ],
        [
            _edge(_uri("host", HOST), _uri("service", SERVICE), "host_has_service"),
            _edge(_uri("service", SERVICE), _uri("credential", CRED),
                  "service_yields_credential"),
            _edge(_uri("credential", CRED), _uri("privilege", HOST),
                  "credential_grants_privilege"),
        ],
        engagement_id=ENGAGEMENT,
    )[0]
    assert chain.steps == steps

    text = render_markdown(replace(report, attack_chain=(chain,)))

    assert "## Cadena de ataque" in text
    assert f"**{HOST}** → `22/tcp ssh` → `lin (ssh)` → **root**" in text
