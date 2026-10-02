"""Unit tests for the durable engagement blackboard (no network)."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest

from nexus_core.kernel.blackboard import Blackboard
from nexus_core.kernel.control_store import ControlStore
from nexus_core.kernel.models import Identity, RunContext
from nexus_core.tools.handlers.knowledge_facts import (
    query_facts_definition,
    query_facts_handler,
    record_fact_definition,
    record_fact_handler,
)

TENANT = "system"
ENGAGEMENT = "eng-1"


@pytest.fixture()
def board(tmp_path):
    store = ControlStore(tmp_path / "control.db")
    store.initialize()
    return Blackboard(store), store


# --------------------------------------------------------------------- storage
def test_record_and_list_round_trip(board):
    blackboard, _ = board
    blackboard.record(
        tenant_id=TENANT,
        engagement_id=ENGAGEMENT,
        fact_type="service",
        key="10.0.0.5:21/tcp",
        value={"product": "vsftpd 3.0.5", "anonymous": True},
        source="nexus.recon.nmap",
        created_by="operator-1",
    )
    facts = blackboard.list_facts(TENANT, ENGAGEMENT)
    assert len(facts) == 1
    assert facts[0]["fact_type"] == "service"
    assert facts[0]["value"]["anonymous"] is True
    assert facts[0]["verified"] is True


def test_latest_version_wins(board):
    blackboard, _ = board
    for product in ("vsftpd 3.0.5", "vsftpd 3.0.5-updated"):
        blackboard.record(
            tenant_id=TENANT,
            engagement_id=ENGAGEMENT,
            fact_type="service",
            key="10.0.0.5:21/tcp",
            value={"product": product},
            source="nexus.recon.nmap",
            created_by="operator-1",
        )
    facts = blackboard.list_facts(TENANT, ENGAGEMENT)
    assert len(facts) == 1
    assert facts[0]["value"]["product"] == "vsftpd 3.0.5-updated"


def test_list_filters_by_type(board):
    blackboard, _ = board
    blackboard.record(tenant_id=TENANT, engagement_id=ENGAGEMENT, fact_type="service",
                      key="s1", value={}, source="x", created_by="op")
    blackboard.record(tenant_id=TENANT, engagement_id=ENGAGEMENT, fact_type="user",
                      key="lin", value={}, source="x", created_by="op")
    assert len(blackboard.list_facts(TENANT, ENGAGEMENT, fact_type="user")) == 1
    assert len(blackboard.list_facts(TENANT, ENGAGEMENT)) == 2


def test_unknown_fact_type_is_rejected(board):
    blackboard, _ = board
    with pytest.raises(ValueError):
        blackboard.record(tenant_id=TENANT, engagement_id=ENGAGEMENT, fact_type="bogus",
                          key="k", value={}, source="x", created_by="op")


def test_count_counts_distinct_facts(board):
    blackboard, _ = board
    blackboard.record(tenant_id=TENANT, engagement_id=ENGAGEMENT, fact_type="service",
                      key="s1", value={}, source="x", created_by="op")
    blackboard.record(tenant_id=TENANT, engagement_id=ENGAGEMENT, fact_type="user",
                      key="lin", value={}, source="x", created_by="op")
    assert blackboard.count(TENANT, ENGAGEMENT) == 2


def test_render_returns_prompt_lines(board):
    blackboard, _ = board
    blackboard.record(tenant_id=TENANT, engagement_id=ENGAGEMENT, fact_type="service",
                      key="10.0.0.5:21/tcp", value={"anonymous": True},
                      source="nexus.recon.nmap", created_by="op")
    text = blackboard.render(TENANT, ENGAGEMENT)
    assert "[service]" in text
    assert "verificado" in text
    assert "nexus.recon.nmap" in text


def test_render_empty_when_no_facts(board):
    blackboard, _ = board
    assert blackboard.render(TENANT, ENGAGEMENT) == ""


def test_summary_counts_by_type(board):
    blackboard, _ = board
    blackboard.record(tenant_id=TENANT, engagement_id=ENGAGEMENT, fact_type="service",
                      key="s1", value={}, source="x", created_by="op")
    blackboard.record(tenant_id=TENANT, engagement_id=ENGAGEMENT, fact_type="service",
                      key="s2", value={}, source="x", created_by="op")
    blackboard.record(tenant_id=TENANT, engagement_id=ENGAGEMENT, fact_type="credential",
                      key="c1", value={}, source="x", created_by="op")
    summary = blackboard.summary(TENANT, ENGAGEMENT)
    assert summary["total"] == 3
    assert summary["counts"] == {"service": 2, "credential": 1}


# --------------------------------------------------------------------- handler
def _context(store, engagement: str | None = ENGAGEMENT) -> RunContext:
    scope = SimpleNamespace(engagement_id=engagement) if engagement else None
    return RunContext(
        TENANT, Identity("operator-1", TENANT, roles=("operator",)), scope=scope, store=store
    )


def test_record_fact_handler_persists(board):
    _, store = board
    result = asyncio.run(
        record_fact_handler(
            {"fact_type": "credential", "key": "lin", "value": {"username": "lin"}},
            _context(store),
        )
    )
    assert result.verified is True
    assert result.verification_method == "blackboard_fact_recorded"


def test_query_facts_handler_returns_recorded(board):
    _, store = board
    asyncio.run(
        record_fact_handler(
            {"fact_type": "service", "key": "s1", "value": {"port": 21}},
            _context(store),
        )
    )
    result = asyncio.run(query_facts_handler({}, _context(store)))
    assert result.verified is True
    assert result.output["count"] == 1
    assert result.output["facts"][0]["value"]["port"] == 21


def test_record_fact_without_engagement_fails_closed(board):
    _, store = board
    result = asyncio.run(
        record_fact_handler({"fact_type": "service", "key": "s1"}, _context(store, None))
    )
    assert result.verified is False
    assert result.verification_method == "blackboard_no_engagement"


def test_definitions_need_no_scope():
    assert record_fact_definition().scope_required is False
    assert query_facts_definition().scope_required is False
