"""Unit tests for the durable engagement blackboard (no network)."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest

from nexus_core.kernel import blackboard as blackboard_module
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
    assert facts[0]["verified"] is False


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


# ------------------------------------------------------- ceiling before merge
def test_a_key_rerecorded_many_times_does_not_evict_other_facts(board, monkeypatch):
    """V0-2: the read window is per key, not per row.

    With a row ceiling applied first, twelve versions of one key filled the
    window and every neighbour disappeared from the board while the merge still
    looked successful. The ceiling is shrunk here to make that window reachable
    in a unit test.
    """
    blackboard, _ = board
    monkeypatch.setattr(blackboard_module, "FACT_ROWS_CEILING", 4)
    blackboard.record(tenant_id=TENANT, engagement_id=ENGAGEMENT, fact_type="service",
                      key="10.0.0.5:22/tcp", value={}, source="x", created_by="op")
    blackboard.record(tenant_id=TENANT, engagement_id=ENGAGEMENT, fact_type="user",
                      key="lin", value={}, source="x", created_by="op")
    # The neighbours above are the *oldest* rows on purpose: a row window of 4
    # now holds only versions of this key, exactly what erased them in V0-2.
    for attempt in range(12):
        blackboard.record(
            tenant_id=TENANT, engagement_id=ENGAGEMENT, fact_type="service",
            key="10.0.0.5:21/tcp", value={"attempt": attempt},
            source="nexus.recon.nmap", created_by="op",
        )

    facts = blackboard.list_facts(TENANT, ENGAGEMENT)

    assert {fact["key"] for fact in facts} == {"10.0.0.5:21/tcp", "10.0.0.5:22/tcp", "lin"}


def test_a_verified_fact_survives_many_newer_agent_versions(board, monkeypatch):
    """The key cap cannot hide the row V1-33 exists to protect."""
    blackboard, _ = board
    monkeypatch.setattr(blackboard_module, "MAX_VERSIONS_PER_KEY", 3)
    blackboard.record(
        tenant_id=TENANT, engagement_id=ENGAGEMENT, fact_type="credential",
        key="cred:ssh:lin", value={"username": "lin"}, source="ssh_exec",
        created_by="verifier", verified=True, asserted_by="verifier",
        verification_method="shellpass", invocation_id="inv-1",
    )
    for attempt in range(6):
        blackboard.record(
            tenant_id=TENANT, engagement_id=ENGAGEMENT, fact_type="credential",
            key="cred:ssh:lin", value={"username": f"lin{attempt}"},
            source="agent", created_by="agent",
        )

    facts = blackboard.list_facts(TENANT, ENGAGEMENT)

    assert len(facts) == 1
    assert facts[0]["verified"] is True
    assert facts[0]["value"]["username"] == "lin"


def test_the_limit_counts_keys_not_versions(board):
    blackboard, _ = board
    for key in ("k1", "k2", "k3", "k4", "k5"):
        for version in range(3):
            blackboard.record(
                tenant_id=TENANT, engagement_id=ENGAGEMENT, fact_type="service",
                key=key, value={"version": version}, source="x", created_by="op",
            )

    facts = blackboard.list_facts(TENANT, ENGAGEMENT, limit=3)

    assert [fact["key"] for fact in facts] == ["k5", "k4", "k3"]
    assert facts[0]["value"]["version"] == 2


def test_the_summary_sees_the_board_past_the_default_page(board):
    """A page of 100 keys must not be read as the whole board."""
    blackboard, _ = board
    for index in range(120):
        blackboard.record(
            tenant_id=TENANT, engagement_id=ENGAGEMENT, fact_type="service",
            key=f"10.0.0.9:{index}/tcp", value={"port": index},
            source="nexus.recon.nmap", created_by="op",
        )

    summary = blackboard.summary(TENANT, ENGAGEMENT)

    assert summary["total"] == 120
    assert sum(summary["leads"].values()) == 120


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
    assert "sin verificar" in text
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
    assert summary["counts"] == {}


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


def test_record_fact_accepts_a_plain_string_and_wraps_it(board):
    """A model that writes prose loses no turn: the string becomes ``detail``."""
    from nexus_core.kernel.schema_validation import validate

    arguments = {
        "fact_type": "service",
        "key": "ssh-22",
        "value": "SSH abierto en 22",
    }
    validate(arguments, record_fact_definition().input_schema)
    _, store = board
    result = asyncio.run(record_fact_handler(arguments, _context(store)))
    assert result.verified is True
    facts = asyncio.run(query_facts_handler({}, _context(store))).output["facts"]
    assert facts[0]["value"] == {"detail": "SSH abierto en 22"}
