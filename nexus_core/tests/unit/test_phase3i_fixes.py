"""Phase 3i fixes: verified facts are immune to shadowing and ``cred`` has an exit.

Measured in rerun 9 (``run_8f23f9…`` against Bounty Hacker, commit ``8712b47``):
``hydra`` validated ``lin``'s SSH password, the verifier recorded the
``credential`` fact (V1-29 already emits the ``secret_ref`` handle), and the run
still died in ``enumeration``, worse than rerun 8. Two independent engine bugs:

* V1-33 - **fact shadowing**: ``blackboard.list_facts`` merged rows "latest wins
  per source_uri", so the agent's re-registration of the very same key one
  iteration later (``verified=false``, ``asserted_by=agent``) shadowed the
  verifier's row, the credential stopped being evidence, ``active_phase``
  reopened ``enumeration`` and the plan regressed ``[2,6] → [1,6]``.
* V1-34 - **``cred`` is a dead end**: the profile that owns credential-testing
  has no access tool (no ``ssh_exec``/``winrm_exec``/``session.*``) and 6
  iterations, while the completion gate demands the next phase; and the profile
  that owns initial access could not *consume* a credential either.

Each test below fails on the pre-fix engine.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest

from nexus_core.agent.planner import (
    CREDENTIAL_FOUND_REASON,
    STATUS_CURRENT,
    STATUS_DONE,
    build_plan,
    credential_handover,
    escalate_credential,
    plan_from_summary,
    verified_credential,
)
from nexus_core.agent.subagents import SUBAGENTS_BY_ID, select_for_plan, validate_registry
from nexus_core.kernel.blackboard import Blackboard, is_verified_fact
from nexus_core.kernel.control_store import ControlStore
from nexus_core.kernel.models import Identity, RunContext
from nexus_core.tools.handlers.knowledge_facts import (
    query_facts_handler,
    record_fact_handler,
)
from nexus_core.tools.registry import durable_tool_definitions

pytestmark = pytest.mark.unit

TENANT = "system"
ENGAGEMENT = "eng-3i"
TARGET = "10.0.0.1"
CRED_KEY = f"cred:ssh:lin@{TARGET}"
#: Handle the verifier issued in rerun 9 (never a plaintext on the board).
SECRET_REF = "vault:d0d73c96c1f34950b085015af67dee7c"
PASSWORD = "synthetic-password"


# --------------------------------------------------------------------- helpers
@pytest.fixture()
def board(tmp_path):
    store = ControlStore(tmp_path / "control.db")
    store.initialize()
    return Blackboard(store), store


def _context(store: ControlStore) -> RunContext:
    return RunContext(
        TENANT,
        Identity("operator-1", TENANT, kind="agent", roles=("operator",)),
        scope=SimpleNamespace(engagement_id=ENGAGEMENT),
        store=store,
    )


def _record_verified_credential(blackboard: Blackboard) -> dict:
    """The verifier's row from rerun 9: a validated credential with a handle."""
    return blackboard.record(
        tenant_id=TENANT,
        engagement_id=ENGAGEMENT,
        fact_type="credential",
        key=CRED_KEY,
        value={"username": "lin", "service": "ssh", "secret_ref": SECRET_REF},
        source="nexus.cred.bruteforce",
        created_by="verifier",
        verified=True,
        asserted_by="verifier",
        verification_method="cred_bruteforce_completed",
        invocation_id="inv-rerun9-1",
    )


def _record_verified_surface(blackboard: Blackboard) -> None:
    """The recon evidence rerun 9 had on the board (counts ``{host, service}``)."""
    for fact_type, key in (("host", TARGET), ("service", f"{TARGET}:22/tcp")):
        blackboard.record(
            tenant_id=TENANT,
            engagement_id=ENGAGEMENT,
            fact_type=fact_type,
            key=key,
            value={},
            source="nexus.recon.nmap",
            created_by="verifier",
            verified=True,
            asserted_by="verifier",
            verification_method="nmap_scan_completed",
            invocation_id=f"inv-{fact_type}",
        )


def _agent_reregisters(store: ControlStore, *, fact_type: str = "credential",
                       key: str = CRED_KEY, value: dict | None = None):
    """The agent's ``record_fact`` of iteration 9 of rerun 9 (unverified row)."""
    return asyncio.run(
        record_fact_handler(
            {
                "fact_type": fact_type,
                "key": key,
                "value": value if value is not None else {"username": "lin", "password": PASSWORD},
            },
            _context(store),
        )
    )


def _enumeration_plan():
    """The plan rerun 9 fell back to: recon done, enumeration open, ``[1, 6]``."""
    plan = build_plan(objective="room", engagement_id=ENGAGEMENT, counts={"host": 1, "service": 1})
    assert plan.current == "enumeration" and plan.progress == (1, 6)
    return plan


def _verified_credential_fact() -> dict:
    return {
        "fact_type": "credential",
        "key": CRED_KEY,
        "value": {"username": "lin", "service": "ssh", "secret_ref": SECRET_REF},
        "verified": True,
        "asserted_by": "verifier",
        "verification_method": "cred_bruteforce_completed",
        "invocation_id": "inv-rerun9-1",
    }


# ------------------------------------------------------------- V1-33 · shadowing
def test_verified_fact_is_not_shadowed_by_agent_fact(board):
    blackboard, _ = board
    _record_verified_credential(blackboard)
    # The agent re-registers the same key afterwards (newer row, same source_uri).
    blackboard.record(
        tenant_id=TENANT,
        engagement_id=ENGAGEMENT,
        fact_type="credential",
        key=CRED_KEY,
        value={"username": "lin", "password": PASSWORD},
        source="agent",
        created_by="agent",
    )

    facts = blackboard.list_facts(TENANT, ENGAGEMENT, fact_type="credential")

    assert len(facts) == 1
    assert is_verified_fact(facts[0]), "the verifier's fact must survive the shadow"
    assert facts[0]["asserted_by"] == "verifier"
    assert facts[0]["value"]["secret_ref"] == SECRET_REF


def test_agent_record_fact_on_verified_key_preserves_verified_value(board):
    blackboard, store = board
    _record_verified_credential(blackboard)

    result = _agent_reregisters(store)

    # ``record_fact`` is not blocked: the registration is persisted.
    assert result.output["recorded"]["verified"] is False
    facts = blackboard.list_facts(TENANT, ENGAGEMENT, fact_type="credential")
    assert len(facts) == 1
    assert facts[0]["verified"] is True
    assert facts[0]["value"]["secret_ref"] == SECRET_REF
    assert "password" not in facts[0]["value"]


def test_agent_record_fact_on_verified_key_returns_warning(board):
    blackboard, store = board
    _record_verified_credential(blackboard)

    result = _agent_reregisters(store)

    warning = result.output["warning"]
    assert CRED_KEY in warning
    assert "verificado" in warning
    assert result.output["existing_verified"]["verification_method"] == "cred_bruteforce_completed"


def test_record_fact_on_a_new_key_has_no_warning(board):
    blackboard, store = board
    _record_verified_credential(blackboard)

    result = _agent_reregisters(store, fact_type="user", key="lin",
                                value={"username": "lin"})

    assert "warning" not in result.output
    assert len(blackboard.list_facts(TENANT, ENGAGEMENT, fact_type="user")) == 1


def test_list_facts_prefers_verified_over_latest(board):
    blackboard, _ = board
    # Between two unverified facts of the same key the latest still wins.
    for product in ("vsftpd 3.0.5", "vsftpd 3.0.5-updated"):
        blackboard.record(
            tenant_id=TENANT, engagement_id=ENGAGEMENT, fact_type="service", key="s1",
            value={"product": product}, source="nexus.recon.nmap", created_by="agent",
        )
    service = blackboard.list_facts(TENANT, ENGAGEMENT, fact_type="service")
    assert len(service) == 1
    assert service[0]["value"]["product"] == "vsftpd 3.0.5-updated"

    # A verified fact recorded *before* an unverified one wins anyway.
    _record_verified_credential(blackboard)
    blackboard.record(
        tenant_id=TENANT, engagement_id=ENGAGEMENT, fact_type="credential", key=CRED_KEY,
        value={"username": "lin", "password": PASSWORD}, source="agent", created_by="agent",
    )
    credential = blackboard.list_facts(TENANT, ENGAGEMENT, fact_type="credential")
    assert len(credential) == 1
    assert is_verified_fact(credential[0])


def test_blackboard_merge_keeps_verifier_value_when_agent_reregisters(board):
    blackboard, store = board
    _record_verified_credential(blackboard)

    _agent_reregisters(store)
    summary = blackboard.summary(TENANT, ENGAGEMENT)

    # The credential counts as *evidence*, never as a lead: the pre-fix run
    # degraded it here and `_refine` then pushed the enumeration phase to `cred`.
    assert summary["counts"].get("credential") == 1
    assert "credential" not in summary["leads"]


def test_rerun9_fixture_verified_credential_survives_agent_reregistration(board):
    """Exact rerun 9 sequence: verifier credential → agent re-register → plan."""
    blackboard, store = board
    _record_verified_surface(blackboard)
    _record_verified_credential(blackboard)

    # Iteration 9: the agent re-registered the key it had just seen.
    _agent_reregisters(store)

    queried = asyncio.run(query_facts_handler({"fact_type": "credential"}, _context(store)))
    facts = queried.output["facts"]
    assert len(facts) == 1
    assert is_verified_fact(facts[0])
    assert facts[0]["value"]["secret_ref"] == SECRET_REF
    assert queried.output["summary"]["counts"].get("credential") == 1
    assert "credential" not in queried.output["summary"]["leads"]

    # The regression the run measured: the plan must not fall back to enumeration
    # (`[1, 6]`) and hand the phase to the profile that cannot use it.
    plan = plan_from_summary(queried.output["summary"], engagement_id=ENGAGEMENT)
    assert plan.current == "exploitation"
    assert plan.progress == (2, 6)
    assert select_for_plan(plan).id == "exploit"


# ------------------------------------------------- V1-34 · `cred` has an exit
def test_planner_hands_credential_found_to_exploit():
    plan = _enumeration_plan()

    handover = credential_handover(plan, subagent_id="cred", credential_found=True)

    assert handover is not None
    assert (handover.phase, handover.subagent) == ("exploitation", "exploit")
    assert handover.reason == CREDENTIAL_FOUND_REASON

    # Only the profile that owns credential-testing may trigger the hand-over.
    for subagent in ("recon", "services", "web", "exploit", "postexploit", None, ""):
        assert credential_handover(plan, subagent_id=subagent, credential_found=True) is None
    # No credential, no hand-over.
    assert credential_handover(plan, subagent_id="cred", credential_found=False) is None

    # A credential the model recorded by hand is a lead: it never turns the rule
    # on. Only a fact the verifier attested does.
    lead = {
        **_verified_credential_fact(),
        "verified": False,
        "asserted_by": "agent",
        "verification_method": "",
        "invocation_id": "",
    }
    assert verified_credential([lead]) is False
    assert verified_credential([_verified_credential_fact()]) is True
    # Another type proven by the verifier is not this case.
    assert verified_credential([{**_verified_credential_fact(), "fact_type": "user"}]) is False


def test_plan_marks_enumeration_done_on_credential_handoff():
    plan = _enumeration_plan()
    assert plan.progress == (1, 6)

    handed = escalate_credential(
        plan, credential_handover(plan, subagent_id="cred", credential_found=True)
    )

    statuses = {item.id: item.status for item in handed.phases}
    assert statuses["enumeration"] == STATUS_DONE
    assert statuses["exploitation"] == STATUS_CURRENT
    # [2, 6], never stuck on [1, 6]: the completion gate can still reach
    # `reporting` instead of waiting for a phase nobody is going to work again.
    assert handed.progress == (2, 6)
    assert handed.current == "exploitation"


def _bare_coordinator(store: ControlStore, *, subagent_id: str):
    """The coordinator stripped to the state the hand-over reads.

    ``_apply_credential_handover`` only touches the plan, the reason, the latch,
    the previous profile id and the board reader, so the wiring is exercised
    without standing up a whole run loop.
    """
    from nexus_core.agent.react_coordinator import ReActCoordinator

    coordinator = ReActCoordinator.__new__(ReActCoordinator)
    coordinator.tenant_id = TENANT
    coordinator.engagement_id = ENGAGEMENT
    coordinator.store = store
    coordinator.plan = _enumeration_plan()
    coordinator.plan_reason = None
    coordinator.last_subagent_id = subagent_id
    coordinator.credential_handed_over = False
    return coordinator


def test_coordinator_applies_the_credential_handover(board):
    """The delivered wiring: enumeration + ``cred`` + a verified credential."""
    blackboard, store = board
    _record_verified_surface(blackboard)
    _record_verified_credential(blackboard)
    coordinator = _bare_coordinator(store, subagent_id="cred")

    coordinator._apply_credential_handover()

    assert coordinator.plan.current == "exploitation"
    assert coordinator.plan_reason == CREDENTIAL_FOUND_REASON
    assert coordinator.credential_handed_over is True
    assert select_for_plan(coordinator.plan).id == "exploit"

    # The latch never drags a plan that already moved forward back.
    moved_on = build_plan(counts={"host": 1, "service": 1, "credential": 1, "session": 1})
    assert moved_on.current == "privilege_escalation"
    coordinator.plan = moved_on
    coordinator._apply_credential_handover()
    assert coordinator.plan.current == "privilege_escalation"


def test_coordinator_does_not_hand_over_without_a_verified_credential(board):
    _, store = board
    coordinator = _bare_coordinator(store, subagent_id="cred")

    coordinator._apply_credential_handover()

    assert coordinator.plan.current == "enumeration"
    assert coordinator.plan_reason is None
    assert coordinator.credential_handed_over is False


# ------------------------------------------------- PART B · exploit can consume
def test_exploit_profile_has_credential_consumer_tools():
    """Initial access must be able to *use* the credential the board validated."""
    catalog = durable_tool_definitions(TENANT)
    profile = SUBAGENTS_BY_ID["exploit"]
    assert profile.phase == "exploitation"

    for tool_id in (
        "nexus.post.ssh_exec",
        "nexus.win.winrm_exec",
        "nexus.session.list",
        "nexus.session.interact",
    ):
        assert tool_id in profile.tools, tool_id
        assert tool_id in catalog, tool_id

    # The consumer takes the handle the verifier issued, not only a plaintext.
    ssh_definition, _handler = catalog["nexus.post.ssh_exec"]
    assert "credential_ref" in ssh_definition.input_schema["properties"]
    winrm_definition, _handler = catalog["nexus.win.winrm_exec"]
    assert "credential_ref" in winrm_definition.input_schema["properties"]

    # Widening `exploit` must not break the registry invariants.
    assert profile.read_only is False
    assert validate_registry(catalog) == []
