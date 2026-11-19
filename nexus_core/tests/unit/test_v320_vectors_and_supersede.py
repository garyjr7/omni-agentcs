"""v3.2.0: multi-vector closure, canonical supersession and approver roles."""

from __future__ import annotations

import asyncio
import json
import time
from types import SimpleNamespace

import pytest

from nexus_core.agent.coverage import build_coverage
from nexus_core.agent.react_services import CompletionVerifier
from nexus_core.agent.vector_plan import (
    VECTOR_DISCARDED,
    VECTOR_DISCOVERED,
    VECTOR_EXPLOITED,
    VectorPlan,
    open_vector_objection,
)
from nexus_core.kernel.approvals import ApprovalService
from nexus_core.kernel.blackboard import Blackboard, fact_uri
from nexus_core.kernel.control_store import ControlStore
from nexus_core.kernel.models import Identity, RunContext
from nexus_core.report.extract_facts import _fact_findings

pytestmark = pytest.mark.unit

TENANT = "system"
ENGAGEMENT = "eng-v320"
HOST = "10.20.30.5"


def _store(tmp_path) -> ControlStore:
    store = ControlStore(tmp_path / "nexus.db")
    store.initialize()
    return store


def _service(port: int, service: str, *, stamp: str) -> dict:
    return {
        "fact_type": "service",
        "key": f"{HOST}:{port}:tcp",
        "value": {"service": service, "protocol": "tcp"},
        "verified": False,
        "asserted_by": "agent",
        "recorded_at": stamp,
    }


def _barrier(port: int, reason: str, *, stamp: str) -> dict:
    return {
        "fact_type": "barrier",
        "key": f"{HOST}:{port}",
        "value": {"reason": reason, "sweep_attempted": True},
        "verified": False,
        "asserted_by": "agent",
        "recorded_at": stamp,
    }


def _three_routes() -> tuple[list[dict], list[dict]]:
    services = [
        _service(22, "ssh", stamp="2026-11-20T10:00:00+00:00"),
        _service(80, "http", stamp="2026-11-20T10:00:01+00:00"),
        _service(8080, "http", stamp="2026-11-20T10:00:02+00:00"),
    ]
    return services, []


def test_three_routes_are_queued_and_each_one_is_explored_before_closure():
    services, barriers = _three_routes()
    coverage = build_coverage([*services, *barriers])
    plan = VectorPlan.from_coverage(coverage)
    assert {item.ref for item in plan.vectors} == {
        f"{HOST}:22",
        f"{HOST}:80",
        f"{HOST}:8080",
    }
    assert all(item.status == VECTOR_DISCOVERED for item in plan.vectors)

    seen: list[str] = []
    stamps = [
        "2026-11-20T10:01:00+00:00",
        "2026-11-20T10:02:00+00:00",
        "2026-11-20T10:03:00+00:00",
    ]
    for stamp in stamps:
        following = VectorPlan.from_coverage(build_coverage([*services, *barriers])).next_vector
        assert following is not None
        seen.append(following.ref)
        port = int(following.ref.rsplit(":", 1)[1])
        barriers = [*barriers, _barrier(port, "probado y sin vector", stamp=stamp)]

    assert seen == [f"{HOST}:22", f"{HOST}:80", f"{HOST}:8080"]
    final = VectorPlan.from_coverage(build_coverage([*services, *barriers]))
    assert final.open_vectors == ()
    assert all(item.status == VECTOR_DISCARDED for item in final.vectors)
    assert open_vector_objection(final) is None


def test_a_verified_web_credential_is_offered_to_the_open_ssh_vector():
    services, _ = _three_routes()
    credential = {
        "fact_type": "credential",
        "key": f"cred:web:lin@{HOST}",
        "value": {"host": HOST, "username": "lin", "protocol": "web"},
        "verified": True,
        "asserted_by": "verifier",
        "verification_method": "web_login",
        "invocation_id": "inv-web",
        "recorded_at": "2026-11-20T10:01:00+00:00",
    }
    coverage = build_coverage([*services, credential])
    assert coverage.credential_reuse == (f"cred:web:lin@{HOST}",)
    from nexus_core.agent.coverage import render_coverage

    ledger = render_coverage(coverage)
    assert "REUTILIZACIÓN DE CREDENCIALES" in ledger
    assert f"cred:web:lin@{HOST}" in ledger


def test_one_owned_route_does_not_close_the_other_open_vectors():
    services, _ = _three_routes()
    access = {
        "fact_type": "access",
        "key": f"{HOST}:80:www-data",
        "value": {"host": HOST, "user": "www-data"},
        "verified": True,
        "asserted_by": "verifier",
        "verification_method": "web_shell",
        "invocation_id": "inv-web",
        "recorded_at": "2026-11-20T10:01:00+00:00",
    }
    coverage = build_coverage([*services, access])
    plan = VectorPlan.from_coverage(coverage)
    statuses = {item.ref: item.status for item in plan.vectors}
    assert statuses[f"{HOST}:80"] == VECTOR_EXPLOITED
    assert statuses[f"{HOST}:22"] == VECTOR_DISCOVERED
    assert statuses[f"{HOST}:8080"] == VECTOR_DISCOVERED
    objection = open_vector_objection(plan)
    assert objection is not None
    assert f"{HOST}:22" in objection
    assert f"{HOST}:8080" in objection
    assert plan.next_vector is not None
    assert plan.next_vector.ref != f"{HOST}:80"


def test_task_complete_is_refused_by_the_real_verifier_while_a_vector_is_open(tmp_path):
    store = _store(tmp_path)
    board = Blackboard(store)
    for port, service in ((22, "ssh"), (80, "http"), (8080, "http")):
        board.record(
            tenant_id=TENANT,
            engagement_id=ENGAGEMENT,
            fact_type="service",
            key=f"{HOST}:{port}:tcp",
            value={"service": service, "protocol": "tcp"},
            source="test",
            created_by="test",
        )

    class Hooks:
        async def verify_stop(self, **_kwargs):
            return []

    assessment = asyncio.run(
        CompletionVerifier().verify(
            findings=[],
            observations=[],
            run_id="run-v320",
            plan=SimpleNamespace(current="reporting", phases=(), progress=(6, 6)),
            config=SimpleNamespace(enforce_completion_gates=True),
            engagement_id=ENGAGEMENT,
            store=store,
            tenant_id=TENANT,
            hooks=Hooks(),
            objective="comprometer el host",
            require_plan_phase=False,
            require_plan_first=False,
            background_tasks=[],
        )
    )
    assert any("vector" in objection and "sin veredicto" in objection for objection in assessment.objections)


def test_the_vector_queue_is_persisted_in_kernel_run_state(tmp_path):
    from nexus_core.agent.react_coordinator import ReActCoordinator

    store = _store(tmp_path)
    services, _ = _three_routes()
    coverage = build_coverage(services)

    coordinator = object.__new__(ReActCoordinator)
    coordinator.tenant_id = TENANT
    coordinator.run_id = "run-vector-state"
    coordinator.store = store
    coordinator.vector_failures = {}
    coordinator.vector_last_failure = {}
    coordinator.vector_locked = set()
    coordinator.unavailable_tools = set()
    coordinator.tool_failures = {}
    coordinator.refusal_retired = set()
    coordinator.resurrected_tools = set()
    coordinator.phase_turns = {}
    coordinator.vector_plan = VectorPlan()
    coordinator.snapshot = SimpleNamespace(coverage=coverage)
    coordinator._persist_run_state()

    state = store.load_run_state(TENANT, "run-vector-state")
    assert {item["ref"] for item in state["attack_vectors"]} == {
        f"{HOST}:22",
        f"{HOST}:80",
        f"{HOST}:8080",
    }
    assert state["vector_next"] == f"{HOST}:22"
    restored = VectorPlan.from_state(state["attack_vectors"])
    assert restored.next_vector is not None
    assert restored.next_vector.ref == f"{HOST}:22"


def _record_credential(board: Blackboard, key: str, *, verified: bool, stamp: str) -> dict:
    return board.record(
        tenant_id=TENANT,
        engagement_id=ENGAGEMENT,
        fact_type="credential",
        key=key,
        value={"username": "lin", "protocol": "ssh", "host": HOST, "secret_ref": "vault:test"},
        source="deterministic-verifier" if verified else "agent",
        created_by="test",
        verified=verified,
        asserted_by="verifier" if verified else "agent",
        verification_method="cred_bruteforce_completed" if verified else "",
        invocation_id="inv-cred" if verified else "",
    )


def test_a_second_spelling_of_one_credential_supersedes_the_first(tmp_path):
    board = Blackboard(_store(tmp_path))
    original = _record_credential(board, f"cred:ssh:lin@{HOST}", verified=True, stamp="one")
    alias = _record_credential(board, f"lin@{HOST}", verified=False, stamp="two")

    facts = board.list_facts(TENANT, ENGAGEMENT, fact_type="credential")
    assert len(facts) == 1
    assert facts[0]["key"] == f"cred:ssh:lin@{HOST}"
    assert alias["superseded_by"] == original["fact_id"]

    newer = _record_credential(board, f"ssh:lin@{HOST}", verified=True, stamp="three")
    facts = board.list_facts(TENANT, ENGAGEMENT, fact_type="credential")
    assert len(facts) == 1
    assert facts[0]["fact_id"] == newer["fact_id"]

    old_uri = fact_uri(ENGAGEMENT, "credential", f"cred:ssh:lin@{HOST}")
    with board.store.connect() as conn:
        rows = conn.execute(
            "SELECT content FROM kernel_knowledge_documents "
            "WHERE tenant_id=? AND source_uri=? ORDER BY created_at DESC",
            (TENANT, old_uri),
        ).fetchall()
    assert rows
    assert json.loads(rows[0]["content"])["superseded_by"] == newer["fact_id"]


def test_rerecording_the_same_key_marks_its_previous_version(tmp_path):
    board = Blackboard(_store(tmp_path))
    first = _record_credential(board, f"cred:ssh:lin@{HOST}", verified=True, stamp="one")
    time.sleep(0.002)
    second = _record_credential(board, f"cred:ssh:lin@{HOST}", verified=True, stamp="two")

    facts = board.list_facts(TENANT, ENGAGEMENT, fact_type="credential")
    assert len(facts) == 1
    assert facts[0]["fact_id"] == second["fact_id"]

    uri = fact_uri(ENGAGEMENT, "credential", f"cred:ssh:lin@{HOST}")
    with board.store.connect() as conn:
        rows = conn.execute(
            "SELECT content FROM kernel_knowledge_documents "
            "WHERE tenant_id=? AND source_uri=? ORDER BY created_at",
            (TENANT, uri),
        ).fetchall()
    markers = [json.loads(row["content"]).get("superseded_by") for row in rows]
    assert second["fact_id"] in markers
    assert first["fact_id"] not in markers


def test_the_report_emits_one_finding_for_one_canonical_credential(tmp_path):
    board = Blackboard(_store(tmp_path))
    verified = _record_credential(board, f"cred:ssh:lin@{HOST}", verified=True, stamp="one")
    duplicate = _record_credential(board, f"lin@{HOST}", verified=False, stamp="two")
    facts = board.list_facts(TENANT, ENGAGEMENT, fact_type="credential")
    assert len(facts) == 1

    # Legacy input (both rows without a marker) still deduplicates by canonical
    # identity, preferring the verified version over the agent's duplicate.
    findings = _fact_findings([verified, duplicate])
    assert len(findings) == 1
    assert findings[0].title == f"cred:ssh:lin@{HOST}"


def _insert_user(store: ControlStore, user_id: str, role: str) -> None:
    from nexus_core.kernel.models import utc_now

    with store.connect() as conn:
        conn.execute(
            """INSERT INTO kernel_users
            (id,tenant_id,email,name,hashed_pw,role,active,created_at)
            VALUES(?,?,?,?,?,?,1,?)""",
            (user_id, TENANT, f"{user_id}@example.test", user_id, "x", role, utc_now()),
        )


def test_a_viewer_cannot_approve_and_an_approver_can(tmp_path):
    store = _store(tmp_path)  # initialize() seeds the system tenant
    _insert_user(store, "viewer-1", "viewer")
    _insert_user(store, "approver-1", "approver")

    service = ApprovalService(store)
    context = RunContext(TENANT, Identity("requester-1", TENANT, kind="human"))
    approval = service.request(context, "execute:tool:nexus.exploit.impacket_psexec")

    with pytest.raises(PermissionError, match="approver/admin"):
        service.decide(approval["id"], TENANT, "viewer-1", True)

    decided = service.decide(approval["id"], TENANT, "approver-1", True)
    assert decided["status"] == "approved"
    assert decided["decided_by"] == "approver-1"
