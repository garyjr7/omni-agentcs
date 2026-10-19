"""The surface ledger: one verdict per open service, and the pivot order.

These tests pin the *general* contract the user asked for, not a room:

* a service discovered by recon becomes an item, whatever the room;
* a documented dead end (``barrier``) closes it for good, so the run cannot
  keep insisting on a patched or vectorless port;
* an unexplored service is a pending *branch* shown in the prompt;
* when the run stalls -or aims at a closed branch- one deterministic order
  names the next branch and the fact to record.

Nothing here knows about FTP, SMB or a specific CVE: the same code works for any
surface nmap discovers.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from nexus_core.agent.coverage import (
    MAX_LEDGER_ENTRIES,
    STATUS_CLOSED,
    STATUS_OWNED,
    STATUS_PENDING,
    STATUS_PROBED,
    build_coverage,
    focus_entry,
    load_coverage,
    pivot_hint,
    render_coverage,
)
from nexus_core.agent.planner import build_plan
from nexus_core.agent.prompts import render_system_prompt
from nexus_core.agent.react_services import ContextBuilder, ContextSnapshot
from nexus_core.agent.subagents import OMNI_PROFILE
from nexus_core.kernel.control_store import ControlStore
from nexus_core.tools.handlers.knowledge_facts import record_fact_definition

ENGAGEMENT = "eng-coverage"
TENANT = "system"
TARGET = "10.10.10.5"


def service(port: int, name: str, *, product: str = "", version: str = "", host: str = TARGET):
    return {
        "fact_type": "service",
        "key": f"{host}:{port}:tcp",
        "value": {
            "port": port,
            "protocol": "tcp",
            "state": "open",
            "service": name,
            "product": product,
            "version": version,
        },
        "verified": True,
        "asserted_by": "verifier",
        "verification_method": "nmap_xml_parsed",
        "invocation_id": "inv-nmap",
    }


def fact(fact_type: str, key: str, value: dict, *, verified: bool = False):
    return {
        "fact_type": fact_type,
        "key": key,
        "value": value,
        "verified": verified,
        "asserted_by": "verifier" if verified else "agent",
        "verification_method": "test" if verified else "",
        "invocation_id": "inv-1" if verified else "",
    }


# --------------------------------------------------------------------------- #
# Ledger derivation
# --------------------------------------------------------------------------- #
def test_every_discovered_service_is_an_item_with_a_ref_and_a_status():
    coverage = build_coverage(
        [
            service(21, "ftp", product="vsftpd", version="3.0.3"),
            service(80, "http", product="Apache httpd", version="2.4.41"),
            service(22, "ssh", product="OpenSSH", version="8.2p1"),
        ]
    )
    assert [item.ref for item in coverage.entries] == [
        f"{TARGET}:21",
        f"{TARGET}:22",
        f"{TARGET}:80",
    ]
    assert all(item.status == STATUS_PENDING for item in coverage.entries)
    assert coverage.counts == {STATUS_PENDING: 3}
    # The label is what the prompt and the operator read: host, port, service
    # and the banner the scan proved.
    assert coverage.entries[0].label == f"{TARGET}:21/tcp ftp vsftpd 3.0.3"


def test_a_non_service_fact_never_creates_an_entry():
    """Only recon discovers ports; a stray endpoint is not a service."""
    coverage = build_coverage([fact("endpoint", "http://x/", {"status": 200})])
    assert coverage.entries == ()
    assert render_coverage(coverage) == ""


def test_an_endpoint_or_user_probes_only_the_service_it_names():
    coverage = build_coverage(
        [
            service(21, "ftp"),
            service(8080, "http"),
            fact("endpoint", f"http://{TARGET}:8080/admin", {"status": 200}),
            fact("user", "ftpuser", {"service": "ftp", "host": TARGET}),
        ]
    )
    by_ref = {item.ref: item for item in coverage.entries}
    assert by_ref[f"{TARGET}:8080"].status == STATUS_PROBED
    assert by_ref[f"{TARGET}:21"].status == STATUS_PROBED
    assert by_ref[f"{TARGET}:8080"].evidence >= 1


def test_a_web_endpoint_only_probes_the_port_it_actually_names():
    """Measured false positive: an :80 endpoint marked a :8080 service sondeado."""
    explicit = build_coverage(
        [service(80, "http"), service(8080, "http-proxy")]
    )
    # No endpoint yet: both are pending.
    assert all(item.status == STATUS_PENDING for item in explicit.entries)
    probed_80 = build_coverage(
        [
            service(80, "http"),
            service(8080, "http-proxy"),
            fact("endpoint", "/admin", {"url": f"http://{TARGET}/admin", "status": 200}),
            fact("endpoint", "/proxy", {"url": f"http://{TARGET}:8080/proxy", "status": 200}),
        ]
    )
    by_port = {item.port: item for item in probed_80.entries}
    assert by_port[80].status == STATUS_PROBED
    assert by_port[8080].status == STATUS_PROBED
    # A bare URL without a port says nothing about :8080.
    bare = build_coverage(
        [
            service(80, "http"),
            service(8080, "http-proxy"),
            fact("endpoint", "/admin", {"url": f"http://{TARGET}/admin", "status": 200}),
        ]
    )
    by_port = {item.port: item for item in bare.entries}
    assert by_port[80].status == STATUS_PROBED
    assert by_port[8080].status == STATUS_PENDING


def test_verified_access_tied_to_a_service_marks_it_owned():
    coverage = build_coverage(
        [
            service(22, "ssh"),
            fact("access", f"ssh://lin@{TARGET}", {"service": "ssh", "port": 22}, verified=True),
        ]
    )
    assert coverage.entries[0].status == STATUS_OWNED
    assert "comprometido" in render_coverage(coverage)


def test_a_barrier_closes_the_service_with_its_reason_and_survives_a_rescan():
    """The measured Blackbox case: patched service, agent keeps probing it.

    The barrier is agent-recorded (not verified): the decision to stop is the
    agent's, and it must be enough to close the branch. A later nmap that
    rediscovers the same port must not reopen it.
    """
    coverage = build_coverage(
        [
            service(21, "ftp", product="vsftpd", version="3.0.3"),
            service(22, "ssh"),
            fact(
                "barrier",
                f"{TARGET}:21",
                {"reason": "vsftpd 3.0.3 parcheado para CVE-2011-2523"},
            ),
            service(21, "ftp", product="vsftpd", version="3.0.3"),
        ]
    )
    closed = coverage.find(f"{TARGET}:21")
    assert closed is not None and closed.status == STATUS_CLOSED
    assert "CVE-2011-2523" in closed.verdict
    # The duplicate scan did not create a second entry nor reopen the branch.
    assert len(coverage.entries) == 2
    rendered = render_coverage(coverage)
    assert closed.label in rendered
    assert "→ descartado: vsftpd 3.0.3 parcheado para CVE-2011-2523" in rendered
    assert "Siguiente rama:" in rendered and f"{TARGET}:22" in rendered


def test_barrier_without_a_reason_still_reads_as_a_closed_branch():
    coverage = build_coverage(
        [service(3306, "mysql"), fact("barrier", f"{TARGET}:3306", {})]
    )
    item = coverage.entries[0]
    assert item.status == STATUS_CLOSED and item.verdict
    assert "descartado" in item.render()


# --------------------------------------------------------------------------- #
# Frontier and rendering
# --------------------------------------------------------------------------- #
def test_frontier_orders_pending_branches_first_and_names_the_next_one():
    coverage = build_coverage(
        [
            service(22, "ssh"),
            service(80, "http"),
            service(21, "ftp"),
            fact("endpoint", f"http://{TARGET}/", {"status": 200}),
            fact("barrier", f"{TARGET}:22", {"reason": "sin vector"}),
        ]
    )
    rendered = render_coverage(coverage)
    lines = [line for line in rendered.splitlines() if line.startswith("- ")]
    # pending (21) first, then probed (80), then the closed one (22).
    assert lines[0].startswith(f"- {TARGET}:21")
    assert lines[1].startswith(f"- {TARGET}:80")
    assert lines[2].startswith(f"- {TARGET}:22")
    assert f"Siguiente rama: {TARGET}:21/tcp ftp" in rendered
    assert "fact_type=\"barrier\"" in rendered


def test_ledger_is_bounded_so_a_wide_scan_cannot_flood_the_prompt():
    facts = [service(port, "http") for port in range(1000, 1000 + MAX_LEDGER_ENTRIES + 6)]
    rendered = render_coverage(build_coverage(facts))
    assert "y 6 servicio(s) más" in rendered
    assert len([line for line in rendered.splitlines() if line.startswith("- ")]) == (
        MAX_LEDGER_ENTRIES + 1  # entries + the "… y N más" line
    )


def test_a_fully_closed_surface_says_so():
    coverage = build_coverage(
        [service(80, "http"), fact("barrier", f"{TARGET}:80", {"reason": "sin vector"})]
    )
    rendered = render_coverage(coverage)
    assert "0/1 servicios sin veredicto" in rendered
    assert "no repitas trabajo sobre un descartado" in rendered


# --------------------------------------------------------------------------- #
# The pivot correction
# --------------------------------------------------------------------------- #
def _patched_ftp_with_pending_ssh():
    return build_coverage(
        [
            service(21, "ftp", version="3.0.3"),
            service(22, "ssh"),
            fact("barrier", f"{TARGET}:21", {"reason": "parchado"}),
        ]
    )


def test_pivot_fires_immediately_when_the_action_aims_at_a_closed_branch():
    coverage = _patched_ftp_with_pending_ssh()
    focus = focus_entry(coverage, {"target": f"{TARGET}:21", "username": "x"})
    assert focus is not None and focus.status == STATUS_CLOSED
    hint = pivot_hint(coverage, no_progress=0, threshold=5, focus=focus)
    assert "RAMAL CERRADO" in hint
    assert f"{TARGET}:22/tcp ssh" in hint


def test_pivot_does_not_fire_on_a_healthy_branch():
    coverage = build_coverage([service(22, "ssh")])
    focus = focus_entry(coverage, {"target": f"{TARGET}:22"})
    assert pivot_hint(coverage, no_progress=0, threshold=5, focus=focus) == ""
    # Below the threshold the barren streak alone is not enough either.
    assert pivot_hint(coverage, no_progress=4, threshold=5) == ""


def test_pivot_fires_on_a_barren_streak_only_while_work_is_open():
    coverage = _patched_ftp_with_pending_ssh()
    hint = pivot_hint(coverage, no_progress=5, threshold=5)
    assert "FIN DE CALLEJÓN" in hint
    assert "fact_type=\"barrier\"" in hint
    assert f"{TARGET}:22" in hint
    # With every branch closed there is no branch to switch to.
    closed = build_coverage(
        [
            service(21, "ftp"),
            fact("barrier", f"{TARGET}:21", {"reason": "parchado"}),
        ]
    )
    assert pivot_hint(closed, no_progress=9, threshold=5) == ""


def test_focus_reads_arguments_and_never_guesses_from_nothing():
    coverage = build_coverage([service(8080, "http"), service(22, "ssh")])
    assert focus_entry(coverage, {"url": f"http://{TARGET}:8080/x"}).ref == f"{TARGET}:8080"
    assert focus_entry(coverage, {"host": TARGET, "port": 22}).ref == f"{TARGET}:22"
    assert focus_entry(coverage, {"target": "other-host"}) is None
    assert focus_entry(coverage, None) is None


# --------------------------------------------------------------------------- #
# Wiring into the prompt and the durable board
# --------------------------------------------------------------------------- #
def test_the_prompt_carries_the_ledger_and_the_verdict_rule():
    coverage = build_coverage(
        [service(21, "ftp", version="3.0.3"), fact("barrier", f"{TARGET}:21", {"reason": "parchado"})]
    )
    prompt = render_system_prompt(
        catalog={},
        objective="audita el objetivo",
        engagement_id=ENGAGEMENT,
        scope_summary="cidr=10.10.10.0/24",
        coverage_summary=render_coverage(coverage),
    )
    assert "COBERTURA DE SERVICIOS (ledger determinista" in prompt
    assert "REGLA DE COBERTURA" in prompt
    assert "barrier" in prompt
    # Generic by construction: no room or product of a past engagement.
    lowered = prompt.lower()
    for room in ("rootme", "blue", "blackbox", "vulnversity", "simple ctf"):
        assert room not in lowered


def test_the_builder_injects_the_pivot_as_an_order_in_the_system_prompt():
    coverage = _patched_ftp_with_pending_ssh()
    focus = focus_entry(coverage, {"target": f"{TARGET}:21"})
    hint = pivot_hint(coverage, focus=focus)
    messages = ContextBuilder().render(
        ContextSnapshot(
            run_history=[],
            history_summary="",
            plan=build_plan(objective="audita", engagement_id=ENGAGEMENT),
            facts_text="",
            coverage=coverage,
        ),
        allowed_catalog={},
        objective="audita",
        engagement_id=ENGAGEMENT,
        scope=None,
        subagent=OMNI_PROFILE,
        project_instruction=None,
        active_skills=[],
        store=None,
        tenant_id=TENANT,
        coverage_hint=hint,
    )
    system = "\n".join(str(message.content) for message in messages if message.role == "system")
    assert "RAMAL CERRADO" in system
    assert f"{TARGET}:22" in system


def test_the_coordinator_audits_the_pivot_once_and_keeps_the_order_in_the_hint(tmp_path):
    """The loop wiring itself: a closed branch in focus produces the order.

    The rule is unit-tested above; this pins that the coordinator reads the
    board of this turn and audits the correction once per run, which is what
    the next prompt renders.
    """
    from nexus_core.agent.react_coordinator import ReActCoordinator
    from nexus_core.agent.react_types import COVERAGE_PIVOT_EVENT_TYPE
    from nexus_core.kernel.audit import AuditWriter
    from nexus_core.kernel.blackboard import Blackboard

    store = ControlStore(tmp_path / "pivot.db")
    store.initialize()
    board = Blackboard(store)
    for key, value in (
        (f"{TARGET}:21:tcp", {"port": 21, "protocol": "tcp", "service": "ftp"}),
        (f"{TARGET}:22:tcp", {"port": 22, "protocol": "tcp", "service": "ssh"}),
    ):
        board.record(
            tenant_id=TENANT,
            engagement_id=ENGAGEMENT,
            fact_type="service",
            key=key,
            value=value,
            source="nmap",
            created_by="verifier",
            verified=True,
            asserted_by="verifier",
            verification_method="nmap_xml_parsed",
            invocation_id="inv-nmap",
        )
    board.record(
        tenant_id=TENANT,
        engagement_id=ENGAGEMENT,
        fact_type="barrier",
        key=f"{TARGET}:21",
        value={"reason": "parchado"},
        source="agent",
        created_by="agent",
    )
    coverage = load_coverage(store, TENANT, ENGAGEMENT)
    run = store.create_run(TENANT, {})

    coordinator = ReActCoordinator.__new__(ReActCoordinator)
    coordinator.tenant_id = TENANT
    coordinator.engagement_id = ENGAGEMENT
    coordinator.agent_id = "omni"
    coordinator.active_subagent_id = "omni"
    coordinator.store = store
    coordinator.run_id = run["id"]
    coordinator.iteration = 4
    coordinator.plan = build_plan(
        objective="audita", engagement_id=ENGAGEMENT, counts={"service": 2}
    )
    coordinator.audit = AuditWriter(store)
    coordinator.snapshot = ContextSnapshot(
        run_history=[],
        history_summary="",
        plan=coordinator.plan,
        facts_text="",
        coverage=coverage,
    )
    coordinator.action = SimpleNamespace(arguments={"target": f"{TARGET}:21"})
    coordinator.consecutive_no_progress = 0
    coordinator.stuck_threshold = 5
    coordinator.coverage_hint = ""
    coordinator.coverage_hint_emitted = False

    coordinator._refresh_coverage_hint()

    assert "RAMAL CERRADO" in coordinator.coverage_hint
    assert f"{TARGET}:22/tcp ssh" in coordinator.coverage_hint
    events = [
        event
        for event in store.list_run_events(TENANT, run["id"])
        if event.get("event_type") == COVERAGE_PIVOT_EVENT_TYPE
    ]
    assert len(events) == 1
    assert events[0]["payload"]["focus"] == f"{TARGET}:21"
    assert events[0]["payload"]["focus_status"] == STATUS_CLOSED

    # The audit is per run: the next turn keeps the order but does not duplicate
    # the event.
    coordinator.iteration = 5
    coordinator._refresh_coverage_hint()
    assert "RAMAL CERRADO" in coordinator.coverage_hint
    assert len(
        [
            event
            for event in store.list_run_events(TENANT, run["id"])
            if event.get("event_type") == COVERAGE_PIVOT_EVENT_TYPE
        ]
    ) == 1


async def test_a_real_loop_turn_carries_the_ledger_from_the_store(tmp_path, lab_scope):
    """End to end: blackboard → snapshot → system prompt of the first turn.

    The unit tests above check the ledger and the hint in isolation; this one
    runs the real loop over a real store, so a broken wiring (the snapshot not
    loading the coverage, or the builder not rendering it) fails here instead of
    silently dropping the map from every prompt.
    """
    from nexus_core.agent.react import ReActConfig, run_react_loop
    from nexus_core.kernel.blackboard import Blackboard
    from nexus_core.kernel.runtime import ExecutionContext
    from nexus_core.llm.abstraction import LLMProvider, LLMResponse
    from nexus_core.scope import EngagementScope, EngagementStore

    store = ControlStore(tmp_path / "loop.db")
    store.initialize()
    now = datetime.now(timezone.utc)
    EngagementStore(store).create(
        EngagementScope(
            engagement_id=ENGAGEMENT,
            tenant_id=TENANT,
            name="coverage",
            client="acme",
            owner_id="owner-1",
            valid_from=(now - timedelta(days=1)).isoformat(),
            valid_until=(now + timedelta(days=1)).isoformat(),
            cidrs=("10.10.10.0/24",),
            domains=(),
            urls=(),
            exclusions=(),
            created_at=now.isoformat(),
        )
    )
    board = Blackboard(store)
    for port, name in ((21, "ftp"), (22, "ssh")):
        board.record(
            tenant_id=TENANT,
            engagement_id=ENGAGEMENT,
            fact_type="service",
            key=f"{TARGET}:{port}:tcp",
            value={"port": port, "protocol": "tcp", "service": name},
            source="nexus.recon.nmap",
            created_by="verifier",
            verified=True,
            asserted_by="verifier",
            verification_method="nmap_xml_parsed",
            invocation_id="inv-nmap",
        )
    board.record(
        tenant_id=TENANT,
        engagement_id=ENGAGEMENT,
        fact_type="barrier",
        key=f"{TARGET}:21",
        value={"reason": "parchado"},
        source="agent",
        created_by="agent",
    )
    run = store.create_run(TENANT, {})
    context = ExecutionContext(
        store,
        {
            "id": f"task-{run['id']}",
            "tenant_id": TENANT,
            "run_id": run["id"],
            "task_type": "react.run",
            "payload": {
                "objective": "audita el objetivo",
                "engagement_id": ENGAGEMENT,
                "identity": {"subject_id": "operator-1", "roles": ["operator"]},
                "permissions": [],
            },
        },
        "worker-test",
    )

    class ScriptedLLM:
        def __init__(self) -> None:
            self.prompts: list[str] = []

        async def complete(self, messages, **kwargs):
            self.prompts.append("\n".join(str(message.content) for message in messages))
            return LLMResponse(
                content=(
                    '{"thought": "cierro el engagement", "action": "task_complete", '
                    '"summary": "sin hallazgos verificados", "findings": []}'
                ),
                model="scripted-test",
                provider=LLMProvider.FAKE,
            )

    llm = ScriptedLLM()
    await run_react_loop(
        context=context,
        objective="audita el objetivo",
        engagement_id=ENGAGEMENT,
        llm_client=llm,
        config=ReActConfig(max_iterations=1, enforce_completion_gates=False),
    )

    assert llm.prompts, "the loop never called the provider"
    first = llm.prompts[0]
    assert "COBERTURA DE SERVICIOS (ledger determinista" in first
    assert f"{TARGET}:21/tcp ftp" in first and "descartado: parchado" in first
    assert "FRONTERA: 1/2 servicios sin veredicto" in first
    assert f"Siguiente rama: {TARGET}:22/tcp ssh" in first


def test_barrier_is_a_first_class_fact_type_and_reaches_the_tool_contract():
    definition = record_fact_definition()
    enum = definition.input_schema["properties"]["fact_type"]["enum"]
    assert "barrier" in enum


def test_the_ledger_reads_a_real_blackboard_and_a_barrier_closes_the_entry(tmp_path):
    store = ControlStore(tmp_path / "coverage.db")
    store.initialize()
    from nexus_core.kernel.blackboard import Blackboard

    board = Blackboard(store)
    board.record(
        tenant_id=TENANT,
        engagement_id=ENGAGEMENT,
        fact_type="service",
        key=f"{TARGET}:21:tcp",
        value={"port": 21, "protocol": "tcp", "service": "ftp", "version": "3.0.3"},
        source="nmap",
        created_by="verifier",
        verified=True,
        asserted_by="verifier",
        verification_method="nmap_xml_parsed",
        invocation_id="inv-nmap",
    )
    board.record(
        tenant_id=TENANT,
        engagement_id=ENGAGEMENT,
        fact_type="barrier",
        key=f"{TARGET}:21",
        value={"reason": "parchado"},
        source="agent",
        created_by="agent",
    )
    coverage = load_coverage(store, TENANT, ENGAGEMENT)
    assert coverage.find(f"{TARGET}:21").status == STATUS_CLOSED
    assert "parchado" in render_coverage(coverage)


def test_load_coverage_degrades_to_empty_without_a_board():
    assert load_coverage(None, TENANT, ENGAGEMENT).entries == ()
    assert load_coverage(None, TENANT, None).entries == ()


@pytest.mark.parametrize("status", [STATUS_PENDING, STATUS_PROBED, STATUS_OWNED, STATUS_CLOSED])
def test_every_status_renders_without_raising(status):
    from nexus_core.agent.coverage import Coverage, SurfaceEntry

    entry = SurfaceEntry(
        host=TARGET,
        port=22,
        protocol="tcp",
        service="ssh",
        product="OpenSSH",
        version="9.6",
        key=f"{TARGET}:22:tcp",
        status=status,
        verdict="parchado" if status == STATUS_CLOSED else "",
        evidence=1,
    )
    text = render_coverage(Coverage(entries=(entry,), counts={status: 1}))
    assert f"{TARGET}:22/tcp" in text
