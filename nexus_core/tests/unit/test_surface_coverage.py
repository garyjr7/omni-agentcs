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


def fact(
    fact_type: str,
    key: str,
    value: dict,
    *,
    verified: bool = False,
    recorded_at: str = "",
):
    return {
        "fact_type": fact_type,
        "key": key,
        "value": value,
        "verified": verified,
        "asserted_by": "verifier" if verified else "agent",
        "verification_method": "test" if verified else "",
        "invocation_id": "inv-1" if verified else "",
        "recorded_at": recorded_at,
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


# --------------------------------------------------------------------------- #
# The newest verdict wins (measured in run_3d90f7f388144557ae97466b0a19ce55)
# --------------------------------------------------------------------------- #
def test_a_newer_vulnerability_reopens_a_service_an_older_barrier_closed():
    """The ledger cannot order the model to abandon a vector it just proved.

    Measured on 2026-10-20: the agent recorded the CVE-2017-8917 barrier at
    23:34, then proved error-based SQLi on the same :80 at 00:23 and recorded
    it; ``pivot_hint`` kept answering "RAMAL CERRADO" -its own text promises a
    new vector reopens the branch- and the run abandoned the only working one.
    """
    coverage = build_coverage(
        [
            service(80, "http", product="Apache httpd", version="2.4.6"),
            fact(
                "barrier",
                f"{TARGET}:80:sqli_union",
                {"reason": "sqlmap UNION no logra inyección estable"},
                recorded_at="2026-10-19T23:34:21.911216+00:00",
            ),
            fact(
                "vulnerability",
                f"{TARGET}:80:sqli_error_based_confirmed",
                {"endpoint": "http://10.10.10.5/index.php?list[fullordering]="},
                recorded_at="2026-10-20T00:23:42.662846+00:00",
            ),
        ]
    )
    reopened = coverage.find(f"{TARGET}:80")
    assert reopened is not None and reopened.status == STATUS_PROBED
    assert coverage.find(f"{TARGET}:80").verdict == ""
    # The correction follows the ledger: no "RAMAL CERRADO" for a live branch.
    focus = focus_entry(coverage, {"url": f"http://{TARGET}/index.php"})
    assert focus is not None and focus.status == STATUS_PROBED
    assert pivot_hint(coverage, no_progress=0, threshold=5, focus=focus) == ""


def test_a_barrier_recorded_after_the_vector_closes_it_again():
    """The model changed its mind: the later verdict is the current one."""
    coverage = build_coverage(
        [
            service(80, "http"),
            fact(
                "vulnerability",
                f"{TARGET}:80:cve-x",
                {"cve": "CVE-X"},
                recorded_at="2026-10-20T00:00:00.000000+00:00",
            ),
            fact(
                "barrier",
                f"{TARGET}:80",
                {"reason": "el parche del vendor lo cubre"},
                recorded_at="2026-10-20T01:00:00.000000+00:00",
            ),
        ]
    )
    closed = coverage.find(f"{TARGET}:80")
    assert closed is not None and closed.status == STATUS_CLOSED
    assert "parche del vendor" in closed.verdict


def test_verified_access_outranks_any_barrier():
    """A service already reached is comprometido, never "descartado"."""
    coverage = build_coverage(
        [
            service(22, "ssh"),
            fact(
                "access", f"ssh://lin@{TARGET}", {"port": 22}, verified=True,
                recorded_at="2026-10-20T00:00:00.000000+00:00",
            ),
            fact(
                "barrier",
                f"{TARGET}:22",
                {"reason": "sin vector de escalada"},
                recorded_at="2026-10-20T01:00:00.000000+00:00",
            ),
        ]
    )
    assert coverage.find(f"{TARGET}:22").status == STATUS_OWNED


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
# The operator's directive outranks the ledger (measured in V15, HackPark)
# --------------------------------------------------------------------------- #
#: The objective of ``run_e971fff78593498081567bdfc602d23a`` (V15, 2026-10-21),
#: verbatim in its decisive parts: it names the host, forbids pivoting and fixes
#: the endpoint. The pivot at iteration 12 ordered ``3389/tcp ms-wbt-server``
#: anyway and the agent obeyed it for 28 turns.
V15_OBJECTIVE = (
    "Realiza una prueba de penetración. Compromete el sistema, escala a root y "
    "captura las flags. NOTA: El alcance es ÚNICO HOST (10.10.10.5). NO hagas "
    "pivoteo. Para el exploit CVE-2019-6714 de BlogEngine, sube el tema "
    "PostView.ascx a POST /admin/app_themes.aspx con theme_name='pwned'."
)


def _v15_surface():
    return build_coverage(
        [
            service(80, "http"),
            service(3389, "ms-wbt-server"),
            fact("endpoint", f"http://{TARGET}/admin/", {"status": 302}),
        ]
    )


def test_the_objective_is_read_for_the_branches_it_fixes():
    from nexus_core.agent.coverage import parse_directive

    directive = parse_directive(V15_OBJECTIVE)
    assert directive.active and directive.no_pivot
    assert directive.hosts == (TARGET,)
    assert directive.paths == ("/admin/app_themes.aspx",)
    coverage = _v15_surface()
    # The route names the web service; the same host's RDP is not named.
    assert directive.names(coverage.find(f"{TARGET}:80"))
    assert not directive.names(coverage.find(f"{TARGET}:3389"))
    # The objective is quoted back, so the model re-reads the order next to the
    # heuristic that contradicts it.
    assert "no hagas pivoteo" in directive.text.casefold()
    assert "/admin/app_themes.aspx" in directive.text


def test_an_empty_objective_leaves_the_ledger_alone():
    from nexus_core.agent.coverage import parse_directive

    for objective in ("", None, "   "):
        assert parse_directive(objective).active is False
    assert parse_directive("audita el objetivo").active is False


def test_the_pivot_never_orders_a_branch_the_objective_excluded():
    """The V15 inversion: the human's branch wins over the heuristic's."""
    from nexus_core.agent.coverage import parse_directive

    coverage = _v15_surface()
    focus = focus_entry(coverage, {"url": f"http://{TARGET}/Account/login.aspx"})
    assert focus is not None and focus.ref == f"{TARGET}:80"
    hint = pivot_hint(
        coverage,
        no_progress=5,
        threshold=5,
        focus=focus,
        directive=parse_directive(V15_OBJECTIVE),
    )
    assert "DIRECTIVA DEL OPERADOR" in hint
    assert "FIN DE CALLEJÓN" not in hint
    assert "Siguiente rama:" not in hint
    # The excluded service cannot even be named as an option.
    assert "3389" not in hint
    assert f"{TARGET}:80" in hint
    assert "/admin/app_themes.aspx" in hint


def test_a_directive_brings_a_wandered_run_back_to_the_named_branch():
    """The model already moved to RDP: the order is to go back, not onward."""
    from nexus_core.agent.coverage import parse_directive

    coverage = _v15_surface()
    focus = focus_entry(coverage, {"target": f"{TARGET}:3389"})
    hint = pivot_hint(
        coverage,
        no_progress=5,
        threshold=5,
        focus=focus,
        directive=parse_directive(V15_OBJECTIVE),
    )
    assert f"{TARGET}:80" in hint
    assert "reintenta" in hint


def test_a_directive_does_not_order_a_pivot_out_of_a_dead_branch():
    """Even a closed branch is not a licence to break the operator's limit."""
    from nexus_core.agent.coverage import parse_directive

    coverage = build_coverage(
        [
            service(80, "http"),
            service(3389, "ms-wbt-server"),
            fact("barrier", f"{TARGET}:80", {"reason": "el tema se rechaza"}),
        ]
    )
    focus = focus_entry(coverage, {"url": f"http://{TARGET}/"})
    hint = pivot_hint(coverage, focus=focus, directive=parse_directive(V15_OBJECTIVE))
    assert "DIRECTIVA DEL OPERADOR" in hint
    assert "desbloquear el ledger" in hint
    assert "3389" not in hint
    assert "request_clarification" in hint


def test_without_a_directive_the_pivot_keeps_its_measured_order():
    coverage = _v15_surface()
    hint = pivot_hint(coverage, no_progress=5, threshold=5)
    assert "FIN DE CALLEJÓN" in hint
    assert f"Siguiente rama: {TARGET}:3389/tcp ms-wbt-server" in hint


def test_the_frontier_line_does_not_point_at_an_excluded_branch():
    from nexus_core.agent.coverage import parse_directive

    rendered = render_coverage(_v15_surface(), directive=parse_directive(V15_OBJECTIVE))
    assert "DIRECTIVA DEL OPERADOR (prioridad sobre este ledger)" in rendered
    assert "/admin/app_themes.aspx" in rendered
    assert f"Siguiente rama: {TARGET}:80/tcp http" in rendered


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


def test_the_prompt_carries_the_directive_ahead_of_the_frontier():
    """A real render: the objective of the run reaches the ledger block."""
    messages = ContextBuilder().render(
        ContextSnapshot(
            run_history=[],
            history_summary="",
            plan=build_plan(objective=V15_OBJECTIVE, engagement_id=ENGAGEMENT),
            facts_text="",
            coverage=_v15_surface(),
        ),
        allowed_catalog={},
        objective=V15_OBJECTIVE,
        engagement_id=ENGAGEMENT,
        scope=None,
        subagent=OMNI_PROFILE,
        project_instruction=None,
        active_skills=[],
        store=None,
        tenant_id=TENANT,
    )
    system = "\n".join(
        str(message.content) for message in messages if message.role == "system"
    )
    assert "DIRECTIVA DEL OPERADOR (prioridad sobre este ledger)" in system
    assert f"Siguiente rama: {TARGET}:80/tcp http" in system
    assert "/admin/app_themes.aspx" in system


def test_the_coordinator_honours_the_objective_it_was_given(tmp_path):
    """The loop wiring: ``self.objective`` is parsed, not a stale snapshot."""
    from nexus_core.agent.react_coordinator import ReActCoordinator
    from nexus_core.agent.react_types import COVERAGE_PIVOT_EVENT_TYPE
    from nexus_core.kernel.audit import AuditWriter
    from nexus_core.kernel.blackboard import Blackboard

    store = ControlStore(tmp_path / "directive.db")
    store.initialize()
    board = Blackboard(store)
    for port, name in ((80, "http"), (3389, "ms-wbt-server")):
        board.record(
            tenant_id=TENANT,
            engagement_id=ENGAGEMENT,
            fact_type="service",
            key=f"{TARGET}:{port}:tcp",
            value={"port": port, "protocol": "tcp", "service": name},
            source="nmap",
            created_by="verifier",
            verified=True,
            asserted_by="verifier",
            verification_method="nmap_xml_parsed",
            invocation_id="inv-nmap",
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
    coordinator.iteration = 12
    coordinator.objective = V15_OBJECTIVE
    coordinator.plan = build_plan(
        objective=V15_OBJECTIVE, engagement_id=ENGAGEMENT, counts={"service": 2}
    )
    coordinator.audit = AuditWriter(store)
    coordinator.snapshot = ContextSnapshot(
        run_history=[],
        history_summary="",
        plan=coordinator.plan,
        facts_text="",
        coverage=coverage,
    )
    coordinator.action = SimpleNamespace(arguments={"url": f"http://{TARGET}/Account/login.aspx"})
    coordinator.consecutive_no_progress = 5
    coordinator.stuck_threshold = 5
    coordinator.coverage_hint = ""
    coordinator.coverage_hint_emitted = False

    coordinator._refresh_coverage_hint()

    assert "DIRECTIVA DEL OPERADOR" in coordinator.coverage_hint
    assert "FIN DE CALLEJÓN" not in coordinator.coverage_hint
    events = [
        event
        for event in store.list_run_events(TENANT, run["id"])
        if event.get("event_type") == COVERAGE_PIVOT_EVENT_TYPE
    ]
    assert len(events) == 1
    payload = events[0]["payload"]
    assert payload["directive"]["no_pivot"] is True
    assert payload["directive"]["paths"] == ["/admin/app_themes.aspx"]
    assert payload["focus"] == f"{TARGET}:80"


def test_the_loop_injects_the_login_probe_hint_once(tmp_path):
    """The wiring: a read login form becomes one order to probe it.

    DeadDrop P1/P3 (2026-10-22): the form was read twice and the run went back
    to directory wordlists, so the rule has to reach the prompt, not only the
    planner.
    """
    from nexus_core.agent.react_coordinator import ReActCoordinator
    from nexus_core.kernel.audit import AuditWriter

    store = ControlStore(tmp_path / "login.db")
    store.initialize()
    run = store.create_run(TENANT, {})
    coordinator = ReActCoordinator.__new__(ReActCoordinator)
    coordinator.tenant_id = TENANT
    coordinator.engagement_id = ENGAGEMENT
    coordinator.agent_id = "omni"
    coordinator.active_subagent_id = "omni"
    coordinator.store = store
    coordinator.run_id = run["id"]
    coordinator.iteration = 6
    coordinator.plan = build_plan(counts={"service": 2})
    coordinator.audit = AuditWriter(store)
    coordinator.login_hint = ""
    coordinator.login_hint_emitted = False
    coordinator.login_hints_sent = set()
    coordinator.login_withheld = set()
    coordinator.login_withheld_announced = False
    coordinator.actions = [
        {
            "tool_id": "nexus.web.request",
            "arguments": {"url": f"http://{TARGET}/login"},
            "tool_result": {
                "output": {
                    "body_preview": (
                        '<form method="POST" action="/login">'
                        '<input type="password" name="password"></form>'
                    )
                }
            },
        }
    ]

    coordinator._refresh_login_hint()

    assert f"http://{TARGET}/login" in coordinator.login_hint
    events = [
        event
        for event in store.list_run_events(TENANT, run["id"])
        if event.get("event_type") == "react.login_probe"
    ]
    assert len(events) == 1
    coordinator._refresh_login_hint()
    assert coordinator.login_hint_emitted is True
    assert (
        len(
            [
                event
                for event in store.list_run_events(TENANT, run["id"])
                if event.get("event_type") == "react.login_probe"
            ]
        )
        == 1
    )


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


def test_the_real_board_reopens_a_barrier_with_a_newer_vulnerability(tmp_path):
    """Same sequence as the measured run, over the real store and clock.

    ``service`` → ``barrier`` → ``vulnerability``: the duplicate merge in
    ``Blackboard.list_facts`` must not drop ``recorded_at``, or the ledger could
    not tell which verdict came last.
    """
    from nexus_core.kernel.blackboard import Blackboard

    store = ControlStore(tmp_path / "reopen.db")
    store.initialize()
    board = Blackboard(store)
    board.record(
        tenant_id=TENANT,
        engagement_id=ENGAGEMENT,
        fact_type="service",
        key=f"{TARGET}:80:tcp",
        value={"port": 80, "protocol": "tcp", "service": "http"},
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
        key=f"{TARGET}:80:sqli_union",
        value={"reason": "sqlmap UNION no logra inyección estable"},
        source="agent",
        created_by="agent",
    )
    closed = load_coverage(store, TENANT, ENGAGEMENT)
    assert closed.find(f"{TARGET}:80").status == STATUS_CLOSED

    board.record(
        tenant_id=TENANT,
        engagement_id=ENGAGEMENT,
        fact_type="vulnerability",
        key=f"{TARGET}:80:sqli_error_based_confirmed",
        value={"note": "extractvalue devuelve el nombre de la base"},
        source="agent",
        created_by="agent",
    )
    reopened = load_coverage(store, TENANT, ENGAGEMENT)
    assert reopened.find(f"{TARGET}:80").status == STATUS_PROBED
    entry_lines = [
        line for line in render_coverage(reopened).splitlines() if line.startswith("- ")
    ]
    assert entry_lines == [f"- {TARGET}:80/tcp http → sondeado (2 hechos)"]


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


def test_the_loop_injects_the_pivot_hint_once(tmp_path):
    """The wiring of ``pivot_hint``: an internal host gets the tunnel order.

    DeadDrop P8 (2026-10-22, iterations 51-69): with SSH access on
    ``192.168.11.200`` and the DC at ``192.168.11.100``, the run kept running
    local tools against the DC; nothing in the prompt named the tunnel.
    """
    from nexus_core.agent.react_coordinator import ReActCoordinator
    from nexus_core.kernel.audit import AuditWriter

    store = ControlStore(tmp_path / "pivot.db")
    store.initialize()
    run = store.create_run(TENANT, {})
    coordinator = ReActCoordinator.__new__(ReActCoordinator)
    coordinator.tenant_id = TENANT
    coordinator.engagement_id = ENGAGEMENT
    coordinator.agent_id = "omni"
    coordinator.active_subagent_id = "omni"
    coordinator.store = store
    coordinator.run_id = run["id"]
    coordinator.iteration = 12
    coordinator.plan = build_plan(counts={"service": 2})
    coordinator.audit = AuditWriter(store)
    coordinator.pivot_hint = ""
    coordinator.pivot_hint_emitted = False
    coordinator.actions = [
        {
            "tool_id": "nexus.recon.nmap",
            "arguments": {"target": "192.168.11.200"},
            "tool_result": {"output": {"hosts": ["192.168.11.200"]}},
        },
        {
            "tool_id": "nexus.post.ssh_exec",
            "arguments": {
                "target": "192.168.11.200",
                "username": "svc-drop",
                "command": "id",
            },
            "tool_result": {"output": {"stdout": "uid=1001(svc-drop)\n"}},
        },
        {
            "tool_id": "nexus.recon.nmap",
            "arguments": {"target": "192.168.11.100"},
            "tool_result": {"output": {}},
        },
    ]

    coordinator._refresh_pivot_hint()

    assert "PIVOTE NECESARIO" in coordinator.pivot_hint
    assert "svc-drop@192.168.11.200" in coordinator.pivot_hint
    events = [
        event
        for event in store.list_run_events(TENANT, run["id"])
        if event.get("event_type") == "react.pivot"
    ]
    assert len(events) == 1
    coordinator._refresh_pivot_hint()
    assert (
        len(
            [
                event
                for event in store.list_run_events(TENANT, run["id"])
                if event.get("event_type") == "react.pivot"
            ]
        )
        == 1
    )


def test_the_loop_withholds_the_directory_sweeps_until_the_login_is_probed(tmp_path):
    """P9 (2026-10-22): el aviso llegó en la 6 y el run fue a gobuster en la 8.

    Una orden en prosa no bastó dos veces (P1/P3 y P9), así que las tools de
    barrido salen del catálogo mientras el formulario leído no reciba la sonda
    canónica; vuelven en cuanto el bypass corre.
    """
    from nexus_core.agent.react_coordinator import ReActCoordinator
    from nexus_core.kernel.audit import AuditWriter

    store = ControlStore(tmp_path / "withhold.db")
    store.initialize()
    run = store.create_run(TENANT, {})
    coordinator = ReActCoordinator.__new__(ReActCoordinator)
    coordinator.tenant_id = TENANT
    coordinator.engagement_id = ENGAGEMENT
    coordinator.agent_id = "omni"
    coordinator.active_subagent_id = "omni"
    coordinator.store = store
    coordinator.run_id = run["id"]
    coordinator.iteration = 6
    coordinator.plan = build_plan(counts={"service": 2})
    coordinator.audit = AuditWriter(store)
    coordinator.login_hint = ""
    coordinator.login_hint_emitted = False
    coordinator.login_hints_sent = set()
    coordinator.login_withheld = set()
    coordinator.login_withheld_announced = False
    coordinator.actions = [
        {
            "tool_id": "nexus.web.request",
            "arguments": {"url": f"http://{TARGET}/login"},
            "tool_result": {
                "output": {
                    "body_preview": (
                        '<form method="POST" action="/login">'
                        '<input type="password" name="password"></form>'
                    )
                }
            },
        }
    ]

    coordinator._refresh_login_hint()

    assert "nexus.recon.gobuster" in coordinator.login_withheld
    assert "nexus.web.ffuf" in coordinator.login_withheld
    events = [
        event
        for event in store.list_run_events(TENANT, run["id"])
        if event.get("event_type") == "react.login_probe_withheld"
    ]
    assert len(events) == 1

    # The canonical bypass lands: the sweeps come back.
    coordinator.actions.append(
        {
            "tool_id": "nexus.web.request",
            "arguments": {
                "url": f"http://{TARGET}/login",
                "method": "POST",
                "data": "username=admin'-- -&password=x",
            },
            "tool_result": {"output": {"status": 302}},
        }
    )
    coordinator._refresh_login_hint()
    assert coordinator.login_withheld == set()
