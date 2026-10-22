"""Tanda C, Fix 6: the four gates, over N synthetic scenarios, no network.

Till this file every gate had its own unit test and no test ran them **in
sequence** against a scenario, so nothing caught the case the campaign actually
produced: each gate green on its own while the run closed with the plan at 7/12.
DeadDrop (2026-10-22) is the measured origin of each rule exercised here.

The harness is declarative on purpose. A scenario is a ``Scenario`` value that
names the surface (hosts, subnets, what the run already proved) and the gates the
run must pass; :func:`_run_gate_chain` walks them in the order the loop does:

``login_probe`` -> ``pivot_gate`` -> ``replay_fence`` -> ``completion_verifier``

Adding **S6** (an AD with Exchange, a cloud tenant) is a new entry in
``SCENARIOS``; the harness needs no change. Nothing here touches the network:
the LLM is not used, the reachability probe is injected, the tools are a
gateway handler that raises on purpose, and every host is synthetic
(``10.10.10.x``, ``172.16.x.x``, ``2001:db8::x``).
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest

from nexus_core.agent.engagement_plan import EngagementPlan, Todo, reconcile
from nexus_core.agent.planner import (
    LOGIN_PROBE_BYPASS,
    login_probe_pending,
    pivot_gate,
)
from nexus_core.agent.react_support import _completion_objections
from nexus_core.kernel.blackboard import Blackboard
from nexus_core.kernel.control_store import ControlStore
from nexus_core.kernel.credentials import resolve_credential_for
from nexus_core.kernel.errors import ApprovalRequired
from nexus_core.kernel.models import Identity, RunContext, ToolDefinition
from nexus_core.kernel.route_facts import route_key
from nexus_core.scope import EngagementScope

pytestmark = [pytest.mark.integration, pytest.mark.usefixtures("lab_scope")]

TENANT = "system"
#: Budget each scenario has in CI (Fix 6.4). The whole file runs in a second; the
#: assert is what keeps a future fixture from quietly needing a network timeout.
SCENARIO_BUDGET_SECONDS = 90

GATE_LOGIN = "login_probe"
GATE_PIVOT = "pivot_gate"
GATE_CREDENTIAL = "resolve_credential_for"
GATE_REPLAY = "replay_fence"
GATE_COMPLETION = "completion_verifier"


# --------------------------------------------------------------- scenario model
@dataclass(frozen=True)
class WebLogin:
    """A form the run read. ``probed=False`` means no canonical probe has run."""

    url: str
    probed: bool = False
    form_html: str = (
        '<form method="post" action="/login">'
        '<input name="username"><input type="password" name="password">'
        "</form>"
    )


@dataclass(frozen=True)
class PivotCase:
    """One unexecuted sweep and what the gate must decide about it."""

    access_host: str
    target: str
    scanned: tuple[str, ...]
    access_user: str = "svc-low"
    tool_id: str = "nexus.recon.nmap"
    #: The operator can reach the target itself: no pivot is needed.
    reachable: bool = False
    #: A verifier-proved route already covers access -> target.
    route: bool = False
    #: The same route, but asserted by the agent: a hypothesis, not a proof.
    agent_route: bool = False
    #: No SSH access at all: the rule does not apply and must stay silent.
    access: bool = True
    expect_blocked: bool = True


@dataclass(frozen=True)
class CredentialCase:
    """A board credential the Windows channel resolves (or refuses to guess)."""

    host: str
    username: str
    protocol: str
    service: str
    #: ``True``: a vault handle on the fact. ``False``: a hash somebody pasted,
    #: which is never injected.
    handle: bool = True
    expect_resolved: bool = True


@dataclass(frozen=True)
class CompletionCase:
    """What ``task_complete`` meets when the model tries to close."""

    open_todo: tuple[str, str, tuple[str, ...]] | None = None
    stale_finding: bool = False


@dataclass(frozen=True)
class Scenario:
    id: str
    surface: str
    web: WebLogin | None = None
    pivot: tuple[PivotCase, ...] = field(default_factory=tuple)
    credential: CredentialCase | None = None
    completion: CompletionCase = field(default_factory=CompletionCase)


# ------------------------------------------------------------------ the cases
#: Synthetic addresses only: no DeadDrop host appears here, so a failing run is
#: never confused with a live engagement.
SCENARIOS: tuple[Scenario, ...] = (
    Scenario(
        id="S1-linux-single-host",
        surface="1 host 10.10.10.11: sshd + web app with SQLi; svc-low -> root",
        web=WebLogin(url="http://10.10.10.11/login"),
        # Only one host was ever scanned and it is the access host, so no sweep
        # aims anywhere new: the pre-scan gate has nothing to refuse.
        pivot=(
            PivotCase(
                access_host="10.10.10.11",
                target="10.10.10.11",
                scanned=("10.10.10.11",),
                expect_blocked=False,
            ),
        ),
        completion=CompletionCase(
            open_todo=("root", "escalar a root en 10.10.10.11", ("privilege",)),
            stale_finding=True,
        ),
    ),
    Scenario(
        id="S2-dmz-ad",
        surface="2 hosts 10.10.10.200 (web+ssh) -> 10.10.10.100 (DC, internal)",
        web=WebLogin(url="http://10.10.10.200:8080/login.php"),
        pivot=(
            # No access: nothing to compare against, the gate stays silent.
            PivotCase(
                access_host="10.10.10.200",
                target="10.10.10.100",
                scanned=("10.10.10.200",),
                access=False,
                expect_blocked=False,
            ),
            # Access, no route, target unreachable: the sweep is refused.
            PivotCase(
                access_host="10.10.10.200",
                target="10.10.10.100",
                scanned=("10.10.10.200",),
                expect_blocked=True,
            ),
            # Same call once a verifier proved the tunnel: it runs.
            PivotCase(
                access_host="10.10.10.200",
                target="10.10.10.100",
                scanned=("10.10.10.200",),
                route=True,
                expect_blocked=False,
            ),
            # A route the agent asserted is not a route: still refused.
            PivotCase(
                access_host="10.10.10.200",
                target="10.10.10.100",
                scanned=("10.10.10.200",),
                agent_route=True,
                expect_blocked=True,
            ),
        ),
        completion=CompletionCase(
            open_todo=("pivot-dc", "llegar al DC 10.10.10.100", ("route",)),
        ),
    ),
    Scenario(
        id="S3-windows-ad-smb-pivot",
        surface="1 host 172.16.5.50 (SMB+WinRM), domain credential via pivote SMB",
        web=None,
        pivot=(
            PivotCase(
                access_host="172.16.5.50",
                target="172.16.5.10",
                scanned=("172.16.5.50",),
                tool_id="nexus.recon.netexec",
                expect_blocked=True,
            ),
            PivotCase(
                access_host="172.16.5.50",
                target="172.16.5.10",
                scanned=("172.16.5.50",),
                tool_id="nexus.recon.netexec",
                route=True,
                expect_blocked=False,
            ),
        ),
        credential=CredentialCase(
            host="172.16.5.50", username="svc_backup", protocol="winrm", service="smb"
        ),
        completion=CompletionCase(
            open_todo=("domain-admin", "probar admin de dominio", ("access",)),
        ),
    ),
    Scenario(
        id="S4-web-only",
        surface="1 host 2001:db8::10: app web sin SSH (la regla de pivote no aplica)",
        web=WebLogin(url="http://[2001:db8::10]/admin/login", probed=True),
        pivot=(),
        completion=CompletionCase(open_todo=None, stale_finding=False),
    ),
    Scenario(
        id="S5-three-subnets",
        surface="3 hosts en 3 subredes: 10.10.10.11 -> 10.20.20.22 -> 10.30.30.33",
        web=None,
        pivot=(
            # First hop: the tunnel to .22 is proved, the sweep runs.
            PivotCase(
                access_host="10.10.10.11",
                target="10.20.20.22",
                scanned=("10.10.10.11",),
                route=True,
                expect_blocked=False,
            ),
            # Second hop from the new access host: no route to .33 yet.
            PivotCase(
                access_host="10.20.20.22",
                target="10.30.30.33",
                scanned=("10.20.20.22",),
                expect_blocked=True,
            ),
            # ... and with the second verified route the cascade completes.
            PivotCase(
                access_host="10.20.20.22",
                target="10.30.30.33",
                scanned=("10.20.20.22",),
                route=True,
                expect_blocked=False,
            ),
        ),
        completion=CompletionCase(
            open_todo=("lan-33", "alcanzar 10.30.30.33", ("route",)),
        ),
    ),
)


# --------------------------------------------------------------- history model
def _web_actions(scenario: Scenario) -> list[dict[str, Any]]:
    web = scenario.web
    if web is None:
        return []
    actions: list[dict[str, Any]] = [
        {
            "tool_id": "nexus.web.http",
            "arguments": {"url": web.url},
            "tool_result": {"output": {"body_preview": web.form_html}},
        }
    ]
    if web.probed:
        actions.append(
            {
                "tool_id": "nexus.web.http",
                "arguments": {"url": web.url, "method": "POST", "data": LOGIN_PROBE_BYPASS},
                "tool_result": {"output": {"status_code": 302}},
            }
        )
    return actions


def _pivot_actions(case: PivotCase) -> list[dict[str, Any]]:
    """Recon from the operator, then (maybe) the interior shell."""
    actions = [
        {"tool_id": "nexus.recon.nmap", "arguments": {"target": host}}
        for host in case.scanned
    ]
    if case.access:
        actions.append(
            {
                "tool_id": "nexus.post.ssh_exec",
                "arguments": {
                    "target": case.access_host,
                    "username": case.access_user,
                    "command": "ip a",
                },
            }
        )
    return actions


def _route_fact(from_host: str, to_host: str, *, asserted_by: str = "verifier") -> dict[str, Any]:
    return {
        "fact_type": "route",
        "key": route_key(from_host, to_host),
        "verified": True,
        "asserted_by": asserted_by,
        "value": {
            "from_host": from_host,
            "to_host": to_host,
            "to_port": None,
            "method": "socks",
            "forwarder_ref": "127.0.0.1:1080",
            "verified_by": f"inv-route-{from_host}",
        },
    }


# ------------------------------------------------------------------- the gates
def _gate_login_probe(scenario: Scenario) -> None:
    """A read login form withholds the directory sweeps until it is probed."""
    expected = scenario.web is not None and not scenario.web.probed
    history = _web_actions(scenario)
    pending = login_probe_pending(history)
    assert pending == expected, (
        f"esperaba login_probe_pending={expected}, obtuvo {pending} "
        f"(url={getattr(scenario.web, 'url', None)})"
    )
    if scenario.web is None or scenario.web.probed:
        return
    # The gate has to open by itself once the bypass probe ran, otherwise the
    # withheld sweep comes back only in the next run.
    probed = history + [
        {
            "tool_id": "nexus.web.http",
            "arguments": {
                "url": scenario.web.url,
                "method": "POST",
                "data": LOGIN_PROBE_BYPASS,
            },
        }
    ]
    assert login_probe_pending(probed) is False, (
        "la sonda de bypass no desbloquea el gate: la herramienta retenida "
        "volvería en el run siguiente"
    )


def _gate_pivot(scenario: Scenario) -> None:
    """The pre-scan gate refuses a sweep with no proven route and no answer."""
    for index, case in enumerate(scenario.pivot):
        facts = []
        if case.route:
            facts.append(_route_fact(case.access_host, case.target))
        if case.agent_route:
            facts.append(_route_fact(case.access_host, case.target, asserted_by="agent"))

        async def probe(_host: str, _ports: Any, *, reachable: bool = case.reachable) -> bool:
            return reachable

        order = asyncio.run(
            pivot_gate(
                case.tool_id,
                {"target": case.target, "ports": "88,389,445"},
                _pivot_actions(case),
                probe=probe,
                facts=facts,
            )
        )
        blocked = bool(order)
        assert blocked == case.expect_blocked, (
            f"paso {index}: esperaba blocked={case.expect_blocked}, obtuve "
            f"blocked={blocked} (access={case.access_host if case.access else '(sin acceso)'}, "
            f"target={case.target}, reachable={case.reachable}, route={case.route}, "
            f"agent_route={case.agent_route})"
        )
        if blocked:
            assert case.target in order and case.access_host in order, (
                f"paso {index}: la orden de pivote no nombra host de acceso ni objetivo: {order!r}"
            )


def _gate_replay(scenario: Scenario, tmp_path) -> None:
    """An effect with unknown outcome is never replayed without a human."""
    from nexus_core.kernel.approvals import ApprovalService
    from nexus_core.kernel.audit import AuditWriter
    from nexus_core.kernel.invocation_journal import InvocationJournal
    from nexus_core.kernel.policy import PolicyEngine
    from nexus_core.kernel.tool_gateway import ToolGateway

    store = ControlStore(tmp_path / f"{scenario.id}-replay.db")
    store.initialize()
    gateway = ToolGateway(PolicyEngine(store), AuditWriter(store), ApprovalService(store))
    calls: list[dict[str, Any]] = []

    def handler(arguments: dict[str, Any], context: Any) -> Any:
        calls.append(dict(arguments))
        # The channel died after the command was sent: the effect may have
        # begun and nobody can say whether it did.
        raise RuntimeError("ssh channel closed after the command was sent")

    gateway.register(
        ToolDefinition("probe", TENANT, {}, tool_id="probe", effect="active"), handler
    )
    context = RunContext(
        TENANT,
        Identity("agent:omni", TENANT, kind="agent", roles=("operator",)),
        run_id=f"run-{scenario.id}",
        worker_id="cli:operator:kali",
        phase="exploitation",
        objective="prueba de la valla de replay",
        resume_policy="",
    )
    try:
        asyncio.run(gateway.invoke("probe", {"target": "10.10.10.11"}, context))
    except RuntimeError:
        pass
    else:  # pragma: no cover - the gateway always surfaces the failure
        pytest.fail("la primera invocación no propagó el fallo del handler")

    journal = InvocationJournal(store)
    states = journal.unknown_for_run(TENANT, context.run_id)
    assert len(states) == 1 and states[0]["state"] == "unknown", (
        f"el journal no dejó la invocación en unknown: {states}"
    )

    with pytest.raises(ApprovalRequired):
        asyncio.run(gateway.invoke("probe", {"target": "10.10.10.11"}, context))
    assert len(calls) == 1, (
        "el segundo intento llegó al handler sin aprobación: se reejecutó un "
        "efecto de resultado desconocido"
    )


def _gate_credential(scenario: Scenario, tmp_path, monkeypatch) -> None:
    """WinRM resolves exactly one board credential; a handle-less fact never."""
    case = scenario.credential
    if case is None:
        return
    from nexus_core.kernel.secret_store import default_secret_store

    monkeypatch.setenv("NEXUS_VAULT_ROOT", str(tmp_path / f"{scenario.id}-vault"))
    store = ControlStore(tmp_path / f"{scenario.id}-board.db")
    store.initialize()
    reference = ""
    if case.handle:
        reference = default_secret_store().put(
            b"Sup3rS3cret!", kind=case.service, tenant_id=TENANT
        )
    Blackboard(store).record(
        tenant_id=TENANT,
        engagement_id=f"eng-{scenario.id}",
        fact_type="credential",
        key=f"{case.username}@{case.host}",
        value={
            "username": case.username,
            "service": case.service,
            "host": case.host,
            "secret_ref": reference,
        },
        source="nexus.cred.bruteforce",
        created_by="verifier",
        verified=True,
        asserted_by="verifier",
        verification_method="smb_auth_ok",
        invocation_id=f"inv-{scenario.id}",
    )
    context = RunContext(
        TENANT,
        Identity("agent:omni", TENANT, kind="agent"),
        store=store,
        scope=_scope(scenario),
    )
    resolved = resolve_credential_for(
        case.host, case.username, case.protocol, context=context
    )
    if case.expect_resolved:
        assert resolved is not None and resolved.handle == reference, (
            f"esperaba resolver {case.username}@{case.host} por {case.protocol}, "
            f"obtuve {getattr(resolved, 'handle', None)!r}"
        )
    else:
        assert resolved is None, (
            f"un hecho sin handle no debe inyectarse, obtuve {getattr(resolved, 'handle', None)!r}"
        )


def _gate_completion(scenario: Scenario) -> None:
    """``task_complete`` is refused while the plan or the evidence says no."""
    case = scenario.completion
    engagement_id = f"eng-{scenario.id}"
    plan = None
    if case.open_todo is not None:
        todo_id, description, fact_types = case.open_todo
        plan = EngagementPlan(
            objective="objetivo sintético",
            engagement_id=engagement_id,
            todos=(Todo(id=todo_id, description=description, fact_types=fact_types),),
        )
    evidence: dict[str, Any] = {}
    if case.stale_finding:
        evidence = {
            "stale": 1,
            "unsupported": 0,
            "rejected_findings": [
                {
                    "finding_ref": "f1",
                    "reason": "stale_evidence",
                    "cited": {"invocation_id": "inv-missing", "fact_type": "loot"},
                    "found_in_corpus": False,
                }
            ],
        }
    objections = _completion_objections(
        None,
        enforce_completion_gates=True,
        evidence_stats=evidence,
        engagement_id=engagement_id,
        require_plan_phase=False,
        engagement_plan=plan,
        require_plan_first=False,
    )
    text = " | ".join(objections)
    if case.open_todo is not None:
        assert any("TODO(s) del plan" in item for item in objections), (
            f"esperaba un TODO abierto que bloquee el cierre, obtuve: {text!r}"
        )
    if case.stale_finding:
        assert any("stale_evidence" in item for item in objections), (
            f"esperaba el rechazo de la evidencia no soportada, obtuve: {text!r}"
        )
    if case.open_todo is None and not case.stale_finding:
        assert objections == [], (
            f"un cierre con la evidencia en orden no debe tener objeciones: {text!r}"
        )


def _scope(scenario: Scenario) -> EngagementScope:
    now = datetime.now(timezone.utc)
    return EngagementScope(
        engagement_id=f"eng-{scenario.id}",
        tenant_id=TENANT,
        name=scenario.id,
        client="synthetic",
        owner_id="owner-1",
        valid_from=(now - timedelta(days=1)).isoformat(),
        valid_until=(now + timedelta(days=1)).isoformat(),
        cidrs=("10.0.0.0/8", "172.16.0.0/12", "2001:db8::/32"),
        domains=(),
        urls=(),
        exclusions=(),
        created_at=now.isoformat(),
    )


def _run_gate_chain(scenario: Scenario, tmp_path, monkeypatch) -> None:
    """Run the four gates in loop order, naming the gate that failed."""
    gates = (
        (GATE_LOGIN, lambda: _gate_login_probe(scenario)),
        (GATE_PIVOT, lambda: _gate_pivot(scenario)),
        (GATE_REPLAY, lambda: _gate_replay(scenario, tmp_path)),
        (GATE_CREDENTIAL, lambda: _gate_credential(scenario, tmp_path, monkeypatch)),
        (GATE_COMPLETION, lambda: _gate_completion(scenario)),
    )
    started = time.perf_counter()
    for name, run in gates:
        try:
            run()
        except AssertionError as exc:
            raise AssertionError(f"[{scenario.id}] gate {name}: {exc}") from exc
    elapsed = time.perf_counter() - started
    assert elapsed < SCENARIO_BUDGET_SECONDS, (
        f"[{scenario.id}] la cadena de gates tardó {elapsed:.1f}s "
        f"(presupuesto {SCENARIO_BUDGET_SECONDS}s): algo está tocando la red"
    )


@pytest.mark.parametrize("scenario", SCENARIOS, ids=[item.id for item in SCENARIOS])
def test_gate_chain(scenario: Scenario, tmp_path, monkeypatch) -> None:
    _run_gate_chain(scenario, tmp_path, monkeypatch)


# ------------------------------------------------- 5b: the plan recalculates
def _dead_drop_plan() -> EngagementPlan:
    """The 7/12 shape of ``loot/ENGAGEMENT_PLAN.md``, reduced to what matters.

    ``apk-creds`` asked for a credential whose ``source`` was ``apk_decompile``
    and was ticked by the shadow crack instead, because both TODOs declared
    ``credential`` and nothing distinguished them.
    """
    return EngagementPlan(
        objective="comprometer el DMZ y el DC",
        engagement_id="eng-deaddrop",
        todos=(
            Todo(
                id="apk-creds",
                description="credenciales del APK descompilado",
                fact_types=("credential",),
                condition={"credential": {"source": "apk_decompile"}},
                status="done",
                verified_by="credential:hash:5f4dcc3b5aa765d61d8327deb882cf99",
            ),
            Todo(
                id="shadow-creds",
                description="credenciales del shadow crackeado",
                fact_types=("credential",),
                condition={"credential": {"source": "shadow_crack"}},
                status="done",
                verified_by="credential:hash:5f4dcc3b5aa765d61d8327deb882cf99",
            ),
            Todo(
                id="pivot-dc",
                description="llegar al DC",
                fact_types=("route",),
                status="pending",
            ),
        ),
    )


def _credential_fact(source: str) -> dict[str, Any]:
    """A verified credential fact whose *provenance* is ``source``.

    ``_condition_matches`` reads ``source`` from the fact's provenance -the
    verifier that produced it-, not from its value, so the TODO condition
    ``{"source": "apk_decompile"}`` distinguishes a decompilation from a shadow
    crack even though both write ``credential``.
    """
    return {
        "fact_type": "credential",
        "key": "svc-deploy",
        "source": source,
        "verified": True,
        "asserted_by": "verifier",
        "value": {"username": "svc-deploy", "source": source},
    }


def test_the_self_congratulated_todo_is_demoted_on_resume() -> None:
    plan = _dead_drop_plan()
    updated, ticks = reconcile(
        plan, [_credential_fact("shadow_crack")], revalidate=True
    )

    assert updated is not None and updated is not plan
    apk = updated.by_id("apk-creds")
    assert apk is not None and apk.status == "pending", (
        f"apk-creds seguía en {getattr(apk, 'status', None)!r} pese a que su "
        "condición no se cumple"
    )
    assert apk.verified_by == "", "la prueba falsa debe borrarse, no quedarse al lado"
    assert "expected source=apk_decompile" in apk.reason
    assert "got source=shadow_crack" in apk.reason
    # The TODO whose condition *is* satisfied keeps its tick.
    shadow = updated.by_id("shadow-creds")
    assert shadow is not None and shadow.done
    # Nothing new closed: the sweep is not a tick.
    assert ticks == []
    assert updated.counts()["done"] == 1


def test_revalidation_leaves_a_plan_whose_evidence_holds_untouched() -> None:
    facts = [
        _credential_fact("apk_decompile"),
        _credential_fact("shadow_crack"),
    ]
    plan = _dead_drop_plan()

    updated, _ = reconcile(plan, facts, revalidate=True)

    assert updated is plan, "un plan correcto no se reescribe"


def test_revalidation_is_off_by_default() -> None:
    """``update_plan`` keeps its behaviour: only resume turns the check on."""
    plan = _dead_drop_plan()

    updated, _ = reconcile(plan, [_credential_fact("shadow_crack")])

    assert updated is plan
    apk = plan.by_id("apk-creds")
    assert apk is not None and apk.done


def test_an_empty_board_never_demotes() -> None:
    """An unreadable board is "nothing loaded", not "nothing happened"."""
    plan = _dead_drop_plan()

    updated, _ = reconcile(plan, [], revalidate=True)

    assert updated is plan
