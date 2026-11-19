"""Phase 3j fixes: knowing when to stop once the room is already solved.

Measured in rerun 10 (``run_179cef8b7b424b339caba3d2093eed9d`` against Bounty
Hacker, commit ``0525fa9``): the flow finally worked -FTP → hydra → the verified
credential consumed through its vault ref → ``ssh_exec`` → ``sudo /bin/tar`` →
``uid=0(root)`` → ``root.txt = flag{fake_flag}`` -and the run still ended
badly. The four problems are all about *closure*:

* V1-35 - the planner never saw that the objective was met, so the agent kept
  hunting a ``user.txt`` that does not exist on the instance.
* V1-36 - ``post_exploitation`` never selected the ``postexploit`` profile.
* V1-37 - a verified ``loot`` fact (the captured flag) produced no finding, so the
  deliverable reported ``findings: 0`` with the room compromised.
* V1-38 - ``privesc`` spent 63 224 of its 60 000 tokens *after* the success and the
  run died without ``task_complete``.

Each test below fails on the pre-fix engine.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest

from nexus_core.agent.planner import (
    SSH_ACCESS_METHOD,
    apply_objective_completion,
    build_plan,
    enumeration_still_open,
    loot_is_evidence,
    objective_completion,
    top_privilege,
)
from nexus_core.agent.react_coordinator import ReActCoordinator
from nexus_core.agent.react_types import OBJECTIVE_COMPLETE_EVENT_TYPE
from nexus_core.agent.subagents import select_for_plan
from nexus_core.agent.turn_telemetry import TurnTelemetryRecorder
from nexus_core.kernel.blackboard import Blackboard
from nexus_core.kernel.control_store import ControlStore
from nexus_core.report.extract_facts import _fact_findings
from nexus_core.report.extraction_support import _Collection, _Context

pytestmark = pytest.mark.unit

TENANT = "system"
ENGAGEMENT = "eng-3j"
TARGET = "10.0.0.1"
FLAG = "flag{fake_flag}"

#: The evidence rerun 10 had on the board when it died.
RERUN10_COUNTS = {"host": 1, "service": 3, "credential": 1, "access": 1, "loot": 1}


# --------------------------------------------------------------------- helpers
def _board(tmp_path, *, host="10.0.0.1"):
    store = ControlStore(tmp_path / "control.db")
    store.initialize()
    return Blackboard(store), store


def _verified(board, *, fact_type, key, value, method="ssh_exec_completed"):
    return board.record(
        tenant_id=TENANT,
        engagement_id=ENGAGEMENT,
        fact_type=fact_type,
        key=key,
        value=value,
        source="nexus.post.ssh_exec",
        created_by="deterministic-verifier",
        verified=True,
        asserted_by="verifier",
        verification_method=method,
        invocation_id="inv-rerun10-1",
    )


def _privilege_fact(*, verified=True, user="root", uid=0):
    return {
        "fact_type": "privilege",
        "key": TARGET,
        "value": {"uid": uid, "user": user},
        "source": "nexus.post.ssh_exec",
        "verified": verified,
        "asserted_by": "verifier" if verified else "agent",
        "verification_method": SSH_ACCESS_METHOD if verified else "",
        "invocation_id": "inv-1" if verified else "",
    }


def _loot_fact(*, verified=True, key=FLAG, **value):
    payload = {"flag": key, "command": "cat /root/root.txt", "service": "ssh"}
    payload.update(value)
    return {
        "fact_type": "loot",
        "key": key,
        "value": payload,
        "source": "nexus.post.ssh_exec",
        "verified": verified,
        "asserted_by": "verifier" if verified else "agent",
        "verification_method": SSH_ACCESS_METHOD if verified else "",
        "invocation_id": "inv-1" if verified else "",
    }


def _bare_coordinator(store, *, run_id, plan, subagent_id="privesc", iteration=14):
    """The coordinator stripped to the state the closure rules read."""
    coordinator = ReActCoordinator.__new__(ReActCoordinator)
    coordinator.tenant_id = TENANT
    coordinator.engagement_id = ENGAGEMENT
    coordinator.store = store
    coordinator.run_id = run_id
    coordinator.iteration = iteration
    coordinator.plan = plan
    coordinator.plan_reason = None
    coordinator.status = ""
    coordinator.final_summary = ""
    coordinator.last_phase = plan.current
    coordinator.last_subagent_id = subagent_id
    coordinator.subagent_override = None
    coordinator.subagent_iterations = 1
    coordinator.previous_profile = None
    coordinator.objective_complete = False
    coordinator.objective_complete_emitted = False
    coordinator.budget_exempt = False
    coordinator.telemetry = TurnTelemetryRecorder(
        store=store, tenant_id=TENANT, run_id=run_id
    )
    return coordinator


def _events(store, run_id, event_type):
    return [e for e in store.list_run_events(TENANT, run_id) if e.get("event_type") == event_type]


def _scope(*cidrs):
    return SimpleNamespace(cidrs=tuple(cidrs), domains=(), exclusions=(), urls=())


def _collection(scope):
    return _Collection(
        scope=scope,
        events=[],
        scoped_events=[],
        observations=[],
        selected=set(),
        context=_Context(scope=scope),
        undecodable=0,
    )


# ---------------------------------------------------------------- FIX A · V1-35
def test_planner_detects_objective_complete_with_root_and_loot():
    completion = objective_completion(
        [_privilege_fact(), _loot_fact()], subagent_id="privesc"
    )

    assert completion.complete is True
    assert completion.privilege_ref == TARGET
    assert completion.loot_refs == (FLAG,)
    assert completion.hint and "task_complete" in completion.hint
    assert completion.to_payload() == {"privilege_ref": TARGET, "loot_refs": [FLAG]}

    # The hint travels in the prompt, and it is a hint: the phases are untouched.
    plan = build_plan(counts={"host": 1, "service": 1, "credential": 1, "access": 1})
    hinted = apply_objective_completion(plan, completion)
    assert hinted.objective_complete is True
    assert "OBJETIVO CUMPLIDO" in hinted.render()
    assert hinted.progress == plan.progress and hinted.current == plan.current
    assert hinted.to_dict()["objective_complete"] is True

    # Only the profiles that own the tail of the chain are the rule's case.
    for subagent in ("recon", "services", "cred", "web", "exploit", None, ""):
        assert objective_completion(
            [_privilege_fact(), _loot_fact()], subagent_id=subagent
        ).complete is False


def test_planner_does_not_flag_complete_without_root():
    assert objective_completion([_loot_fact()], subagent_id="privesc").complete is False
    # A privilege fact naming a non-top account is real evidence, not the top.
    assert objective_completion(
        [_privilege_fact(user="lin", uid=1001), _loot_fact()], subagent_id="privesc"
    ).complete is False
    # An agent-recorded privilege is a lead.
    assert objective_completion(
        [_privilege_fact(verified=False), _loot_fact()], subagent_id="privesc"
    ).complete is False

    assert top_privilege({"uid": 0}) is True
    assert top_privilege({"user": "root"}) is True
    assert top_privilege({"username": "SYSTEM"}) is True
    assert top_privilege({"account": "NT AUTHORITY\\SYSTEM"}) is True
    assert top_privilege({"uid": 1001, "user": "lin"}) is False
    assert top_privilege({}) is False


def test_planner_does_not_flag_complete_without_loot():
    assert objective_completion([_privilege_fact()], subagent_id="privesc").complete is False
    # A loot fact without a digest or a flag-shaped token is a note, not loot.
    note = _loot_fact(key="notas", flag="", sha256="")
    assert loot_is_evidence(note["value"]) is False
    assert objective_completion(
        [_privilege_fact(), note], subagent_id="privesc"
    ).complete is False
    # An agent-recorded loot is a lead.
    assert objective_completion(
        [_privilege_fact(), _loot_fact(verified=False)], subagent_id="privesc"
    ).complete is False

    assert loot_is_evidence({"flag": FLAG}) is True
    assert loot_is_evidence({"sha256": "a" * 64}) is True
    assert loot_is_evidence({"flag": "", "note": "visto algo"}) is False


def test_objective_complete_event_is_emitted(tmp_path):
    board, store = _board(tmp_path)
    run = store.create_run(TENANT, {})
    _verified(board, fact_type="privilege", key=TARGET, value={"uid": 0, "user": "root"})
    _verified(board, fact_type="loot", key=FLAG, value={"flag": FLAG, "service": "ssh"})
    # V1-39: the board carries the escalated privilege too, so every phase is
    # closed by its own evidence and the plan sits on the closing phase. Without
    # it the plan no longer reaches `reporting` -that is exactly what the fix
    # changes- and the field below would be measuring the other bug.
    coordinator = _bare_coordinator(
        store, run_id=run["id"], plan=build_plan(counts=RERUN10_COUNTS | {"privilege": 1})
    )

    coordinator._refresh_objective_complete()

    assert coordinator.objective_complete is True
    assert coordinator.plan.objective_complete is True
    events = _events(store, run["id"], OBJECTIVE_COMPLETE_EVENT_TYPE)
    assert len(events) == 1
    payload = events[0]["payload"]
    assert payload["privilege_ref"] == TARGET
    assert payload["loot_refs"] == [FLAG]
    # The turn that notices it is still the previous profile's: the plan is
    # rebuilt from the board (here every phase is closed, so `reporting`) and the
    # profile only changes on the *next* selection -which is the window the rule
    # covers.
    assert payload["subagent_id"] == "privesc"
    assert payload["phase"] == "reporting"

    # The signal is per run: refreshing again must not duplicate it.
    coordinator._refresh_objective_complete()
    assert len(_events(store, run["id"], OBJECTIVE_COMPLETE_EVENT_TYPE)) == 1


# ---------------------------------------------------------------- FIX B · V1-36
def test_ssh_access_handoff_selects_postexploit_subagent():
    """An SSH-based access hand-off lands on the profile that owns `post.*`."""
    plan = build_plan(
        counts={"host": 1, "service": 1, "credential": 1, "access": 1, "privilege": 1}
    )

    assert plan.current == "post_exploitation"
    assert "loot" not in plan.counts
    assert select_for_plan(plan).id == "postexploit"
    assert SSH_ACCESS_METHOD == "ssh_exec_completed"

    # The enumeration latch is bounded by the board's own counts: it keeps the
    # forced phase while nothing closes `enumeration`, and lets go as soon as the
    # evidence does (otherwise the phase -and with it the profile- is monopolised).
    assert enumeration_still_open(build_plan(counts={"host": 1, "service": 1})) is True
    assert enumeration_still_open(
        build_plan(counts={"host": 1, "service": 1, "access": 1})
    ) is False
    assert enumeration_still_open(
        build_plan(counts={"host": 1, "service": 1, "credential": 1})
    ) is False


def test_postexploit_profile_is_selected_on_post_phase_without_loot():
    without_loot = build_plan(
        counts={"host": 1, "service": 1, "credential": 1, "access": 1, "privilege": 1}
    )
    assert select_for_plan(without_loot).id == "postexploit"

    # With the flag already captured the phase is closed by that evidence, so the
    # plan moves on to `reporting` and the closing profile takes over: in rerun 10
    # `postexploit` was legitimately never needed once the loot landed.
    with_loot = build_plan(counts=RERUN10_COUNTS | {"privilege": 1})
    assert with_loot.current == "reporting"
    assert select_for_plan(with_loot).id == "reporter"


# ---------------------------------------------------------------- FIX C · V1-37
def test_loot_verified_fact_becomes_confirmed_finding():
    findings = _fact_findings([_loot_fact()], scope=_scope(f"{TARGET}/32"))

    assert len(findings) == 1
    finding = findings[0]
    assert finding.kind == "fact_loot"
    assert finding.verification_status == "confirmed_finding"
    assert finding.severity == "high"
    assert finding.cvss_score is not None and finding.cvss_vector
    assert FLAG in finding.title and FLAG in finding.description
    assert finding.discovered_by_tool == "nexus.post.ssh_exec"

    # A captured secret is a credential exposure, not just a captured file.
    secret = _fact_findings(
        [_loot_fact(key="creds", secret_ref="vault:" + "a" * 32)], scope=_scope(f"{TARGET}/32")
    )[0]
    assert secret.severity == "critical"
    assert secret.cvss_score is not None

    # An agent-recorded loot is a hypothesis, and the report does not confirm it.
    lead = _fact_findings([_loot_fact(verified=False)], scope=_scope(f"{TARGET}/32"))
    assert lead == []


def test_loot_from_out_of_scope_target_is_not_finding():
    scope = _scope(f"{TARGET}/32")
    inside = _fact_findings([_loot_fact(key="in", target=TARGET)], scope=scope)
    outside = _fact_findings([_loot_fact(key="out", target="10.0.0.99")], scope=scope)

    assert len(inside) == 1 and inside[0].affected_targets == (TARGET,)
    assert outside == []
    # Without a scope the extractor cannot filter, so the fact is reported.
    assert len(_fact_findings([_loot_fact(key="out", target="10.0.0.99")])) == 1


def test_report_findings_count_matches_verified_loot_count(tmp_path):
    from nexus_core.report.extractor import findings_from_collection

    scope = _scope(f"{TARGET}/32")
    facts = [
        _loot_fact(key=FLAG, target=TARGET),
        _loot_fact(key="flag{fake_flag}", target=TARGET),
        _loot_fact(key="dump", sha256="b" * 64, target=TARGET),
        _loot_fact(key="lead-only", verified=False, target=TARGET),
        _loot_fact(key="elsewhere", target="10.0.0.99"),
    ]

    findings, failed = findings_from_collection(_collection(scope), facts)

    loot = [finding for finding in findings if finding.kind == "fact_loot"]
    # V0-33: the first two facts use the *same* loot key, so they are one
    # canonical fact, not two findings. ``dump`` is the second distinct one;
    # the unverified lead and the out-of-scope target stay out of the count.
    assert len(loot) == 2
    assert {finding.title for finding in loot} == {
        f"Loot capturado: {FLAG}",
        "Loot capturado: dump",
    }
    assert all(finding.verification_status == "confirmed_finding" for finding in loot)
    assert failed == []


# ---------------------------------------------------------------- FIX D · V1-38
def _over_budget_coordinator(tmp_path, *, with_objective: bool):
    """The state rerun 10 died in: the closing phase, over the profile's ceiling.

    ``objective_complete`` is set directly: *detecting* it is V1-35's test above,
    this one isolates what the flag changes in the budget check.
    """
    board, store = _board(tmp_path)
    run = store.create_run(TENANT, {})
    plan = build_plan(counts=RERUN10_COUNTS | {"privilege": 1})
    assert plan.current == "reporting"
    coordinator = _bare_coordinator(
        store, run_id=run["id"], plan=plan, subagent_id="reporter", iteration=18
    )
    _verified(board, fact_type="privilege", key=TARGET, value={"uid": 0, "user": "root"})
    _verified(board, fact_type="loot", key=FLAG, value={"flag": FLAG, "service": "ssh"})
    # The board says so, and the tail profiles are the ones that see it.
    assert objective_completion(coordinator._blackboard_facts(), subagent_id="postexploit").complete
    coordinator.objective_complete = with_objective
    # The profile that owns the turn is already over its own ceiling.
    store.record_usage(TENANT, run["id"], "model_route", "react:reporter", "tokens", 31_000)
    return coordinator, store, run


def test_objective_complete_allows_task_complete_over_budget(tmp_path):
    """The turn that closes the run is not the turn the ceiling kills."""
    coordinator, store, run = _over_budget_coordinator(tmp_path, with_objective=True)
    # `reporting` is the phase the completion gate requires, so the model can
    # actually close instead of being refused as premature.
    assert coordinator.plan.current == "reporting"

    transition = asyncio.run(coordinator._select_profile())

    assert transition.name == "READY"
    assert coordinator.budget_exempt is True
    assert coordinator.status != "subagent_budget_exceeded"
    exempt = _events(store, run["id"], "react.budget_exempt")
    assert len(exempt) == 1
    payload = exempt[0]["payload"]
    assert payload["budget_exempt_if_objective_complete"] is True
    assert payload["subagent_id"] == "reporter"
    assert payload["spent"] == 31_000


def test_budget_still_enforced_without_objective_complete(tmp_path):
    coordinator, _, _ = _over_budget_coordinator(tmp_path, with_objective=False)
    assert coordinator.objective_complete is False
    assert coordinator._blackboard_facts()  # the facts are there; the verdict is not

    transition = asyncio.run(coordinator._select_profile())

    assert transition.name == "STOP"
    assert coordinator.status == "subagent_budget_exceeded"
    assert "exhausted its token budget" in coordinator.final_summary
    assert coordinator.budget_exempt is False


@pytest.fixture(autouse=True)
def _legacy_phase_loop(monkeypatch):
    """WP2: these tests pin the phase-gated loop, now behind the legacy flag."""
    monkeypatch.setenv("NEXUS_LEGACY_PROFILES", "1")
