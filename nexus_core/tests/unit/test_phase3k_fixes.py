"""Phase 3k fixes: the evidence order of the kill chain, and the report's scope.

Measured in rerun 11 (``run_30bfde08591f47ad89c1c4d7bb1537bb`` against Bounty
Hacker, commit ``36b56e9``): the engine did the hard part again -anonymous FTP →
``locks.txt``/``task.txt`` → ``lin`` → hydra → the credential consumed through its
vault ref → ``ssh_exec`` → ``/home/lin/Desktop/user.txt`` = ``flag{fake_flag}``-
and then lost the run to its own plan:

* iteration 10 recorded the verified ``loot`` fact of the **user** flag;
* that alone closed ``post_exploitation`` (its evidence was ``loot``), so
  ``active_phase`` jumped to ``reporting`` and ``build_plan`` marked
  ``privilege_escalation`` ``done`` *by position*, with no ``privilege`` fact on
  the board -the pipeline literally claimed "Escalada de privilegios ✓" for a root
  the run never got;
* iteration 11 therefore selected the ``reporter`` profile, which is read-only and
  has no ``ssh_exec``: the model's ``sudo tar`` attempt was refused
  (``subagent_tool_denied``) and root became unreachable, so the four closure fixes
  of V1-35..V1-38 (which require a verified ``privilege``) could not fire at all;
* the reporter then generated a report whose ``run_ids`` included *another*
  engagement's runs (rerun 10 attacked the same IP and the selector fell back to
  "runs whose targets match this scope"), dated two hours before the engagement
  existed, and whose loot finding was the only one with an empty
  ``affected_targets``;
* it died on ``max_iterations=4`` right after the recovery turn that fetched the
  ``invocation_id`` it needed.

Five fixes, each pinned below: V1-39 (a bare ``loot`` does not close
post-exploitation), V1-40 (no phase is closed by position), V1-41 (the reporter has
the margin for one rejection and its recovery), V1-42 (the report is
engagement-scoped), V1-43 (the loot finding carries its target).
"""

from __future__ import annotations

from nexus_core.agent.planner import (
    STATUS_CURRENT,
    STATUS_DONE,
    STATUS_PENDING,
    active_phase,
    build_plan,
    escalate_session,
    session_handover,
)
from nexus_core.agent.subagents import SUBAGENTS_BY_ID
from nexus_core.kernel.audit import AuditWriter
from nexus_core.report.extract_facts import _fact_findings
from nexus_core.report.extractor import build_report
from nexus_core.tests import report_support as support

import pytest

pytestmark = pytest.mark.unit

TENANT = support.TENANT
TARGET = "10.0.0.1"
FLAG = "flag{fake_flag}"
SCOPE_TARGET = "203.0.113.10"

#: The board rerun 11 held when the user flag landed: recon, enumeration, initial
#: access and the loot -and no ``privilege``, because the escalation never ran.
RERUN11_COUNTS = {"host": 1, "service": 3, "credential": 1, "access": 1, "loot": 1}

#: The runner that must not have moved (V1-21's experiment owns ``exploit``, V1-41
#: owns ``reporter``).
UNTOUCHED_ITERATION_BUDGETS = {
    "recon": 8,
    "web": 10,
    "services": 10,
    "cred": 6,
    "postexploit": 8,
    "privesc": 10,
    "lateral": 8,
}


def _statuses(counts):
    return {item.id: item.status for item in build_plan(counts=counts).phases}


# =============================================================== FIX 1 · V1-39
def test_loot_alone_does_not_close_post_exploitation():
    """The measured bug: the user flag closed a phase the run had not reached."""
    plan = build_plan(counts=RERUN11_COUNTS)

    statuses = {item.id: item.status for item in plan.phases}
    assert statuses["post_exploitation"] == STATUS_PENDING
    # The chain stays where the escalation evidence is missing, instead of
    # claiming post-exploitation and jumping to the report.
    assert plan.current == "privilege_escalation"
    assert active_phase(RERUN11_COUNTS) == "privilege_escalation"
    assert plan.progress == (3, 6)


def test_loot_with_privilege_closes_post_exploitation():
    """Loot plus the escalated privilege is the real post-exploitation."""
    counts = {**RERUN11_COUNTS, "privilege": 1}
    plan = build_plan(counts=counts)

    statuses = {item.id: item.status for item in plan.phases}
    assert statuses["post_exploitation"] == STATUS_DONE
    assert plan.current == "reporting"
    assert plan.progress == (5, 6)


def test_loot_with_session_closes_post_exploitation():
    """An interactive session sustains the phase just like a privilege does."""
    counts = {**RERUN11_COUNTS, "session": 1}
    plan = build_plan(counts=counts)

    statuses = {item.id: item.status for item in plan.phases}
    assert statuses["post_exploitation"] == STATUS_DONE
    # Accepted consequence: the session closes post-exploitation without closing
    # the escalation phase -which is reported ``pending``, never ``done`` (V1-40).
    assert statuses["privilege_escalation"] == STATUS_PENDING
    assert plan.current == "reporting"


def test_post_exploitation_requires_real_escalation_evidence():
    """The sustainer is required: neither half of the rule closes it alone."""
    for counts in (
        {"host": 1, "service": 1, "access": 1, "artifact": 1},  # a bare artifact
        {**RERUN11_COUNTS, "artifact": 1},  # loot + artifact, no escalation
        {"host": 1, "service": 1, "access": 1, "privilege": 1},  # privilege, no loot
        {"host": 1, "service": 1, "access": 1, "session": 1},  # session, no loot
    ):
        assert _statuses(counts)["post_exploitation"] != STATUS_DONE, counts

    # And the session hand-over remains the deliberate way into the phase: the
    # rule (V1-25) closes the phase it leaves, because the hand-off *is* the
    # decision -unlike a status derived from a position.
    plan = build_plan(counts={"host": 1, "service": 1, "endpoint": 1, "session": 1})
    handed = escalate_session(
        plan, session_handover(plan, subagent_id="exploit", session_established=True)
    )
    assert handed.current == "post_exploitation"


# =============================================================== FIX 2 · V1-40
def test_build_plan_does_not_mark_prior_phase_done_without_evidence():
    """A later closed phase never closes an earlier mandatory one."""
    # `session` closes post-exploitation while privilege_escalation has no
    # `privilege` fact: the exact shape of the measured lie.
    counts = {**RERUN11_COUNTS, "session": 1}
    plan = build_plan(counts=counts)

    statuses = {item.id: item.status for item in plan.phases}
    assert statuses["post_exploitation"] == STATUS_DONE
    assert statuses["exploitation"] == STATUS_DONE
    assert statuses["privilege_escalation"] == STATUS_PENDING
    assert "privilege" not in plan.counts


def test_privilege_escalation_stays_pending_without_privilege_fact():
    """Without a ``privilege`` fact the phase is never ``done``."""
    # Current while nothing later is closed...
    assert _statuses(RERUN11_COUNTS)["privilege_escalation"] == STATUS_CURRENT
    # ...and pending (not done) as soon as a later phase closes.
    assert _statuses({**RERUN11_COUNTS, "session": 1})["privilege_escalation"] == STATUS_PENDING
    # A privilege fact -and only it- closes it.
    assert (
        _statuses({**RERUN11_COUNTS, "privilege": 1})["privilege_escalation"] == STATUS_DONE
    )


def test_plan_pipeline_does_not_lie_about_completed_phases():
    """The rendered pipeline is a claim about evidence, never about position."""
    rendered = build_plan(counts=RERUN11_COUNTS).pipeline()
    assert "Escalada de privilegios ▶" in rendered
    assert "Escalada de privilegios ✓" not in rendered
    assert "Post-explotación ·" in rendered

    with_session = build_plan(counts={**RERUN11_COUNTS, "session": 1}).pipeline()
    assert "Escalada de privilegios ·" in with_session
    assert "Escalada de privilegios ✓" not in with_session

    # The measurement, literally: with the privilege proven the phase reads ✓.
    proven = build_plan(counts={**RERUN11_COUNTS, "privilege": 1}).pipeline()
    assert "Escalada de privilegios ✓" in proven


def test_single_session_does_not_close_lateral():
    """Regression of the optional phase: it too is closed only by its evidence."""
    statuses = _statuses({**RERUN11_COUNTS, "privilege": 1, "session": 1})
    assert statuses["lateral_movement"] == STATUS_PENDING
    assert _statuses({**RERUN11_COUNTS, "privilege": 1, "session": 2})[
        "lateral_movement"
    ] == STATUS_DONE


# =============================================================== FIX 3 · V1-41
def test_reporter_subagent_max_iterations_is_six():
    """The rejection loop needs a turn more than it had."""
    reporter = SUBAGENTS_BY_ID["reporter"]
    assert reporter.max_iterations == 6
    # The lever is the iteration count: the token budget and the profile's
    # read-only boundary are untouched (V1-21 stays closed).
    assert reporter.token_budget == 30_000
    assert reporter.read_only is True


def test_other_subagents_iteration_budgets_are_unchanged():
    """Only the two deliberate budgets moved (V1-21's ``exploit``, V1-41's)."""
    budgets = {profile.id: profile.max_iterations for profile in SUBAGENTS_BY_ID.values()}
    assert budgets == {"exploit": 15, "reporter": 6, **UNTOUCHED_ITERATION_BUDGETS}


# =============================================================== FIX 4 · V1-42
def _run_for(store, engagement_id: str) -> str:
    """Create a run exactly like the CLI does: the context names the engagement."""
    return str(
        store.create_run(
            TENANT, {"source": "omni-headless", "engagement_id": engagement_id}
        )["id"]
    )


def _two_engagements_same_target(tmp_path):
    """The rerun 11 shape: two engagements whose scopes cover the same host."""
    store = support.make_store(tmp_path)
    support.seed_engagement(store, support.lab_scope("eng-a", name="eng-a"))
    support.seed_engagement(store, support.lab_scope("eng-b", name="eng-b"))
    run_a = _run_for(store, "eng-a")
    run_b = _run_for(store, "eng-b")
    # eng-a worked the same host with a tool eng-b never used, and left a failure.
    support.record(
        store,
        run_a,
        "nexus.recon.nmap",
        {"target": SCOPE_TARGET, "ports": "22,80"},
        support.result(support.nmap_output(), verification_method="nmap_xml_parsed"),
        engagement_id="eng-a",
    )
    support.record(
        store,
        run_a,
        "nexus.web.nuclei",
        {"targets": [SCOPE_TARGET]},
        support.result(
            support.nuclei_output((support.nuclei_finding(),)),
            verification_method="nuclei_jsonl_parsed",
        ),
        engagement_id="eng-a",
    )
    support.record(
        store,
        run_a,
        "nexus.web.ffuf",
        {"url": f"http://{SCOPE_TARGET}/FUZZ"},
        support.result({}, verified=False, verification_method="ffuf_failed"),
        engagement_id="eng-a",
    )
    support.record(
        store,
        run_b,
        "nexus.recon.nmap",
        {"target": SCOPE_TARGET, "ports": "22,80"},
        support.result(support.nmap_output(), verification_method="nmap_xml_parsed"),
        engagement_id="eng-b",
    )
    return store, run_a, run_b


async def test_report_generate_filters_by_engagement_not_tenant(tmp_path):
    """The report of one engagement never contains another one's work."""
    store, run_a, run_b = _two_engagements_same_target(tmp_path)

    report_b = await build_report(store, TENANT, "eng-b", enrich_cves=False)
    report_a = await build_report(store, TENANT, "eng-a", enrich_cves=False)

    # eng-a's exclusive tool and its failure stay out of eng-b's deliverable.
    assert "nexus.recon.nmap" in report_b.tools_used
    assert "nexus.web.nuclei" not in report_b.tools_used
    assert "nexus.web.ffuf" not in report_b.tools_used
    assert all(item.tool_id != "nexus.web.nuclei" for item in report_b.timeline)
    assert report_b.failed_attempts == ()
    assert report_a.failed_attempts  # the failure is real, and it belongs to eng-a

    # The counts are the engagement's, not the tenant's.
    events = list(AuditWriter(store).export(TENANT))
    own_b = [event for event in events if str(event.get("trace_id") or "") == run_b]
    assert len(own_b) > 0 and len(own_b) < len(events)
    assert report_b.audit_events_total == len(own_b)
    assert report_a.audit_events_total == len(events) - len(own_b)

    # Two engagements on the same host produce two disjoint finding sets.
    ids_a = {finding.finding_id for finding in report_a.findings}
    ids_b = {finding.finding_id for finding in report_b.findings}
    assert ids_a and ids_b and not (ids_a & ids_b)


async def test_report_run_ids_only_include_engagement_runs(tmp_path):
    store, run_a, run_b = _two_engagements_same_target(tmp_path)

    report_b = await build_report(store, TENANT, "eng-b", enrich_cves=False)
    report_a = await build_report(store, TENANT, "eng-a", enrich_cves=False)

    assert report_b.run_ids == (run_b,)
    assert report_a.run_ids == (run_a,)
    assert run_a not in report_b.run_ids
    assert run_b not in report_a.run_ids


async def test_report_started_at_matches_first_engagement_run(tmp_path):
    store, run_a, run_b = _two_engagements_same_target(tmp_path)
    # A second run of eng-b, so "first" has to be a real choice.
    later = str(
        store.create_run(
            TENANT, {"source": "omni-headless", "engagement_id": "eng-b"}
        )["id"]
    )
    support.record(
        store,
        later,
        "nexus.recon.nmap",
        {"target": SCOPE_TARGET, "ports": "22,80"},
        support.result(support.nmap_output(), verification_method="nmap_xml_parsed"),
        engagement_id="eng-b",
    )
    first = str(store.get_run(run_b, TENANT)["created_at"])
    other = str(store.get_run(later, TENANT)["created_at"])
    foreign = str(store.get_run(run_a, TENANT)["created_at"])

    report = await build_report(store, TENANT, "eng-b", enrich_cves=False)

    assert report.started_at == min(first, other)
    # The measured bug: the earliest event of the *tenant* won, so the report was
    # dated before the engagement existed.
    assert report.started_at != foreign
    assert report.run_ids == tuple(sorted({run_b, later}))


# =============================================================== FIX 5 · V1-43
def _verified_fact(fact_type: str, key: str, value: dict, invocation_id: str):
    return {
        "fact_type": fact_type,
        "key": key,
        "value": value,
        "verified": True,
        "asserted_by": "verifier",
        "verification_method": "ssh_exec_completed",
        "invocation_id": invocation_id,
    }


def test_loot_finding_includes_target():
    """The captured artifact carries the host its invocation ran against."""
    invocation = "a7206eadee9941b3b53bde21537458bf"
    access = _verified_fact(
        "access", TARGET, {"transport": "ssh", "username": "lin"}, invocation
    )
    loot = _verified_fact(
        "loot",
        FLAG,
        {"flag": FLAG, "command": "cat /home/lin/Desktop/user.txt", "service": "ssh"},
        invocation,
    )
    # The scope covers the invocation's host and the second host of the case
    # below, so only the deliberate out-of-scope variant is filtered.
    scope = support.lab_scope(
        "eng-3k", cidrs=(f"{TARGET}/32", "203.0.113.0/24"), domains=()
    )

    findings = _fact_findings([access, loot], scope=scope)
    loot_findings = [finding for finding in findings if finding.kind == "fact_loot"]

    assert len(loot_findings) == 1
    assert loot_findings[0].affected_targets == (TARGET,)

    # The recovered target takes part in the scope filter: attributed to a host
    # outside the signed scope, the artifact is still a fact but not an impact.
    outside = support.lab_scope("eng-out", cidrs=("192.168.0.0/16",), domains=())
    assert [finding for finding in _fact_findings([access, loot], scope=outside)
            if finding.kind == "fact_loot"] == []

    # An explicit target in the value wins over the invocation's host...
    explicit = _verified_fact(
        "loot", "explicit", {"flag": FLAG, "target": SCOPE_TARGET}, invocation
    )
    value_target = [
        finding
        for finding in _fact_findings([access, explicit], scope=scope)
        if finding.kind == "fact_loot"
    ]
    assert value_target and value_target[0].affected_targets == (SCOPE_TARGET,)

    # ...and with no host to recover, nothing is invented.
    lone = _verified_fact("loot", "lone", {"flag": FLAG}, "invocation-without-host")
    lonely = _fact_findings([lone], scope=scope)
    assert len(lonely) == 1 and lonely[0].affected_targets == ()
