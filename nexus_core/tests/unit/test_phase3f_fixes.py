"""V1-24 / V1-25: an accepted MSF session reaches the planner (rerun 6).

Measured in ``run_66eb363ed2fd42bf9d30985b76bf3248``
(``docs/missions/diag/diag_rerun6_2026-10-15.md``): ``ms17_010_psexec`` opened a
SYSTEM Meterpreter, the 9A provenance verifier accepted it
(``session_established``), ``kernel_sessions`` got its first row -and the plan
never moved. ``derive_assertions`` had no branch for ``nexus.exploit.msf_exploit``,
so an accepted session asserted nothing (``assertions: []``), ``exploitation``
could not close (``progress [2, 6]``) and the ``exploit`` profile -which has no
session tools- burned its whole token budget on the phase it had already won.

These tests pin both halves of the fix and nothing else: the fact is derived from
the result the handler really returns, and the deterministic rule hands the
engagement over to post-exploitation only when that fact exists.
"""

import json
from pathlib import Path
from types import SimpleNamespace

from nexus_core.agent.planner import (
    SESSION_ESTABLISHED_REASON,
    STATUS_CURRENT,
    STATUS_DONE,
    build_plan,
    escalate_session,
    established_msf_session,
    session_handover,
)
from nexus_core.kernel.fact_verification import MSF_SESSION_METHOD, derive_assertions
from nexus_core.kernel.models import ToolResult

FIXTURE = (
    Path(__file__).resolve().parents[1]
    / "fixtures"
    / "metasploit"
    / "rerun5_session_provenance.json"
)
TARGET = "10.65.175.32"
MODULE = "exploit/windows/smb/ms17_010_psexec"
SYSTEM_INFO = "NT AUTHORITY\\SYSTEM @ WIN-JO6REVNMMMP"


def _context():
    return SimpleNamespace(invocation_id="inv-1", run_id="run-1")


def _session_record(**overrides):
    """The session record rerun 6's own result carried, verbatim in its fields."""
    record = {
        "uuid": "xeftgmsm",
        "type": "meterpreter",
        "via_exploit": MODULE,
        "via_payload": "payload/windows/x64/meterpreter/reverse_tcp",
        "session_host": TARGET,
        "session_port": 445,
        "target_host": TARGET,
        "tunnel_peer": f"{TARGET}:50300",
        "tunnel_local": "192.168.144.132:4444",
        "username": "kali",
        # msfrpcd answered an empty descriptor when the session had just opened.
        "info": "",
    }
    record.update(overrides)
    return record


def _exploit_result(session, *, method="session_established", verified=True, evidence=None):
    """The ``ToolResult`` shape ``msf_exploit`` really produces (rerun 6 artifact)."""
    return ToolResult(
        output={
            "status": "session_opened" if session else "failed",
            "module": MODULE,
            "target": TARGET,
            "session": session,
            "job_uuid": "Yeq7Bo0Ccjh6KywmeXJ0PjZf",
            "raw_sha256": "a" * 64,
            "duration_seconds": 11.092,
        },
        verified=verified,
        verification_method=method,
        evidence=evidence or {},
    )


def _facts(result):
    return derive_assertions("nexus.exploit.msf_exploit", {}, result, _context())


def test_msf_exploit_derives_session_fact_on_success():
    session = _session_record()
    facts = _facts(_exploit_result(session, evidence={"session_uuid": "xeftgmsm"}))

    assert [fact["fact_type"] for fact in facts] == ["session"]
    fact = facts[0]
    assert fact["key"] == f"{TARGET}:xeftgmsm"
    assert fact["target"] == TARGET
    assert fact["value"] == {
        "session_uuid": "xeftgmsm",
        "via_exploit": MODULE,
        "target": TARGET,
        # The descriptor was empty, so no account is claimed; ``username`` of the
        # session record ("kali") is never read as the target's identity.
        "user": None,
        "sid": None,
    }
    assert fact["verified"] is True
    assert fact["asserted_by"] == "verifier"
    assert fact["verification_method"] == MSF_SESSION_METHOD
    assert fact["invocation_id"] == "inv-1" and fact["run_id"] == "run-1"


def test_msf_exploit_derives_access_fact_on_success():
    facts = _facts(
        _exploit_result(_session_record(info=SYSTEM_INFO), evidence={"sid": 2})
    )

    assert [fact["fact_type"] for fact in facts] == ["session", "access"]
    session, access = facts
    # The sid travels from the evidence when the result exposes it, so the
    # operator can tie the fact to a `session.list` row (the result carries the
    # RPC job id instead: 9 vs 2 in the measured run).
    assert session["value"]["user"] == "NT AUTHORITY\\SYSTEM"
    assert session["value"]["sid"] == 2
    assert access["key"] == f"{TARGET}:NT AUTHORITY\\SYSTEM@xeftgmsm"
    assert access["target"] == TARGET
    assert access["value"] == {
        "kind": "meterpreter",
        "user": "NT AUTHORITY\\SYSTEM",
        "via_exploit": MODULE,
    }
    assert access["verified"] is True and access["asserted_by"] == "verifier"
    assert access["verification_method"] == MSF_SESSION_METHOD


def test_msf_exploit_does_not_derive_on_ambiguous_or_unverified():
    session = _session_record(info=SYSTEM_INFO)
    for method in ("session_provenance_ambiguous", "session_provenance_unverified"):
        result = _exploit_result(session, method=method, verified=False)
        assert _facts(result) == []
    # Nor from a result that names a session it did not carry, nor from a
    # descriptor that names no account turning into an invented one.
    assert _facts(_exploit_result(None, method="session_established")) == []
    only_session = _facts(_exploit_result(_session_record(info="Meterpreter")))
    assert [fact["fact_type"] for fact in only_session] == ["session"]
    assert only_session[0]["value"]["user"] is None


def test_msf_exploit_derives_session_fact_from_rerun5_fixture():
    fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
    record, job_uuid = fixture["session"], fixture["job_uuid"]

    # The ids the old verifier compared (8 vs 24 characters) never match, and
    # deriving the fact must not depend on them: the 9A verifier already decided
    # the provenance by window + target.
    assert record["exploit_uuid"] != job_uuid
    from nexus_core.tools.parsers.metasploit import parse_msf_exploit

    parsed = parse_msf_exploit(
        {"status": "session_opened", "session": record, "job_uuid": job_uuid,
         "duration_seconds": 9.94},
        MODULE,
        TARGET,
    )
    result = ToolResult(
        output=parsed.to_dict(),
        verified=True,
        verification_method="session_established",
        evidence={"session_uuid": parsed.session.uuid, "job_uuid": parsed.job_uuid},
    )

    facts = _facts(result)
    assert {fact["fact_type"] for fact in facts} == {"session", "access"}
    session = next(fact for fact in facts if fact["fact_type"] == "session")
    assert session["key"] == f"{TARGET}:{fixture['session_uuid']}"
    assert session["value"]["user"] == "NT AUTHORITY\\SYSTEM"
    assert session["value"]["via_exploit"] == MODULE
    access = next(fact for fact in facts if fact["fact_type"] == "access")
    assert access["key"] == f"{TARGET}:NT AUTHORITY\\SYSTEM@{fixture['session_uuid']}"


def _exploitation_plan():
    """The plan rerun 6 died on: recon and enumeration done, initial access open."""
    plan = build_plan(
        objective="room", engagement_id="eng-1",
        counts={"host": 1, "service": 1, "endpoint": 1},
    )
    assert plan.current == "exploitation" and plan.progress == (2, 6)
    return plan


def test_planner_hands_session_established_to_post_exploitation():
    plan = _exploitation_plan()
    handover = session_handover(plan, subagent_id="exploit", session_established=True)

    assert handover is not None
    assert (handover.phase, handover.subagent) == ("post_exploitation", "postexploit")
    assert handover.reason == SESSION_ESTABLISHED_REASON
    handed = escalate_session(plan, handover)
    assert handed.current == "post_exploitation"
    assert handed.phase.label == "Post-explotación"

    # The measured iteration: with the ``session`` fact on the board the plan is
    # rebuilt on ``privilege_escalation`` (that fact is what closes
    # ``exploitation`` for the table), and the rule has to fire there too or it
    # could never fire at all.
    measured = build_plan(
        counts={"host": 1, "service": 1, "endpoint": 1, "session": 1}
    )
    assert measured.current == "privilege_escalation"
    assert session_handover(
        measured, subagent_id="exploit", session_established=True
    ) is not None


def test_planner_does_not_handoff_without_verified_session():
    plan = _exploitation_plan()
    assert session_handover(plan, subagent_id="exploit", session_established=False) is None

    # A ``session`` fact the model recorded by hand is a lead: it must not move a
    # phase (rerun 6: the agent recorded exactly that one, and the gate answered
    # `stale_evidence`).
    lead = {
        "fact_type": "session", "key": f"{TARGET}:xeftgmsm", "value": {"session_uuid": "xeftgmsm"},
        "verified": False, "asserted_by": "agent", "verification_method": "",
        "invocation_id": "",
    }
    assert established_msf_session([lead]) is False
    assert session_handover(
        plan, subagent_id="exploit", session_established=established_msf_session([lead])
    ) is None

    proven = {
        **lead, "verified": True, "asserted_by": "verifier",
        "verification_method": MSF_SESSION_METHOD, "invocation_id": "inv-1",
    }
    assert established_msf_session([proven]) is True
    # Another method proving another thing never turns this rule on.
    assert established_msf_session([{**proven, "verification_method": "wp_command_executed"}]) is False
    # Nor does a non-session fact (a verified access from another vector is not
    # this case: V1-25 is scoped to the measured MSF session).
    assert established_msf_session([{**proven, "fact_type": "access"}]) is False

    for subagent in ("web", "services", "privesc", "postexploit", None, ""):
        assert session_handover(plan, subagent_id=subagent, session_established=True) is None

    already_there = escalate_session(
        plan, session_handover(plan, subagent_id="exploit", session_established=True)
    )
    assert session_handover(
        already_there, subagent_id="exploit", session_established=True
    ) is None


def test_plan_marks_exploitation_done_on_session_handoff():
    plan = _exploitation_plan()
    assert plan.progress == (2, 6)

    handed = escalate_session(
        plan, session_handover(plan, subagent_id="exploit", session_established=True)
    )

    statuses = {item.id: item.status for item in handed.phases}
    assert statuses["exploitation"] == STATUS_DONE
    assert statuses["post_exploitation"] == STATUS_CURRENT
    # [3, 6], never stuck on [2, 6]: the completion gate can still reach
    # `reporting` instead of waiting for a phase nobody will work on again.
    assert handed.progress == (3, 6)
    assert handed.done_required == 3


def test_postexploit_subagent_has_session_tools():
    """The profile the session hand-over lands on can actually use a session.

    `nexus.post.shell_exec` reaches a Meterpreter session through its
    ``transport='metasploit'`` gate (``ShellRequest.transport:
    Literal['metasploit', 'sliver', 'webshell']``, read in the handler). This test
    asserts the tool ids only: that handler is a **not-yet-committed** file of
    someone else's work, and a committed test must not import it.
    """
    from nexus_core.agent.subagents import SUBAGENTS_BY_ID

    profile = SUBAGENTS_BY_ID["postexploit"]
    assert profile.phase == "post_exploitation"
    for tool_id in (
        "nexus.session.list",
        "nexus.session.interact",
        "nexus.post.shell_exec",
        "nexus.post.enum_system",
        "nexus.post.privesc_hints",
    ):
        assert tool_id in profile.tools, tool_id
