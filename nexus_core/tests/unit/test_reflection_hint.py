"""B3: the run is asked what it already has, and the answer is auditable.

The rule is deterministic: a verified, actionable fact whose value appears in no
action's arguments is "unused". These tests pin the two properties that make the
hint trustworthy -it never invents a use, and it never counts a tool's *output*
as if it were the model's own decision- plus the loop wiring: one audit event per
distinct list, and the text reaches the system prompt.
"""

from __future__ import annotations

from nexus_core.agent.planner import build_plan
from nexus_core.agent.react_services import ContextBuilder, ContextSnapshot
from nexus_core.agent.reflection import (
    REFLECTION_AFTER_TURNS,
    render_reflection,
    unused_facts,
)
from nexus_core.agent.subagents import OMNI_PROFILE
from nexus_core.kernel.audit import AuditWriter
from nexus_core.kernel.blackboard import Blackboard
from nexus_core.kernel.control_store import ControlStore

TENANT = "system"
ENGAGEMENT = "eng-reflect"


def _fact(fact_type: str, key: str, value: dict, *, verified: bool = True) -> dict:
    payload = {
        "fact_type": fact_type,
        "key": key,
        "value": value,
        "verified": verified,
        "asserted_by": "verifier" if verified else "agent",
    }
    if verified:
        payload["verification_method"] = "test_method"
        payload["invocation_id"] = "inv-1"
    return payload


def _credential() -> dict:
    return _fact(
        "credential",
        "cred:sshd:svcdeploy@10.0.0.9",
        {"username": "svcdeploy", "domain": "corp.local", "service": "ssh",
         "secret_ref": "vault:abc"},
    )


def _vulnerability() -> dict:
    return _fact(
        "vulnerability",
        "CVE-2019-6714",
        {"id": "CVE-2019-6714", "url": "http://10.0.0.9/admin/app_themes.aspx"},
    )


def _user() -> dict:
    return _fact("user", "j.rock", {"username": "j.rock", "domain": "corp.local"})


def _actions(*arguments: dict) -> list[dict]:
    return [{"tool_id": "nexus.web.request", "arguments": item} for item in arguments]


# ------------------------------------------------------------------ pure rule
def test_a_credential_no_action_used_is_the_first_thing_reflected():
    unused = unused_facts([_credential(), _vulnerability(), _user()], _actions({"target": "10.0.0.9"}))
    assert [item["fact_type"] for item in unused] == ["credential", "vulnerability", "user"]
    assert "credential_ref" in unused[0]["suggestion"]


def test_a_fact_whose_value_appears_in_the_arguments_is_not_unused():
    actions = _actions({"username": "svcdeploy", "target": "10.0.0.9"})
    types = {item["fact_type"] for item in unused_facts([_credential()], actions)}
    assert types == set()


def test_the_tool_output_is_not_confused_with_use():
    """The action that *produced* the fact does not count as spending it."""
    actions = _actions({"url": "http://10.0.0.9/admin/app_themes.aspx"})
    # The path is in the arguments here, so this one *was* used.
    assert unused_facts([_vulnerability()], actions) == ()
    # A recon action that merely discovered the host proves nothing.
    assert unused_facts([_vulnerability()], _actions({"target": "10.0.0.9"}))


def test_recon_outputs_are_not_actionable_leads():
    endpoint = _fact("endpoint", "/admin", {"status": 200, "path": "/admin"})
    assert unused_facts([endpoint], _actions({"target": "10.0.0.9"})) == ()


def test_an_unverified_fact_is_never_reflected():
    hypothesis = _fact("user", "j.rock", {"username": "j.rock"}, verified=False)
    assert unused_facts([hypothesis], _actions({"target": "10.0.0.9"})) == ()


def test_the_hint_only_appears_after_a_barren_streak():
    facts, actions = [_credential()], _actions({"target": "10.0.0.9"})
    assert render_reflection(facts, actions, no_progress=REFLECTION_AFTER_TURNS - 1) == ""
    text = render_reflection(facts, actions, no_progress=REFLECTION_AFTER_TURNS)
    assert "REFLEXIÓN" in text
    assert "[credential] svcdeploy@corp.local (ssh)" in text
    assert "No repitas la última acción" in text


def test_a_progressing_run_pays_nothing():
    assert render_reflection([_credential()], [], no_progress=0) == ""


def test_the_list_is_bounded_and_ranked():
    facts = [
        _fact("user", f"analyst{index}", {"username": f"analyst{index}"})
        for index in range(10)
    ] + [_credential()]
    unused = unused_facts(facts, [])
    assert len(unused) == 5
    assert unused[0]["fact_type"] == "credential"


# --------------------------------------------------------------- loop wiring
def _store_with_credential(tmp_path) -> tuple[ControlStore, str, dict]:
    store = ControlStore(tmp_path / "reflection.db")
    store.initialize()
    board = Blackboard(store)
    board.record(
        tenant_id=TENANT,
        engagement_id=ENGAGEMENT,
        fact_type="credential",
        key="cred:sshd:svcdeploy@10.0.0.9",
        value={"username": "svcdeploy", "service": "ssh", "secret_ref": "vault:abc"},
        source="ssh_exec",
        created_by="verifier",
        verified=True,
        asserted_by="verifier",
        verification_method="shellpass",
        invocation_id="inv-9",
    )
    run = store.create_run(TENANT, {})
    return store, run["id"], {}


def _coordinator(tmp_path, store, run_id):
    from nexus_core.agent.react_coordinator import ReActCoordinator

    coordinator = ReActCoordinator.__new__(ReActCoordinator)
    coordinator.tenant_id = TENANT
    coordinator.engagement_id = ENGAGEMENT
    coordinator.agent_id = "omni"
    coordinator.active_subagent_id = "omni"
    coordinator.store = store
    coordinator.run_id = run_id
    coordinator.iteration = 7
    coordinator.plan = build_plan(objective="audita", engagement_id=ENGAGEMENT,
                                  counts={"service": 1})
    coordinator.audit = AuditWriter(store)
    coordinator.actions = _actions({"target": "10.0.0.9"})
    coordinator.consecutive_no_progress = REFLECTION_AFTER_TURNS
    coordinator.reflection_hint = ""
    coordinator.reflection_hints_sent = set()
    return coordinator


def test_the_coordinator_audits_the_reflection_once_per_list(tmp_path):
    store, run_id, _ = _store_with_credential(tmp_path)
    coordinator = _coordinator(tmp_path, store, run_id)

    coordinator._refresh_reflection_hint()

    assert "REFLEXIÓN" in coordinator.reflection_hint
    assert "svcdeploy" in coordinator.reflection_hint
    events = [
        event for event in store.list_run_events(TENANT, run_id)
        if event.get("event_type") == "react.reflection"
    ]
    assert len(events) == 1
    assert "svcdeploy" in events[0]["payload"]["hint"]

    # Same list, next turn: the text still travels, the event is not duplicated.
    coordinator.iteration = 8
    coordinator._refresh_reflection_hint()
    assert "REFLEXIÓN" in coordinator.reflection_hint
    assert len([
        event for event in store.list_run_events(TENANT, run_id)
        if event.get("event_type") == "react.reflection"
    ]) == 1


def test_a_action_that_spends_the_fact_silences_the_reflection(tmp_path):
    store, run_id, _ = _store_with_credential(tmp_path)
    coordinator = _coordinator(tmp_path, store, run_id)
    coordinator.actions = _actions({"username": "svcdeploy", "target": "10.0.0.9"})
    coordinator._refresh_reflection_hint()
    assert coordinator.reflection_hint == ""


def test_the_prompt_carries_the_reflection_block(tmp_path):
    store, run_id, _ = _store_with_credential(tmp_path)
    coordinator = _coordinator(tmp_path, store, run_id)
    coordinator._refresh_reflection_hint()
    messages = ContextBuilder().render(
        ContextSnapshot(
            run_history=[],
            history_summary="",
            plan=coordinator.plan,
            facts_text="",
            coverage=None,
        ),
        allowed_catalog={},
        objective="audita",
        engagement_id=ENGAGEMENT,
        scope=None,
        subagent=OMNI_PROFILE,
        project_instruction=None,
        active_skills=[],
        store=store,
        tenant_id=TENANT,
        reflection_hint=coordinator.reflection_hint,
    )
    system = "\n".join(str(message.content) for message in messages if message.role == "system")
    assert "REFLEXIÓN" in system
    assert "credential_ref" in system
