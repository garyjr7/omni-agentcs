"""WP2 · Loop v2: one profile, an advisory planner and one hard budget.

Measured in rerun 13 (``run_c1b80861…``): the agent got ``uid=0(root)`` and
``user.txt``, the planner then closed the phase, moved the run to the ``reporter``
profile (read-only) and the profile denied ``ssh_exec`` for ``root.txt``. The
agent died with the work done. The four fixes pinned here are:

* FIX 1 - one ``omni`` profile with the whole catalog. The phase profiles become
  prompt *hints*; ``NEXUS_LEGACY_PROFILES=1`` restores the old tool gate.
* FIX 2 - ``objective_completion`` reads the board only (verified top privilege
  plus verified loot), never the profile that happens to hold the turn.
* FIX 3 - one global budget (``NEXUS_RUN_BUDGET_TOKENS``, 250k); the per-profile
  numbers are soft telemetry and a profile can never kill the run, plus a
  5-turn grace once the board is complete; ``premature_completion`` names the
  finding and the reference it should have cited.
* FIX 4 - a closed phase never reopens (the phase is a monotone function of the
  evidence) and an identical repeat of a failed action gets the change-of-vector
  correction (V1-26, covered in ``test_phase3g_fixes.py``).

The legacy behaviour itself stays covered: the old phase-correctness modules pin
``NEXUS_LEGACY_PROFILES=1`` with an autouse fixture, and two tests below assert
the flag both ways on the same board.
"""

from __future__ import annotations

import asyncio
import copy
import json
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest import mock

import pytest

from nexus_core.agent.coverage import STATUS_CLOSED, build_coverage
from nexus_core.agent.planner import (
    ENUMERATION_ENDPOINT_REASON,
    PHASE_IDS,
    apply_objective_completion,
    build_plan,
    objective_completion,
    top_privilege,
)
from nexus_core.agent.react import (
    PREMATURE_COMPLETION_EVENT_TYPE,
    STATUS_BUDGET_EXCEEDED,
    STATUS_COMPLETED,
    STATUS_PREMATURE_COMPLETION,
    STATUS_SUBAGENT_BUDGET,
    ReActConfig,
    run_react_loop,
)
from nexus_core.agent.react_coordinator import ReActCoordinator
from nexus_core.agent.react_support import (
    DEFAULT_RUN_BUDGET_TOKENS,
    _budget_tokens,
    _invocation_signature,
    _keep_going_after_failures,
    _premature_completion_message,
    missing_evidence,
    repeated_action_correction,
    barren_repeat_correction,
)
from nexus_core.agent.react_types import (
    BUDGET_GRACE_EVENT_TYPE,
    LOOP_BARRIER_EVENT_TYPE,
    OBJECTIVE_GRACE_EVENT_TYPE,
    OBJECTIVE_GRACE_TURNS,
    ROBOTS_HINT_EVENT_TYPE,
    SMART_BUDGET_EVENT_TYPE,
    SUBAGENT_EVENT_TYPE,
    WEBSHELL_STALL_EVENT_TYPE,
    SUBAGENT_SOFT_LIMIT_EVENT_TYPE,
)
from nexus_core.agent.subagents import (
    LEGACY_PROFILES_ENV,
    OMNI_PROFILE,
    filter_catalog,
    permits,
    select_run_profile,
)
from nexus_core.agent.turn_telemetry import TurnTelemetryRecorder
from nexus_core.kernel import runtime as runtime_module
from nexus_core.kernel.audit import AuditWriter
from nexus_core.kernel.blackboard import Blackboard
from nexus_core.kernel.control_store import ControlStore
from nexus_core.kernel.domain_dto import ToolCall
from nexus_core.kernel.runtime import ExecutionContext
from nexus_core.llm.abstraction import LLMProvider, LLMResponse
from nexus_core.scope import EngagementScope, EngagementStore
from nexus_core.tools.registry import durable_tool_definitions

#: The replay of rerun 13 drives a real engagement run; the fixtures of this repo
#: are unsigned on purpose (``lab`` scope mode), exactly like the other loop suites.
pytestmark = [pytest.mark.unit, pytest.mark.usefixtures("lab_scope")]

TENANT = "system"
ENGAGEMENT = "eng-wp2"
TARGET = "10.0.0.1"
FLAG = "flag{fake_flag}"
INVOCATION = "wp2-invocation"

#: The board rerun 13 had when the profile gate denied the tool that read
#: ``root.txt``: everything up to and including root, minus the file.
RERUN13_COUNTS = {
    "host": 1,
    "service": 3,
    "endpoint": 2,
    "credential": 1,
    "access": 1,
    "privilege": 1,
}

SHELL_OK = {
    "tool_id": "nexus.shell.exec",
    "output": {
        "success": True,
        "verified": True,
        "verification_method": "shell_exit_code",
        "evidence": {"exit_code": 0, "stdout_lines": 1},
        "output": {"command": "cat /root/root.txt", "stdout": f"{FLAG}\n", "exit_code": 0},
    },
}

NMAP_OK = {
    "tool_id": "nexus.recon.nmap",
    "output": {
        "success": True,
        "verified": True,
        "verification_method": "nmap_xml_parsed",
        "evidence": {"hosts_up": 1, "ports_open_total": 1},
        "output": {
            "target": TARGET,
            "scan": {"hosts": [{"address": TARGET, "ports": [{"port": 22, "service": "ssh"}]}]},
        },
    },
}


# ------------------------------------------------------------------- primitives
def _iso(delta: timedelta) -> str:
    return (datetime.now(timezone.utc) + delta).isoformat()


def _privilege_fact(*, verified: bool = True, uid: int = 0, user: str = "root") -> dict:
    return {
        "fact_type": "privilege",
        "key": TARGET,
        "value": {"uid": uid, "user": user},
        "source": "nexus.post.ssh_exec",
        "verified": verified,
        "asserted_by": "verifier" if verified else "agent",
        "verification_method": "ssh_exec_completed" if verified else "",
        "invocation_id": INVOCATION if verified else "",
    }


def _loot_fact(*, verified: bool = True, key: str = FLAG) -> dict:
    return {
        "fact_type": "loot",
        "key": key,
        "value": {"flag": key, "command": "cat /root/root.txt", "service": "ssh"},
        "source": "nexus.post.ssh_exec",
        "verified": verified,
        "asserted_by": "verifier" if verified else "agent",
        "verification_method": "ssh_exec_completed" if verified else "",
        "invocation_id": INVOCATION if verified else "",
    }


def _catalog() -> dict:
    """The durable catalog the loop really runs with (not a stub)."""
    return durable_tool_definitions(TENANT)


def _phase_index(plan) -> int:
    return PHASE_IDS.index(plan.current)


# ----------------------------------------------------------------- FIX 1 · profile
def test_default_loop_runs_one_profile_with_the_whole_catalog():
    """Every phase selects the same profile, and it carries every tool."""
    catalog = _catalog()
    profile = select_run_profile(build_plan(counts=RERUN13_COUNTS))

    assert profile.id == OMNI_PROFILE.id == "omni"
    assert profile.unrestricted is True
    assert filter_catalog(profile, catalog) == catalog
    # The exact denial of rerun 13 (the tool that read root.txt) is now permitted
    # in *any* phase, along with the WP1 substrate.
    for tool_id in ("nexus.shell.exec", "nexus.post.ssh_exec", "nexus.session.pty"):
        assert tool_id in catalog
        assert permits(profile, tool_id, catalog.get(tool_id)) is True
    assert len(catalog) >= 70

    for phase in PHASE_IDS:
        assert select_run_profile(build_plan(counts=RERUN13_COUNTS), override=None).id == "omni"


def test_the_failure_abort_measures_the_unrestricted_profile_by_the_catalog():
    """Three failed calls must not kill a run that still has the whole catalog.

    ``omni`` is ``unrestricted`` with an **empty** ``tools`` set, so measuring it
    by that set answered "no usable tool left" and closed the run as
    ``aborted after 3 consecutive tool failures``. Measured in the Simple CTF
    runs of 2026-10-17 (19:36, 20:49 and 23:16 UTC): the last one had the
    verified password on the board and died three turns later.
    """
    catalog = _catalog()
    assert OMNI_PROFILE.tools == frozenset()

    assert _keep_going_after_failures(OMNI_PROFILE, set(), 3, catalog) is True
    # A tool that failed enough times is retired, not the whole engagement: only
    # an empty remaining catalog stops the loop.
    retired = set(catalog) - {"nexus.post.ssh_exec"}
    assert _keep_going_after_failures(OMNI_PROFILE, retired, 3, catalog) is True
    assert _keep_going_after_failures(OMNI_PROFILE, set(catalog), 3, catalog) is False
    # Two failures are never fatal.
    assert _keep_going_after_failures(OMNI_PROFILE, set(catalog), 2, catalog) is True


def test_the_failure_abort_still_holds_a_restricted_profile_to_its_subset():
    """The legacy gate keeps its meaning: no route left in the subset, no run."""
    from nexus_core.agent.subagents import SUBAGENTS_BY_ID

    recon = SUBAGENTS_BY_ID["recon"]
    catalog = _catalog()

    assert _keep_going_after_failures(recon, set(recon.tools) - {"nexus.recon.nmap"}, 3, catalog) is True
    assert _keep_going_after_failures(recon, set(recon.tools), 3, catalog) is False


def test_legacy_flag_restores_the_phase_tool_gate(monkeypatch):
    """``NEXUS_LEGACY_PROFILES=1`` is the escape hatch, and it is a real gate."""
    monkeypatch.setenv(LEGACY_PROFILES_ENV, "1")
    catalog = _catalog()
    plan = build_plan(counts=RERUN13_COUNTS | {"loot": 1})
    assert plan.current == "reporting"

    reporter = select_run_profile(plan)
    assert reporter.id == "reporter"
    assert reporter.read_only is True
    allowed = filter_catalog(reporter, catalog)
    # The rerun-13 denial comes back verbatim: the closing profile cannot reach
    # the session tool that reads the file, nor any other active kill-chain tool.
    assert "nexus.post.ssh_exec" not in allowed
    assert "nexus.recon.nmap" not in allowed
    # ... except the WP1 universal substrate, which is profile-independent on
    # purpose (it is the shell, not a phase tool) and decided in WP1.
    assert "nexus.shell.exec" in allowed and "nexus.session.pty" in allowed


def test_objective_complete_verdict_ignores_the_active_profile(monkeypatch):
    """The acceptance criterion: root + loot on the board closes, whoever runs."""
    facts = [_privilege_fact(), _loot_fact()]

    assert objective_completion(facts, subagent_id="reporter").complete is True
    assert objective_completion(facts, subagent_id="recon").complete is True
    assert objective_completion(facts, subagent_id="privesc").complete is True
    assert objective_completion(facts, subagent_id="omni").complete is True
    # Material condition unchanged: a lead is a hypothesis, and an incomplete
    # board is incomplete.
    assert objective_completion([_privilege_fact(verified=False), _loot_fact()], subagent_id="reporter").complete is False
    assert objective_completion([_privilege_fact(), _loot_fact(verified=False)], subagent_id="reporter").complete is False
    assert objective_completion([_privilege_fact(uid=1000, user="lin")], subagent_id="omni").complete is False

    # The legacy flag restores the profile gate, so the old suite keeps its meaning.
    monkeypatch.setenv(LEGACY_PROFILES_ENV, "1")
    assert objective_completion(facts, subagent_id="reporter").complete is True
    assert objective_completion(facts, subagent_id="recon").complete is False
    assert objective_completion(facts, subagent_id="omni", legacy=False).complete is True


# ------------------------------------------------------- FIX 1+2 · the real loop
class ScriptedLLM:
    """Replays scripted answers, repeating the last one when exhausted."""

    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = 0
        self.prompts: list[str] = []

    async def complete(self, messages, **kwargs):
        self.calls += 1
        index = min(self.calls - 1, max(0, len(self.responses) - 1))
        self.prompts.append("\n".join(str(m.content) for m in messages))
        return LLMResponse(
            content=self.responses[index] if self.responses else "",
            model="scripted-test",
            provider=LLMProvider.FAKE,
        )


class ToolSpy:
    """Stands in for ``execute_tool``: records the payload and returns *response*."""

    def __init__(
        self,
        response: dict | None = None,
        *,
        assertion: str = INVOCATION,
        fact_type: str = "loot",
    ):
        self.payloads: list[dict] = []
        self.response = response or SHELL_OK
        self.assertion = assertion
        self.fact_type = fact_type

    async def __call__(self, payload, context):
        self.payloads.append(payload)
        result = copy.deepcopy(self.response)
        result["tool_id"] = payload["tool_id"]
        result["output"]["assertions"] = [
            {
                "invocation_id": self.assertion,
                "run_id": context.run_id,
                "target": TARGET,
                "fact_type": self.fact_type,
                "verified": True,
                "verification_method": "shell_exit_code",
            }
        ]
        return result


def _shell_call(command: str = "cat root.txt\nid") -> str:
    return json.dumps(
        {
            "thought": "Tengo el privilegio máximo; leo la flag final.",
            "action": "tool_call",
            "tool_id": "nexus.shell.exec",
            "arguments": {"command": command},
            "expected_outcome": "root.txt",
        }
    )


def _complete(payload: dict | None = None) -> str:
    finding = payload or {
        "severity": "critical",
        "title": f"Flag verificada en {TARGET}",
        "invocation_id": INVOCATION,
        "target": TARGET,
        "fact_type": "loot",
        "evidence": f"la captura devolvió {FLAG} en {TARGET}",
    }
    return json.dumps(
        {
            "thought": "Objetivo cumplido: privilegio máximo + flag verificados.",
            "action": "task_complete",
            "summary": "privilegio máximo y flag capturados",
            "findings": [finding],
        }
    )


@pytest.fixture()
def harness(tmp_path):
    """The rerun-13 end state: the board already carries root and the flag."""
    return _engagement(tmp_path, "wp2.db", complete_board=True)


@pytest.fixture()
def mid_chain_harness(tmp_path):
    """A board that only knows about the host and one service (FIX 2.1)."""
    return _engagement(tmp_path, "wp2-mid.db", complete_board=False)


def _engagement(tmp_path, name: str, *, complete_board: bool):
    store = ControlStore(tmp_path / name)
    store.initialize()
    EngagementStore(store).create(
        EngagementScope(
            engagement_id=ENGAGEMENT,
            tenant_id=TENANT,
            name="wp2",
            client="acme",
            owner_id="owner-1",
            valid_from=_iso(-timedelta(days=1)),
            valid_until=_iso(timedelta(days=1)),
            cidrs=("10.0.0.0/24",),
            domains=(),
            urls=(),
            exclusions=(),
            created_at=_iso(timedelta(0)),
        )
    )
    board = Blackboard(store)
    facts = [
        ("host", TARGET, {"ip": TARGET}),
        ("service", f"{TARGET}:22/ssh", {"port": 22, "service": "ssh"}),
    ]
    if complete_board:
        facts += [
            ("endpoint", f"{TARGET}/", {"path": "/"}),
            ("credential", "lin", {"user": "lin", "service": "ssh"}),
            ("access", "ssh", {"user": "lin", "method": "ssh"}),
            ("privilege", TARGET, {"uid": 0, "user": "root"}),
            ("loot", FLAG, {"flag": FLAG, "command": "cat /home/lin/user.txt"}),
        ]
    for fact_type, key, value in facts:
        board.record(
            tenant_id=TENANT,
            engagement_id=ENGAGEMENT,
            fact_type=fact_type,
            key=key,
            value=value,
            source="nexus.post.ssh_exec",
            created_by="deterministic-verifier",
            verified=True,
            asserted_by="verifier",
            verification_method="ssh_exec_completed",
            invocation_id=INVOCATION,
        )
    return store, _context(store)


def _context(store) -> ExecutionContext:
    """A fresh run over an existing store (never reuses another run's transcript)."""
    run = store.create_run(TENANT, {})
    task = {
        "id": f"task-{run['id']}",
        "tenant_id": TENANT,
        "run_id": run["id"],
        "task_type": "react.run",
        "payload": {
            "objective": "Comprometer al objetivo y capturar las dos flags",
            "engagement_id": ENGAGEMENT,
            "identity": {"subject_id": "operator-1", "roles": ["operator"]},
            "permissions": [],
        },
    }
    return ExecutionContext(store, task, "worker-test")


def _events(store, run_id, event_type):
    return [
        event
        for event in store.list_run_events(TENANT, run_id)
        if event.get("event_type") == event_type
    ]


async def test_shell_exec_runs_from_the_reporting_phase_and_the_run_closes(harness):
    """The rerun-13 regression, end to end: root+loot on the board, no death."""
    store, context = harness
    plan = build_plan(counts=RERUN13_COUNTS | {"loot": 1})
    assert plan.current == "reporting", "the board must sit on the closing phase"

    llm = ScriptedLLM([_shell_call(), _complete()])
    spy = ToolSpy()

    with mock.patch.object(runtime_module, "execute_tool", spy):
        result = await run_react_loop(
            context=context,
            objective="Comprometer al objetivo y capturar las dos flags",
            engagement_id=ENGAGEMENT,
            llm_client=llm,
            config=ReActConfig(max_iterations=6, enforce_completion_gates=True),
        )

    # The tool the old profile gate refused reached the executor, from the phase
    # the old loop had already moved to `reporter`.
    assert [payload["tool_id"] for payload in spy.payloads] == ["nexus.shell.exec"]
    assert spy.payloads[0]["arguments"]["command"] == "cat root.txt\nid"
    # ... and the run closes with the work done instead of dying on it.
    assert result.status == STATUS_COMPLETED
    assert not result.completion_objections
    assert _events(store, context.run_id, PREMATURE_COMPLETION_EVENT_TYPE) == []

    profiles = _events(store, context.run_id, SUBAGENT_EVENT_TYPE)
    assert profiles, "the selected profile is audited"
    payload = profiles[0]["payload"]
    assert payload["subagent_id"] == "omni"
    assert payload["unrestricted"] is True
    assert payload["tools_count"] == len(_catalog())
    assert payload["read_only"] is False
    assert payload["phase"] == "reporting"

    # The board-only verdict fired and granted the grace to close.
    assert _events(store, context.run_id, OBJECTIVE_GRACE_EVENT_TYPE)
    assert "nexus.shell.exec" in llm.prompts[0]


async def test_the_plan_phase_is_not_a_completion_gate(mid_chain_harness, monkeypatch):
    """FIX 2.1: mid-chain plan + grounded evidence closes the run.

    The old gate refused a ``task_complete`` because the plan was not on
    ``reporting`` yet ("el plan sigue en la fase …"), whatever the evidence
    said. The default loop only asks the evidence to be grounded; the legacy
    flag restores the refusal, which is what makes this test falsifiable.
    """
    store, context = mid_chain_harness
    plan = build_plan(counts={"host": 1, "service": 1})
    assert plan.current == "enumeration", "the plan must be mid-chain"

    grounded = {
        "severity": "info",
        "title": f"SSH confirmado en {TARGET}",
        "invocation_id": INVOCATION,
        "target": TARGET,
        "fact_type": "service",
        "evidence": f"22/tcp open ssh en {TARGET}",
    }
    llm = ScriptedLLM([_shell_call("id"), _complete(grounded)])
    spy = ToolSpy(fact_type="service")

    with mock.patch.object(runtime_module, "execute_tool", spy):
        result = await run_react_loop(
            context=context,
            objective="Enumerar y explotar el objetivo",
            engagement_id=ENGAGEMENT,
            llm_client=llm,
            config=ReActConfig(max_iterations=6, enforce_completion_gates=True),
        )

    assert result.status == STATUS_COMPLETED
    assert result.completion_objections == []
    assert _events(store, context.run_id, PREMATURE_COMPLETION_EVENT_TYPE) == []

    # Same board, same scripted turn, old loop: the unfinished plan is the objection.
    monkeypatch.setenv(LEGACY_PROFILES_ENV, "1")
    context2 = _context(store)  # a fresh run: the first one's turns are not reused
    legacy_llm = ScriptedLLM([_shell_call("id"), _complete(grounded)])
    with mock.patch.object(runtime_module, "execute_tool", ToolSpy(fact_type="service")):
        legacy = await run_react_loop(
            context=context2,
            objective="Enumerar y explotar el objetivo",
            engagement_id=ENGAGEMENT,
            llm_client=legacy_llm,
            config=ReActConfig(max_iterations=6, enforce_completion_gates=True),
        )
    assert legacy.status == STATUS_PREMATURE_COMPLETION
    assert any("fase" in item for item in legacy.completion_objections)


def test_reported_phase_is_a_hint_in_the_prompt_not_a_gate():
    """The hint survives: the plan block still names the phase and the next step."""
    plan = apply_objective_completion(
        build_plan(counts=RERUN13_COUNTS | {"loot": 1}),
        objective_completion([_privilege_fact(), _loot_fact()], subagent_id="omni"),
    )
    rendered = plan.render()

    assert "fase actual:" in rendered
    assert "SIGUIENTE PASO DEL PLAN:" in rendered
    assert "OBJETIVO CUMPLIDO:" in rendered
    # A hint closes nothing: the phase the evidence closed is the one reported.
    assert plan.current == "reporting"
    assert top_privilege({"uid": 0}) is True


# ------------------------------------------------------------- FIX 3 · budgets
def _bare_coordinator(store, *, run_id, plan, subagent_id="omni", iteration=9):
    coordinator = ReActCoordinator.__new__(ReActCoordinator)
    coordinator.tenant_id = TENANT
    coordinator.engagement_id = ENGAGEMENT
    coordinator.agent_id = "omni"
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
    coordinator.last_selected = None
    coordinator.objective_complete = False
    coordinator.objective_complete_emitted = False
    coordinator.budget_exempt = False
    coordinator.grace_turns_remaining = None
    coordinator.grace_granted = False
    coordinator.soft_limits_reported = set()
    coordinator.iteration_limit = 40
    coordinator.cancel_event = None
    coordinator.audit = AuditWriter(store)
    coordinator.telemetry = TurnTelemetryRecorder(
        store=store, tenant_id=TENANT, run_id=run_id
    )
    # WP6 state (the endpoint ceiling and the smart-budget hint).
    coordinator.endpoint_ceiling_applied = False
    coordinator.budget_hint = ""
    coordinator.budget_hint_emitted = False
    coordinator.webshell_hint = ""
    coordinator.webshell_hint_emitted = False
    coordinator.coverage_hint = ""
    coordinator.coverage_hint_emitted = False
    coordinator.robots_hint = ""
    coordinator.robots_hint_emitted = False
    coordinator.budget = 400_000
    return coordinator


def _verified_board(tmp_path):
    store = ControlStore(tmp_path / "board.db")
    store.initialize()
    board = Blackboard(store)
    for fact_type, key, value in (
        ("privilege", TARGET, {"uid": 0, "user": "root"}),
        ("loot", FLAG, {"flag": FLAG, "service": "ssh"}),
    ):
        board.record(
            tenant_id=TENANT,
            engagement_id=ENGAGEMENT,
            fact_type=fact_type,
            key=key,
            value=value,
            source="nexus.post.ssh_exec",
            created_by="deterministic-verifier",
            verified=True,
            asserted_by="verifier",
            verification_method="ssh_exec_completed",
            invocation_id=INVOCATION,
        )
    return store


def test_run_budget_default_is_the_wp2_ceiling(monkeypatch):
    monkeypatch.delenv("NEXUS_RUN_BUDGET_TOKENS", raising=False)
    assert DEFAULT_RUN_BUDGET_TOKENS == 250_000
    assert _budget_tokens({}, None) == 250_000
    # Documented escape hatches: an explicit value (payload or arg) still wins.
    monkeypatch.setenv("NEXUS_RUN_BUDGET_TOKENS", "1000")
    assert _budget_tokens({}, None) == 1000
    assert _budget_tokens({"budget_tokens": 7}, None) == 7
    assert _budget_tokens({}, 0) == 0


def test_global_budget_does_not_kill_a_run_with_the_objective_complete(tmp_path):
    """Acceptance: the ceiling bends for the turns that close the run."""
    store = _verified_board(tmp_path)
    run = store.create_run(TENANT, {})
    plan = build_plan(counts=RERUN13_COUNTS | {"loot": 1})
    coordinator = _bare_coordinator(store, run_id=run["id"], plan=plan)
    coordinator.budget = 10_000
    store.record_usage(TENANT, run["id"], "model_route", "react", "tokens", 10_000)

    transition = coordinator._guard()

    assert transition.name == "READY"
    assert coordinator.status != STATUS_BUDGET_EXCEEDED
    assert coordinator.objective_complete is True
    grace = _events(store, run["id"], BUDGET_GRACE_EVENT_TYPE)
    assert len(grace) == 1
    assert grace[0]["payload"]["grace_turns_remaining"] == OBJECTIVE_GRACE_TURNS - 1
    assert grace[0]["payload"]["used"] == 10_000

    # The grace is finite: once spent, the ceiling is the ceiling again.
    for _ in range(OBJECTIVE_GRACE_TURNS - 1):
        assert coordinator._guard().name == "READY"
    stopped = coordinator._guard()
    assert stopped.name == "STOP"
    assert coordinator.status == STATUS_BUDGET_EXCEEDED


def test_global_budget_kills_a_run_without_the_objective(tmp_path):
    """The board is re-read, but only a *complete* board buys the grace."""
    store = ControlStore(tmp_path / "empty.db")
    store.initialize()
    run = store.create_run(TENANT, {})
    coordinator = _bare_coordinator(
        store,
        run_id=run["id"],
        plan=build_plan(counts={"host": 1, "service": 1}),
    )
    coordinator.budget = 10_000
    store.record_usage(TENANT, run["id"], "model_route", "react", "tokens", 10_000)

    transition = coordinator._guard()

    assert transition.name == "STOP"
    assert coordinator.status == STATUS_BUDGET_EXCEEDED
    assert coordinator.objective_complete is False
    assert _events(store, run["id"], BUDGET_GRACE_EVENT_TYPE) == []


def test_a_profile_ceiling_is_soft_and_cannot_kill_the_run(tmp_path):
    """FIX 3: the per-profile numbers are telemetry in the default loop."""
    store = _verified_board(tmp_path)
    run = store.create_run(TENANT, {})
    plan = build_plan(counts=RERUN13_COUNTS)
    coordinator = _bare_coordinator(
        store, run_id=run["id"], plan=plan, subagent_id="privesc"
    )
    coordinator.subagent_override = "privesc"  # the profile that died in rerun 13
    store.record_usage(
        TENANT, run["id"], "model_route", "react:privesc", "tokens", 60_000
    )

    transition = asyncio.run(coordinator._select_profile())

    assert transition.name == "READY"
    assert coordinator.status != STATUS_SUBAGENT_BUDGET
    soft = _events(store, run["id"], SUBAGENT_SOFT_LIMIT_EVENT_TYPE)
    assert len(soft) == 1
    assert soft[0]["payload"]["limit"] == "tokens"
    assert soft[0]["payload"]["soft"] is True
    assert soft[0]["payload"]["spent"] == 60_000


def test_the_legacy_loop_still_dies_of_a_profile_ceiling(tmp_path, monkeypatch):
    """Regression pairing: the flag restores the hard per-profile ceiling."""
    monkeypatch.setenv(LEGACY_PROFILES_ENV, "1")
    store = _verified_board(tmp_path)
    run = store.create_run(TENANT, {})
    coordinator = _bare_coordinator(
        store,
        run_id=run["id"],
        plan=build_plan(counts=RERUN13_COUNTS),
        subagent_id="privesc",
    )
    coordinator.subagent_override = "privesc"
    store.record_usage(
        TENANT, run["id"], "model_route", "react:privesc", "tokens", 60_000
    )

    transition = asyncio.run(coordinator._select_profile())

    assert transition.name == "STOP"
    assert coordinator.status == STATUS_SUBAGENT_BUDGET
    assert _events(store, run["id"], SUBAGENT_SOFT_LIMIT_EVENT_TYPE) == []


def test_soft_iteration_ceiling_is_reported_not_fatal(tmp_path, monkeypatch):
    store = _verified_board(tmp_path)
    run = store.create_run(TENANT, {})
    coordinator = _bare_coordinator(
        store, run_id=run["id"], plan=build_plan(counts=RERUN13_COUNTS)
    )
    coordinator.subagent_override = "reporter"  # max_iterations = 6
    coordinator.last_subagent_id = "reporter"
    coordinator.subagent_iterations = 8

    transition = asyncio.run(coordinator._select_profile())

    assert transition.name == "READY"
    assert coordinator.status != STATUS_SUBAGENT_BUDGET
    soft = _events(store, run["id"], SUBAGENT_SOFT_LIMIT_EVENT_TYPE)
    assert [item["payload"]["limit"] for item in soft] == ["iterations"]


# ----------------------------------------------- FIX 3.3 · missing_evidence detail
def _rejected_stats() -> dict:
    return {
        "findings_total": 2,
        "grounded": 0,
        "stale": 1,
        "unsupported": 1,
        "rejected_findings": [
            {
                "finding_ref": "Credenciales de 10.65.163.65",
                "reason": "stale_evidence",
                "cited": {"invocation_id": "inv-old", "fact_type": "credential", "target": "10.65.163.65"},
                "found_in_corpus": False,
                "closest_match": {"invocation_id": "inv-run", "fact_type": "loot", "target": TARGET},
            },
            {
                "finding_ref": "SSH expuesto",
                "reason": "unsupported_evidence",
                "cited": {"invocation_id": "", "fact_type": "", "target": ""},
                "found_in_corpus": False,
                "closest_match": None,
            },
        ],
    }


def test_missing_evidence_returns_the_exact_reference_to_fix():
    entries = missing_evidence(_rejected_stats())

    assert entries == [
        {
            "finding_id": "Credenciales de 10.65.163.65",
            "reason": "stale_evidence",
            "observation_ref_expected": "inv-run",
        },
        {
            "finding_id": "SSH expuesto",
            "reason": "unsupported_evidence",
            "observation_ref_expected": "",
        },
    ]
    assert missing_evidence(None) == []
    # The human-facing correction names the finding, its bad citation and how to
    # get the right id.
    message = _premature_completion_message(
        [
            "Hallazgo 'Credenciales de 10.65.163.65' (stale_evidence) citó "
            "invocation_id=inv-old, pero no coincide."
        ],
        None,
    )
    assert "RECHAZADO" in message
    assert "Credenciales de 10.65.163.65" in message
    assert "inv-old" in message


async def test_premature_completion_event_carries_the_missing_id(harness):
    """Loop level: the refusal tells the model *which* citation to repair."""
    store, context = harness
    llm = ScriptedLLM(
        [
            _shell_call("nmap -Pn -p22 10.0.0.1"),
            _complete(
                {
                    "severity": "high",
                    "title": "Credenciales de 10.65.163.65",
                    # The citation is *internally* inconsistent: the id is invented
                    # while type/target do coincide with this run's observation,
                    # which is why the gate can offer the right reference.
                    "invocation_id": "inv-old",
                    "fact_type": "loot",
                    "target": TARGET,
                    "evidence": "10.65.163.65 usuario harry locks.txt",
                }
            ),
        ]
    )

    with mock.patch.object(runtime_module, "execute_tool", ToolSpy(NMAP_OK)):
        result = await run_react_loop(
            context=context,
            objective="comprometer 10.65.163.65",
            engagement_id=ENGAGEMENT,
            llm_client=llm,
            config=ReActConfig(max_iterations=6, enforce_completion_gates=True),
        )

    assert result.status == STATUS_PREMATURE_COMPLETION
    events = _events(store, context.run_id, PREMATURE_COMPLETION_EVENT_TYPE)
    assert events, "the refusal is audited"
    detail = events[0]["payload"]["missing_evidence"]
    assert detail, "the event names the finding, not just the count"
    assert detail[0]["finding_id"] == "Credenciales de 10.65.163.65"
    assert detail[0]["reason"] == "stale_evidence"
    # The run's own observation is offered as the reference to cite instead.
    assert detail[0]["observation_ref_expected"] == INVOCATION


# -------------------------------------------------------- FIX 4 · no oscillation
def test_a_closed_phase_never_reopens_as_evidence_grows():
    """FIX 4.1: the phase is a monotone function of the ledger.

    Rerun 9 spent ~28% of its tokens oscillating between enumeration and
    exploitation. With the phase derived from evidence that only grows, a phase
    the chain left behind cannot come back, and replaying the same ledger yields
    the same phase (idempotent: a repeated turn cannot re-open anything).
    """
    ledger = [
        {},
        {"host": 1},
        {"host": 1, "service": 3},
        {"host": 1, "service": 3, "endpoint": 2},
        {"host": 1, "service": 3, "endpoint": 2, "credential": 1},
        {"host": 1, "service": 3, "endpoint": 2, "credential": 1, "access": 1},
        {"host": 1, "service": 3, "endpoint": 2, "credential": 1, "access": 1, "privilege": 1},
        {"host": 1, "service": 3, "endpoint": 2, "credential": 1, "access": 1, "privilege": 1, "loot": 1},
    ]

    indexes = [_phase_index(build_plan(counts=counts)) for counts in ledger]
    assert indexes == sorted(indexes), "a visited phase never moves backwards"
    assert indexes[0] == PHASE_IDS.index("recon")
    assert indexes[-1] == PHASE_IDS.index("reporting")

    # A turnaround that re-observes the same facts changes nothing ...
    for counts in ledger:
        first = build_plan(counts=counts)
        second = build_plan(counts=counts)
        assert first.current == second.current
    # ... and extra evidence on a *closed* phase never drags the plan back.
    late = build_plan(counts={**ledger[-1], "endpoint": 9, "service": 12})
    assert _phase_index(late) >= _phase_index(build_plan(counts=ledger[-1]))


def test_an_identical_repeat_of_a_failed_action_is_corrected_not_replayed(tmp_path):
    """FIX 4.2: the change-of-vector hint, on the real state the rule reads.

    The loop's V1-26 mechanism (``test_phase3g_fixes.py`` covers it end to end)
    keys on the signature of the *immediately preceding* turn: same tool, same
    canonical arguments, and that call failed. Anything else is a new attempt.
    """
    store = _verified_board(tmp_path)
    run = store.create_run(TENANT, {})
    coordinator = _bare_coordinator(
        store, run_id=run["id"], plan=build_plan(counts=RERUN13_COUNTS)
    )
    failed = ToolCall(tool_id="nexus.shell.exec", arguments={"command": "id"})
    coordinator.actions = [
        {
            "tool_id": failed.tool_id,
            "arguments": failed.arguments,
            "invocation_signature": _invocation_signature(failed.tool_id, failed.arguments),
            "tool_result": {"success": False, "outcome": "failed"},
        }
    ]

    # The byte-identical repeat is the one the rule catches.
    coordinator.action = ToolCall(tool_id="nexus.shell.exec", arguments={"command": "id"})
    assert coordinator._repeated_failed_action() == "nexus.shell.exec"
    assert "mismos argumentos" in repeated_action_correction("nexus.shell.exec")

    # Other arguments are a new attempt, not a repeat.
    coordinator.action = ToolCall(tool_id="nexus.shell.exec", arguments={"command": "id -u"})
    assert coordinator._repeated_failed_action() is None

    # A call that *worked* keeps its own governance (the gateway's dedup, V1-14).
    coordinator.actions[0]["tool_result"] = {"success": True}
    coordinator.action = ToolCall(tool_id="nexus.shell.exec", arguments={"command": "id"})
    assert coordinator._repeated_failed_action() is None


def test_a_slow_repeat_that_added_nothing_is_corrected_before_the_tool_layer(tmp_path):
    """A 500 s probe relaunched byte-identically is a budget leak, not a retry.

    Measured in run_1052d63f9bba4838902b3aa21bd27d21 (Joomla, 2026-10-19): the
    same sqlmap URL ran twice at ~500 s each with ``blackboard_delta = 0`` while
    the ledger still had two open branches; the run died at the token budget with
    zero findings. The guard is narrow on purpose -fast idempotent repeats, or a
    repeat of a turn that did add a fact, keep the gateway's dedup (V1-14).
    """
    store = _verified_board(tmp_path)
    run = store.create_run(TENANT, {})
    coordinator = _bare_coordinator(
        store, run_id=run["id"], plan=build_plan(counts=RERUN13_COUNTS)
    )
    coordinator.consecutive_no_progress = 1
    coordinator.last_tool_elapsed_ms = 500_000
    call = ToolCall(
        tool_id="nexus.web.sqlmap", arguments={"url": "http://10.0.0.5/?id=1"}
    )
    coordinator.actions = [
        {
            "tool_id": call.tool_id,
            "arguments": call.arguments,
            "invocation_signature": _invocation_signature(call.tool_id, call.arguments),
            "tool_result": {"success": True},
        }
    ]
    coordinator.action = ToolCall(
        tool_id="nexus.web.sqlmap", arguments={"url": "http://10.0.0.5/?id=1"}
    )
    assert coordinator._repeated_barren_action() == "nexus.web.sqlmap"
    assert "no aportó ningún hecho nuevo" in barren_repeat_correction(
        "nexus.web.sqlmap", 500
    )

    # A turn that produced a verified fact is progress, not a barren repeat.
    coordinator.consecutive_no_progress = 0
    assert coordinator._repeated_barren_action() is None

    # A fast repeat is the gateway's business, not the loop's.
    coordinator.consecutive_no_progress = 1
    coordinator.last_tool_elapsed_ms = 2_000
    assert coordinator._repeated_barren_action() is None

    # Different arguments are a new attempt.
    coordinator.last_tool_elapsed_ms = 500_000
    coordinator.action = ToolCall(
        tool_id="nexus.web.sqlmap", arguments={"url": "http://10.0.0.5/?id=2"}
    )
    assert coordinator._repeated_barren_action() is None


def test_a_fast_repeat_is_stopped_once_the_run_has_stalled(tmp_path):
    """Cheap is not the same as harmless.

    Measured in run_c71035d9818047eaa80dfd859e887b7c (Joomla, 2026-10-20): the
    same SQLi URL three times and the same ``hashcat`` wordlist twice, 0.3 s per
    call, 49 barren turns in a row and 0 findings. The slow-path guard never
    fired (nothing took 30 s) and the gateway dedup is per invocation id, so a
    new turn was always a new invocation. The model also alternated two probes,
    so an adjacency-only rule would have missed every one of them.
    """
    store = _verified_board(tmp_path)
    run = store.create_run(TENANT, {})
    coordinator = _bare_coordinator(
        store, run_id=run["id"], plan=build_plan(counts=RERUN13_COUNTS)
    )
    probe_a = ToolCall(
        tool_id="nexus.web.request", arguments={"url": "http://10.0.0.5/?id=1'"}
    )
    probe_b = ToolCall(
        tool_id="nexus.web.request", arguments={"url": "http://10.0.0.5/?id=2'"}
    )

    def entry(call):
        return {
            "tool_id": call.tool_id,
            "arguments": call.arguments,
            "invocation_signature": _invocation_signature(call.tool_id, call.arguments),
            "tool_result": {"success": True},
        }

    coordinator.consecutive_no_progress = 3
    coordinator.last_tool_elapsed_ms = 300

    # A, B, then A again: still fast, but the run has stalled -that is the loop.
    coordinator.actions = [entry(probe_a), entry(probe_b)]
    coordinator.action = ToolCall(tool_id=probe_a.tool_id, arguments=probe_a.arguments)
    assert coordinator._repeated_barren_action() == "nexus.web.request"

    # A signature that did not run in the window is a new attempt, not a repeat.
    coordinator.actions = [entry(probe_b)]
    coordinator.action = ToolCall(tool_id=probe_a.tool_id, arguments=probe_a.arguments)
    assert coordinator._repeated_barren_action() is None

    # With no barren streak behind it, the same repeat is left to the dedup.
    coordinator.consecutive_no_progress = 0
    coordinator.actions = [entry(probe_a), entry(probe_b)]
    coordinator.action = ToolCall(tool_id=probe_a.tool_id, arguments=probe_a.arguments)
    assert coordinator._repeated_barren_action() is None


# ------------------- stalled branches (joomla run 2026-10-20, 49 barren turns)
def _surface_board(tmp_path, *, vulnerability=False, barrier=False):
    """One scanned host and the two services the Joomla run kept as open work.

    ``barrier=True`` writes the ``barrier`` a *previous* run left on ``:80``: the
    v2 DeadDrop run resumed with one on the board and no in-memory record of it.
    """
    store = ControlStore(tmp_path / "surface.db")
    store.initialize()
    board = Blackboard(store)
    for key, value in (
        (
            f"{TARGET}:22:tcp",
            {"port": 22, "protocol": "tcp", "service": "ssh",
             "product": "OpenSSH", "version": "7.4"},
        ),
        (
            f"{TARGET}:80:tcp",
            {"port": 80, "protocol": "tcp", "service": "http",
             "product": "Apache httpd", "version": "2.4.6"},
        ),
    ):
        board.record(
            tenant_id=TENANT, engagement_id=ENGAGEMENT, fact_type="service",
            key=key, value=value, source="nexus.recon.nmap",
            created_by="deterministic-verifier", verified=True,
            asserted_by="verifier", verification_method="nmap_xml_parsed",
            invocation_id=INVOCATION,
        )
    if barrier:
        board.record(
            tenant_id=TENANT, engagement_id=ENGAGEMENT, fact_type="barrier",
            key=f"{TARGET}:80",
            value={"reason": "sin vector", "sweep_attempted": True},
            source="nexus.knowledge.record_fact", created_by="react.loop",
            verified=False, asserted_by="agent", invocation_id=INVOCATION,
        )
    if vulnerability:
        board.record(
            tenant_id=TENANT, engagement_id=ENGAGEMENT, fact_type="vulnerability",
            key=TARGET,
            value={"class": "error-based SQL injection", "dbms": "mysql",
                   "parameter": "list[fullordering]",
                   "url": f"http://{TARGET}/index.php?option=com_fields"},
            source="nexus.web.request", created_by="deterministic-verifier",
            verified=True, asserted_by="verifier",
            verification_method="http_sql_error", invocation_id=INVOCATION,
        )
    return store


def _surface_coordinator(store, *, threshold=5):
    run = store.create_run(TENANT, {})
    coordinator = _bare_coordinator(
        store, run_id=run["id"], plan=build_plan(counts=RERUN13_COUNTS)
    )
    coordinator.active_subagent_id = "omni"
    coordinator.subagent = SimpleNamespace(id="omni")
    coordinator.closed_branches = set()
    # A real coordinator owns the dict from ``__init__``; a resumed run starts
    # with it empty even when the ledger already reports a closed branch.
    coordinator.closed_branch_at = {}
    coordinator.stuck_threshold = threshold
    coordinator.consecutive_no_progress = 0
    coordinator.actions = []
    coordinator.context = mock.Mock()
    coordinator.snapshot = SimpleNamespace(
        coverage=build_coverage(Blackboard(store).list_facts(TENANT, ENGAGEMENT))
    )
    return coordinator, run


def _barren_turns(coordinator, counts, *, turns):
    """Drive real barren turns through the loop's own counter."""
    for _ in range(turns):
        coordinator.telemetry.begin_turn(
            iteration=coordinator.iteration,
            phase=coordinator.plan.current,
            subagent_id="omni",
            facts_total=sum(counts.values()),
            counts=counts,
        )
        coordinator.telemetry.note_blackboard(
            facts_total=sum(counts.values()), counts=counts
        )
        coordinator._track_no_progress()
        coordinator.telemetry.finish(outcome="completed_turn")


def test_the_loop_writes_the_barrier_the_pivot_asked_for(tmp_path):
    """The advisory line was ignored for 43 turns, so the loop takes the decision.

    Measured in run_c71035d9818047eaa80dfd859e887b7c (Joomla, 2026-10-20): the
    coverage pivot fired at iteration 7 ordering the model to record a
    ``barrier`` for the branch it was hammering; it never did, the ledger kept
    both services as open work, the plan could not move and the run ended at
    ``max_iterations`` with 49 barren turns and 0 findings.
    """
    store = _surface_board(tmp_path)
    coordinator, run = _surface_coordinator(store)
    counts = coordinator._blackboard_counts()
    probe = ToolCall(
        tool_id="nexus.web.request",
        arguments={"url": f"http://{TARGET}/index.php?option=com_fields"},
    )
    coordinator.actions = [
        {"tool_id": probe.tool_id, "arguments": probe.arguments} for _ in range(4)
    ]

    # The first threshold is the advisory line: the loop is still asking.
    _barren_turns(coordinator, counts, turns=5)
    assert _events(store, run["id"], LOOP_BARRIER_EVENT_TYPE) == []

    # The second one is the margin spent: the loop closes what the model did not.
    coordinator.iteration = 11
    _barren_turns(coordinator, counts, turns=5)
    events = _events(store, run["id"], LOOP_BARRIER_EVENT_TYPE)
    assert len(events) == 1
    assert events[0]["payload"]["branch"] == f"{TARGET}:80"

    barriers = Blackboard(store).list_facts(TENANT, ENGAGEMENT, fact_type="barrier")
    assert len(barriers) == 1
    barrier = barriers[0]
    # It is the loop's verdict, never evidence: the operator can tell them apart.
    assert barrier["key"] == f"{TARGET}:80"
    assert barrier["verified"] is False
    assert barrier["asserted_by"] == "agent"
    assert barrier["source"] == "react.loop"
    assert "turnos consecutivos sin hechos nuevos" in barrier["value"]["reason"]

    # The frontier moved: the hammered service is closed, the other one is next.
    coverage = build_coverage(Blackboard(store).list_facts(TENANT, ENGAGEMENT))
    assert coverage.find(f"{TARGET}:80").status == STATUS_CLOSED
    assert coverage.first_open().ref == f"{TARGET}:22"

    # Idempotent: another margin does not write a second barrier for the branch.
    coordinator.iteration = 12
    _barren_turns(coordinator, counts, turns=10)
    assert len(_events(store, run["id"], LOOP_BARRIER_EVENT_TYPE)) == 1


def test_the_loop_barrier_is_not_progress(tmp_path):
    """A loop-authored barrier must not reset the streak it was born from.

    The fact is unverified, so ``Blackboard.summary`` files it under ``leads``;
    counting it would add +1 to the next turn's delta, reset
    ``consecutive_no_progress`` and hand the run a fresh margin of barren turns
    for free.
    """
    store = _surface_board(tmp_path)
    coordinator, _ = _surface_coordinator(store)
    counts = coordinator._blackboard_counts()
    before = sum(counts.values())

    probe = ToolCall(
        tool_id="nexus.web.request",
        arguments={"url": f"http://{TARGET}/index.php?option=com_fields"},
    )
    coordinator.actions = [
        {"tool_id": probe.tool_id, "arguments": probe.arguments} for _ in range(3)
    ]
    _barren_turns(coordinator, counts, turns=10)

    assert coordinator.closed_branches == {f"{TARGET}:80"}
    after = coordinator._blackboard_counts()
    assert sum(after.values()) == before
    assert "barrier" not in after


def test_a_branch_with_a_registered_vector_is_never_closed(tmp_path):
    """Hiding a proven vector behind a dead branch is worse than stalling.

    The ledger would then order the run to the other port, where the vector does
    not live. The branch stays open and the pivot keeps asking the model to
    exploit it.
    """
    store = _surface_board(tmp_path, vulnerability=True)
    coordinator, run = _surface_coordinator(store)
    counts = coordinator._blackboard_counts()
    probe = ToolCall(
        tool_id="nexus.web.request",
        arguments={"url": f"http://{TARGET}/index.php?option=com_fields"},
    )
    coordinator.actions = [
        {"tool_id": probe.tool_id, "arguments": probe.arguments} for _ in range(4)
    ]

    _barren_turns(coordinator, counts, turns=10)

    assert _events(store, run["id"], LOOP_BARRIER_EVENT_TYPE) == []
    assert Blackboard(store).list_facts(
        TENANT, ENGAGEMENT, fact_type="barrier"
    ) == []


def test_the_loop_does_not_close_a_branch_it_cannot_attribute(tmp_path):
    """Two services in the window is breadth, not a stall on one."""
    store = _surface_board(tmp_path)
    coordinator, run = _surface_coordinator(store)
    counts = coordinator._blackboard_counts()
    coordinator.actions = [
        {"tool_id": "nexus.shell.exec", "arguments": {"target": f"{TARGET}:22"}},
        {"tool_id": "nexus.web.request", "arguments": {"url": f"http://{TARGET}/"}},
        {"tool_id": "nexus.shell.exec", "arguments": {"target": f"{TARGET}:22"}},
        {"tool_id": "nexus.web.request", "arguments": {"url": f"http://{TARGET}/"}},
    ]

    _barren_turns(coordinator, counts, turns=10)

    assert _events(store, run["id"], LOOP_BARRIER_EVENT_TYPE) == []
    assert coordinator.closed_branches == set()


# ---------------------- Tanda D: the closed branch is actually refused
def _branch_call(coordinator, tool_id, arguments):
    """Wire one pending action into a bare coordinator (the gates read these)."""
    from nexus_core.agent.react_support import _action_entry

    coordinator.action = ToolCall(tool_id=tool_id, arguments=arguments)
    coordinator.entry = _action_entry(
        coordinator.iteration,
        "tool_call",
        tool_id=tool_id,
        arguments=arguments,
    )
    coordinator.conversation_id = coordinator.store.create_conversation(
        TENANT, "operator:kali", "branch gate"
    )["id"]
    coordinator.allowed_catalog = {}
    return coordinator


def test_a_closed_branch_refuses_the_next_web_call(tmp_path):
    """Measured in DeadDrop P12: the loop closed the branch and the model kept
    calling ``web.*`` on it for fifteen turns because the event was descriptive.
    """
    store = _surface_board(tmp_path)
    coordinator, run = _surface_coordinator(store)
    counts = coordinator._blackboard_counts()
    coordinator.actions = [
        {"tool_id": "nexus.web.request", "arguments": {"url": f"http://{TARGET}/"}}
        for _ in range(4)
    ]
    _barren_turns(coordinator, counts, turns=10)
    assert coordinator.closed_branch_at == {f"{TARGET}:80": coordinator.iteration}

    coordinator.iteration += 1
    _branch_call(coordinator, "nexus.web.request", {"url": f"http://{TARGET}/dashboard"})
    transition = coordinator._refuse_closed_branch()

    assert transition is not None
    assert coordinator.observation["outcome"] == "branch_closed_recent"
    assert coordinator.observation["branch_closed_recent"] is True
    assert f"{TARGET}:80" in coordinator.observation["guidance"]
    assert f"{TARGET}:22" in coordinator.observation["guidance"]

    # Another branch is untouched: the gate is per host:port, not global.
    _branch_call(coordinator, "nexus.post.ssh_exec", {"target": TARGET})
    assert coordinator._refuse_closed_branch() is None


def test_a_single_upload_cannot_close_the_web_branch(tmp_path):
    """DeadDrop P12 iteration 21: one payload, ``{}``, and a false barrier."""
    store = _surface_board(tmp_path)
    coordinator, run = _surface_coordinator(store)
    coordinator.actions = [
        {
            "tool_id": "nexus.web.upload",
            "arguments": {"url": f"http://{TARGET}/upload"},
            "tool_result": {"success": True, "output": {}},
        }
    ]
    assert coordinator._coverage_snapshot().find(f"{TARGET}:80") is not None

    _branch_call(
        coordinator,
        "nexus.knowledge.record_fact",
        {"fact_type": "barrier", "key": f"{TARGET}:80", "value": {"reason": "no RCE"}},
    )
    transition = coordinator._refuse_barrier_without_attempts()

    assert transition is not None
    assert coordinator.observation["outcome"] == "barrier_refused"
    assert "al menos 2" in coordinator.observation["guidance"]
    # The fact never reaches the board, so the ledger stays open.
    assert Blackboard(store).list_facts(
        TENANT, ENGAGEMENT, fact_type="barrier"
    ) == []


def test_an_insisted_barrier_is_recorded_as_unsubstantiated(tmp_path):
    """The pivot tells the model to document a dead end with a ``barrier``.

    hijack_v7 (2026-10-30) refused that same call nine times -one attempt is not
    the two distinct tools the policy wants- and seventeen turns produced no
    fact at all. Insisting now records the verdict, stamped ``invalid_*`` so
    ``coverage.barrier_is_conclusive`` keeps the branch open.
    """
    store = _surface_board(tmp_path)
    coordinator, run = _surface_coordinator(store)
    coordinator.actions = [
        {
            "tool_id": "nexus.web.upload",
            "arguments": {"url": f"http://{TARGET}/upload"},
            "tool_result": {"success": True, "output": {}},
        }
    ]
    arguments = {
        "fact_type": "barrier",
        "key": f"{TARGET}:80",
        "value": {"reason": "one payload, no execution"},
    }

    _branch_call(coordinator, "nexus.knowledge.record_fact", arguments)
    assert coordinator._refuse_barrier_without_attempts() is not None

    coordinator.iteration += 1
    _branch_call(coordinator, "nexus.knowledge.record_fact", arguments)
    assert coordinator._refuse_barrier_without_attempts() is None

    value = coordinator.action.arguments["value"]
    assert value["outcome"] == "invalid_unsubstantiated"
    assert value["sweep_attempted"] is False
    assert value["reason"] == "one payload, no execution"
    events = [
        event["event_type"]
        for event in store.list_run_events(TENANT, run["id"])
    ]
    assert "react.barrier_downgraded" in events


def test_the_pivot_stamps_the_branch_a_previous_run_closed(tmp_path):
    """DeadDrop P12 v2: the ledger said ``descartado`` and nothing enforced it.

    The run resumed with a persisted ``barrier`` on ``192.168.11.200:80``; the
    pivot fired on iteration 4 ordering the model off that branch, and the model
    kept calling ``web.*`` on it for 43 turns. ``closed_branch_at`` only knew the
    closures ``_close_stalled_branch`` wrote itself, so the refusal window never
    started: the acknowledgement *is* the closure, and it has to be stamped.
    """
    store = _surface_board(tmp_path, barrier=True)
    coordinator, run = _surface_coordinator(store)
    assert coordinator.closed_branch_at == {}

    coordinator.iteration = 4
    _branch_call(coordinator, "nexus.web.request", {"url": f"http://{TARGET}/dashboard"})
    coordinator._refresh_coverage_hint()

    assert coordinator.coverage_hint and "RAMAL CERRADO" in coordinator.coverage_hint
    assert coordinator.closed_branch_at == {f"{TARGET}:80": 4}

    transition = coordinator._refuse_closed_branch()

    assert transition is not None
    assert coordinator.observation["outcome"] == "branch_closed_recent"
    assert f"{TARGET}:80" in coordinator.observation["guidance"]


def test_a_branch_the_pivot_stamped_reopens_after_the_block_window(tmp_path):
    """The window is a stop, not a tombstone: coverage still owns reopening."""
    from nexus_core.agent.branch_discipline import CLOSED_BRANCH_BLOCK_TURNS

    store = _surface_board(tmp_path, barrier=True)
    coordinator, run = _surface_coordinator(store)
    coordinator.iteration = 4
    _branch_call(coordinator, "nexus.web.request", {"url": f"http://{TARGET}/dashboard"})
    coordinator._refresh_coverage_hint()
    assert coordinator._refuse_closed_branch() is not None

    # Closed at 4: turns 5..9 are refused (five turns) and 10 runs again.
    coordinator.iteration = 4 + CLOSED_BRANCH_BLOCK_TURNS + 1
    _branch_call(coordinator, "nexus.web.request", {"url": f"http://{TARGET}/dashboard"})
    assert coordinator.closed_branch_at == {f"{TARGET}:80": 4}
    assert coordinator._refuse_closed_branch() is None


def test_an_objective_that_names_the_branch_outranks_the_pivot(tmp_path):
    """An operator order is not a dead end the ledger gets to close.

    ``parse_directive`` reports the branch the objective fixes; stamping it would
    turn the human's own instruction into a five-turn refusal.
    """
    store = _surface_board(tmp_path, barrier=True)
    coordinator, run = _surface_coordinator(store)
    coordinator.objective = f"Ataca solo {TARGET}:80 y documenta el panel"
    coordinator.iteration = 4
    _branch_call(coordinator, "nexus.web.request", {"url": f"http://{TARGET}/dashboard"})

    coordinator._refresh_coverage_hint()

    assert coordinator.closed_branch_at == {}


def test_the_loop_still_stamps_its_own_barrier(tmp_path):
    """``_close_stalled_branch`` and the pivot share one stamping rule."""
    store = _surface_board(tmp_path)
    coordinator, run = _surface_coordinator(store)
    counts = coordinator._blackboard_counts()
    coordinator.actions = [
        {"tool_id": "nexus.web.request", "arguments": {"url": f"http://{TARGET}/"}}
        for _ in range(4)
    ]
    _barren_turns(coordinator, counts, turns=10)

    assert coordinator.closed_branch_at == {f"{TARGET}:80": coordinator.iteration}


# ------------------------------------------- WP6 · endpoint ceiling and budget
def test_the_endpoint_ceiling_forces_exploitation_and_stays_latched(tmp_path):
    """5 mapped endpoints close enumeration by decision, not by model mood.

    Simple CTF 2026-10-18 02:35 UTC: gobuster mapped 17 endpoints and the model
    kept enumerating routes until the token budget ended the run.
    """
    store = _verified_board(tmp_path)
    run = store.create_run(TENANT, {})
    plan = build_plan(counts={"host": 1, "service": 3}, leads={"endpoint": 5})
    assert plan.current == "enumeration"
    coordinator = _bare_coordinator(store, run_id=run["id"], plan=plan)

    coordinator._apply_endpoint_ceiling()

    assert coordinator.plan.current == "exploitation"
    assert coordinator.plan_reason == ENUMERATION_ENDPOINT_REASON
    assert coordinator.endpoint_ceiling_applied is True
    # The plan is rebuilt every turn: a rebuild that computes ``enumeration``
    # again must be closed again while the endpoints are still on the board.
    coordinator.plan = plan
    coordinator._apply_endpoint_ceiling()
    assert coordinator.plan.current == "exploitation"


async def test_the_loop_injects_the_smart_budget_hint_into_the_prompt(tmp_path):
    """End to end: the prompt of turn 11 carries the order to stop enumerating."""
    store, context = _engagement(tmp_path, "wp6-hint.db", complete_board=False)
    board = Blackboard(store)
    for port, service in ((21, "ftp"), (80, "http"), (2222, "ssh")):
        board.record(
            tenant_id=TENANT, engagement_id=ENGAGEMENT, fact_type="service",
            key=f"{TARGET}:{port}/{service}",
            value={"port": port, "service": service},
            source="nexus.recon.nmap", created_by="verifier", verified=True,
            asserted_by="verifier", verification_method="nmap_xml_parsed",
            invocation_id=INVOCATION,
        )
    board.record(
        tenant_id=TENANT, engagement_id=ENGAGEMENT, fact_type="endpoint",
        key=f"{TARGET}/simple/", value={"path": "/simple/"},
        source="nexus.recon.gobuster", created_by="verifier", verified=True,
        asserted_by="verifier", verification_method="gobuster_text_parsed",
        invocation_id=INVOCATION,
    )

    class _NeutralSpy:
        async def __call__(self, payload, context):
            return {
                "tool_id": payload["tool_id"],
                "output": {
                    "success": True, "verified": True,
                    "verification_method": "shell_exit_code",
                    "evidence": {"exit_code": 0},
                    "output": {"stdout": "uid=1001(mitch)", "exit_code": 0},
                },
            }

    llm = ScriptedLLM([_shell_call("id")] * 12)
    with mock.patch.object(runtime_module, "execute_tool", _NeutralSpy()):
        await run_react_loop(
            context=context,
            objective="Enumerar y explotar el objetivo",
            engagement_id=ENGAGEMENT,
            llm_client=llm,
            config=ReActConfig(max_iterations=12, enforce_completion_gates=False),
        )

    assert len(llm.prompts) >= 11
    assert "gastando demasiado presupuesto en enumeración" in llm.prompts[10]
    assert "gastando demasiado presupuesto en enumeración" not in llm.prompts[0]
    assert len(_events(store, context.run_id, SMART_BUDGET_EVENT_TYPE)) == 1


async def test_the_loop_orders_the_paths_a_robots_txt_lists(tmp_path):
    """Brute It: ``/robots.txt`` was read and its routes never requested.

    The order has to reach the *next* prompt, with the concrete URL, before the
    model can close the branch; a static rule in the skill was already in place
    when the measured run skipped it.
    """
    store, context = _engagement(tmp_path, "wp-robots-hint.db", complete_board=False)
    host = "10.0.0.9"

    class _WebSpy:
        async def __call__(self, payload, context):
            url = str((payload.get("arguments") or {}).get("url") or "")
            body = (
                "User-agent: *\nDisallow: /secret/\n"
                if url.endswith("robots.txt")
                else "<html>login</html>"
            )
            return {
                "tool_id": payload["tool_id"],
                "output": {
                    "success": True,
                    "verified": True,
                    "verification_method": "http_response_received",
                    "evidence": {"status": 200},
                    "output": {
                        "url": url,
                        "status": 200,
                        "body_preview": body,
                        "body_complete": True,
                    },
                },
            }

    def _web_call(url: str) -> str:
        return json.dumps(
            {
                "thought": "Enumero la web.",
                "action": "tool_call",
                "tool_id": "nexus.web.request",
                "arguments": {"url": url},
                "expected_outcome": "rutas",
            }
        )

    llm = ScriptedLLM(
        [
            _web_call(f"http://{host}/robots.txt"),
            _web_call(f"http://{host}/login.php"),
        ]
        * 2
    )
    with mock.patch.object(runtime_module, "execute_tool", _WebSpy()):
        await run_react_loop(
            context=context,
            objective="Enumerar y explotar el objetivo",
            engagement_id=ENGAGEMENT,
            llm_client=llm,
            config=ReActConfig(max_iterations=4, enforce_completion_gates=False),
        )

    assert "ÍNDICE SIN SEGUIR" not in llm.prompts[0]
    assert "ÍNDICE SIN SEGUIR" in llm.prompts[1]
    assert f"http://{host}/secret/" in llm.prompts[1]
    assert len(_events(store, context.run_id, ROBOTS_HINT_EVENT_TYPE)) == 1


async def test_the_loop_injects_the_webshell_hint_into_the_prompt(tmp_path):
    """Vulnversity's stall: ten build/transfer turns through a webshell."""
    store, context = _engagement(tmp_path, "wp-shell-hint.db", complete_board=False)
    build = (
        "cd /tmp/pwnkit && gcc -static -o pwnkit pwnkit.c && "
        "base64 -w0 pwnkit | curl -s -G \"$U\" --data-urlencode cmd=@-"
    )

    class _NeutralSpy:
        async def __call__(self, payload, context):
            return {
                "tool_id": payload["tool_id"],
                "output": {
                    "success": True, "verified": True,
                    "verification_method": "shell_exit_code",
                    "evidence": {"exit_code": 0},
                    "output": {"stdout": "ok", "exit_code": 0},
                },
            }

    llm = ScriptedLLM([_shell_call(build)] * 13)
    with mock.patch.object(runtime_module, "execute_tool", _NeutralSpy()):
        await run_react_loop(
            context=context,
            objective="Compromete el objetivo y escala privilegios",
            engagement_id=ENGAGEMENT,
            llm_client=llm,
            config=ReActConfig(max_iterations=13, enforce_completion_gates=False),
        )

    assert len(llm.prompts) >= 11
    assert "Estás atascado en un webshell" in llm.prompts[10]
    assert "nexus.session.pty" in llm.prompts[10]
    assert "Estás atascado en un webshell" not in llm.prompts[0]
    assert len(_events(store, context.run_id, WEBSHELL_STALL_EVENT_TYPE)) == 1


def test_the_webshell_hint_is_audited_once_per_run(tmp_path):
    store = _verified_board(tmp_path)
    run = store.create_run(TENANT, {})
    plan = build_plan(counts={"host": 1, "service": 1})
    coordinator = _bare_coordinator(store, run_id=run["id"], plan=plan, iteration=11)
    coordinator.subagent = mock.Mock(id="omni")
    coordinator.actions = [
        {"tool_id": "nexus.shell.exec", "arguments": {"command": "gcc -o p p.c"}}
    ] * 10
    coordinator.consecutive_no_progress = 10

    coordinator._refresh_webshell_hint()

    assert "Estás atascado en un webshell" in coordinator.webshell_hint
    events = _events(store, run["id"], WEBSHELL_STALL_EVENT_TYPE)
    assert len(events) == 1
    assert events[0]["payload"]["no_progress"] == 10
    # The audit is per run, not per turn.
    coordinator.iteration = 12
    coordinator._refresh_webshell_hint()
    assert len(_events(store, run["id"], WEBSHELL_STALL_EVENT_TYPE)) == 1


async def test_the_loop_applies_the_endpoint_ceiling(tmp_path):
    """Five endpoint leads are enough: the plan is forced to exploitation."""
    store, context = _engagement(tmp_path, "wp6-ceiling.db", complete_board=False)
    board = Blackboard(store)
    for path in ("/simple/", "/login", "/assets", "/robots.txt", "/admin"):
        board.record(
            tenant_id=TENANT, engagement_id=ENGAGEMENT, fact_type="endpoint",
            key=path, value={"path": path},
            source="agent", created_by="agent", asserted_by="agent",
        )

    with mock.patch.object(runtime_module, "execute_tool", mock.AsyncMock()):
        result = await run_react_loop(
            context=context,
            objective="Enumerar y explotar el objetivo",
            engagement_id=ENGAGEMENT,
            llm_client=ScriptedLLM([_complete()]),
            config=ReActConfig(max_iterations=2, enforce_completion_gates=False),
        )

    events = _events(store, context.run_id, "orchestrator.plan")
    assert any(
        event["payload"].get("reason") == ENUMERATION_ENDPOINT_REASON
        and event["payload"]["phase"] == "exploitation"
        for event in events
    )
    assert result.plan["current"] == "exploitation"


def test_the_smart_budget_hint_is_injected_and_audited_once(tmp_path):
    """After 10 turns with 3 services and an endpoint, the prompt orders a pivot."""
    store = _verified_board(tmp_path)
    run = store.create_run(TENANT, {})
    plan = build_plan(counts={"host": 1, "service": 3, "endpoint": 2})
    coordinator = _bare_coordinator(store, run_id=run["id"], plan=plan, iteration=11)

    coordinator._refresh_budget_hint()

    assert "gastando demasiado presupuesto en enumeración" in coordinator.budget_hint
    events = _events(store, run["id"], SMART_BUDGET_EVENT_TYPE)
    assert len(events) == 1
    payload = events[0]["payload"]
    assert payload["iteration"] == 11
    assert payload["services"] == 3 and payload["endpoints"] == 2
    # The audit is per run, not per turn.
    coordinator.iteration = 12
    coordinator._refresh_budget_hint()
    assert len(_events(store, run["id"], SMART_BUDGET_EVENT_TYPE)) == 1
    # At 10 turns exactly the contract says "more than 10": no hint.
    late = _bare_coordinator(
        store, run_id=store.create_run(TENANT, {})["id"], plan=plan, iteration=10
    )
    late._refresh_budget_hint()
    assert late.budget_hint == ""


# ------------------------------- guardrail: el mismo fallo dos veces seguidas
def _failure_loop(tool_id: str = "nexus.recon.nmap"):
    coordinator = ReActCoordinator.__new__(ReActCoordinator)
    coordinator.action = SimpleNamespace(tool_id=tool_id)
    coordinator.observation = {
        "success": False,
        "outcome": "error",
        "invocation_id": "inv-unit",
        "verification_method": "nmap_xml_parse_failed",
        "output": {"error": "nmap xml is empty"},
    }
    coordinator.repeated_failure_tool = None
    coordinator.repeated_failure_detail = ""
    coordinator.repeated_failure_streak = 0
    return coordinator


def test_the_same_tool_and_error_four_times_stops_the_run():
    coordinator = _failure_loop()
    # The reviewed contract pins two as transient and three as the retirement /
    # vector-lock point; this brake catches the fourth identical error.
    for _ in range(3):
        assert coordinator._repeated_failure_summary() is None
    summary = coordinator._repeated_failure_summary()
    assert summary is not None
    assert "nexus.recon.nmap" in summary and "4 veces" in summary
    assert "nmap xml is empty" in summary


def test_a_different_error_or_a_success_breaks_the_streak():
    coordinator = _failure_loop()
    assert coordinator._repeated_failure_summary() is None
    coordinator.observation = {
        "success": False, "outcome": "error", "invocation_id": "inv-unit",
        "output": {"error": "timeout"},
    }
    # A different error is a different route: no abort.
    assert coordinator._repeated_failure_summary() is None
    coordinator.observation = {"success": True, "outcome": "ok"}
    assert coordinator._repeated_failure_summary() is None
    # After a success the same error must repeat four times again.
    coordinator.observation = {
        "success": False, "outcome": "error", "invocation_id": "inv-unit",
        "output": {"error": "timeout"},
    }
    for _ in range(3):
        assert coordinator._repeated_failure_summary() is None
    assert coordinator._repeated_failure_summary() is not None
