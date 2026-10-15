"""Fase 3 fixes: the four defects measured in run_abe04509c5064c6e8e475f46ba8f8c60.

That run (10.65.175.32, eleven turns) lost 30,6 % of its tokens to three schema
rejections the catalog could have prevented, spent ten turns with
``blackboard_delta = 0`` without ever pivoting, burned its enumeration profile on
SMB/AD while the signals to hand over to initial access were already on the
board, and re-issued two identical calls it had already made. One measurement per
test, all four against the real components (catalog renderer, loop, planner and
gateway).
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from unittest import mock

import pytest

from nexus_core.agent.planner import (
    ENUMERATION_EXHAUSTED_REASON,
    EnumerationEscalation,
    build_plan,
    enumeration_escalation,
    escalate_enumeration,
)
from nexus_core.agent.prompts import render_tool_catalog
from nexus_core.agent.react import ReActConfig, run_react_loop, stuck_threshold
from nexus_core.agent.react_types import (
    DEFAULT_STUCK_THRESHOLD,
    STUCK_EVENT_TYPE,
    STUCK_PROMPT_LINE,
    STUCK_THRESHOLD_ENV,
    SUBAGENT_EVENT_TYPE,
)
from nexus_core.agent.subagents import select_for_plan
from nexus_core.agent.turn_telemetry import TurnTelemetryRecorder
from nexus_core.kernel import runtime as runtime_module
from nexus_core.kernel.approvals import ApprovalService
from nexus_core.kernel.audit import AuditWriter
from nexus_core.kernel.blackboard import Blackboard
from nexus_core.kernel.control_store import ControlStore
from nexus_core.kernel.errors import ApprovalRequired
from nexus_core.kernel.invocation_journal import InvocationJournal
from nexus_core.kernel.models import (
    Identity,
    RiskLevel,
    RunContext,
    ToolDefinition,
    ToolResult,
)
from nexus_core.kernel.policy import PolicyEngine
from nexus_core.kernel.runtime import ExecutionContext
from nexus_core.kernel.tool_gateway import ToolGateway
from nexus_core.llm.abstraction import LLMMessage, LLMProvider, LLMResponse
from nexus_core.scope import EngagementScope, EngagementStore
from nexus_core.tools.registry import durable_tool_definitions

pytestmark = [pytest.mark.unit, pytest.mark.usefixtures("lab_scope")]

TENANT = "system"
ENGAGEMENT = "eng-1"
TARGET = "10.65.175.32"
OTHER_TARGET = "10.65.175.99"
SMB_SERVICE = f"{TARGET}:445/tcp"


# --------------------------------------------------------------------------- #
# Problema 1 - the catalog shows the legal values of every declared enum
# --------------------------------------------------------------------------- #


@pytest.fixture()
def catalog() -> dict[str, Any]:
    return durable_tool_definitions(TENANT)


def _line(catalog: dict[str, Any], tool_id: str) -> str:
    text = render_tool_catalog(catalog)
    return next(line for line in text.splitlines() if line.startswith(f"- {tool_id}:"))


def _definition(catalog: dict[str, Any], tool_id: str) -> Any:
    entry = catalog[tool_id]
    return entry[0] if isinstance(entry, tuple) else entry


def _declared_enums(definition: Any) -> dict[str, tuple[str, ...]]:
    properties = (definition.input_schema or {}).get("properties") or {}
    return {
        name: tuple(str(value) for value in spec["enum"])
        for name, spec in properties.items()
        if isinstance(spec, dict) and spec.get("enum")
    }


#: The enums the model guessed wrong in the measured run (``enum_shares`` for
#: ``operation``, ``winrm`` for ``protocol``, ``login`` for ``operation``) plus
#: the two tools used to measure the catalog budget.
ENUM_TOOLS: tuple[str, ...] = (
    "nexus.recon.netexec",
    "nexus.win.winrm_exec",
    "nexus.cred.bruteforce",
    "nexus.knowledge.record_fact",
    "nexus.recon.nmap",
)


@pytest.mark.parametrize("tool_id", ENUM_TOOLS)
def test_catalog_renders_enums(catalog: dict[str, Any], tool_id: str) -> None:
    """Every legal value of every enum the tool declares is on its catalog line."""
    declared = _declared_enums(_definition(catalog, tool_id))
    assert declared, f"{tool_id} declares no enum: this case would prove nothing"
    line = _line(catalog, tool_id)
    for name, values in declared.items():
        assert f"{name}∈{{" in line, f"{tool_id}.{name} is listed without its legal values"
        for value in values:
            assert value in line, f"{tool_id}.{name}: {value!r} was cut from the line"


def test_catalog_never_lists_a_partial_enum(catalog: dict[str, Any]) -> None:
    """An enum is either fully listed or not listed at all - never half of it."""
    for tool_id in catalog:
        line = _line(catalog, tool_id)
        for name, values in _declared_enums(_definition(catalog, tool_id)).items():
            if f"{name}∈{{" not in line:
                continue  # the argument cap kept it out entirely (next test)
            missing = [value for value in values if value not in line]
            assert missing == [], f"{tool_id}.{name}: truncated {missing}"


#: The only arguments the five-slot cap still keeps out. A tool that declares
#: seven required arguments cannot show them all inside a cap of five; both
#: hidden ones are named in favour of the arguments the first call needs.
HIDDEN_BY_THE_CAP: dict[str, set[str]] = {
    "nexus.post.pivot_bruteforce": {"failure_marker", "password_file"},
}


def test_catalog_keeps_every_required_argument_visible(catalog: dict[str, Any]) -> None:
    """A required argument is what a rejection bites on, so none is cut by the cap."""
    hidden: dict[str, set[str]] = {}
    for tool_id in catalog:
        definition = _definition(catalog, tool_id)
        required = set((definition.input_schema or {}).get("required") or ())
        line = _line(catalog, tool_id)
        missing = {
            name
            for name in required
            if f"{name}:" not in line and f"{name}∈" not in line
        }
        if missing:
            hidden[tool_id] = missing
    assert hidden == HIDDEN_BY_THE_CAP


# --------------------------------------------------------------------------- #
# Harness: the real loop over a real store, with only the model and tool faked
# --------------------------------------------------------------------------- #


def _iso(delta: timedelta) -> str:
    return (datetime.now(timezone.utc) + delta).isoformat()


def _create_scope(store: ControlStore) -> None:
    EngagementStore(store).create(
        EngagementScope(
            engagement_id=ENGAGEMENT,
            tenant_id=TENANT,
            name="phase3",
            client="acme",
            owner_id="owner-1",
            valid_from=_iso(-timedelta(days=1)),
            valid_until=_iso(timedelta(days=1)),
            cidrs=("10.65.175.0/24",),
            domains=(),
            urls=(),
            exclusions=(),
            created_at=_iso(timedelta(0)),
        )
    )


class ScriptedLLM:
    """Replays the scripted replies (the last one forever), keeping each prompt."""

    def __init__(self, responses: list[str]) -> None:
        self.responses = list(responses)
        self.calls = 0
        self.system_prompts: list[str] = []

    async def complete(self, messages: list[LLMMessage], **kwargs: Any) -> LLMResponse:
        self.calls += 1
        self.system_prompts.append(
            "\n".join(
                str(getattr(message, "content", ""))
                for message in messages
                if getattr(message, "role", "") == "system"
            )
        )
        index = min(self.calls - 1, max(0, len(self.responses) - 1))
        return LLMResponse(
            content=self.responses[index] if self.responses else "",
            model="scripted-test",
            provider=LLMProvider.FAKE,
            tokens_input=100,
            tokens_output=25,
        )


def tool_call(tool_id: str = "nexus.recon.nmap", **arguments: Any) -> str:
    return json.dumps(
        {
            "thought": "Enumero el objetivo autorizado.",
            "action": "tool_call",
            "tool_id": tool_id,
            "arguments": arguments or {"target": TARGET},
            "expected_outcome": "servicios enumerados",
        }
    )


TOOL_SUCCESS: dict[str, Any] = {
    "tool_id": "nexus.recon.nmap",
    "output": {
        "success": True,
        "verified": True,
        "verification_method": "nmap_xml_parsed",
        "evidence": {"hosts_up": 1},
        "output": {"target": TARGET, "scan": {"hosts": []}},
    },
}


def _harness(tmp_path: Path) -> tuple[ControlStore, ExecutionContext]:
    """A real store, scope and run; only the provider and the tool are faked."""
    store = ControlStore(tmp_path / "phase3.db")
    store.initialize()
    _create_scope(store)
    run = store.create_run(TENANT, {})
    task = {
        "id": "task-1",
        "tenant_id": TENANT,
        "run_id": run["id"],
        "task_type": "react.run",
        "payload": {
            "objective": "Enumera 10.65.175.32",
            "engagement_id": ENGAGEMENT,
            "identity": {"subject_id": "operator-1", "roles": ["operator"]},
            "permissions": [
                "execute:tool:nexus.recon.nmap",
                "execute:tool:nexus.recon.netexec",
            ],
        },
    }
    return store, ExecutionContext(store, task, "worker-test")


def _loop_config(**kwargs: Any) -> ReActConfig:
    kwargs.setdefault("enforce_completion_gates", False)
    return ReActConfig(**kwargs)


def _events(
    store: ControlStore, context: ExecutionContext, event_type: str | None = None
) -> list[dict[str, Any]]:
    events = store.list_run_events(context.tenant_id, context.run_id)
    return [event for event in events if event_type is None or event["event_type"] == event_type]


def _seed_smb_surface(board: Blackboard) -> None:
    """A host with an SMB service and nothing else: the measured dead end."""
    board.record(
        tenant_id=TENANT,
        engagement_id=ENGAGEMENT,
        fact_type="host",
        key=TARGET,
        value={"state": "up"},
        source="nexus.recon.nmap",
        created_by="deterministic-verifier",
        verified=True,
        asserted_by="verifier",
        verification_method="nmap_xml_parsed",
        invocation_id="inv-host",
    )
    board.record(
        tenant_id=TENANT,
        engagement_id=ENGAGEMENT,
        fact_type="service",
        key=SMB_SERVICE,
        value={"port": 445, "protocol": "smb"},
        source="nexus.recon.nmap",
        created_by="deterministic-verifier",
        verified=True,
        asserted_by="verifier",
        verification_method="nmap_xml_parsed",
        invocation_id="inv-service",
    )


# --------------------------------------------------------------------------- #
# Problema 2 - ten silent turns become a signal and a prompt line
# --------------------------------------------------------------------------- #


def test_stuck_threshold_defaults_to_five_and_reads_the_env(monkeypatch) -> None:
    monkeypatch.delenv(STUCK_THRESHOLD_ENV, raising=False)
    assert stuck_threshold() == DEFAULT_STUCK_THRESHOLD == 5
    monkeypatch.setenv(STUCK_THRESHOLD_ENV, "2")
    assert stuck_threshold() == 2
    # A non-positive or malformed value falls back to the default: it never
    # disables the signal by accident.
    monkeypatch.setenv(STUCK_THRESHOLD_ENV, "0")
    assert stuck_threshold() == DEFAULT_STUCK_THRESHOLD
    monkeypatch.setenv(STUCK_THRESHOLD_ENV, "no")
    assert stuck_threshold() == DEFAULT_STUCK_THRESHOLD


def test_no_progress_is_part_of_the_turn_record() -> None:
    recorder = TurnTelemetryRecorder(emit=False)
    recorder.begin_turn(iteration=6, phase="enumeration", subagent_id="services")
    recorder.note_no_progress(consecutive=4)
    record = recorder.finish(outcome="completed_turn")
    assert record is not None
    assert record.consecutive_no_progress == 4
    assert record.to_dict()["consecutive_no_progress"] == 4


async def test_loop_signals_stuck_at_the_threshold_and_warns_the_next_prompt(
    tmp_path: Path,
) -> None:
    """Six turns with ``blackboard_delta = 0``: the signal lands on turn 5 and
    the warning reaches the model on turn 6, exactly as measured."""
    store, context = _harness(tmp_path)
    llm = ScriptedLLM([tool_call()])

    async def fake_tool(payload: dict[str, Any], run_context: ExecutionContext) -> dict[str, Any]:
        return dict(TOOL_SUCCESS)

    with mock.patch.object(runtime_module, "execute_tool", fake_tool):
        result = await run_react_loop(
            context=context,
            objective="Enumera 10.65.175.32",
            engagement_id=ENGAGEMENT,
            llm_client=llm,
            config=_loop_config(max_iterations=6),
        )

    assert [turn["blackboard_delta"] for turn in result.turns] == [0] * 6
    assert [turn["consecutive_no_progress"] for turn in result.turns] == [1, 2, 3, 4, 5, 6]

    signals = _events(store, context, STUCK_EVENT_TYPE)
    assert len(signals) == 1
    payload = signals[0]["payload"]
    assert payload["iterations_stuck"] == 5
    assert payload["phase"] == "recon"
    assert payload["subagent_id"] == "recon"
    assert payload["last_tools"] == ["nexus.recon.nmap"]
    # The signal never kills the run nor changes the phase by itself.
    assert result.status != "completed"
    assert result.iterations == 6

    # The prompt already sent on turn 5 cannot warn; the next one does.
    assert "Detectado estancamiento" not in llm.system_prompts[4]
    assert STUCK_PROMPT_LINE.format(iterations=5) in llm.system_prompts[5]


async def test_no_progress_counter_resets_when_a_fact_arrives(tmp_path: Path) -> None:
    store, context = _harness(tmp_path)
    llm = ScriptedLLM([tool_call()])
    board = Blackboard(store)
    calls = {"count": 0}

    async def fake_tool(payload: dict[str, Any], run_context: ExecutionContext) -> dict[str, Any]:
        calls["count"] += 1
        if calls["count"] == 3:
            board.record(
                tenant_id=TENANT,
                engagement_id=ENGAGEMENT,
                fact_type="service",
                key=f"{TARGET}:22/tcp",
                value={"port": 22},
                source="nexus.recon.nmap",
                created_by="deterministic-verifier",
                verified=True,
                asserted_by="verifier",
                verification_method="nmap_xml_parsed",
                invocation_id="inv-1",
            )
        return dict(TOOL_SUCCESS)

    with mock.patch.object(runtime_module, "execute_tool", fake_tool):
        result = await run_react_loop(
            context=context,
            objective="Enumera 10.65.175.32",
            engagement_id=ENGAGEMENT,
            llm_client=llm,
            config=_loop_config(max_iterations=4),
        )

    assert [turn["blackboard_delta"] for turn in result.turns] == [0, 0, 1, 0]
    # Two silent turns, then the fact resets the streak, which starts over.
    assert [turn["consecutive_no_progress"] for turn in result.turns] == [1, 2, 0, 1]
    assert _events(store, context, STUCK_EVENT_TYPE) == []


# --------------------------------------------------------------------------- #
# Problema 3 - an exhausted SMB enumeration hands over to initial access
# --------------------------------------------------------------------------- #


def _enumeration_plan(**counts: int) -> Any:
    return build_plan("enumera los servicios SMB", counts=counts, engagement_id=ENGAGEMENT)


@pytest.mark.parametrize("subagent_id", ["services", "cred"])
def test_planner_hands_exhausted_smb_enumeration_to_exploit(subagent_id: str) -> None:
    plan = _enumeration_plan(host=1, service=1)
    assert plan.current == "enumeration"

    escalation = enumeration_escalation(
        plan, subagent_id=subagent_id, no_progress=3, services=[SMB_SERVICE]
    )

    assert escalation == EnumerationEscalation(
        phase="exploitation", subagent="exploit", reason=ENUMERATION_EXHAUSTED_REASON
    )
    escalated = escalate_enumeration(plan, escalation)
    assert escalated.current == "exploitation"
    # The phase the plan moves to is the one that makes the loop pick ``exploit``.
    assert select_for_plan(escalated).id == "exploit"
    # The hand-off *is* the decision that the exhausted phase yielded all it will
    # yield, so it closes as ``done`` (V1-18/Fase 3c). Leaving it ``pending``
    # behind a ``current`` phase is a plan the completion gate can never close:
    # measured in the rerun #3 as ``enumeration: pending`` + ``exploitation:
    # current`` with ``progress=[1, 6]``.
    statuses = {item.id: item.status for item in escalated.phases}
    assert statuses["exploitation"] == "current"
    assert statuses["enumeration"] == "done"
    assert escalated.progress == (2, 6)


@pytest.mark.parametrize(
    "case",
    [
        pytest.param(
            {"counts": {"host": 1, "service": 1}, "subagent_id": "web"},
            id="web-profile-is-not-the-measured-case",
        ),
        pytest.param(
            {"counts": {"host": 1, "service": 1, "credential": 1}, "subagent_id": "cred"},
            id="a-credential-is-on-the-board",
        ),
        pytest.param(
            {"counts": {"host": 1, "service": 1, "access": 1}, "subagent_id": "services"},
            id="access-is-on-the-board",
        ),
        pytest.param(
            {"counts": {"host": 1, "service": 1}, "subagent_id": "services", "no_progress": 2},
            id="below-the-local-threshold",
        ),
        pytest.param(
            {"counts": {"host": 1, "service": 1}, "subagent_id": "services", "services": ["10.65.175.32:21/tcp"]},
            id="no-smb-surface",
        ),
        pytest.param(
            {"counts": {"service": 1}, "subagent_id": "services"},
            id="phase-is-not-enumeration",
        ),
    ],
)
def test_planner_does_not_escalate_outside_the_measured_case(case: dict[str, Any]) -> None:
    plan = build_plan("x", counts=case["counts"], engagement_id=ENGAGEMENT)
    escalation = enumeration_escalation(
        plan,
        subagent_id=case["subagent_id"],
        no_progress=case.get("no_progress", 3),
        services=case.get("services", [SMB_SERVICE]),
    )
    assert escalation is None


async def test_loop_audits_the_hand_over_with_its_reason(tmp_path: Path) -> None:
    """End to end: the profile really changes and the event carries the reason."""
    store, context = _harness(tmp_path)
    _seed_smb_surface(Blackboard(store))
    llm = ScriptedLLM(
        [tool_call("nexus.recon.netexec", protocol="smb", target=TARGET, operation="shares")]
    )

    async def fake_tool(payload: dict[str, Any], run_context: ExecutionContext) -> dict[str, Any]:
        return dict(TOOL_SUCCESS)

    with mock.patch.object(runtime_module, "execute_tool", fake_tool):
        result = await run_react_loop(
            context=context,
            objective="Enumera 10.65.175.32",
            engagement_id=ENGAGEMENT,
            llm_client=llm,
            config=_loop_config(max_iterations=5),
        )

    # A pre-seeded board: the first turn adds nothing, so the streak starts at 1
    # and reaches the local threshold of 3 at the end of the third turn.
    assert [turn["consecutive_no_progress"] for turn in result.turns] == [1, 2, 3, 4, 5]
    plan_events = _events(store, context, "orchestrator.plan")
    # The hand-over is announced once and never flaps back: the plan is rebuilt
    # from the blackboard every turn, and without the one-way rule the phase
    # would return to ``enumeration`` on the very next turn.
    assert [event["payload"]["phase"] for event in plan_events] == ["enumeration", "exploitation"]
    escalation_events = [event for event in plan_events if "reason" in event["payload"]]
    assert len(escalation_events) == 1
    payload = escalation_events[0]["payload"]
    assert payload["reason"] == ENUMERATION_EXHAUSTED_REASON
    assert payload["phase"] == "exploitation"
    assert payload["previous"] == "enumeration"
    assert payload["subagent_id"] == "exploit"
    # Early enough to matter: the hand-over happens on the turn after the third
    # silent one, not at the end of the budget.
    assert payload["iteration"] == 4
    assert _events(store, context, SUBAGENT_EVENT_TYPE)[-1]["payload"]["subagent_id"] == "exploit"
    # The global signal still fires on turn 5, one turn later: both fixes coexist.
    assert [e["payload"]["iterations_stuck"] for e in _events(store, context, STUCK_EVENT_TYPE)] == [5]
    assert result.plan is not None and result.plan["current"] == "exploitation"
    # Nothing was authorized by the hand-over: the loop keeps running under the
    # same governance and ends at the iteration budget, not with an exploit.
    assert result.status == "max_iterations"


# --------------------------------------------------------------------------- #
# Problema 4 - an identical call that already succeeded is answered, not re-run
# --------------------------------------------------------------------------- #


NETEXEC_TOOL = "nexus.recon.netexec"


def _gateway(
    tmp_path: Path,
    *,
    risk: RiskLevel = RiskLevel.READ_ONLY,
    effect: str = "read_only",
    idempotent: bool = False,
    fail_first: bool = False,
) -> tuple[ControlStore, ToolGateway, RunContext, list[dict[str, Any]]]:
    """The real gateway over a real store; the handler only counts its calls."""
    store = ControlStore(tmp_path / "gateway.db")
    store.initialize()
    calls: list[dict[str, Any]] = []

    def handler(arguments: dict[str, Any], context: RunContext) -> ToolResult:
        calls.append(dict(arguments))
        if fail_first and len(calls) == 1:
            raise RuntimeError("netexec answered nothing parseable")
        return ToolResult(
            output={"target": arguments.get("target"), "operation": arguments.get("operation")},
            verified=True,
            verification_method="netexec_parsed",
            evidence={"shares": []},
            exit_code=0,
        )

    gateway = ToolGateway(
        PolicyEngine(store), AuditWriter(store), ApprovalService(store)
    )
    gateway.register(
        ToolDefinition(
            "netexec",
            TENANT,
            {
                "type": "object",
                "properties": {
                    "target": {"type": "string"},
                    "operation": {"type": "string"},
                },
                "required": ["target", "operation"],
            },
            tool_id=NETEXEC_TOOL,
            effect=effect,
            risk=risk,
            idempotent=idempotent,
        ),
        handler,
    )
    context = RunContext(TENANT, Identity("operator-1", TENANT, roles=("operator",)), run_id="run-1")
    return store, gateway, context, calls


def _invoke(
    gateway: ToolGateway,
    context: RunContext,
    arguments: dict[str, Any],
    *,
    phase: str | None = None,
    **kwargs: Any,
) -> dict[str, Any]:
    if phase is not None:
        context = replace(context, phase=phase)
    return asyncio.run(gateway.invoke(NETEXEC_TOOL, arguments, context, **kwargs))


def _approve(store: ControlStore, context: RunContext, action: str) -> str:
    service = ApprovalService(store)
    approval = service.request(context, action)
    service.decide(approval["id"], TENANT, "admin-2", True, "ok")
    return approval["id"]


def test_gateway_deduplicates_identical_calls(tmp_path: Path) -> None:
    """A: runs. B: identical, answered without touching the handler. C: another
    target, runs. D: another operation on the same target, runs."""
    store, gateway, context, calls = _gateway(tmp_path)
    same = {"target": TARGET, "operation": "shares"}

    first = _invoke(gateway, context, same)
    second = _invoke(gateway, context, same)
    other_target = _invoke(gateway, context, {"target": OTHER_TARGET, "operation": "shares"})
    other_operation = _invoke(gateway, context, {"target": TARGET, "operation": "fingerprint"})

    # B never reached the handler: only three of the four calls really ran.
    assert len(calls) == 3
    assert calls[0] == same
    assert calls[1]["target"] == OTHER_TARGET
    assert calls[2]["operation"] == "fingerprint"

    assert first["success"] is True
    assert first["verification_method"] == "netexec_parsed"
    assert first["output"]["operation"] == "shares"

    assert second["success"] is True
    assert second["verified"] is True
    assert second["verification_method"] == "tool_already_invoked"
    # No new invocation happened: the answer *is* the previous one, marked.
    assert second["invocation_id"] == first["invocation_id"]
    assert second["evidence"]["previous_invocation_id"] == first["invocation_id"]
    assert second["evidence"]["previous_outcome"] == "succeeded"
    assert second["output"]["deduplicated"] is True
    assert second["output"]["operation"] == "shares"
    assert "ya se ejecutó" in second["output"]["message"]
    assert "cambiar de estrategia" in second["output"]["message"]

    assert other_target["verification_method"] == "netexec_parsed"
    assert other_operation["verification_method"] == "netexec_parsed"

    # The decision is auditable, with the invocation it reused.
    deduped = [
        row for row in AuditWriter(store).export(TENANT) if row["action"] == "invocation.reused"
    ]
    assert len(deduped) == 1
    assert deduped[0]["payload"]["invocation_id"] == first["invocation_id"]
    assert deduped[0]["payload"]["verification_method"] == "tool_already_invoked"
    assert deduped[0]["payload"]["run_id"] == "run-1"


def test_a_repeat_in_another_phase_is_a_new_intent_and_runs(tmp_path: Path) -> None:
    """The dedup key is the journal's ``step_key`` (tool + args + phase +
    objective), never ``tool + args`` alone: a call re-issued in another phase is
    a new intent and must really run."""
    store, gateway, context, calls = _gateway(tmp_path)
    same = {"target": TARGET, "operation": "shares"}
    first = _invoke(gateway, context, same)
    second = _invoke(gateway, context, same, phase="exploitation")
    assert len(calls) == 2
    assert second["verification_method"] == "netexec_parsed"
    assert second["invocation_id"] != first["invocation_id"]


def test_idempotent_tools_are_never_deduplicated(tmp_path: Path) -> None:
    """Re-running an idempotent tool is meaningful, exactly as the reuse branch says."""
    store, gateway, context, calls = _gateway(tmp_path, idempotent=True)
    same = {"target": TARGET, "operation": "shares"}
    _invoke(gateway, context, same)
    _invoke(gateway, context, same)
    assert len(calls) == 2


def test_a_failed_call_keeps_its_retry_path(tmp_path: Path) -> None:
    """Only a success is reused: a real failure is retried, never answered as a
    duplicate."""
    store, gateway, context, calls = _gateway(tmp_path, fail_first=True)
    same = {"target": TARGET, "operation": "shares"}

    with pytest.raises(RuntimeError):
        _invoke(gateway, context, same)
    assert len(calls) == 1

    # A timeout/exception leaves no ``succeeded`` row, so there is nothing to
    # reuse: the identical retry is not answered as a duplicate.
    journal = InvocationJournal(store)
    previous = journal.matching(context, NETEXEC_TOOL, same)
    assert previous is not None and previous["state"] == "unknown"

    # The retry is not answered with ``tool_already_invoked``; it reaches the
    # journal's own policy for an unknown outcome, which asks the operator.
    with pytest.raises(ApprovalRequired):
        _invoke(gateway, context, same)
    assert len(calls) == 1

    retried = _invoke(
        gateway,
        context,
        same,
        retry_approval_id=_approve(store, context, f"retry:invocation:{previous['invocation_id']}"),
    )
    assert len(calls) == 2
    assert retried["success"] is True
    assert retried["verification_method"] == "netexec_parsed"


def test_the_approval_flow_is_untouched(tmp_path: Path) -> None:
    """An approval-gated call keeps its gate: it is authorized once, and the
    identical repeat is still refused by the single-use approval instead of being
    answered as a duplicate (the gate runs before the journal is consulted)."""
    store, gateway, context, calls = _gateway(tmp_path, risk=RiskLevel.HIGH, effect="active")
    same = {"target": TARGET, "operation": "shares"}

    with pytest.raises(ApprovalRequired):
        _invoke(gateway, context, same)
    assert calls == []

    approval_id = _approve(store, context, f"execute:tool:{NETEXEC_TOOL}")
    first = _invoke(gateway, context, same, approval_id=approval_id)
    assert first["success"] is True
    assert calls == [same]

    with pytest.raises(PermissionError):
        _invoke(gateway, context, same, approval_id=approval_id)
    assert calls == [same]
