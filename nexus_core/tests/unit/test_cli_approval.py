"""Unit tests for the interactive approval callback of the omni CLI.

These cover the *human* half of the gate: the durable ``kernel_approvals`` row,
the ``y/n/e/?`` protocol, separation of duties, and the fact that the loop can
only execute a high-risk tool after a verified approval.
"""

from __future__ import annotations

import json
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from unittest import mock

import pytest

from nexus_core.agent.react import (
    STATUS_COMPLETED,
    STATUS_MAX_ITERATIONS,
    ReActConfig,
    run_react_loop,
)
from nexus_core.cli.approval import make_approval_callback
from nexus_core.cli.session import OmniSession
from nexus_core.kernel.approvals import ApprovalService
from nexus_core.kernel.audit import AuditWriter
from nexus_core.kernel.control_store import ControlStore
from nexus_core.kernel.models import Identity, PolicyDecision, Resource, RiskLevel
from nexus_core.kernel.policy import PolicyEngine
from nexus_core.kernel.runtime import ExecutionContext
from nexus_core.llm.abstraction import LLMProvider, LLMResponse
from nexus_core.scope import EngagementScope, EngagementStore
from nexus_core.tools.handlers.system import system_status_definition, system_status_handler

TOOL_ID = "nexus.system.status"
ACTION = f"execute:tool:{TOOL_ID}"
TENANT = "system"


def _iso(delta: timedelta) -> str:
    return (datetime.now(timezone.utc) + delta).isoformat()


def high_risk_definition():
    return replace(system_status_definition(TENANT), risk=RiskLevel.HIGH)


def high_risk_catalog() -> dict:
    return {TOOL_ID: (high_risk_definition(), system_status_handler)}


class Feed:
    """Deterministic ``input()`` replacement that replays a script."""

    def __init__(self, answers: list[str], fallback: str = "n") -> None:
        self.answers = list(answers)
        self.fallback = fallback
        self.prompts: list[str] = []

    def __call__(self, prompt: str = "") -> str:
        self.prompts.append(prompt)
        return self.answers.pop(0) if self.answers else self.fallback


class ScriptedLLM:
    def __init__(self, responses: list[str]) -> None:
        self.responses = list(responses)
        self._calls = 0

    async def complete(self, messages, **kwargs):
        index = min(self._calls, max(0, len(self.responses) - 1))
        self._calls += 1
        return LLMResponse(
            content=self.responses[index] if self.responses else "",
            model="scripted-test",
            provider=LLMProvider.FAKE,
        )


def tool_call() -> str:
    return json.dumps(
        {
            "thought": "Consulta el estado.",
            "action": "tool_call",
            "tool_id": TOOL_ID,
            "arguments": {},
            "expected_outcome": "estado",
        }
    )


def task_complete(summary: str = "Listo") -> str:
    return json.dumps(
        {"thought": "fin", "action": "task_complete", "summary": summary, "findings": []}
    )


@pytest.fixture()
def session(tmp_path) -> OmniSession:
    store = ControlStore(tmp_path / "cli-approval.db")
    store.initialize()
    scope = EngagementStore(store).create(
        EngagementScope(
            engagement_id="eng-1",
            tenant_id=TENANT,
            name="engagement-1",
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
    run = store.create_run(TENANT, {})
    value = OmniSession(
        store=store,
        tenant_id=TENANT,
        engagement=scope,
        llm_client=None,
        max_iterations=3,
        operator_id="operator:tester",
    )
    value.run_id = str(run["id"])
    return value


def _request_decision(session: OmniSession) -> PolicyDecision:
    """The decision the loop passes to the callback (policy, not scope)."""
    definition = high_risk_definition()
    identity = Identity(
        subject_id=session.agent_subject_id, tenant_id=TENANT, kind="agent", roles=("operator",)
    )
    return PolicyEngine(session.store).decide(
        identity,
        "execute:tool",
        Resource(definition.tool_id, definition.tenant_id, "tool"),
        (),
        definition,
    )


def _approval_statuses(session: OmniSession) -> list[str]:
    with session.store.connect() as conn:
        return [row["status"] for row in conn.execute("SELECT status FROM kernel_approvals")]


def test_callback_granting_y_registers_durable_approval(session, capsys):
    session.input_reader = Feed(["y"])
    callback = make_approval_callback(session, session.store, TENANT, session.run_id)

    decision = callback(TOOL_ID, {"target": "10.0.0.5"}, _request_decision(session))

    assert decision.approved is True
    assert decision.approval_id and decision.approval_id.startswith("approval_")
    row = ApprovalService(session.store).get(decision.approval_id, TENANT)
    assert row["status"] == "approved"
    assert row["requested_by"] == session.agent_subject_id
    assert row["decided_by"] == session.operator_id
    assert (
        ApprovalService(session.store).verify(
            decision.approval_id, session.build_run_context(session.run_id), ACTION
        )
        is True
    )
    assert "aprobado por operator:tester" in capsys.readouterr().out


def test_callback_denying_n_returns_denial_and_registers_nothing(session, capsys):
    session.input_reader = Feed(["n"])
    callback = make_approval_callback(session, session.store, TENANT, session.run_id)

    decision = callback(TOOL_ID, {}, _request_decision(session))

    assert decision.approved is False
    assert decision.reason == "user denied"
    assert ApprovalService(session.store).list_pending(TENANT) == []
    assert _approval_statuses(session) == []
    assert "rechazado por el operador" in capsys.readouterr().out


def test_callback_edit_returns_edited_arguments(session, capsys):
    session.input_reader = Feed(["e", "10.0.0.9", "22,80"])
    callback = make_approval_callback(session, session.store, TENANT, session.run_id)

    decision = callback(
        TOOL_ID, {"target": "10.0.0.5", "flags": ["-Pn"]}, _request_decision(session)
    )

    assert decision.approved is True
    assert decision.edited_arguments == {"target": "10.0.0.9", "flags": ["22", "80"]}
    assert decision.approval_id is not None
    assert _approval_statuses(session) == ["approved"]
    assert "aprobado con argumentos editados" in capsys.readouterr().out


def test_callback_question_mark_shows_definition_then_approves(session, capsys):
    session.input_reader = Feed(["?", "y"])
    callback = make_approval_callback(session, session.store, TENANT, session.run_id)

    decision = callback(TOOL_ID, {}, _request_decision(session))

    out = capsys.readouterr().out
    assert decision.approved is True
    assert "input_schema" in out
    assert "riesgo:" in out
    assert "aprobado por operator:tester" in out


def test_callback_denies_after_invalid_answers(session, capsys):
    session.input_reader = Feed(["zzz", "??", "e2", "x", "y2"])
    callback = make_approval_callback(session, session.store, TENANT, session.run_id)

    decision = callback(TOOL_ID, {}, _request_decision(session))

    out = capsys.readouterr().out
    assert decision.approved is False
    assert "no valid answer after 5 attempts" in decision.reason
    assert out.count("opción no válida") == 5
    assert _approval_statuses(session) == []


def test_callback_refuses_when_operator_is_the_requester(session, capsys):
    """Separation of duties: the requester cannot approve its own action."""
    session.input_reader = Feed(["y"])
    session.operator_id = session.agent_subject_id
    callback = make_approval_callback(session, session.store, TENANT, session.run_id)

    decision = callback(TOOL_ID, {}, _request_decision(session))

    assert decision.approved is False
    assert "approval" in decision.reason
    assert "no se pudo registrar la aprobación durable" in capsys.readouterr().out
    assert _approval_statuses(session) == ["pending"]


async def test_loop_with_real_gateway_executes_after_a_granted_approval(session):
    """Policy → CLI callback → durable approval → gateway verify → handler runs."""
    catalog = high_risk_catalog()
    session.input_reader = Feed(["y"])
    context = ExecutionContext(
        session.store,
        {
            "id": "task-cli-approval",
            "tenant_id": TENANT,
            "run_id": session.run_id,
            "task_type": "react.run",
            "payload": {
                "objective": "Consulta el estado del sistema",
                "identity": {"subject_id": session.agent_subject_id, "roles": ["operator"]},
            },
        },
        "worker-test",
    )
    callback = make_approval_callback(session, session.store, TENANT, session.run_id)

    with mock.patch("nexus_core.tools.registry.durable_tool_definitions", return_value=catalog):
        result = await run_react_loop(
            context=context,
            objective="Consulta el estado del sistema",
            engagement_id="eng-1",
            llm_client=ScriptedLLM([tool_call(), task_complete("hecho")]),
            config=ReActConfig(max_iterations=4, on_approval_needed=callback),
            tool_catalog=catalog,
        )

    assert result.status == STATUS_COMPLETED
    assert result.iterations == 2
    observation = result.actions[0]["tool_result"]
    assert observation["success"] is True
    assert observation["verification_method"] == "control_store_query"
    events = {event["action"] for event in AuditWriter(session.store).export(TENANT)}
    assert "tool.complete" in events
    assert _approval_statuses(session) == ["approved"]


def _headless_context(session: OmniSession) -> ExecutionContext:
    return ExecutionContext(
        session.store,
        {
            "id": "task-headless-approval",
            "tenant_id": TENANT,
            "run_id": session.run_id,
            "task_type": "react.run",
            "payload": {
                "objective": "Consulta el estado del sistema",
                "identity": {"subject_id": session.agent_subject_id, "roles": ["operator"]},
            },
        },
        "worker-test",
    )


async def test_headless_without_trust_mode_denies_high_risk_tool(session):
    """P1: the denial route of the gate is exercised, not just assumed."""
    catalog = high_risk_catalog()
    with mock.patch("nexus_core.tools.registry.durable_tool_definitions", return_value=catalog):
        result = await run_react_loop(
            context=_headless_context(session),
            objective="Consulta el estado del sistema",
            engagement_id="eng-1",
            llm_client=ScriptedLLM([tool_call()]),
            config=ReActConfig(max_iterations=3),
            tool_catalog=catalog,
        )

    # No human, no trust mode: the tool is never executed and nothing is approved.
    assert result.status == STATUS_MAX_ITERATIONS
    actions = AuditWriter(session.store).export(TENANT)
    assert not any(row["action"] == "tool.complete" for row in actions)
    assert _approval_statuses(session) == []
    assert all(
        (action.get("tool_result") or {}).get("error_type") == "PermissionError"
        for action in result.actions
        if action.get("tool_result")
    )


async def test_headless_trust_mode_auto_approves_and_audits(session):
    """P1: trust mode reaches a HIGH-risk tool and records *why* it was allowed."""
    catalog = high_risk_catalog()
    callback = make_approval_callback(
        session, session.store, TENANT, session.run_id, trust_mode=True
    )
    with mock.patch("nexus_core.tools.registry.durable_tool_definitions", return_value=catalog):
        result = await run_react_loop(
            context=_headless_context(session),
            objective="Consulta el estado del sistema",
            engagement_id="eng-1",
            llm_client=ScriptedLLM([tool_call(), task_complete("hecho")]),
            config=ReActConfig(max_iterations=4, on_approval_needed=callback),
            tool_catalog=catalog,
        )

    assert result.status == STATUS_COMPLETED
    assert result.actions[0]["tool_result"]["success"] is True
    events = {row["action"] for row in AuditWriter(session.store).export(TENANT)}
    assert "tool.trust_mode_approved" in events
    assert "tool.complete" in events
    assert _approval_statuses(session) == ["approved"]
