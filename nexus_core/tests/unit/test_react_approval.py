"""Unit tests for the ReAct approval callback (human-in-the-loop gate)."""

from __future__ import annotations

import copy
import json
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from unittest import mock

import pytest

from nexus_core.agent.react import (
    ReActConfig,
    STATUS_COMPLETED,
    STATUS_MAX_ITERATIONS,
    ApprovalDecision,
    run_react_loop,
)
from nexus_core.kernel import runtime as runtime_module
from nexus_core.kernel.audit import AuditWriter
from nexus_core.kernel.control_store import ControlStore
from nexus_core.kernel.models import RiskLevel
from nexus_core.kernel.runtime import ExecutionContext
from nexus_core.llm.abstraction import LLMProvider, LLMResponse
from nexus_core.scope import EngagementScope, EngagementStore
from nexus_core.tools.handlers.system import system_status_definition

TOOL_ID = "nexus.system.status"

TOOL_SUCCESS = {
    "tool_id": TOOL_ID,
    "output": {
        "success": True,
        "verified": True,
        "verification_method": "control_store_query",
        "evidence": {"queued_tasks": 0},
        "output": {"status": "healthy"},
    },
}


def _iso(delta: timedelta) -> str:
    return (datetime.now(timezone.utc) + delta).isoformat()


async def _forbidden_handler(arguments, context):  # pragma: no cover - must not run
    raise AssertionError("handler must not be called by these tests")


def catalog_with_risk(risk: RiskLevel) -> dict:
    definition = replace(system_status_definition("system"), risk=risk)
    return {definition.tool_id: (definition, _forbidden_handler)}


def tool_call(tool_id: str = TOOL_ID) -> str:
    return json.dumps(
        {
            "thought": "Consulta el estado del control plane.",
            "action": "tool_call",
            "tool_id": tool_id,
            "arguments": {},
            "expected_outcome": "estado del sistema",
        }
    )


def task_complete(summary: str = "Listo") -> str:
    return json.dumps(
        {
            "thought": "Ya tengo la información.",
            "action": "task_complete",
            "summary": summary,
            "findings": [],
        }
    )


class ScriptedLLM:
    def __init__(self, responses: list[str]) -> None:
        self.responses = list(responses)

    async def complete(self, messages, **kwargs):
        index = min(getattr(self, "_calls", 0), max(0, len(self.responses) - 1))
        self._calls = getattr(self, "_calls", 0) + 1
        return LLMResponse(
            content=self.responses[index] if self.responses else "",
            model="scripted-test",
            provider=LLMProvider.FAKE,
        )


class ToolSpy:
    def __init__(self, result: dict | None = None, error: BaseException | None = None) -> None:
        self.result = result if result is not None else TOOL_SUCCESS
        self.error = error
        self.payloads: list[dict] = []

    async def __call__(self, payload, context):
        self.payloads.append(payload)
        if self.error is not None:
            raise self.error
        return copy.deepcopy(self.result)


class RecordingApproval:
    """Approval callback stub recording every handshake."""

    def __init__(self, decision: ApprovalDecision | None) -> None:
        self.decision = decision
        self.calls: list[tuple[str, dict, object]] = []

    def __call__(self, tool_id, arguments, decision):
        self.calls.append((tool_id, dict(arguments), decision))
        return self.decision


@pytest.fixture()
def harness(tmp_path):
    store = ControlStore(tmp_path / "react-approval.db")
    store.initialize()
    EngagementStore(store).create(
        EngagementScope(
            engagement_id="eng-1",
            tenant_id="system",
            name="engagement-eng-1",
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
    run = store.create_run("system", {})
    task = {
        "id": "task-approval-1",
        "tenant_id": "system",
        "run_id": run["id"],
        "task_type": "react.run",
        "payload": {
            "objective": "Consulta el estado del sistema",
            "engagement_id": "eng-1",
            "identity": {"subject_id": "operator-1", "roles": ["operator"]},
        },
    }
    return store, ExecutionContext(store, task, "worker-test")


def _messages(store, conversation_id: str) -> list[dict]:
    return store.list_messages("system", conversation_id)


def _observations(store, conversation_id: str) -> list[str]:
    return [
        str(message["content"])
        for message in _messages(store, conversation_id)
        if message["metadata"].get("kind") == "react.observation"
    ]


async def test_approval_callback_called_when_policy_requires_it(harness):
    store, context = harness
    approval = RecordingApproval(ApprovalDecision(approved=True, approval_id="approval_ok_1"))
    spy = ToolSpy()

    with mock.patch.object(runtime_module, "execute_tool", spy):
        result = await run_react_loop(
            context=context,
            objective="objetivo",
            engagement_id="eng-1",
            llm_client=ScriptedLLM([tool_call(), task_complete()]),
            config=_loop_config(on_approval_needed=approval),
            tool_catalog=catalog_with_risk(RiskLevel.HIGH),
        )

    assert result.status == STATUS_COMPLETED
    assert len(approval.calls) == 1
    tool_id, arguments, decision = approval.calls[0]
    assert tool_id == TOOL_ID
    assert arguments == {}
    assert decision.requires_approval is True
    assert decision.allowed is True
    assert len(spy.payloads) == 1


async def test_approval_callback_not_called_for_low_risk_tool(harness):
    _, context = harness
    approval = RecordingApproval(ApprovalDecision(approved=True, approval_id="never"))
    spy = ToolSpy()

    with mock.patch.object(runtime_module, "execute_tool", spy):
        result = await run_react_loop(
            context=context,
            objective="objetivo",
            engagement_id="eng-1",
            llm_client=ScriptedLLM([tool_call(), task_complete()]),
            config=_loop_config(on_approval_needed=approval),
            tool_catalog=catalog_with_risk(RiskLevel.MEDIUM),
        )

    assert result.status == STATUS_COMPLETED
    assert approval.calls == []
    assert spy.payloads[0]["approval_id"] is None


async def test_approval_denied_injects_observation_and_continues(harness):
    store, context = harness
    approval = RecordingApproval(
        ApprovalDecision(approved=False, reason="user denied")
    )
    spy = ToolSpy()

    with mock.patch.object(runtime_module, "execute_tool", spy):
        result = await run_react_loop(
            context=context,
            objective="objetivo",
            engagement_id="eng-1",
            llm_client=ScriptedLLM([tool_call(), task_complete("seguí sin la tool")]),
            config=_loop_config(on_approval_needed=approval),
            tool_catalog=catalog_with_risk(RiskLevel.HIGH),
        )

    assert result.status == STATUS_COMPLETED
    assert spy.payloads == [], "a denied tool must never reach execute_tool"
    assert result.iterations == 2
    observation = _observations(store, result.conversation_id)[0]
    assert "denied_by_operator" in observation
    assert "user denied" in observation
    events = [
        event
        for event in AuditWriter(store).export("system")
        if event["action"] == "react.step"
    ]
    denied = [event for event in events if event["payload"].get("reason") == "denied_by_operator"]
    assert len(denied) == 1
    assert denied[0]["decision"] == "deny"


async def test_approval_granted_passes_approval_id_to_tool(harness):
    store, context = harness
    approval = RecordingApproval(ApprovalDecision(approved=True, approval_id="approval_abc"))
    spy = ToolSpy()

    with mock.patch.object(runtime_module, "execute_tool", spy):
        result = await run_react_loop(
            context=context,
            objective="objetivo",
            engagement_id="eng-1",
            llm_client=ScriptedLLM([tool_call(), task_complete()]),
            config=_loop_config(on_approval_needed=approval),
            tool_catalog=catalog_with_risk(RiskLevel.HIGH),
        )

    assert result.status == STATUS_COMPLETED
    assert spy.payloads[0]["approval_id"] == "approval_abc"
    assert result.actions[0]["tool_result"]["success"] is True


async def test_approval_edited_arguments_replace_original(harness):
    _, context = harness
    approval = RecordingApproval(
        ApprovalDecision(
            approved=True,
            approval_id="approval_edited",
            edited_arguments={"target": "10.0.0.9", "flags": ["-sn"]},
        )
    )
    spy = ToolSpy()

    with mock.patch.object(runtime_module, "execute_tool", spy):
        result = await run_react_loop(
            context=context,
            objective="objetivo",
            engagement_id="eng-1",
            llm_client=ScriptedLLM([tool_call(), task_complete()]),
            config=_loop_config(on_approval_needed=approval),
            tool_catalog=catalog_with_risk(RiskLevel.HIGH),
        )

    assert result.status == STATUS_COMPLETED
    assert spy.payloads[0]["arguments"] == {"target": "10.0.0.9", "flags": ["-sn"]}
    assert spy.payloads[0]["approval_id"] == "approval_edited"


async def test_approval_callback_returning_none_aborts_gracefully(harness):
    store, context = harness
    approval = RecordingApproval(None)
    spy = ToolSpy()

    with mock.patch.object(runtime_module, "execute_tool", spy):
        result = await run_react_loop(
            context=context,
            objective="objetivo",
            engagement_id="eng-1",
            llm_client=ScriptedLLM([tool_call()]),
            config=_loop_config(max_iterations=3, on_approval_needed=approval),
            tool_catalog=catalog_with_risk(RiskLevel.HIGH),
        )

    assert result.status == STATUS_MAX_ITERATIONS
    assert result.iterations == 3
    assert len(approval.calls) == 3
    assert spy.payloads == []
    assert all("denied_by_operator" in item for item in _observations(store, result.conversation_id))


async def test_loop_continues_after_denial_does_not_count_as_tool_failure(harness):
    store, context = harness
    approval = RecordingApproval(ApprovalDecision(approved=False, reason="user denied"))
    spy = ToolSpy()

    with mock.patch.object(runtime_module, "execute_tool", spy):
        result = await run_react_loop(
            context=context,
            objective="objetivo",
            engagement_id="eng-1",
            llm_client=ScriptedLLM([tool_call()]),
            config=_loop_config(max_iterations=4, on_approval_needed=approval),
            tool_catalog=catalog_with_risk(RiskLevel.HIGH),
        )

    # Three consecutive denials would be `failed` if they counted as tool errors.
    assert result.status == STATUS_MAX_ITERATIONS
    assert result.iterations == 4
    assert len(approval.calls) == 4
    assert len(_observations(store, result.conversation_id)) == 4


async def test_loop_without_callback_never_executes_high_risk_tool(harness):
    """Regression: no callback and no approval_id keeps the tool unexecuted.

    A governance denial is *not* a tool failure (B3): it never retires the tool
    and never aborts the run while other routes exist, so the loop runs to the
    iteration budget with the denial repeated.
    """
    store, context = harness
    catalog = catalog_with_risk(RiskLevel.HIGH)

    with mock.patch(
        "nexus_core.tools.registry.durable_tool_definitions", return_value=catalog
    ):
        result = await run_react_loop(
            context=context,
            objective="objetivo",
            engagement_id="eng-1",
            llm_client=ScriptedLLM([tool_call()]),
            config=_loop_config(max_iterations=6),
            tool_catalog=catalog,
        )

    assert result.status == "blocked"
    assert result.iterations == 1
    last = result.actions[-1]["tool_result"]
    assert last["error_type"] == "ApprovalRequired"
    assert last["failure_kind"] == "governance"
    assert "approval" in last["error"]


def _loop_config(**kwargs):
    """Loop config for tests that exercise mechanics, not the completion gates.

    ``require_plan_completion=False`` disables the B8.2.2/B8.2.3 gate on purpose:
    these tests script a ``task_complete`` (or need the loop to keep proposing
    recon tools) while the blackboard is empty, which production must refuse. The
    gate itself is covered by ``test_react_frame.py``. The host-binary preflight
    (B6) is disabled too so the tool catalog never depends on the CI machine.
    """
    kwargs.setdefault("enforce_completion_gates", False)
    return ReActConfig(**kwargs)


# This module's unsigned scopes exercise targeting/session behavior. Authentication
# is covered separately in test_scope_governed_mode with the governed default.
pytestmark = globals().get("pytestmark", [])
if not isinstance(pytestmark, list):
    pytestmark = [pytestmark]
pytestmark.append(pytest.mark.usefixtures("lab_scope"))
