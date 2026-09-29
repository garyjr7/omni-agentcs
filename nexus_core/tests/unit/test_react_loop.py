"""Unit tests for the durable ReAct loop (scripted LLM, spied tool layer)."""

from __future__ import annotations

import copy
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

import pytest

from nexus_core.agent.react import (
    STATUS_CANCELLED,
    STATUS_CLARIFICATION,
    STATUS_COMPLETED,
    STATUS_FAILED,
    STATUS_MAX_ITERATIONS,
    STATUS_SCOPE_VIOLATION,
    ReActConfig,
    run_react_loop,
)
from nexus_core.kernel import runtime as runtime_module
from nexus_core.kernel.audit import AuditWriter
from nexus_core.kernel.control_store import ControlStore
from nexus_core.kernel.runtime import ExecutionContext, build_default_registry
from nexus_core.llm.abstraction import LLMProvider, LLMResponse
from nexus_core.scope import EngagementScope, EngagementStore, ScopeViolation

FIXTURES = Path(__file__).parents[1] / "fixtures" / "react"


def _iso(delta: timedelta) -> str:
    return (datetime.now(timezone.utc) + delta).isoformat()


def create_scope(store, engagement_id: str = "eng-1") -> None:
    EngagementStore(store).create(
        EngagementScope(
            engagement_id=engagement_id,
            tenant_id="system",
            name=f"engagement-{engagement_id}",
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

TOOL_SUCCESS = {
    "tool_id": "nexus.recon.nmap",
    "output": {
        "success": True,
        "verified": True,
        "verification_method": "nmap_xml_parsed",
        "evidence": {"hosts_up": 1, "ports_open_total": 1},
        "output": {
            "target": "10.0.0.5",
            "scan": {
                "hosts": [
                    {
                        "address": "10.0.0.5",
                        "ports": [{"port": 22, "state": "open", "service": "ssh"}],
                    }
                ]
            },
        },
    },
}


def tool_call(tool_id: str = "nexus.recon.nmap", **arguments) -> str:
    payload = {
        "thought": "Escaneo los puertos web del objetivo autorizado.",
        "action": "tool_call",
        "tool_id": tool_id,
        "arguments": arguments or {"target": "10.0.0.5", "flags": ["-Pn", "-p", "22,80"]},
        "expected_outcome": "puertos abiertos",
    }
    return json.dumps(payload)


def task_complete(summary: str = "Escaneo completado") -> str:
    payload = {
        "thought": "Ya tengo la evidencia necesaria.",
        "action": "task_complete",
        "summary": summary,
        "findings": [{"severity": "high", "title": "SSH expuesto", "evidence": "22/tcp open ssh"}],
    }
    return json.dumps(payload)


def clarification(question: str = "¿Puedo usar -T4?") -> str:
    return json.dumps(
        {"thought": "Necesito más contexto.", "action": "request_clarification", "question": question}
    )


class ScriptedLLM:
    """Replays scripted responses, repeating the last one when exhausted."""

    def __init__(self, responses: list[str], on_call=None) -> None:
        self.responses = list(responses)
        self.calls: list[list[dict[str, str]]] = []
        self.on_call = on_call

    async def complete(self, messages, **kwargs):
        self.calls.append([{"role": m.role, "content": m.content} for m in messages])
        index = min(len(self.calls) - 1, max(0, len(self.responses) - 1))
        if self.on_call is not None:
            self.on_call(len(self.calls))
        return LLMResponse(
            content=self.responses[index] if self.responses else "",
            model="scripted-test",
            provider=LLMProvider.FAKE,
        )


class ToolSpy:
    """Stands in for execute_tool, recording the payload it receives."""

    def __init__(self, result: dict | None = None, error: BaseException | None = None, tool_id=None):
        self.result = result
        self.error = error
        self.payloads: list[dict] = []
        self.tool_id = tool_id

    async def __call__(self, payload, context):
        self.payloads.append(payload)
        if self.error is not None:
            raise self.error
        result = copy.deepcopy(self.result if self.result is not None else TOOL_SUCCESS)
        if self.tool_id:
            result["tool_id"] = self.tool_id
        return result


@pytest.fixture()
def harness(tmp_path):
    store = ControlStore(tmp_path / "react.db")
    store.initialize()
    create_scope(store, "eng-1")
    run = store.create_run("system", {})
    task = {
        "id": "task-react-1",
        "tenant_id": "system",
        "run_id": run["id"],
        "task_type": "react.run",
        "payload": {
            "objective": "Escanea 10.0.0.5 en los puertos 22 y 80",
            "engagement_id": "eng-1",
            "identity": {"subject_id": "operator-1", "roles": ["operator"]},
            "permissions": ["execute:tool:nexus.recon.nmap"],
        },
    }
    return store, ExecutionContext(store, task, "worker-test")


def _messages_text(llm: ScriptedLLM, call_index: int) -> str:
    return "\n".join(message["content"] for message in llm.calls[call_index])


def test_react_run_is_registered():
    assert "react.run" in build_default_registry().task_types


async def test_loop_executes_single_tool_call_and_completes(harness):
    store, context = harness
    llm = ScriptedLLM([tool_call(), task_complete("Puertos 22 y 80 revisados")])
    spy = ToolSpy()

    with mock.patch.object(runtime_module, "execute_tool", spy):
        result = await run_react_loop(
            context=context,
            objective="Escanea 10.0.0.5 en los puertos 22 y 80",
            engagement_id="eng-1",
            llm_client=llm,
        )

    assert result.status == STATUS_COMPLETED
    assert result.iterations == 2
    assert result.final_summary == "Puertos 22 y 80 revisados"
    assert len(result.findings) == 1
    assert spy.payloads[0]["tool_id"] == "nexus.recon.nmap"
    assert result.actions[0]["tool_result"]["success"] is True
    kinds = [
        message["metadata"].get("kind")
        for message in store.list_messages("system", result.conversation_id)
    ]
    assert kinds == ["react.system", "react.action", "react.observation", "react.action", "react.final"]


async def test_loop_respects_max_iterations(harness):
    _, context = harness
    llm = ScriptedLLM([tool_call()])
    spy = ToolSpy()

    with mock.patch.object(runtime_module, "execute_tool", spy):
        result = await run_react_loop(
            context=context,
            objective="objetivo",
            engagement_id="eng-1",
            llm_client=llm,
            config=ReActConfig(max_iterations=3),
        )

    assert result.status == STATUS_MAX_ITERATIONS
    assert result.iterations == 3
    assert len(llm.calls) == 3


async def test_loop_injects_tool_result_to_history(harness):
    _, context = harness
    llm = ScriptedLLM([tool_call(), task_complete()])
    spy = ToolSpy()

    with mock.patch.object(runtime_module, "execute_tool", spy):
        await run_react_loop(
            context=context,
            objective="objetivo",
            engagement_id="eng-1",
            llm_client=llm,
        )

    second_prompt = _messages_text(llm, 1)
    assert "ssh" in second_prompt
    assert "22" in second_prompt
    assert "react.observation" in second_prompt or "nexus.recon.nmap" in second_prompt


async def test_loop_aborts_after_3_consecutive_tool_failures(harness):
    _, context = harness
    llm = ScriptedLLM([tool_call()])
    spy = ToolSpy(error=RuntimeError("tool post-condition was not verified"))

    with mock.patch.object(runtime_module, "execute_tool", spy):
        result = await run_react_loop(
            context=context,
            objective="objetivo",
            engagement_id="eng-1",
            llm_client=llm,
            config=ReActConfig(max_iterations=8),
        )

    assert result.status == STATUS_FAILED
    assert result.iterations == 3
    assert len(spy.payloads) == 3
    assert "3 consecutive tool failures" in result.final_summary
    assert result.actions[-1]["tool_result"]["error_type"] == "RuntimeError"


async def test_loop_handles_clarification(harness):
    _, context = harness
    llm = ScriptedLLM([clarification("¿Silencioso o agresivo?")])
    spy = ToolSpy()

    with mock.patch.object(runtime_module, "execute_tool", spy):
        result = await run_react_loop(
            context=context,
            objective="objetivo",
            engagement_id="eng-1",
            llm_client=llm,
        )

    assert result.status == STATUS_CLARIFICATION
    assert result.question == "¿Silencioso o agresivo?"
    assert result.iterations == 1
    assert spy.payloads == []


async def test_loop_propagates_engagement_id_to_tools(harness):
    store, context = harness
    create_scope(store, "eng-42")
    llm = ScriptedLLM([tool_call(), task_complete()])
    spy = ToolSpy()

    with mock.patch.object(runtime_module, "execute_tool", spy):
        await run_react_loop(
            context=context,
            objective="objetivo",
            engagement_id="eng-42",
            llm_client=llm,
        )

    assert spy.payloads
    assert all(payload["engagement_id"] == "eng-42" for payload in spy.payloads)
    assert all(payload["identity"]["subject_id"] == "operator-1" for payload in spy.payloads)
    assert all(payload["arguments"] for payload in spy.payloads)


async def test_loop_audits_each_step(harness):
    store, context = harness
    llm = ScriptedLLM([tool_call(), task_complete()])
    spy = ToolSpy()

    with mock.patch.object(runtime_module, "execute_tool", spy):
        result = await run_react_loop(
            context=context,
            objective="objetivo",
            engagement_id="eng-1",
            llm_client=llm,
        )

    events = [event for event in AuditWriter(store).export("system") if event["action"] == "react.step"]
    assert len(events) == result.iterations == 2
    assert [event["payload"]["iteration"] for event in events] == [1, 2]
    assert events[0]["payload"]["tool_id"] == "nexus.recon.nmap"
    assert events[1]["payload"]["findings_count"] == 1
    assert events[1]["decision"] == "allow"


async def test_loop_aborts_on_scope_violation_immediately(harness):
    store, context = harness
    llm = ScriptedLLM([tool_call()])
    spy = ToolSpy(error=ScopeViolation("203.0.113.9", "ip is outside the engagement scope", "eng-1"))

    with mock.patch.object(runtime_module, "execute_tool", spy):
        result = await run_react_loop(
            context=context,
            objective="objetivo",
            engagement_id="eng-1",
            llm_client=llm,
            config=ReActConfig(max_iterations=10),
        )

    assert result.status == STATUS_SCOPE_VIOLATION
    assert result.iterations == 1
    assert len(spy.payloads) == 1
    assert len(llm.calls) == 1
    assert result.actions[-1]["tool_result"]["scope_violation"] is True
    events = [event for event in AuditWriter(store).export("system") if event["action"] == "react.step"]
    assert events[-1]["decision"] == "deny"
    assert events[-1]["payload"]["reason"] == "scope_violation"


async def test_loop_handles_llm_json_parse_error_gracefully(harness):
    store, context = harness
    llm = ScriptedLLM(["no soy json", task_complete("recuperado")])

    with mock.patch.object(runtime_module, "execute_tool", ToolSpy()):
        result = await run_react_loop(
            context=context,
            objective="objetivo",
            engagement_id="eng-1",
            llm_client=llm,
        )

    assert result.status == STATUS_COMPLETED
    assert result.iterations == 2
    assert result.final_summary == "recuperado"
    correction_prompt = _messages_text(llm, 1)
    assert "no era JSON válido" in correction_prompt
    kinds = [
        message["metadata"].get("kind")
        for message in store.list_messages("system", result.conversation_id)
    ]
    assert "react.correction" in kinds
    assert result.actions[0]["action"] == "parse_error"


async def test_loop_rejects_unknown_tool_without_executing(harness):
    store, context = harness
    llm = ScriptedLLM([tool_call("nexus.recon.masscan")])
    spy = ToolSpy()

    with mock.patch.object(runtime_module, "execute_tool", spy):
        result = await run_react_loop(
            context=context,
            objective="objetivo",
            engagement_id="eng-1",
            llm_client=llm,
            config=ReActConfig(max_iterations=8),
        )

    assert result.status == STATUS_FAILED
    assert spy.payloads == []
    assert result.iterations == 3
    observations = [
        message["content"]
        for message in store.list_messages("system", result.conversation_id)
        if message["metadata"].get("kind") == "react.observation"
    ]
    assert "does not exist" in observations[0]
    assert "nexus.recon.nmap" in observations[0]


async def test_loop_stops_on_cancel_run_event(harness):
    store, context = harness

    def request_cancel(call_index: int) -> None:
        if call_index == 1:
            store.append_run_event("system", context.run_id, "react.cancel_requested", {})

    llm = ScriptedLLM([tool_call()], on_call=request_cancel)
    spy = ToolSpy()

    with mock.patch.object(runtime_module, "execute_tool", spy):
        result = await run_react_loop(
            context=context,
            objective="objetivo",
            engagement_id="eng-1",
            llm_client=llm,
            config=ReActConfig(max_iterations=10),
        )

    assert result.status == STATUS_CANCELLED
    assert result.iterations == 1
    assert len(spy.payloads) == 1
    assert "react.cancelled" in [
        event["event_type"] for event in store.list_run_events("system", context.run_id)
    ]


async def test_loop_conversation_is_resumable(harness):
    store, context = harness

    with mock.patch.object(runtime_module, "execute_tool", ToolSpy()):
        first = await run_react_loop(
            context=context,
            objective="Escanea 10.0.0.5",
            engagement_id="eng-1",
            llm_client=ScriptedLLM([tool_call()]),
            config=ReActConfig(max_iterations=1),
        )

    assert first.status == STATUS_MAX_ITERATIONS
    assert first.iterations == 1

    llm = ScriptedLLM([task_complete("retomado")])
    with mock.patch.object(runtime_module, "execute_tool", ToolSpy()):
        resumed = await run_react_loop(
            context=context,
            objective="Escanea 10.0.0.5",
            engagement_id="eng-1",
            llm_client=llm,
            config=ReActConfig(max_iterations=4),
        )

    assert resumed.conversation_id == first.conversation_id
    assert resumed.status == STATUS_COMPLETED
    assert resumed.iterations == 2
    assert [entry["iteration"] for entry in resumed.actions] == [1, 2]
    assert resumed.actions[0]["tool_result"]["success"] is True
    # The resumed model call already sees the persisted observation.
    assert "ssh" in _messages_text(llm, 0)
    assert len(store.list_conversations("system", "omni")) == 1


async def test_execute_react_requires_objective(harness):
    _, context = harness

    with pytest.raises(ValueError, match="objective is required"):
        await runtime_module.execute_react({"objective": "   "}, context)


async def test_execute_react_runs_through_the_registry(harness, monkeypatch):
    """The durable executor resolves a provider and returns the loop contract."""
    _, context = harness
    monkeypatch.setenv("NEXUS_LLM_DEFAULT_PROVIDER", "fake")
    monkeypatch.setenv("NEXUS_LLM_FIXTURES", str(FIXTURES / "fake_llm_responses.json"))

    result = await runtime_module.execute_react(
        {
            "objective": "Comprueba el estado del engagement",
            "engagement_id": "eng-1",
            "agent_id": "omni",
            "identity": {"subject_id": "operator-1", "roles": ["operator"]},
        },
        context,
    )

    assert set(result) >= {
        "status",
        "iterations",
        "summary",
        "findings",
        "conversation_id",
        "actions",
    }
    assert result["status"] == STATUS_COMPLETED
    assert result["iterations"] == 1
    assert result["findings"]
    assert result["conversation_id"].startswith("conversation_")
