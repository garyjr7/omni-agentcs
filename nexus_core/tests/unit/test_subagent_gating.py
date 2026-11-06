"""Loop integration: a subagent can never invoke a tool outside its subset (3A/3C)."""

from __future__ import annotations

import copy
import json
from datetime import datetime, timedelta, timezone
from unittest import mock

from nexus_core.agent.react import ReActConfig, run_react_loop
from nexus_core.kernel import runtime as runtime_module
from nexus_core.kernel.audit import AuditWriter
from nexus_core.kernel.control_store import ControlStore
from nexus_core.kernel.runtime import ExecutionContext
from nexus_core.llm.abstraction import LLMProvider, LLMResponse
from nexus_core.scope import EngagementScope, EngagementStore


def _iso(delta: timedelta) -> str:
    return (datetime.now(timezone.utc) + delta).isoformat()


def _tool_call(tool_id: str) -> str:
    return json.dumps(
        {
            "thought": "voy a usarla",
            "action": "tool_call",
            "tool_id": tool_id,
            "arguments": {"target": "10.0.0.5"},
            "expected_outcome": "algo",
        }
    )


def _task_complete() -> str:
    return json.dumps(
        {"thought": "listo", "action": "task_complete", "summary": "ok", "findings": []}
    )


class _ScriptedLLM:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls: list[list[dict[str, str]]] = []

    async def complete(self, messages, **kwargs):
        self.calls.append([{"role": m.role, "content": m.content} for m in messages])
        index = min(len(self.calls) - 1, max(0, len(self.responses) - 1))
        return LLMResponse(
            content=self.responses[index], model="scripted", provider=LLMProvider.FAKE
        )


class _ToolSpy:
    def __init__(self, result):
        self.result = result
        self.payloads: list[dict] = []

    async def __call__(self, payload, context):
        self.payloads.append(payload)
        return copy.deepcopy(self.result)


def _result_for(tool_id: str) -> dict:
    return {
        "tool_id": tool_id,
        "output": {
            "success": True,
            "verified": True,
            "verification_method": "deterministic_check",
            "evidence": {"ok": True},
            "output": {"note": "ran"},
        },
    }


def _harness(tmp_path, **payload_extra):
    store = ControlStore(tmp_path / "subagent.db")
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
        "id": "task-sub",
        "tenant_id": "system",
        "run_id": run["id"],
        "task_type": "react.run",
        "payload": {
            "objective": "Escanea 10.0.0.5",
            "engagement_id": "eng-1",
            "identity": {"subject_id": "operator-1", "roles": ["operator"]},
            "permissions": [],
            **payload_extra,
        },
    }
    return store, ExecutionContext(store, task, "worker-sub"), run["id"]


async def test_out_of_subset_tool_is_denied_and_never_executed(tmp_path):
    store, context, run_id = _harness(tmp_path)
    # The recon phase owns the first iteration; nexus.cred.bruteforce is not in
    # its subset even though it is a real, durable tool.
    llm = _ScriptedLLM([_tool_call("nexus.cred.bruteforce"), _task_complete()])
    spy = _ToolSpy(_result_for("nexus.cred.bruteforce"))

    with mock.patch.object(runtime_module, "execute_tool", spy):
        result = await run_react_loop(
            context=context,
            objective="Escanea 10.0.0.5",
            engagement_id="eng-1",
            llm_client=llm,
            config=ReActConfig(max_iterations=3),
        )

    # The gateway was never reached: the subset check is upstream of execution.
    assert spy.payloads == []

    denied = result.actions[0]["tool_result"]
    assert denied["success"] is False
    assert denied["subagent_id"] == "recon"
    assert "outside subagent 'recon' subset" in denied["error"]

    steps = [
        row
        for row in AuditWriter(store).export("system", trace_id=run_id)
        if row["action"] == "react.step"
    ]
    denials = [row for row in steps if row["payload"].get("reason") == "subagent_tool_denied"]
    assert denials, "expected a subagent_tool_denied audit entry"
    assert denials[0]["payload"]["subagent_id"] == "recon"
    assert denials[0]["decision"] == "deny"
    # The chain stays intact even with the new field.
    assert AuditWriter(store).verify_chain() == (True, None)


async def test_persisted_observation_is_tagged_with_the_subagent(tmp_path):
    store, context, _ = _harness(tmp_path)
    llm = _ScriptedLLM([_tool_call("nexus.cred.bruteforce"), _task_complete()])

    with mock.patch.object(runtime_module, "execute_tool", _ToolSpy({})):
        result = await run_react_loop(
            context=context,
            objective="Escanea 10.0.0.5",
            engagement_id="eng-1",
            llm_client=llm,
            config=ReActConfig(max_iterations=3),
        )

    observations = [
        message
        for message in store.list_messages("system", result.conversation_id)
        if message["metadata"].get("kind") == "react.observation"
    ]
    assert observations
    assert observations[0]["metadata"]["subagent_id"] == "recon"


async def test_in_subset_tool_is_executed(tmp_path):
    store, context, _ = _harness(tmp_path)
    llm = _ScriptedLLM([_tool_call("nexus.recon.nmap"), _task_complete()])
    spy = _ToolSpy(_result_for("nexus.recon.nmap"))

    with mock.patch.object(runtime_module, "execute_tool", spy):
        result = await run_react_loop(
            context=context,
            objective="Escanea 10.0.0.5",
            engagement_id="eng-1",
            llm_client=llm,
            config=ReActConfig(max_iterations=3),
        )

    assert [payload["tool_id"] for payload in spy.payloads] == ["nexus.recon.nmap"]
    assert result.actions[0]["tool_result"]["success"] is True
    assert result.subagent_id == "recon"


async def test_system_prompt_only_offers_the_subagent_subset(tmp_path):
    _, context, _ = _harness(tmp_path)
    # Tool hiding (Fase 2): el perfil por defecto muestra cinco tools. Esta
    # prueba es del *subconjunto del subagente*, así que primero se revela el
    # grupo recon del run (lo mismo que haría ``nexus.system.discover_tools``).
    from nexus_core.tools.profiles import activate_tools

    activate_tools(context.run_id, ["nexus.recon.nmap"])
    llm = _ScriptedLLM([_task_complete()])

    with mock.patch.object(runtime_module, "execute_tool", _ToolSpy({})):
        await run_react_loop(
            context=context,
            objective="Escanea 10.0.0.5",
            engagement_id="eng-1",
            llm_client=llm,
            config=ReActConfig(max_iterations=2),
        )

    system = llm.calls[0][0]["content"]
    assert "SUBAGENTE ACTIVO: recon" in system
    assert "nexus.recon.nmap" in system
    # A tool from another phase must not even be offered to the model.
    assert "nexus.cred.bruteforce" not in system
    assert "nexus.web.nuclei" not in system


async def test_planner_selection_is_announced_as_a_run_event(tmp_path):
    store, context, _ = _harness(tmp_path)
    llm = _ScriptedLLM([_task_complete()])

    with mock.patch.object(runtime_module, "execute_tool", _ToolSpy({})):
        result = await run_react_loop(
            context=context,
            objective="Escanea 10.0.0.5",
            engagement_id="eng-1",
            llm_client=llm,
            config=ReActConfig(max_iterations=2),
        )

    # Without an override the deterministic planner picks recon (no facts yet).
    assert result.subagent_id == "recon"

    events = [
        event
        for event in store.list_run_events("system", context.run_id)
        if event["event_type"] == "orchestrator.subagent"
    ]
    assert events and events[0]["payload"]["subagent_id"] == "recon"


async def test_operator_override_switches_the_profile(tmp_path):
    _, context, _ = _harness(tmp_path, subagent="lateral")
    llm = _ScriptedLLM([_task_complete()])

    with mock.patch.object(runtime_module, "execute_tool", _ToolSpy({})):
        result = await run_react_loop(
            context=context,
            objective="Escanea 10.0.0.5",
            engagement_id="eng-1",
            llm_client=llm,
            config=ReActConfig(max_iterations=2),
        )

    assert result.subagent_id == "lateral"
    assert "SUBAGENTE ACTIVO: lateral" in llm.calls[0][0]["content"]


async def test_unknown_override_is_rejected(tmp_path):
    _, context, _ = _harness(tmp_path, subagent="nope")
    llm = _ScriptedLLM([_task_complete()])
    import pytest

    with mock.patch.object(runtime_module, "execute_tool", _ToolSpy({})):
        with pytest.raises(ValueError):
            await run_react_loop(
                context=context,
                objective="Escanea 10.0.0.5",
                engagement_id="eng-1",
                llm_client=llm,
                config=ReActConfig(max_iterations=2),
            )


import pytest

# This module's unsigned scopes exercise targeting/session behavior. Authentication
# is covered separately in test_scope_governed_mode with the governed default.
pytestmark = globals().get("pytestmark", [])
if not isinstance(pytestmark, list):
    pytestmark = [pytestmark]
pytestmark.append(pytest.mark.usefixtures("lab_scope"))


@pytest.fixture(autouse=True)
def _legacy_phase_loop(monkeypatch):
    """WP2: these tests pin the phase-gated loop, now behind the legacy flag."""
    monkeypatch.setenv("NEXUS_LEGACY_PROFILES", "1")
