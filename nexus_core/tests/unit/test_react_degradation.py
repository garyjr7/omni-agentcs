"""Regression tests for B3: degrade the phase, never abort the whole run.

The E2E report's Run #1 died after three failures of the *same* HTTP subsystem.
A broken tool must be retired so the agent can pivot; only when a phase has no
usable tool left may the run abort.
"""

from __future__ import annotations

import copy
import json
from datetime import datetime, timedelta, timezone
from unittest import mock

import pytest

from nexus_core.agent import react as react_module
from nexus_core.agent.react import (
    ReActConfig,
    MAX_TOOL_FAILURES_BEFORE_UNAVAILABLE,
    REACT_DEFAULT_MAX_TOKENS,
    STATUS_COMPLETED,
    STATUS_MAX_ITERATIONS,
    _failure_kind,
    react_max_tokens,
    run_react_loop,
)
from nexus_core.kernel import runtime as runtime_module
from nexus_core.kernel.control_store import ControlStore
from nexus_core.kernel.runtime import ExecutionContext
from nexus_core.llm.abstraction import LLMProvider, LLMResponse
from nexus_core.scope import EngagementScope, EngagementStore

FTP_SUCCESS = {
    "tool_id": "nexus.recon.ftp",
    "output": {
        "success": True,
        "verified": True,
        "verification_method": "ftp_listing_parsed",
        "evidence": {"login_ok": True},
        "output": {"listing": ["locks.txt", "task.txt"]},
    },
}


def _iso(delta: timedelta) -> str:
    return (datetime.now(timezone.utc) + delta).isoformat()


def _tool_call(tool_id: str, **arguments) -> str:
    return json.dumps(
        {
            "thought": "siguiente paso",
            "action": "tool_call",
            "tool_id": tool_id,
            "arguments": arguments,
            "expected_outcome": "evidencia",
        }
    )


def _task_complete() -> str:
    return json.dumps(
        {"thought": "listo", "action": "task_complete", "summary": "ok", "findings": []}
    )


class ScriptedLLM:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = 0
        self.kwargs: list[dict] = []

    async def complete(self, messages, **kwargs):
        self.calls += 1
        self.kwargs.append(dict(kwargs))
        index = min(self.calls - 1, max(0, len(self.responses) - 1))
        return LLMResponse(
            content=self.responses[index] if self.responses else "",
            model="scripted-test",
            provider=LLMProvider.FAKE,
        )


class SelectorSpy:
    """Fails a given tool with ``error``, succeeds everything else."""

    def __init__(self, fail_tool: str, error: BaseException, *, fail_times: int | None = None):
        self.fail_tool = fail_tool
        self.error = error
        self.fail_times = fail_times
        self.payloads: list[dict] = []

    async def __call__(self, payload, context):
        self.payloads.append(payload)
        if payload["tool_id"] == self.fail_tool and (
            self.fail_times is None
            or sum(p["tool_id"] == self.fail_tool for p in self.payloads) <= self.fail_times
        ):
            raise self.error
        result = copy.deepcopy(FTP_SUCCESS)
        result["tool_id"] = payload["tool_id"]
        return result


@pytest.fixture()
def harness(tmp_path):
    store = ControlStore(tmp_path / "degrade.db")
    store.initialize()
    EngagementStore(store).create(
        EngagementScope(
            engagement_id="eng-1",
            tenant_id="system",
            name="eng-1",
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
        "id": "task-degrade-1",
        "tenant_id": "system",
        "run_id": run["id"],
        "task_type": "react.run",
        "payload": {
            "objective": "comprometer 10.0.0.5",
            "engagement_id": "eng-1",
            "identity": {"subject_id": "operator-1", "roles": ["operator"]},
            "permissions": [],
        },
    }
    return store, ExecutionContext(store, task, "worker-test")


def _events(store, run_id, event_type):
    return [
        event
        for event in store.list_run_events("system", run_id)
        if event.get("event_type") == event_type
    ]


def test_react_max_tokens_is_bounded_and_configurable(monkeypatch):
    monkeypatch.delenv("NEXUS_REACT_MAX_TOKENS", raising=False)
    assert react_max_tokens() == REACT_DEFAULT_MAX_TOKENS
    monkeypatch.setenv("NEXUS_REACT_MAX_TOKENS", "512")
    assert react_max_tokens() == 512
    # A nonsense/tiny value can never disable the ceiling entirely.
    monkeypatch.setenv("NEXUS_REACT_MAX_TOKENS", "1")
    assert react_max_tokens() == 256


def test_failure_kind_separates_input_from_tool():
    assert _failure_kind(ValueError("bad flag")) == "input"
    assert _failure_kind(PermissionError("needs approval")) == "input"
    assert _failure_kind(RuntimeError("post-condition")) == "tool"
    assert _failure_kind(TimeoutError("timed out")) == "tool"


async def test_agent_pivots_after_a_broken_tool_is_retired(harness):
    store, context = harness
    llm = ScriptedLLM(
        [
            _tool_call("nexus.recon.httpx", targets=["http://10.0.0.5"]),
            _tool_call("nexus.recon.httpx", targets=["http://10.0.0.5"]),
            _tool_call("nexus.recon.httpx", targets=["http://10.0.0.5"]),
            _tool_call("nexus.recon.ftp", target="10.0.0.5", action="list"),
            _task_complete(),
        ]
    )
    spy = SelectorSpy("nexus.recon.httpx", RuntimeError("post-condition was not verified"))

    with mock.patch.object(runtime_module, "execute_tool", spy):
        result = await run_react_loop(
            context=context,
            objective="comprometer 10.0.0.5",
            engagement_id="eng-1",
            llm_client=llm,
            config=_loop_config(max_iterations=10),
        )

    assert result.status == STATUS_COMPLETED
    # Every model turn carries the bounded output ceiling (B4/TPM budget).
    assert llm.kwargs and all(
        item.get("max_tokens") == REACT_DEFAULT_MAX_TOKENS for item in llm.kwargs
    )
    executed = [payload["tool_id"] for payload in spy.payloads]
    assert executed == ["nexus.recon.httpx"] * 3 + ["nexus.recon.ftp"]
    retired = _events(store, context.run_id, "react.tool_unavailable")
    assert len(retired) == 1
    assert retired[0]["payload"]["tool_id"] == "nexus.recon.httpx"
    assert retired[0]["payload"]["failures"] == MAX_TOOL_FAILURES_BEFORE_UNAVAILABLE


async def test_invalid_input_does_not_retire_the_tool(harness):
    store, context = harness
    llm = ScriptedLLM(
        [
            _tool_call("nexus.recon.nmap", target="10.0.0.5", flags=["--script", "x"]),
            _tool_call("nexus.recon.nmap", target="10.0.0.5", flags=["--script", "x"]),
            _tool_call("nexus.recon.nmap", target="10.0.0.5", flags=["--script", "x"]),
            _tool_call("nexus.recon.nmap", profile="service", target="10.0.0.5"),
            _task_complete(),
        ]
    )
    # Raises ValueError (invalid input) three times, then succeeds.
    spy = SelectorSpy("nexus.recon.nmap", ValueError("nmap flag is forbidden"), fail_times=3)

    with mock.patch.object(runtime_module, "execute_tool", spy):
        result = await run_react_loop(
            context=context,
            objective="comprometer 10.0.0.5",
            engagement_id="eng-1",
            llm_client=llm,
            config=_loop_config(max_iterations=10),
        )

    assert result.status == STATUS_COMPLETED
    assert _events(store, context.run_id, "react.tool_unavailable") == []
    # The tool kept executing after the invalid attempts.
    assert [p["tool_id"] for p in spy.payloads] == ["nexus.recon.nmap"] * 4


async def test_phase_timeout_retires_failing_tools_and_is_audited(harness, monkeypatch):
    store, context = harness
    monkeypatch.setattr(react_module, "_phase_timeout_seconds", lambda: 0.0000001)
    llm = ScriptedLLM([_tool_call("nexus.recon.nmap", target="10.0.0.5")])
    spy = SelectorSpy("nexus.recon.nmap", RuntimeError("post-condition"))

    with mock.patch.object(runtime_module, "execute_tool", spy):
        await run_react_loop(
            context=context,
            objective="comprometer 10.0.0.5",
            engagement_id="eng-1",
            llm_client=llm,
            config=_loop_config(max_iterations=4),
        )

    timeouts = _events(store, context.run_id, "react.phase_timeout")
    assert timeouts
    assert any(
        "nexus.recon.nmap" in (event["payload"].get("retired_tools") or [])
        for event in timeouts
    )


async def test_run_continues_to_budget_while_any_route_remains(harness):
    store, context = harness
    # Keep proposing one tool until it is retired; other routes still exist.
    llm = ScriptedLLM([_tool_call("nexus.recon.ftp", target="10.0.0.5", action="list")])
    spy = SelectorSpy("nexus.recon.ftp", RuntimeError("post-condition"))

    with mock.patch.object(runtime_module, "execute_tool", spy):
        result = await run_react_loop(
            context=context,
            objective="comprometer 10.0.0.5",
            engagement_id="eng-1",
            llm_client=llm,
            config=_loop_config(max_iterations=6),
        )

    # The broken tool was retired after three *tool* failures, but the phase has
    # other routes, so the run keeps going to the iteration budget (B3).
    assert result.status == STATUS_MAX_ITERATIONS
    retired = {
        event["payload"]["tool_id"]
        for event in _events(store, context.run_id, "react.tool_unavailable")
    }
    assert retired == {"nexus.recon.ftp"}
    assert len([p for p in spy.payloads if p["tool_id"] == "nexus.recon.ftp"]) == 3


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
