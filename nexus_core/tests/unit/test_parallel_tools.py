"""Parallel tool calling: contract, bounded concurrency, consolidation.

The loop used to spend one turn per tool. These tests pin the new contract: a
model may answer with ``tool_calls``, every call is still governed on its own,
the batch runs concurrently but never above the ceiling, each call carries its
own timeout, and the model reads **one** consolidated observation with every
result inside.
"""

from __future__ import annotations

import asyncio
import json
import time

import pytest

from nexus_core.agent import parallel
from nexus_core.agent.parser import ACTION_TOOL_CALLS, ReActParseError, parse_react_response
from nexus_core.agent.react import ReActConfig, run_react_loop
from nexus_core.agent.react_coordinator import ReActCoordinator
from nexus_core.agent.react_services import ToolExecutionService
from nexus_core.kernel import hardware
from nexus_core.kernel.domain_dto import (
    MAX_PARALLEL_TOOL_CALLS,
    ToolCall,
    ToolCallBatch,
)
from nexus_core.kernel.models import RiskLevel, ToolDefinition
from nexus_core.kernel.runtime import ExecutionContext
from nexus_core.llm.abstraction import LLMProvider, LLMResponse
from nexus_core.scope import ScopeViolation
from nexus_core.tests.unit.test_hooks_lifecycle import context


# --------------------------------------------------------------------- helpers
def _batch(*tool_ids: str, thought: str = "recon en paralelo") -> str:
    return json.dumps(
        {
            "thought": thought,
            "action": ACTION_TOOL_CALLS,
            "calls": [
                {"tool_id": tool_id, "arguments": {"target": "10.0.0.5"}}
                for tool_id in tool_ids
            ],
        }
    )


_CLARIFY = json.dumps(
    {"thought": "listo", "action": "request_clarification", "question": "¿Sigo?"}
)


class ScriptedLLM:
    """Answers the scripted model turns in order, never touching a provider."""

    supports_streaming = False

    def __init__(self, *answers: str) -> None:
        self.answers = list(answers)
        self.calls = 0

    async def complete(self, messages, **kwargs):
        self.calls += 1
        answer = self.answers[min(self.calls - 1, len(self.answers) - 1)]
        return LLMResponse(content=answer, model="scripted", provider=LLMProvider.FAKE)


def _catalog(*tool_ids: str) -> dict[str, tuple[ToolDefinition, object]]:
    return {
        tool_id: (
            ToolDefinition(
                name=tool_id,
                tenant_id="system",
                input_schema={},
                tool_id=tool_id,
                description=f"stub {tool_id}",
                risk=RiskLevel.LOW,
                effect="read_only",
                effects=("read",),
            ),
            lambda arguments, ctx: None,
        )
        for tool_id in tool_ids
    }


def _invocation(tool_id: str, *, success: bool = True, output=None) -> dict:
    return {
        "output": {
            "success": success,
            "outcome": "success" if success else "negative",
            "output": output if output is not None else {"tool": tool_id, "ports": [22, 80]},
            "verification_method": "unit",
            "invocation_id": f"inv-{tool_id}",
            "assertions": [],
        }
    }


class FakeService:
    """A ToolExecutionService that records concurrency instead of running tools."""

    def __init__(self, delay: float = 0.05, *, fail: str = "", hang: str = "") -> None:
        self.delay = delay
        self.fail = fail
        self.hang = hang
        self.calls: list[str] = []
        self.in_flight = 0
        self.max_in_flight = 0
        self.started: dict[str, float] = {}
        self.finished: dict[str, float] = {}

    async def execute(self, payload, context, *, timeout, cancel_event):
        tool_id = str(payload["tool_id"])
        self.calls.append(tool_id)
        self.in_flight += 1
        self.max_in_flight = max(self.max_in_flight, self.in_flight)
        self.started[tool_id] = time.monotonic()
        try:
            await asyncio.sleep(5 if tool_id == self.hang else self.delay)
        finally:
            self.in_flight -= 1
            self.finished[tool_id] = time.monotonic()
        if tool_id == self.fail:
            raise ScopeViolation("10.0.0.5", "fuera del alcance firmado")
        return _invocation(tool_id), False


class FakeApproval:
    """Records the approval handshake of every call; can deny one of them."""

    def __init__(self, deny: str = "") -> None:
        self.deny = deny
        self.reviews: list[str] = []

    def review(self, *, config, context, definition, tool_payload):
        tool_id = str(tool_payload["tool_id"])
        self.reviews.append(tool_id)
        if tool_id == self.deny:
            return {
                "success": False,
                "status": "denied_by_operator",
                "tool_id": tool_id,
                "reason": "no autorizo este escaneo",
            }
        return None


def _loop_context(tmp_path, monkeypatch) -> ExecutionContext:
    ctx = context(tmp_path, monkeypatch)
    run = ctx.store.create_run("system", {})
    payload = {"objective": "recon", "identity": {"subject_id": "op", "roles": ["operator"]}}
    task = {
        "id": "t",
        "tenant_id": "system",
        "run_id": run["id"],
        "task_type": "react.run",
        "payload": payload,
    }
    return ExecutionContext(ctx.store, task, "worker-test")


def _coordinator(exec_ctx, llm, tools, service, *, approval=None, **config):
    return ReActCoordinator(
        context=exec_ctx,
        objective="recon",
        engagement_id=None,
        llm_client=llm,
        tool_catalog=_catalog(*tools),
        config=ReActConfig(max_iterations=4, enforce_completion_gates=False, **config),
        tool_execution=service,
        approval_coordinator=approval,
    )


def _observations(exec_ctx, coordinator) -> list[dict]:
    from nexus_core.agent import memory

    messages = memory.load_history(
        exec_ctx.store, "system", coordinator.conversation_id, limit=200
    )
    return [
        json.loads(str(message["content"]))
        for message in messages
        if (message.get("metadata") or {}).get("kind") == "react.observation"
    ]


# --------------------------------------------------------------------- contract
def test_a_tool_calls_object_parses_into_a_batch():
    action = parse_react_response(_batch("local.one", "local.two", "local.three"))

    assert isinstance(action, ToolCallBatch)
    assert action.tool_ids == ("local.one", "local.two", "local.three")
    assert action.calls[0].arguments == {"target": "10.0.0.5"}
    # The first call still answers the legacy scalar reads.
    assert action.tool_id == "local.one"


def test_an_array_of_tool_calls_is_understood_as_parallel():
    """A model that stacks three answers in one array meant a batch."""
    text = json.dumps(
        [
            {"thought": "tres a la vez", "action": "tool_call", "tool_id": "a", "arguments": {}},
            {"action": "tool_call", "tool_id": "b", "arguments": {}},
            {"action": "tool_call", "tool_id": "c", "arguments": {}},
        ]
    )

    action = parse_react_response(text)

    assert isinstance(action, ToolCallBatch)
    assert action.tool_ids == ("a", "b", "c")
    assert action.thought == "tres a la vez"
    assert any("parallel" in warning for warning in action.warnings)


def test_tool_calls_without_an_action_label_is_still_understood():
    action = parse_react_response(
        json.dumps({"thought": "x", "tool_calls": [
            {"tool_id": "a", "arguments": {}}, {"tool_id": "b", "arguments": {}}
        ]})
    )

    assert isinstance(action, ToolCallBatch)
    assert action.tool_ids == ("a", "b")


def test_a_lone_call_never_becomes_a_batch():
    single = parse_react_response(
        json.dumps({"action": "tool_calls", "calls": [{"tool_id": "a", "arguments": {}}]})
    )
    array = parse_react_response(
        json.dumps([{"action": "tool_call", "tool_id": "a", "arguments": {}}])
    )

    assert isinstance(single, ToolCall)
    assert isinstance(array, ToolCall)


def test_the_batch_ceiling_is_enforced_by_the_contract():
    text = _batch(*[f"t{index}" for index in range(MAX_PARALLEL_TOOL_CALLS + 1)])

    with pytest.raises(ReActParseError):
        parse_react_response(text)


def test_a_batch_without_arguments_defaults_to_an_empty_call():
    """A missing ``arguments`` is tolerated, as it is on the single-call path."""
    action = parse_react_response(
        json.dumps({"action": "tool_calls", "calls": [{"tool_id": "a"}, {"tool_id": "b"}]})
    )

    assert isinstance(action, ToolCallBatch)
    assert [call.arguments for call in action.calls] == [{}, {}]


# ------------------------------------------------------------- bounded execution
def _run_execute(calls, *, limit, timeout=5.0, execute=None):
    return asyncio.run(
        parallel.execute_calls(
            calls,
            execute=execute
            or (lambda payload, timeout, event: _immediate(payload, timeout, event)),
            limit=limit,
            timeout=timeout,
        )
    )


async def _immediate(payload, timeout, event):
    return _invocation(str(payload["tool_id"])), False


def test_calls_run_concurrently_within_the_ceiling():
    service = FakeService(delay=0.1)
    calls = [
        {"index": index, "tool_id": f"t{index}", "arguments": {}, "payload": {"tool_id": f"t{index}"}}
        for index in range(4)
    ]

    started = time.monotonic()
    results = _run_execute(
        calls,
        limit=2,
        execute=lambda payload, timeout, event: service.execute(
            payload, None, timeout=timeout, cancel_event=event
        ),
    )
    elapsed = time.monotonic() - started

    assert len(results) == 4
    assert all(result.error is None for result in results)
    assert service.max_in_flight == 2, "the ceiling is a ceiling, not a suggestion"
    assert elapsed < 0.45, f"4 x 0.1s at 2 in flight should take ~0.2s, took {elapsed:.2f}s"


def test_a_hung_call_has_its_own_timeout_and_the_rest_finish():
    service = FakeService(delay=0.01, hang="t1")
    calls = [
        {"index": 0, "tool_id": "t0", "arguments": {}, "payload": {"tool_id": "t0"}},
        {"index": 1, "tool_id": "t1", "arguments": {}, "payload": {"tool_id": "t1"}},
    ]

    started = time.monotonic()
    results = _run_execute(
        calls,
        limit=3,
        timeout=0.2,
        execute=lambda payload, timeout, event: service.execute(
            payload, None, timeout=timeout, cancel_event=event
        ),
    )
    elapsed = time.monotonic() - started

    by_tool = {result.tool_id: result for result in results}
    assert by_tool["t0"].error is None and by_tool["t0"].invocation is not None
    assert isinstance(by_tool["t1"].error, TimeoutError)
    assert elapsed < 1.5, "the hung call must not wait its full 5s, let alone the batch"


def test_one_failing_call_never_raises_out_of_the_batch():
    class Failing:
        async def execute(self, payload, context, *, timeout, cancel_event):
            if payload["tool_id"] == "bad":
                raise ScopeViolation("10.0.0.5", "fuera del alcance firmado")
            return _invocation(str(payload["tool_id"])), False

    service = Failing()
    calls = [
        {"index": 0, "tool_id": "bad", "arguments": {}, "payload": {"tool_id": "bad"}},
        {"index": 1, "tool_id": "good", "arguments": {}, "payload": {"tool_id": "good"}},
    ]

    results = _run_execute(
        calls,
        limit=3,
        execute=lambda payload, timeout, event: service.execute(
            payload, None, timeout=timeout, cancel_event=event
        ),
    )

    by_tool = {result.tool_id: result for result in results}
    assert isinstance(by_tool["bad"].error, ScopeViolation)
    assert by_tool["good"].error is None


def test_the_operator_can_turn_parallelism_off(monkeypatch):
    monkeypatch.setenv(parallel.PARALLEL_LIMIT_ENV, "1")
    assert parallel.parallel_limit() == 1

    monkeypatch.setenv(parallel.PARALLEL_LIMIT_ENV, "99")
    assert parallel.parallel_limit() == parallel.PARALLEL_MAX_CONCURRENCY, (
        "the override is clamped, never trusted above the hard ceiling"
    )

    monkeypatch.delenv(parallel.PARALLEL_LIMIT_ENV)
    # Without an override the number comes from the machine, so the assertion is
    # the tier of *this* host's profile -not a constant that would pass on a
    # laptop and lie on a 32-core server.
    assert parallel.parallel_limit() == hardware.concurrency_for(hardware.detect_hardware())


# ------------------------------------------------------------------ consolidation
def test_consolidation_packs_every_result_and_counts_them():
    observation = parallel.consolidate(
        [
            {"tool_id": "nmap", "success": True, "output": {"ports": [22]}},
            {"tool_id": "gobuster", "success": True, "output": {"dirs": ["/admin"]}},
        ]
    )

    assert observation["success"] is True
    assert observation["parallel"] is True
    assert observation["tool_calls"] == 2 and observation["succeeded"] == 2
    assert [entry["tool_id"] for entry in observation["results"]] == ["nmap", "gobuster"]


def test_a_failed_call_is_named_in_the_guidance():
    observation = parallel.consolidate(
        [
            {"tool_id": "nmap", "success": True, "output": {}},
            {"tool_id": "gobuster", "success": False, "outcome": "negative", "error": "403"},
        ]
    )

    assert observation["success"] is False
    assert observation["failed"] == 1
    assert "gobuster" in observation["guidance"]
    assert "no las repitas" in observation["guidance"]


def test_a_huge_output_is_bounded_but_the_evidence_is_kept():
    observation = parallel.consolidate(
        [
            {
                "tool_id": "nmap",
                "success": True,
                "output": {"raw": "x" * (parallel.RESULT_OUTPUT_CHARS * 2)},
                "assertions": [{"fact_type": "host", "value": "10.0.0.5"}],
            }
        ]
    )

    entry = observation["results"][0]
    assert entry["output"]["truncated"] is True
    assert len(entry["output"]["preview"]) == parallel.RESULT_OUTPUT_CHARS
    assert entry["assertions"] == [{"fact_type": "host", "value": "10.0.0.5"}]


# ---------------------------------------------------------------- the ReAct loop
def _simulate(monkeypatch, *, logical: int, ram_gib: int = 32) -> None:
    """Pretend the host has ``logical`` cores, so the tier is deterministic."""
    profile = hardware.HardwareProfile(
        cpu_logical=logical,
        cpu_physical=max(1, logical // 2),
        ram_total_bytes=ram_gib * hardware.GIB,
        ram_available_bytes=ram_gib * hardware.GIB // 2,
        source="test",
    )
    monkeypatch.setattr(hardware, "detect_hardware", lambda: profile)


def test_three_tools_run_at_once_and_arrive_as_one_observation(tmp_path, monkeypatch):
    _simulate(monkeypatch, logical=16)
    exec_ctx = _loop_context(tmp_path, monkeypatch)
    service = FakeService(delay=0.12)
    llm = ScriptedLLM(_batch("local.one", "local.two", "local.three"), _CLARIFY)
    coordinator = _coordinator(exec_ctx, llm, ("local.one", "local.two", "local.three"), service)

    result = asyncio.run(coordinator.run())

    assert result.status == "clarification"
    assert service.calls == ["local.one", "local.two", "local.three"]
    assert service.max_in_flight == 3, "the three calls must overlap"
    first_finished = min(service.finished.values())
    last_started = max(service.started.values())
    assert last_started < first_finished, "no call waited for the previous one to finish"

    observations = _observations(exec_ctx, coordinator)
    assert len(observations) == 1, "one consolidated block, not one message per tool"
    block = observations[0]
    assert block["parallel"] is True
    assert block["tool_calls"] == 3 and block["succeeded"] == 3
    assert [entry["tool_id"] for entry in block["results"]] == [
        "local.one",
        "local.two",
        "local.three",
    ]
    # Every call is its own action-log entry, so the run stays auditable per tool.
    assert [entry["tool_id"] for entry in result.actions if entry["tool_id"]] == [
        "local.one",
        "local.two",
        "local.three",
    ]
    events = [
        event
        for event in exec_ctx.store.list_run_events("system", exec_ctx.run_id)
        if event["event_type"] == "react.parallel_batch"
    ]
    assert len(events) == 1
    assert events[0]["payload"]["tool_calls"] == 3


def test_a_two_core_box_runs_the_batch_one_call_at_a_time(tmp_path, monkeypatch):
    """The hardware tier wins over the old fixed 3: no lock-up on a laptop."""
    _simulate(monkeypatch, logical=2)
    exec_ctx = _loop_context(tmp_path, monkeypatch)
    service = FakeService(delay=0.01)
    llm = ScriptedLLM(_batch("local.one", "local.two", "local.three"), _CLARIFY)
    coordinator = _coordinator(exec_ctx, llm, ("local.one", "local.two", "local.three"), service)

    result = asyncio.run(coordinator.run())

    assert result.status == "clarification"
    assert service.max_in_flight == 1, "2 cores -> one tool at a time"
    block = _observations(exec_ctx, coordinator)[0]
    assert block["concurrency"] == 1
    assert block["tool_calls"] == 3 and block["succeeded"] == 3


def test_each_call_gets_its_own_approval_and_a_denial_is_local(tmp_path, monkeypatch):
    exec_ctx = _loop_context(tmp_path, monkeypatch)
    service = FakeService(delay=0.01)
    approval = FakeApproval(deny="local.two")
    llm = ScriptedLLM(_batch("local.one", "local.two", "local.three"), _CLARIFY)
    coordinator = _coordinator(
        exec_ctx,
        llm,
        ("local.one", "local.two", "local.three"),
        service,
        approval=approval,
        # The handshake only runs when the caller can ask someone.
        on_approval_needed=lambda *args: None,
    )

    result = asyncio.run(coordinator.run())

    assert approval.reviews == ["local.one", "local.two", "local.three"]
    assert service.calls == ["local.one", "local.three"], "the denied call never ran"
    block = _observations(exec_ctx, coordinator)[0]
    assert block["tool_calls"] == 3 and block["succeeded"] == 2 and block["failed"] == 1
    denied = next(entry for entry in block["results"] if entry["tool_id"] == "local.two")
    assert denied["outcome"] == "denied"
    assert denied["reason"] == "denied_by_operator"
    assert "no autorizo" in denied["error"]
    assert result.status == "clarification", "one denial does not end the run"


def test_an_unknown_tool_is_refused_locally_and_the_others_run(tmp_path, monkeypatch):
    exec_ctx = _loop_context(tmp_path, monkeypatch)
    service = FakeService(delay=0.01)
    llm = ScriptedLLM(_batch("local.one", "local.nope"), _CLARIFY)
    coordinator = _coordinator(exec_ctx, llm, ("local.one",), service)

    result = asyncio.run(coordinator.run())

    assert service.calls == ["local.one"]
    block = _observations(exec_ctx, coordinator)[0]
    refusal = next(entry for entry in block["results"] if entry["tool_id"] == "local.nope")
    assert refusal["reason"] == "unknown_tool"
    assert block["refused"] == 1 and block["succeeded"] == 1
    assert result.status == "clarification"


def test_a_scope_violation_in_one_call_does_not_cancel_the_other(tmp_path, monkeypatch):
    exec_ctx = _loop_context(tmp_path, monkeypatch)
    service = FakeService(delay=0.01, fail="local.two")
    llm = ScriptedLLM(_batch("local.one", "local.two"), _CLARIFY)
    coordinator = _coordinator(exec_ctx, llm, ("local.one", "local.two"), service)

    result = asyncio.run(coordinator.run())

    assert service.calls == ["local.one", "local.two"]
    block = _observations(exec_ctx, coordinator)[0]
    denied = next(entry for entry in block["results"] if entry["tool_id"] == "local.two")
    assert denied["outcome"] == "scope_denied"
    assert denied["scope_denial_streak"] == 1
    assert block["succeeded"] == 1 and block["failed"] == 1
    assert result.status == "clarification"


def test_the_public_entry_point_accepts_a_batch(tmp_path, monkeypatch):
    """``run_react_loop`` (what the CLI calls) routes a batch the same way."""
    exec_ctx = _loop_context(tmp_path, monkeypatch)
    service = FakeService(delay=0.01)

    async def execute(self, payload, context, *, timeout, cancel_event):
        return await service.execute(payload, context, timeout=timeout, cancel_event=cancel_event)

    monkeypatch.setattr(ToolExecutionService, "execute", execute)
    llm = ScriptedLLM(_batch("local.one", "local.two"), _CLARIFY)

    result = asyncio.run(
        run_react_loop(
            context=exec_ctx,
            objective="recon",
            engagement_id=None,
            llm_client=llm,
            tool_catalog=_catalog("local.one", "local.two"),
            config=ReActConfig(max_iterations=4, enforce_completion_gates=False),
        )
    )

    assert result.status == "clarification"
    assert service.calls == ["local.one", "local.two"]
    assert result.actions and result.actions[0]["batch_size"] == 2
