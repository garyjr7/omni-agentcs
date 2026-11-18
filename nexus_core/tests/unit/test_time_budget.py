"""Work-time budget: wrap-up window, forced closure and the durable clock.

The loop's own run of 2026-11-18 (``--time-budget 300``) is reproduced here with
an injected monotonic clock: forty seconds per model turn, so the last 150
seconds are the wrap-up window and the run closes as ``time_budget`` after eight
turns instead of being cancelled mid-call.
"""

from __future__ import annotations

import copy
import json
from datetime import datetime, timedelta, timezone
from unittest import mock

import pytest

from nexus_core.agent.react import ReActConfig
from nexus_core.agent.react_coordinator import ReActCoordinator
from nexus_core.agent.react_support import clamp_tool_timeout, wrap_up_window
from nexus_core.agent.react_types import (
    MIN_TOOL_SECONDS,
    STATUS_TIME_BUDGET,
    TIME_BUDGET_EVENT_TYPE,
    WORK_CLOCK_EVENT_TYPE,
    WRAP_UP_EVENT_TYPE,
)
from nexus_core.kernel import runtime as runtime_module
from nexus_core.kernel.control_store import ControlStore
from nexus_core.kernel.runtime import ExecutionContext
from nexus_core.llm.abstraction import LLMProvider, LLMResponse
from nexus_core.scope import EngagementScope, EngagementStore

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


# Unsigned lab scopes exercise the loop, not authentication (same as the other
# scripted-loop modules; governed scope tests live in test_scope_governed_mode).
pytestmark = pytest.mark.usefixtures("lab_scope")


def _iso(delta: timedelta) -> str:
    return (datetime.now(timezone.utc) + delta).isoformat()


def _scope(store, engagement_id: str = "eng-1") -> None:
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


class FakeClock:
    """Monotonic clock under test control (seconds)."""

    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


class ScriptedLLM:
    """Always asks for the same recon call; each turn costs ``seconds``."""

    def __init__(self, clock: FakeClock, seconds: float = 40.0) -> None:
        self.clock = clock
        self.seconds = seconds
        self.calls: list[list[dict[str, str]]] = []

    async def complete(self, messages, **kwargs):
        self.calls.append([{"role": m.role, "content": m.content} for m in messages])
        self.clock.advance(self.seconds)
        payload = {
            "thought": "Sigo enumerando el objetivo.",
            "action": "tool_call",
            "tool_id": "nexus.recon.nmap",
            "arguments": {"target": "10.0.0.5", "flags": ["-Pn", "-p", "22,80"]},
            "expected_outcome": "puertos abiertos",
        }
        return LLMResponse(
            content=json.dumps(payload), model="scripted-test", provider=LLMProvider.FAKE
        )


class ToolSpy:
    def __init__(self) -> None:
        self.payloads: list[dict] = []

    async def __call__(self, payload, context):
        self.payloads.append(payload)
        return copy.deepcopy(TOOL_SUCCESS)


@pytest.fixture()
def harness(tmp_path):
    store = ControlStore(tmp_path / "time_budget.db")
    store.initialize()
    _scope(store)
    run = store.create_run("system", {})
    task = {
        "id": "task-time-budget",
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


def _config(**kwargs) -> ReActConfig:
    kwargs.setdefault("enforce_completion_gates", False)
    kwargs.setdefault("max_iterations", 12)
    kwargs.setdefault("time_budget_seconds", 300)
    return ReActConfig(**kwargs)


async def _run(store, context, clock, **config_kwargs) -> tuple[object, ScriptedLLM, ToolSpy]:
    llm = ScriptedLLM(clock)
    spy = ToolSpy()
    coordinator = ReActCoordinator(
        context=context,
        objective="Escanea 10.0.0.5 en los puertos 22 y 80",
        engagement_id="eng-1",
        llm_client=llm,
        config=_config(**config_kwargs),
        clock=clock,
    )
    with mock.patch.object(runtime_module, "execute_tool", spy):
        result = await coordinator.run()
    return result, llm, spy


# ------------------------------------------------------------------ pure rules
def test_the_wrap_up_window_never_costs_more_than_half_the_budget():
    assert wrap_up_window(300, 600) == 150
    assert wrap_up_window(10_800, 600) == 600
    assert wrap_up_window(0, 600) == 0
    assert wrap_up_window(60, 0) == 0


def test_a_tool_timeout_is_clamped_to_the_work_time_left():
    assert clamp_tool_timeout(1860, None) == 1860
    assert clamp_tool_timeout(1860, 120) == 120
    # Never a one-second call: that would be cancelled mid-effect.
    assert clamp_tool_timeout(1860, 1) == MIN_TOOL_SECONDS


# ------------------------------------------------------------- simulated run
async def test_a_five_minute_run_wraps_up_and_closes_as_time_budget(harness, tmp_path):
    store, context = harness
    clock = FakeClock()

    result, llm, spy = await _run(store, context, clock)

    assert result.status == STATUS_TIME_BUDGET
    assert 4 <= result.iterations < 12
    assert "presupuesto de tiempo" in result.final_summary.lower()
    # The wrap-up prompt reached the model before the deadline, not after it.
    system_prompts = [call[0]["content"] for call in llm.calls]
    assert any("PRESUPUESTO DE TIEMPO" in prompt for prompt in system_prompts)
    wrap_up_calls = [
        index for index, prompt in enumerate(system_prompts)
        if "PRESUPUESTO DE TIEMPO" in prompt
    ]
    assert wrap_up_calls and wrap_up_calls[0] > 0
    # Inside the window the engine refuses exploration deterministically.
    denied = [
        action for action in result.actions
        if isinstance(action.get("tool_result"), dict)
        and action["tool_result"].get("status") == "denied_time_budget"
    ]
    assert denied
    assert spy.payloads  # the work before the window did run

    events = store.list_run_events("system", context.task["run_id"])
    types = [event["event_type"] for event in events]
    assert WRAP_UP_EVENT_TYPE in types
    assert TIME_BUDGET_EVENT_TYPE in types
    assert WORK_CLOCK_EVENT_TYPE in types
    forced = next(e for e in events if e["event_type"] == TIME_BUDGET_EVENT_TYPE)
    assert forced["payload"]["work_seconds_used"] >= 300
    assert "report" in forced["payload"]


async def test_the_work_clock_survives_a_resume(harness):
    store, context = harness
    first_clock = FakeClock()
    first, _, _ = await _run(store, context, first_clock)

    # A new process with a fresh monotonic origin, and without repeating
    # ``--time-budget``: the persisted clock and ceiling still apply.
    second_clock = FakeClock()
    result, llm, spy = await _run(
        store, context, second_clock, time_budget_seconds=0
    )

    assert first.status == STATUS_TIME_BUDGET
    assert result.status == STATUS_TIME_BUDGET
    # No new model turn and no tool call: the resumed process closes on the
    # clock it inherited. ``iterations`` is the durable count of the run (8),
    # not the turns this process spent.
    assert llm.calls == [] and spy.payloads == []
    assert "320s" in result.final_summary


async def test_without_a_time_budget_nothing_wraps_up(harness):
    store, context = harness
    clock = FakeClock()

    result, llm, _ = await _run(store, context, clock, time_budget_seconds=0)

    assert result.status != STATUS_TIME_BUDGET
    assert all("PRESUPUESTO DE TIEMPO" not in call[0]["content"] for call in llm.calls)


# ------------------------------------------------------------------- CLI flags
def test_the_cli_accepts_seconds_or_hours_and_resolves_them():
    from nexus_core.cli.main import build_parser, time_budget_seconds

    assert time_budget_seconds(build_parser().parse_args(["--time-budget", "300"])) == 300
    assert (
        time_budget_seconds(build_parser().parse_args(["--time-budget-hours", "1.5"]))
        == 5400
    )
    assert time_budget_seconds(build_parser().parse_args([])) == 0
