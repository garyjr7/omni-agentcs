"""Read-only fan-out wiring (3A §8.5 debt): CIDR → one governed call per host.

The invariant that matters: fan-out never bypasses the gateway, never
parallelises an active phase, and never exceeds the hard concurrency ceiling.
"""

from __future__ import annotations

import asyncio
from unittest import mock

import pytest

from nexus_core.agent import subagents
from nexus_core.cli.session import OmniSession
from nexus_core.kernel import runtime as runtime_module
from nexus_core.kernel.audit import AuditWriter

TENANT = "system"
TOOL_ID = "nexus.recon.nmap"


@pytest.fixture()
def store(tmp_path):
    from nexus_core.kernel.control_store import ControlStore

    value = ControlStore(tmp_path / "fanout.db")
    value.initialize()
    return value


@pytest.fixture()
def session(store):
    return OmniSession(
        store=store,
        tenant_id=TENANT,
        engagement=None,
        use_tui=False,
        operator_id="operator:tester",
    )


class _Spy:
    def __init__(self, *, delay: float = 0.0, fail_on: set[str] | None = None):
        self.delay = delay
        self.fail_on = fail_on or set()
        self.payloads: list[dict] = []
        self.active = 0
        self.peak = 0

    async def __call__(self, payload, context):
        self.payloads.append(payload)
        self.active += 1
        self.peak = max(self.peak, self.active)
        try:
            if self.delay:
                await asyncio.sleep(self.delay)
            target = payload["arguments"]["target"]
            if target in self.fail_on:
                raise RuntimeError(f"probe failed: {target}")
            return {"tool_id": payload["tool_id"], "output": {"target": target}}
        finally:
            self._release()

    def _release(self):
        self.active -= 1


def test_fan_out_routes_every_target_through_the_gateway(session):
    spy = _Spy()
    with mock.patch.object(runtime_module, "execute_tool", spy):
        results = session.fan_out_tool(TOOL_ID, ["10.0.0.1", "10.0.0.2", "10.0.0.3"])

    assert [payload["arguments"]["target"] for payload in spy.payloads] == [
        "10.0.0.1",
        "10.0.0.2",
        "10.0.0.3",
    ]
    # Ordered results, and every payload carries the same governed identity.
    assert [result["output"]["target"] for result in results] == [
        "10.0.0.1",
        "10.0.0.2",
        "10.0.0.3",
    ]
    assert {payload["tool_id"] for payload in spy.payloads} == {TOOL_ID}
    assert all(payload["engagement_id"] is None for payload in spy.payloads)
    assert all(payload["trace_id"] for payload in spy.payloads)


def test_fan_out_defaults_to_the_read_only_recon_profile(session, store):
    spy = _Spy()
    with mock.patch.object(runtime_module, "execute_tool", spy):
        session.fan_out_tool(TOOL_ID, ["10.0.0.1"])

    row = _fanout_audit(store)[-1]
    assert row["payload"]["subagent_id"] == subagents.DEFAULT_SUBAGENT_ID
    assert row["payload"]["read_only"] is True


def test_fan_out_refuses_an_active_profile_before_scheduling(session):
    active = subagents.SUBAGENTS_BY_ID["lateral"]
    assert active.parallel_safe is False
    spy = _Spy()
    with mock.patch.object(runtime_module, "execute_tool", spy), pytest.raises(ValueError):
        session.fan_out_tool(TOOL_ID, ["10.0.0.1"], subagent_id=active.id)
    assert spy.payloads == []  # nothing was scheduled


def test_fan_out_bounds_concurrency(session):
    spy = _Spy(delay=0.02)
    with mock.patch.object(runtime_module, "execute_tool", spy):
        session.fan_out_tool(
            TOOL_ID, [f"10.0.0.{index}" for index in range(1, 9)], concurrency=2
        )
    assert spy.peak == 2


def test_fan_out_caps_concurrency_at_the_hard_ceiling(session):
    spy = _Spy(delay=0.02)
    with mock.patch.object(runtime_module, "execute_tool", spy):
        session.fan_out_tool(
            TOOL_ID, [f"10.0.0.{index}" for index in range(1, 11)], concurrency=99
        )
    assert spy.peak == subagents.DEFAULT_MAX_PARALLEL


def test_fan_out_returns_a_failing_target_in_place(session):
    spy = _Spy(fail_on={"10.0.0.2"})
    with mock.patch.object(runtime_module, "execute_tool", spy):
        results = session.fan_out_tool(TOOL_ID, ["10.0.0.1", "10.0.0.2"])

    assert results[0]["output"]["target"] == "10.0.0.1"
    assert isinstance(results[1], RuntimeError)


def test_fan_out_with_no_targets_returns_empty(session):
    spy = _Spy()
    with mock.patch.object(runtime_module, "execute_tool", spy):
        assert session.fan_out_tool(TOOL_ID, []) == []
    assert spy.payloads == []


def test_fan_out_is_audited_with_its_targets_and_concurrency(session, store):
    spy = _Spy()
    with mock.patch.object(runtime_module, "execute_tool", spy):
        session.fan_out_tool(TOOL_ID, ["10.0.0.1", "10.0.0.2"], concurrency=3)

    row = _fanout_audit(store)[-1]
    assert row["action"] == "fanout.started"
    assert row["decision"] == "allow"
    assert row["resource_id"] == TOOL_ID
    assert row["payload"]["targets"] == ["10.0.0.1", "10.0.0.2"]
    assert row["payload"]["concurrency"] == 3


def _fanout_audit(store) -> list[dict]:
    return [
        row
        for row in AuditWriter(store).export(TENANT)
        if row["action"] == "fanout.started"
    ]
