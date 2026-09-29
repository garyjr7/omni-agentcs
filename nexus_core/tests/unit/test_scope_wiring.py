"""Tests for wiring EngagementScope into the durable runtime (execute_tool/brain)."""

from __future__ import annotations

import asyncio
import contextlib
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from unittest import mock

import pytest

from nexus_core.kernel.control_store import ControlStore
from nexus_core.kernel.runtime import ExecutionContext, build_default_registry
from nexus_core.kernel.tool_gateway import ToolGateway
from nexus_core.scope import EngagementScope, EngagementStore, ScopeViolation


def _iso(delta: timedelta) -> str:
    return (datetime.now(timezone.utc) + delta).isoformat()


def _scope(engagement_id: str = "eng-1") -> EngagementScope:
    return EngagementScope(
        engagement_id=engagement_id,
        tenant_id="system",
        name="engagement",
        client="acme",
        owner_id="owner-1",
        valid_from=_iso(-timedelta(days=1)),
        valid_until=_iso(timedelta(days=1)),
        cidrs=("203.0.113.0/24",),
        domains=(),
        urls=(),
        exclusions=(),
        created_at=_iso(timedelta(0)),
    )


def _run_task(store: ControlStore, task_type: str, payload: dict) -> dict:
    run = store.create_run("system", {})
    store.enqueue_task(tenant_id="system", run_id=run["id"],
                       task_type=task_type, payload=payload)
    claimed = store.claim_task("worker-test")
    assert claimed is not None
    registry = build_default_registry()
    return asyncio.run(registry.execute(claimed, ExecutionContext(store, claimed, "worker-test")))


@contextlib.contextmanager
def _scope_requiring_catalog():
    """Promote the first-party system.status tool to require a scoped target.

    Production only ships non-scoped tools, so tests that exercise the scope
    wiring inject the scope fields onto a built-in tool definition while still
    going through the real ``execute_tool`` catalog and gateway.
    """
    original_register = ToolGateway.register

    def register(self, definition, handler):
        if definition.tool_id == "nexus.system.status":
            definition = replace(
                definition,
                scope_required=True,
                scope_target_field="target",
                input_schema={
                    "type": "object",
                    "properties": {"target": {"type": "string"}},
                    "required": ["target"],
                    "additionalProperties": False,
                },
            )
        return original_register(self, definition, handler)

    with mock.patch.object(ToolGateway, "register", register):
        yield


def test_execute_tool_loads_scope_from_engagement_id(tmp_path):
    store = ControlStore(tmp_path / "control.db")
    store.initialize()
    EngagementStore(store).create(_scope())

    with _scope_requiring_catalog():
        result = _run_task(store, "tool.invoke", {
            "tool_id": "nexus.system.status",
            "arguments": {"target": "203.0.113.10"},
            "engagement_id": "eng-1",
            "identity": {"subject_id": "operator-1", "roles": ["operator"]},
        })

    assert result["output"]["output"]["status"] == "healthy"


def test_execute_tool_denies_when_engagement_not_found(tmp_path):
    store = ControlStore(tmp_path / "control.db")
    store.initialize()

    with pytest.raises(PermissionError):
        _run_task(store, "tool.invoke", {
            "tool_id": "nexus.system.status",
            "arguments": {},
            "engagement_id": "does-not-exist",
            "identity": {"subject_id": "operator-1", "roles": ["operator"]},
        })


def test_execute_tool_denies_when_target_out_of_scope(tmp_path):
    store = ControlStore(tmp_path / "control.db")
    store.initialize()
    EngagementStore(store).create(_scope())

    with _scope_requiring_catalog():
        with pytest.raises(ScopeViolation):
            _run_task(store, "tool.invoke", {
                "tool_id": "nexus.system.status",
                "arguments": {"target": "8.8.8.8"},
                "engagement_id": "eng-1",
                "identity": {"subject_id": "operator-1", "roles": ["operator"]},
            })


def test_execute_tool_allows_no_scope_when_tool_does_not_require_it(tmp_path):
    store = ControlStore(tmp_path / "control.db")
    store.initialize()

    result = _run_task(store, "tool.invoke", {
        "tool_id": "nexus.system.status",
        "arguments": {},
        "identity": {"subject_id": "operator-1", "roles": ["operator"]},
    })

    assert result["output"]["output"]["status"] == "healthy"


def test_execute_brain_propagates_engagement_id_to_steps(tmp_path, monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "fake")
    store = ControlStore(tmp_path / "control.db")
    store.initialize()
    captured: list[dict] = []

    async def fake_execute_tool(payload, context):
        captured.append(payload)
        return {
            "tool_id": payload["tool_id"],
            "output": {
                "success": True,
                "verified": True,
                "verification_method": "test",
                "evidence": {},
            },
        }

    with mock.patch("nexus_core.kernel.runtime.execute_tool", fake_execute_tool):
        result = _run_task(store, "brain.run", {
            "objective": "estado del sistema",
            "model_route": "fake",
            "engagement_id": "eng-1",
            "steps": [{"tool_id": "nexus.system.status", "arguments": {}}],
            "identity": {"subject_id": "operator-1", "roles": ["operator"]},
            "expected_response": "estado del sistema",
        })

    assert captured
    assert all(item.get("engagement_id") == "eng-1" for item in captured)
    assert result["evaluation"]["passed"] is True
