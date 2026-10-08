"""P2-C4 closure: the supervisor root is durable and shared by the whole tree.

Every descendant references one durable root, the root survives a child's
termination (and a fresh process), and the depth limit is enforced against that
shared tree rather than an in-memory counter.
"""
from __future__ import annotations

import asyncio

import pytest

from nexus_core.agent.supervisor import AgentSupervisor, SupervisorTree
from nexus_core.kernel.runtime import ExecutionContext
from nexus_core.tests.unit.test_agent_supervisor import setup
from nexus_core.tests.unit.test_hooks_lifecycle import context


def test_all_children_share_same_root(tmp_path, monkeypatch):
    supervisor, _, _ = setup(tmp_path, monkeypatch, global_budget=1_000_000)
    root = AgentSupervisor.root(
        supervisor.context, supervisor.client, engagement_id=None, global_budget=1_000_000)
    first = asyncio.run(supervisor.spawn("recon", "a", {"tokens": 20, "iterations": 1}))
    second = asyncio.run(supervisor.spawn("recon", "b", {"tokens": 20, "iterations": 1}))
    assert first.root_id == second.root_id == root.root_id == supervisor.root_id


def test_root_persists_across_child_termination(tmp_path, monkeypatch):
    supervisor, _, _ = setup(tmp_path, monkeypatch, global_budget=1_000_000)
    child = asyncio.run(supervisor.spawn("recon", "x", {"tokens": 20, "iterations": 1}))
    tree = SupervisorTree(supervisor.context.store)
    assert tree.get("system", child.run_id)["root_id"] == supervisor.root_id
    assert tree.root_of("system", child.run_id) == supervisor.root_id
    # A brand-new supervisor (a fresh process) resolves the same durable root.
    again = AgentSupervisor.root(
        supervisor.context, supervisor.client, engagement_id=None, global_budget=1_000_000)
    assert again.root_id == supervisor.root_id


def test_root_creation_is_idempotent(tmp_path, monkeypatch):
    supervisor, _, _ = setup(tmp_path, monkeypatch, global_budget=1_000_000)
    first = AgentSupervisor.root(
        supervisor.context, supervisor.client, engagement_id=None, global_budget=1_000_000)
    second = AgentSupervisor.root(
        supervisor.context, supervisor.client, engagement_id=None, global_budget=1_000_000)
    assert first.root_id == second.root_id


def test_depth_limit_shared_across_tree(tmp_path, monkeypatch):
    ctx = context(tmp_path, monkeypatch)
    tree = SupervisorTree(ctx.store)
    tree.register("system", "root-run")
    tree.register("system", "child-run", parent_run_id="root-run")
    tree.register("system", "grandchild-run", parent_run_id="child-run")
    assert tree.depth_of("system", "grandchild-run") == 2
    assert tree.root_of("system", "grandchild-run") == "root-run"
    task = {"id": "t", "tenant_id": "system", "run_id": "grandchild-run",
            "task_type": "react.run", "payload": {}}
    exec_ctx = ExecutionContext(ctx.store, task, "w")
    supervisor = AgentSupervisor(exec_ctx, object(), engagement_id=None,
                                 global_budget=1_000_000)
    assert supervisor.root_id == "root-run"
    with pytest.raises(ValueError, match="depth"):
        asyncio.run(supervisor.spawn("recon", "deeper", {"tokens": 20, "iterations": 1}))
