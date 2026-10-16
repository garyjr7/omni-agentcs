import asyncio

from nexus_core.kernel.control_store import ControlStore
from nexus_core.kernel.runtime import ExecutionContext, build_default_registry


def test_conversation_is_tenant_scoped_and_runtime_appends_response(tmp_path, monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "fake")
    store = ControlStore(tmp_path / "sovereign.db")
    store.initialize()
    conversation = store.create_conversation("system", "user-1", "Prueba")
    run = store.create_run("system", {"kind": "conversation"})
    store.append_message("system", conversation["id"], "user", "hola", run_id=run["id"])
    task = store.enqueue_task(
        tenant_id="system", run_id=run["id"], task_type="conversation.respond",
        payload={"conversation_id": conversation["id"], "model_route": "fake"},
    )
    claimed = store.claim_task("worker-test")
    assert claimed and claimed["id"] == task["id"]
    result = asyncio.run(build_default_registry().execute(
        claimed, ExecutionContext(store, claimed, "worker-test")
    ))
    store.complete_task(claimed["id"], "worker-test", result=result, lease_generation=claimed["lease_generation"])

    messages = store.list_messages("system", conversation["id"])
    assert [message["role"] for message in messages] == ["user", "assistant"]
    assert messages[-1]["content"] == "hola"
    assert store.get_conversation("other", conversation["id"]) is None
    assert [event["event_type"] for event in store.list_run_events("system", run["id"])] == [
        "task.started", "model.started", "message.created", "task.completed"
    ]


def test_runtime_rejects_unknown_executor(tmp_path):
    store = ControlStore(tmp_path / "sovereign.db")
    store.initialize()
    run = store.create_run("system", {})
    store.enqueue_task(tenant_id="system", run_id=run["id"],
                              task_type="unknown.execute", payload={})
    claimed = store.claim_task("worker-test")
    try:
        asyncio.run(build_default_registry().execute(
            claimed, ExecutionContext(store, claimed, "worker-test")
        ))
    except ValueError as exc:
        assert "unsupported durable task type" in str(exc)
    else:
        raise AssertionError("unknown task executor was accepted")


def test_first_party_tool_runs_through_gateway_and_is_audited(tmp_path):
    store = ControlStore(tmp_path / "sovereign.db")
    store.initialize()
    run = store.create_run("system", {})
    store.enqueue_task(tenant_id="system", run_id=run["id"], task_type="tool.invoke",
                       payload={"tool_id": "nexus.system.status", "arguments": {},
                                "identity": {"subject_id": "operator-1",
                                             "roles": ["operator"]}})
    claimed = store.claim_task("worker-test")
    result = asyncio.run(build_default_registry().execute(
        claimed, ExecutionContext(store, claimed, "worker-test")
    ))
    assert result["output"]["output"]["status"] == "healthy"
    with store.connect() as conn:
        audit = conn.execute(
            "SELECT action,decision FROM kernel_audit_events WHERE tenant_id='system'"
        ).fetchall()
    assert [(row["action"], row["decision"]) for row in audit] == [
        ("tool.invoke", "allow"), ("tool.complete", "allow")
    ]


def test_brain_advances_only_after_a_verified_tool_observation(tmp_path, monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "fake")
    store = ControlStore(tmp_path / "sovereign.db")
    store.initialize()
    run = store.create_run("system", {"kind": "agent"})
    store.enqueue_task(
        tenant_id="system", run_id=run["id"], task_type="brain.run",
        payload={
            "objective": "estado del sistema",
            "model_route": "fake",
            "steps": [{"tool_id": "nexus.system.status", "arguments": {}}],
            "identity": {"subject_id": "operator-1", "roles": ["operator"]},
            "expected_response": "estado del sistema",
        },
    )
    claimed = store.claim_task("worker-test")
    result = asyncio.run(build_default_registry().execute(
        claimed, ExecutionContext(store, claimed, "worker-test")
    ))

    assert result["evaluation"]["passed"] is True
    assert result["observations"][0]["output"]["verified"] is True
    events = store.list_run_events("system", run["id"])
    assert "brain.step.verified" in [event["event_type"] for event in events]
