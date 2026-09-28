"""Destructive only within a unique tenant created for this CI process."""

import asyncio
import os
from uuid import uuid4

from nexus_core.kernel.postgres_store import PostgresControlStore
from nexus_core.kernel.workflows import DurableWorkflowEngine
from nexus_core.kernel.runtime import ExecutionContext, build_default_registry


def main() -> None:
    store = PostgresControlStore(os.environ["DATABASE_URL"])
    store.initialize()
    tenant_id = f"ci_{uuid4().hex}"
    store.create_tenant("CI tenant", tenant_id)
    engine = DurableWorkflowEngine(store)
    workflow = engine.register(tenant_id, "smoke", "1.0.0", {
        "steps": [{"key": "offline", "task_type": "debug.fake_llm"}]
    })
    run = engine.start(tenant_id, workflow["id"], {"ci": True}, "postgres-smoke")
    task = store.claim_task("ci-worker")
    assert task and task["tenant_id"] == tenant_id
    store.complete_task(task["id"], "ci-worker", result={"ok": True})
    engine.reconcile(run["id"], tenant_id)
    assert store.get_run(run["id"], tenant_id)["status"] == "completed"
    conversation = store.create_conversation(tenant_id, "ci-user", "Postgres chat")
    chat_run = store.create_run(tenant_id, {"kind": "conversation"}, "postgres-chat")
    store.append_message(tenant_id, conversation["id"], "user", "postgres",
                         run_id=chat_run["id"])
    store.enqueue_task(tenant_id=tenant_id, run_id=chat_run["id"],
                       task_type="conversation.respond",
                       payload={"conversation_id": conversation["id"],
                                "model_route": "fake"})
    chat_task = store.claim_task("ci-worker")
    result = asyncio.run(build_default_registry().execute(
        chat_task, ExecutionContext(store, chat_task, "ci-worker")
    ))
    store.complete_task(chat_task["id"], "ci-worker", result=result)
    assert len(store.list_messages(tenant_id, conversation["id"])) == 2
    with store.connect() as conn:
        conn.execute("DELETE FROM kernel_audit_events WHERE tenant_id=?", (tenant_id,))
        conn.execute("DELETE FROM kernel_usage_ledger WHERE tenant_id=?", (tenant_id,))
        conn.execute("DELETE FROM kernel_run_events WHERE tenant_id=?", (tenant_id,))
        conn.execute("DELETE FROM kernel_messages WHERE tenant_id=?", (tenant_id,))
        conn.execute("DELETE FROM kernel_conversations WHERE tenant_id=?", (tenant_id,))
        conn.execute("DELETE FROM kernel_outbox WHERE tenant_id=?", (tenant_id,))
        conn.execute("DELETE FROM kernel_task_transitions WHERE task_id IN (?,?)",
                     (task["id"], chat_task["id"]))
        conn.execute("DELETE FROM kernel_tasks WHERE tenant_id=?", (tenant_id,))
        conn.execute("DELETE FROM kernel_workflow_steps WHERE run_id=?", (run["id"],))
        conn.execute("DELETE FROM kernel_runs WHERE tenant_id=?", (tenant_id,))
        conn.execute("DELETE FROM kernel_workflows WHERE tenant_id=?", (tenant_id,))
        conn.execute("DELETE FROM kernel_tenants WHERE id=?", (tenant_id,))


if __name__ == "__main__":
    main()
