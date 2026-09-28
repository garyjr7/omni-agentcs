"""Durable, resumable DAG workflows backed by the NEXUS control store."""

from __future__ import annotations

import json
from typing import Any, Dict, List
from uuid import uuid4

from .control_store import ControlStore
from .models import utc_now

TERMINAL_TASKS = {"completed", "failed", "cancelled", "dead_letter"}


class WorkflowValidationError(ValueError):
    pass


class DurableWorkflowEngine:
    def __init__(self, store: ControlStore):
        self.store = store

    @staticmethod
    def validate(definition: Dict[str, Any]) -> None:
        steps = definition.get("steps")
        if not isinstance(steps, list) or not steps:
            raise WorkflowValidationError("workflow requires a non-empty steps list")
        keys = [step.get("key") for step in steps]
        if any(not key for key in keys) or len(keys) != len(set(keys)):
            raise WorkflowValidationError("step keys must be present and unique")
        known = set(keys)
        for step in steps:
            if not step.get("task_type"):
                raise WorkflowValidationError(f"step {step['key']} requires task_type")
            if not set(step.get("depends_on", [])).issubset(known):
                raise WorkflowValidationError(f"step {step['key']} has unknown dependency")
        graph = {step["key"]: set(step.get("depends_on", [])) for step in steps}
        remaining = set(graph)
        while remaining:
            ready = {key for key in remaining if not (graph[key] & remaining)}
            if not ready:
                raise WorkflowValidationError("workflow contains a cycle")
            remaining -= ready

    def register(self, tenant_id: str, name: str, version: str,
                 definition: Dict[str, Any]) -> Dict[str, Any]:
        self.validate(definition)
        workflow_id = f"workflow_{uuid4().hex}"
        now = utc_now()
        with self.store.connect() as conn:
            conn.execute(
                """INSERT INTO kernel_workflows
                (id,tenant_id,name,version,definition,status,created_at)
                VALUES(?,?,?,?,?,'active',?)""",
                (workflow_id, tenant_id, name, version, json.dumps(definition), now),
            )
        return {"id": workflow_id, "tenant_id": tenant_id, "name": name, "version": version}

    def start(self, tenant_id: str, workflow_id: str, context: Dict[str, Any],
              idempotency_key: str) -> Dict[str, Any]:
        run = self.store.create_run(tenant_id, context, idempotency_key, workflow_id)
        now = utc_now()
        with self.store.connect() as conn:
            workflow = conn.execute(
                "SELECT definition FROM kernel_workflows WHERE id=? AND tenant_id=? AND status='active'",
                (workflow_id, tenant_id),
            ).fetchone()
            if not workflow:
                raise KeyError("workflow not found")
            definition = json.loads(workflow["definition"])
            for step in definition["steps"]:
                conn.execute(
                    """INSERT OR IGNORE INTO kernel_workflow_steps
                    (id,run_id,step_key,status,depends_on,compensation_type,created_at,updated_at)
                    VALUES(?,?,?,?,?,?,?,?)""",
                    (f"step_{uuid4().hex}", run["id"], step["key"], "pending",
                     json.dumps(step.get("depends_on", [])), step.get("compensation_type"), now, now),
                )
        self.reconcile(run["id"], tenant_id)
        return self.store.get_run(run["id"], tenant_id) or run

    def reconcile(self, run_id: str, tenant_id: str) -> Dict[str, Any]:
        """Persist task results and enqueue all newly-unblocked steps exactly once."""
        now = utc_now()
        with self.store.connect() as conn:
            run = conn.execute(
                "SELECT * FROM kernel_runs WHERE id=? AND tenant_id=?", (run_id, tenant_id)
            ).fetchone()
            if not run:
                raise KeyError("run not found")
            workflow = conn.execute(
                "SELECT definition FROM kernel_workflows WHERE id=? AND tenant_id=?",
                (run["workflow_id"], tenant_id),
            ).fetchone()
            definition = json.loads(workflow["definition"])
            by_key = {step["key"]: step for step in definition["steps"]}
            rows = conn.execute(
                """SELECT s.*,t.status AS task_status,t.result AS task_result,t.error AS task_error,
                c.status AS compensation_status
                FROM kernel_workflow_steps s LEFT JOIN kernel_tasks t ON t.id=s.task_id
                LEFT JOIN kernel_tasks c ON c.id=s.compensation_task_id
                WHERE s.run_id=?""", (run_id,)
            ).fetchall()
            states = {row["step_key"]: dict(row) for row in rows}

            for key, state in states.items():
                task_status = state.get("task_status")
                if (task_status in TERMINAL_TASKS
                        and state["status"] not in {
                            task_status, "compensating", "compensated", "compensation_failed"
                        }):
                    conn.execute(
                        "UPDATE kernel_workflow_steps SET status=?,result=?,updated_at=? WHERE id=?",
                        (task_status, state.get("task_result"), now, state["id"]),
                    )
                    state["status"] = task_status

            failed = any(
                state["status"] in {"failed", "dead_letter", "cancelled"}
                for state in states.values()
            )
            if failed:
                for key, state in states.items():
                    if state.get("compensation_status") in TERMINAL_TASKS:
                        final = (
                            "compensated" if state["compensation_status"] == "completed"
                            else "compensation_failed"
                        )
                        conn.execute(
                            "UPDATE kernel_workflow_steps SET status=?,updated_at=? WHERE id=?",
                            (final, now, state["id"]),
                        )
                    elif (state["status"] == "completed" and state["compensation_type"]
                          and not state["compensation_task_id"]):
                        task_id = f"task_{uuid4().hex}"
                        payload = {
                            "compensates_step": key,
                            "original_result": json.loads(state["task_result"] or "null"),
                            "workflow_context": json.loads(run["context"]),
                        }
                        conn.execute(
                            """INSERT INTO kernel_tasks
                            (id,tenant_id,run_id,task_type,status,priority,payload,max_attempts,
                             timeout_seconds,available_at,created_at,updated_at)
                            VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                            (task_id, tenant_id, run_id, state["compensation_type"], "queued",
                             1, json.dumps(payload), 3, 300, now, now, now),
                        )
                        conn.execute(
                            """UPDATE kernel_workflow_steps SET compensation_task_id=?,
                            status='compensating',updated_at=? WHERE id=?""",
                            (task_id, now, state["id"]),
                        )
                        self.store._transition(
                            conn, task_id, None, "queued", "workflow compensation", "workflow-engine"
                        )
                        self.store._outbox(
                            conn, tenant_id, "task", task_id, "task.compensation.queued",
                            {"run_id": run_id, "step": key},
                        )
                conn.execute(
                    "UPDATE kernel_runs SET status='failed',error='workflow step failed',updated_at=? WHERE id=?",
                    (now, run_id),
                )
            else:
                for key, state in states.items():
                    dependencies = json.loads(state["depends_on"])
                    if state["status"] == "pending" and all(states[item]["status"] == "completed" for item in dependencies):
                        step = by_key[key]
                        task_id = f"task_{uuid4().hex}"
                        payload = dict(step.get("payload", {}))
                        payload["workflow_context"] = json.loads(run["context"])
                        conn.execute(
                            """INSERT INTO kernel_tasks
                            (id,tenant_id,run_id,task_type,status,priority,payload,max_attempts,
                             timeout_seconds,available_at,created_at,updated_at)
                            VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                            (task_id, tenant_id, run_id, step["task_type"], "queued",
                             step.get("priority", 5), json.dumps(payload), step.get("max_attempts", 3),
                             step.get("timeout_seconds", 300), now, now, now),
                        )
                        conn.execute(
                            "UPDATE kernel_workflow_steps SET task_id=?,status='queued',updated_at=? WHERE id=? AND task_id IS NULL",
                            (task_id, now, state["id"]),
                        )
                        self.store._transition(conn, task_id, None, "queued", "workflow step ready", "workflow-engine")
                        self.store._outbox(conn, tenant_id, "task", task_id, "task.queued", {"run_id": run_id, "step": key})
                refreshed = conn.execute(
                    "SELECT status FROM kernel_workflow_steps WHERE run_id=?", (run_id,)
                ).fetchall()
                statuses = [row["status"] for row in refreshed]
                run_status = "completed" if statuses and all(item == "completed" for item in statuses) else "running"
                conn.execute(
                    "UPDATE kernel_runs SET status=?,updated_at=? WHERE id=?", (run_status, now, run_id)
                )
        return self.store.get_run(run_id, tenant_id) or {}

    def history(self, run_id: str, tenant_id: str) -> List[Dict[str, Any]]:
        with self.store.connect() as conn:
            valid = conn.execute(
                "SELECT id FROM kernel_runs WHERE id=? AND tenant_id=?", (run_id, tenant_id)
            ).fetchone()
            if not valid:
                return []
            return [dict(row) for row in conn.execute(
                "SELECT * FROM kernel_workflow_steps WHERE run_id=? ORDER BY created_at", (run_id,)
            ).fetchall()]
