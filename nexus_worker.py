"""Durable NEXUS Sovereign worker."""

from __future__ import annotations

import argparse
import asyncio
import os
import socket
import time

from nexus_core.config import NEXUS_DB_PATH
from nexus_core.kernel.runtime import ExecutionContext, build_default_registry
from nexus_core.kernel.store_factory import get_control_store
from nexus_core.kernel.workflows import DurableWorkflowEngine


def main() -> None:
    parser = argparse.ArgumentParser(description="NEXUS durable worker")
    parser.add_argument("--once", action="store_true", help="Claim at most one task")
    parser.add_argument("--poll-seconds", type=float, default=2.0)
    args = parser.parse_args()
    worker_id = os.getenv("NEXUS_WORKER_ID", f"{socket.gethostname()}-{os.getpid()}")
    store = get_control_store(NEXUS_DB_PATH)
    store.initialize()
    registry = build_default_registry()

    while True:
        task = store.claim_task(worker_id)
        if task:
            try:
                context = ExecutionContext(store=store, task=task, worker_id=worker_id)
                result = asyncio.run(asyncio.wait_for(
                    registry.execute(task, context), timeout=task["timeout_seconds"]
                ))
                store.complete_task(task["id"], worker_id, result=result)
            except Exception as exc:
                store.append_run_event(task["tenant_id"], task["run_id"], "task.failed",
                                       {"task_id": task["id"],
                                        "error_type": type(exc).__name__,
                                        "error": str(exc)[:1000]})
                store.fail_or_retry_task(task["id"], worker_id, str(exc))
            run = store.get_run(task["run_id"], task["tenant_id"])
            if run and run.get("workflow_id"):
                DurableWorkflowEngine(store).reconcile(task["run_id"], task["tenant_id"])
        if args.once:
            return
        if not task:
            time.sleep(max(0.1, args.poll_seconds))


if __name__ == "__main__":
    main()
