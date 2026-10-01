"""Durable OmniAgentCS worker sharing the CLI's global configuration."""

from __future__ import annotations

import argparse
import asyncio
import os
import socket
import time
from pathlib import Path

from nexus_core.kernel.runtime import ExecutionContext, build_default_registry
from nexus_core.kernel.store_factory import get_control_store
from nexus_core.kernel.workflows import DurableWorkflowEngine

#: How often a running task renews its lease (seconds).
LEASE_RENEW_INTERVAL_SECONDS = 30.0
#: The renewed lease window; comfortably larger than the interval.
LEASE_SECONDS = 120


async def _execute_with_heartbeat(
    store,
    task,
    worker_id: str,
    registry,
    context: ExecutionContext,
    timeout_seconds: float,
    *,
    renew_interval: float = LEASE_RENEW_INTERVAL_SECONDS,
    lease_seconds: int = LEASE_SECONDS,
) -> dict:
    """Run an executor while renewing the task lease in the background.

    If a renewal fails the worker no longer owns the task: the executor is
    signalled through ``context.cancel_event`` so a long tool call can be
    interrupted instead of being re-executed concurrently by another worker.
    """
    stop = asyncio.Event()

    async def renew_loop() -> None:
        while not stop.is_set():
            try:
                await asyncio.wait_for(stop.wait(), timeout=max(0.01, renew_interval))
                return
            except asyncio.TimeoutError:
                pass
            renewed = await asyncio.to_thread(
                store.renew_task_lease, task["id"], worker_id, lease_seconds=lease_seconds
            )
            if not renewed:
                cancel_event = getattr(context, "cancel_event", None)
                if cancel_event is not None:
                    cancel_event.set()
                return

    renew_task = asyncio.create_task(renew_loop())
    try:
        return await asyncio.wait_for(
            registry.execute(task, context), timeout=timeout_seconds
        )
    finally:
        stop.set()
        await asyncio.gather(renew_task, return_exceptions=True)


def main() -> None:
    parser = argparse.ArgumentParser(description="OmniAgentCS durable worker")
    parser.add_argument("--once", action="store_true", help="Claim at most one task")
    parser.add_argument("--poll-seconds", type=float, default=2.0)
    args = parser.parse_args()
    from dotenv import load_dotenv
    from nexus_core.cli.llm_env import configure_logging, publish_default_provider
    from nexus_core.config.loader import apply_environment, load_config
    from nexus_core.config.xdg import resolve_xdg_paths

    load_dotenv(Path(__file__).resolve().parent / ".env", override=False)
    paths = resolve_xdg_paths()
    config = load_config(paths)
    apply_environment(config, paths)
    configure_logging()
    # Same resolution as the CLI: the worker runs the same agentic executors.
    publish_default_provider(config)
    worker_id = os.getenv("NEXUS_WORKER_ID", f"{socket.gethostname()}-{os.getpid()}")
    store = get_control_store()
    store.initialize()
    registry = build_default_registry()

    while True:
        task = store.claim_task(worker_id)
        if task:
            try:
                context = ExecutionContext(
                    store=store,
                    task=task,
                    worker_id=worker_id,
                    cancel_event=asyncio.Event(),
                )
                result = asyncio.run(_execute_with_heartbeat(
                    store, task, worker_id, registry, context, task["timeout_seconds"]
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
