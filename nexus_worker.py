"""Durable OmniAgentCS worker sharing the CLI's global configuration."""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import socket
import time
from pathlib import Path
from typing import Any

from nexus_core.kernel.control_store import ControlStore
from nexus_core.kernel.errors import LeaseLost
from nexus_core.kernel.runtime import ExecutionContext, ExecutorRegistry, build_default_registry
from nexus_core.kernel.store_factory import get_control_store
from nexus_core.kernel.workflows import DurableWorkflowEngine

#: How often a running task renews its lease (seconds).
LEASE_RENEW_INTERVAL_SECONDS = 30.0
#: The renewed lease window; comfortably larger than the interval.
LEASE_SECONDS = 120
logger = logging.getLogger(__name__)


async def _execute_with_heartbeat(
    store: ControlStore,
    task: dict[str, Any],
    worker_id: str,
    registry: ExecutorRegistry,
    context: ExecutionContext,
    timeout_seconds: float,
    *,
    renew_interval: float = LEASE_RENEW_INTERVAL_SECONDS,
    lease_seconds: int = LEASE_SECONDS,
) -> dict[str, Any]:
    """Run an executor while renewing the task lease in the background.

    If a renewal fails the worker no longer owns the task: the executor is
    signalled through ``context.cancel_event`` so a long tool call can be
    interrupted instead of being re-executed concurrently by another worker.
    """
    stop = asyncio.Event()
    lease_error: Exception | None = None
    execution = asyncio.create_task(registry.execute(task, context))

    async def renew_loop() -> None:
        nonlocal lease_error
        while not stop.is_set():
            try:
                await asyncio.wait_for(stop.wait(), timeout=max(0.01, renew_interval))
                return
            except asyncio.TimeoutError:
                pass
            try:
                renewed = await asyncio.to_thread(
                    store.renew_task_lease, task["id"], worker_id,
                    lease_generation=task["lease_generation"], lease_seconds=lease_seconds,
                )
                if not renewed:
                    raise LeaseLost("heartbeat no longer owns an active task lease")
            except Exception as exc:
                # A database failure is also loss of authority: never continue
                # external work while unable to prove ownership.
                lease_error = exc
                cancel_event = getattr(context, "cancel_event", None)
                if cancel_event is not None:
                    cancel_event.set()
                execution.cancel()
                return

    renew_task = asyncio.create_task(renew_loop())
    try:
        return await asyncio.wait_for(execution, timeout=timeout_seconds)
    finally:
        stop.set()
        await asyncio.gather(renew_task, return_exceptions=True)
        if lease_error is not None:
            raise LeaseLost("execution cancelled after heartbeat failure") from lease_error


def _process_task(
    store: ControlStore, task: dict[str, Any], worker_id: str, registry: ExecutorRegistry,
) -> bool:
    """Run one claim; a stale worker exits this iteration without mutating state."""
    generation = int(task["lease_generation"])
    try:
        context = ExecutionContext(
            store=store, task=task, worker_id=worker_id, cancel_event=asyncio.Event(),
        )
        result = asyncio.run(_execute_with_heartbeat(
            store, task, worker_id, registry, context, task["timeout_seconds"],
        ))
        store.complete_task(
            task["id"], worker_id, lease_generation=generation, result=result,
        )
    except LeaseLost:
        logger.warning("Task %s generation %s lost its lease", task["id"], generation)
        return False
    except Exception as exc:
        try:
            store.fail_or_retry_task(
                task["id"], worker_id, str(exc), lease_generation=generation,
            )
        except LeaseLost:
            logger.warning("Task %s lost its lease before recording failure", task["id"])
            return False
        store.append_run_event(
            task["tenant_id"], task["run_id"], "task.failed",
            {"task_id": task["id"], "error_type": type(exc).__name__, "error": str(exc)[:1000]},
        )
    return True


def main() -> None:
    parser = argparse.ArgumentParser(description="OmniAgentCS durable worker")
    parser.add_argument("--once", action="store_true", help="Claim at most one task")
    parser.add_argument("--poll-seconds", type=float, default=2.0)
    args = parser.parse_args()
    from nexus_core.cli.llm_env import configure_logging, publish_default_provider
    from nexus_core.config.bootstrap import bootstrap_secrets_and_config

    paths, config = bootstrap_secrets_and_config(Path(__file__).resolve().parent)
    configure_logging()
    # Same resolution as the CLI: the worker runs the same agentic executors.
    publish_default_provider(config)
    worker_id = os.getenv("NEXUS_WORKER_ID", f"{socket.gethostname()}-{os.getpid()}")
    store = get_control_store()
    store.initialize()
    registry = build_default_registry()

    while True:
        task = store.claim_task(worker_id, lease_seconds=LEASE_SECONDS)
        if task:
            if _process_task(store, task, worker_id, registry):
                run = store.get_run(task["run_id"], task["tenant_id"])
                if run and run.get("workflow_id"):
                    DurableWorkflowEngine(store).reconcile(task["run_id"], task["tenant_id"])
        if args.once:
            return
        if not task:
            time.sleep(max(0.1, args.poll_seconds))


if __name__ == "__main__":
    main()
