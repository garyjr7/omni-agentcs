"""Background tool tasks: long scans without freezing the ReAct turn.

The loop is one model call per iteration. A full ``nmap -p-`` (or a brute force)
therefore costs the run nothing but *wall clock in which the model is blind*:
the turn waits, the operator waits, and the next decision cannot start until the
last byte arrives. This module is the small scheduler that changes that:

* the coordinator hands a governed call to :class:`TaskManager` and answers the
  model immediately (``background_task_started``);
* the task runs in its own ``asyncio.Task`` with its own cancel event, so the
  main loop can keep working on low-risk, independent steps;
* when it finishes, the result is written to the blackboard (callback) and the
  loop is woken through an ``asyncio.Event`` plus a drained queue, so the
  outcome is delivered on the next iteration instead of being polled.

This is *not* a second governance path. The runner the coordinator injects is
the same ``ToolExecutionService``/gateway invocation a foreground call uses; the
manager only decides *when* the await happens. Fail-closed by construction: a
manager without a runner refuses to spawn, a spawn beyond the caps is refused,
and a finished task is delivered exactly once.
"""

from __future__ import annotations

import asyncio
import inspect
import os
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from typing import Any

from nexus_core.kernel.models import utc_now

#: Concurrent background tasks allowed per run (a Kali box is also scanning).
DEFAULT_MAX_CONCURRENT = 3
#: Total tasks one run may spawn. An unbounded spawner is a way to bypass the
#: iteration budget: every task is a tool call the model never waited for.
DEFAULT_MAX_TOTAL = 12
#: Finished records kept for ``get_status`` after delivery.
DEFAULT_RETENTION = 32
#: Overrides the concurrency ceiling.
MAX_CONCURRENT_ENV = "NEXUS_BACKGROUND_TASKS"
#: Ceiling on the label the model gives a task (it is prompt-visible later).
MAX_LABEL_CHARS = 80

RUNNING = "running"
SUCCEEDED = "succeeded"
FAILED = "failed"
CANCELLED = "cancelled"
TIMEOUT = "timeout"

TERMINAL = frozenset({SUCCEEDED, FAILED, CANCELLED, TIMEOUT})

#: A runner executes one prepared call. The payload is the engine payload the
#: coordinator builds for the gateway (never raw model text), and the cancel
#: event belongs to *this* task so cancelling it cannot stop the run.
Runner = Callable[[dict[str, Any], asyncio.Event], Awaitable[dict[str, Any]]]
#: Optional completion hook (blackboard write), awaited before the wake-up.
CompletionHook = Callable[["TaskRecord"], Awaitable[None] | None]


class TaskManagerError(RuntimeError):
    """A task could not be spawned (capacity, duplicate or missing runner)."""


def max_concurrent_from_env(env: Mapping[str, str] | None = None) -> int:
    """Concurrency ceiling from ``NEXUS_BACKGROUND_TASKS`` (>= 1)."""
    environment = os.environ if env is None else env
    raw = str(environment.get(MAX_CONCURRENT_ENV, "") or "").strip()
    if not raw:
        return DEFAULT_MAX_CONCURRENT
    try:
        value = int(raw)
    except ValueError:
        return DEFAULT_MAX_CONCURRENT
    return max(1, min(value, 8))


def _clean_label(value: object, *, fallback: str) -> str:
    """One line, bounded: the label is quoted back to the model."""
    text = " ".join(str(value or "").split())
    return (text or fallback)[:MAX_LABEL_CHARS]


@dataclass
class TaskRecord:
    """Durable-in-memory state of one background call."""

    task_id: str
    label: str
    tool_id: str
    arguments: dict[str, Any] = field(default_factory=dict)
    status: str = RUNNING
    started_at: str = field(default_factory=utc_now)
    finished_at: str = ""
    result: dict[str, Any] | None = None
    error: str = ""
    delivered: bool = False
    cancel_event: asyncio.Event | None = field(default=None, repr=False)
    handle: asyncio.Task | None = field(default=None, repr=False)

    @property
    def terminal(self) -> bool:
        """Whether the task reached a final state."""
        return self.status in TERMINAL

    def to_dict(self) -> dict[str, Any]:
        """Status shape returned to the model and to ``get_status``."""
        summary: dict[str, Any] = {
            "task_id": self.task_id,
            "label": self.label,
            "tool_id": self.tool_id,
            "status": self.status,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "delivered": self.delivered,
        }
        if self.error:
            summary["error"] = self.error[:800]
        if self.result is not None:
            summary["success"] = bool(self.result.get("success"))
            summary["outcome"] = str(self.result.get("outcome") or "")
        return summary

    def observation(self) -> dict[str, Any]:
        """The prompt-facing result of a finished task.

        Mirrors the shape a foreground observation has (``success``, ``outcome``,
        ``verification_method``, ``evidence``, ``assertions``, ``output``) so the
        model reads both through the same contract; the coordinator's
        ``prepare_observation`` still bounds and archives it.
        """
        result = self.result or {}
        observation: dict[str, Any] = {
            "success": bool(result.get("success")) if self.status == SUCCEEDED else False,
            "background": True,
            "task_id": self.task_id,
            "label": self.label,
            "tool_id": self.tool_id,
            "status": self.status,
            "outcome": str(result.get("outcome") or self.status),
            "verification_method": result.get("verification_method"),
            "invocation_id": result.get("invocation_id"),
            "evidence": result.get("evidence"),
            "assertions": list(result.get("assertions") or []),
            "output": result.get("output"),
        }
        if self.error:
            observation["error"] = self.error[:800]
        if self.status in {CANCELLED, TIMEOUT}:
            observation["guidance"] = (
                "La tarea en background no terminó: no esperes su resultado. "
                "Revisa el estado o replanifica esa rama."
            )
        return observation


class TaskManager:
    """Bounded registry of asyncio tasks with a wake-up signal."""

    def __init__(
        self,
        runner: Runner | None = None,
        *,
        on_complete: CompletionHook | None = None,
        max_concurrent: int | None = None,
        max_total: int = DEFAULT_MAX_TOTAL,
        retention: int = DEFAULT_RETENTION,
    ):
        self.runner = runner
        self.on_complete = on_complete
        self.max_concurrent = (
            max_concurrent_from_env() if max_concurrent is None else max(1, int(max_concurrent))
        )
        self.max_total = max(1, int(max_total))
        self.retention = max(1, int(retention))
        self._records: dict[str, TaskRecord] = {}
        self._order: list[str] = []
        self._pending: list[TaskRecord] = []
        self._wakeup = asyncio.Event()
        self._spawned = 0
        self._counter = 0

    # ------------------------------------------------------------------ spawn
    async def spawn_task(
        self,
        *,
        tool_id: str,
        arguments: Mapping[str, Any] | None = None,
        payload: Mapping[str, Any] | None = None,
        label: str | None = None,
        timeout_seconds: float | None = None,
    ) -> TaskRecord:
        """Start one background call and return its record.

        ``payload`` is what the runner receives (the coordinator's engine
        payload). It is kept out of :meth:`to_dict` on purpose: it can carry
        credential references.
        """
        if self.runner is None:
            raise TaskManagerError("no runner configured for background tasks")
        tool = str(tool_id or "").strip()
        if not tool:
            raise TaskManagerError("tool_id is required")
        if self._spawned >= self.max_total:
            raise TaskManagerError(
                f"background task limit reached ({self.max_total} per run)"
            )
        if self.running_count() >= self.max_concurrent:
            raise TaskManagerError(
                f"background concurrency is saturated ({self.max_concurrent} running); "
                "wait for a task to finish or cancel one"
            )
        self._counter += 1
        task_id = f"bg-{self._counter}"
        record = TaskRecord(
            task_id=task_id,
            label=_clean_label(label, fallback=f"{tool} #{self._counter}"),
            tool_id=tool,
            arguments=dict(arguments or {}),
            cancel_event=asyncio.Event(),
        )
        self._records[task_id] = record
        self._order.append(task_id)
        self._spawned += 1
        engine_payload = dict(payload or {"tool_id": tool, "arguments": record.arguments})
        record.handle = asyncio.create_task(
            self._run(record, engine_payload, float(timeout_seconds) if timeout_seconds else None),
            name=f"nexus-bg-{task_id}",
        )
        return record

    async def _run(
        self, record: TaskRecord, payload: dict[str, Any], timeout: float | None
    ) -> None:
        """Execute one task; every failure is local to it."""
        assert self.runner is not None
        try:
            assert record.cancel_event is not None
            running = self.runner(payload, record.cancel_event)
            record.result = await asyncio.wait_for(running, timeout) if timeout else await running
            if not record.terminal:
                record.status = SUCCEEDED if (record.result or {}).get("success", True) else FAILED
        except asyncio.CancelledError:
            # ``cancel_task`` already settled the record when the task had not
            # started yet; never overwrite a terminal state here.
            if not record.terminal:
                record.status = CANCELLED
                record.error = "cancelada por el operador"
            raise
        except (asyncio.TimeoutError, TimeoutError):
            if not record.terminal:
                record.status = TIMEOUT
                record.error = f"la tarea excedió {timeout:g}s" if timeout else "timeout"
        except Exception as error:  # noqa: BLE001 - one task never kills the manager
            if not record.terminal:
                record.status = FAILED
                record.error = f"{type(error).__name__}: {error}"[:800]
        finally:
            if not record.finished_at:
                record.finished_at = utc_now()
            if not record.terminal:  # pragma: no cover - defensive
                record.status = FAILED
            # A cancellation settled by ``cancel_task`` was queued there; queuing
            # it twice would deliver the same outcome to the model twice.
            if not record.delivered and record not in self._pending:
                await self._notify(record)

    async def _notify(self, record: TaskRecord) -> None:
        """Run the completion hook, queue the delivery and wake the loop."""
        if self.on_complete is not None:
            try:
                outcome = self.on_complete(record)
                if inspect.isawaitable(outcome):
                    await outcome
            except Exception as error:  # noqa: BLE001 - a bad hook must not lose the result
                record.error = (record.error or "")[:600]
                record.error = (record.error + f" (hook: {type(error).__name__})").strip()
        record.delivered = False
        self._pending.append(record)
        self._wakeup.set()
        self._trim()

    # ----------------------------------------------------------------- status
    def running_count(self) -> int:
        """Tasks currently running."""
        return sum(1 for record in self._records.values() if record.status == RUNNING)

    def count(self) -> int:
        """Tasks spawned so far in this run."""
        return self._spawned

    def get_status(self, task_id: str) -> dict[str, Any] | None:
        """Status of one task, or ``None`` when unknown."""
        record = self._records.get(str(task_id or ""))
        return record.to_dict() if record is not None else None

    def list_tasks(self) -> list[dict[str, Any]]:
        """Status of every retained task, oldest first."""
        return [self._records[key].to_dict() for key in self._order if key in self._records]

    def cancel_task(self, task_id: str) -> bool:
        """Cancel one running task; ``False`` when it was unknown or finished.

        Idempotent: a second cancel of the same task reports ``False`` even if the
        task has not unwound yet, so a model asking twice cannot mistake it for a
        new cancellation.
        """
        record = self._records.get(str(task_id or ""))
        if record is None or record.handle is None or record.handle.done():
            return False
        if record.cancel_event is not None:
            if record.cancel_event.is_set():
                return False
            record.cancel_event.set()
        # Settle the record here, not only in ``_run``: a task cancelled before
        # its first scheduling step never executes a line of the coroutine, so
        # without this it would stay ``running`` forever.
        record.status = CANCELLED
        record.error = record.error or "cancelada por el operador"
        record.finished_at = utc_now()
        self._pending.append(record)
        self._wakeup.set()
        self._trim()
        record.handle.cancel()
        return True

    async def cancel_all(self) -> None:
        """Cancel every running task and wait for them to settle."""
        handles = []
        for record in self._records.values():
            if record.handle is not None and not record.handle.done():
                self.cancel_task(record.task_id)
                handles.append(record.handle)
        if handles:
            await asyncio.gather(*handles, return_exceptions=True)

    # -------------------------------------------------------------- wake-up
    def pending_results(self) -> list[TaskRecord]:
        """Finished, not-yet-delivered tasks; marks them delivered."""
        pending, self._pending = self._pending, []
        for record in pending:
            record.delivered = True
        if not self._pending:
            self._wakeup.clear()
        return pending

    async def wait_for_result(self, timeout: float | None = None) -> list[TaskRecord]:
        """Block until at least one task finishes (or ``timeout`` expires)."""
        try:
            await asyncio.wait_for(self._wakeup.wait(), timeout)
        except (asyncio.TimeoutError, TimeoutError):
            return []
        return self.pending_results()

    def _trim(self) -> None:
        """Drop the oldest delivered records beyond the retention window."""
        finished = [
            key
            for key in self._order
            if key in self._records and self._records[key].terminal and self._records[key].delivered
        ]
        for key in finished[: max(0, len(finished) - self.retention)]:
            self._records.pop(key, None)
            if key in self._order:
                self._order.remove(key)


__all__ = [
    "CANCELLED",
    "DEFAULT_MAX_CONCURRENT",
    "DEFAULT_MAX_TOTAL",
    "DEFAULT_RETENTION",
    "FAILED",
    "MAX_CONCURRENT_ENV",
    "MAX_LABEL_CHARS",
    "RUNNING",
    "SUCCEEDED",
    "TERMINAL",
    "TIMEOUT",
    "TaskManager",
    "TaskManagerError",
    "TaskRecord",
    "max_concurrent_from_env",
]
