"""Bounded in-process batch runner for governed tool invocations (V0-9).

A sweep of 40 targets used to mean 40 CLI starts: every job paid for a fresh
interpreter, a fresh catalog build and a fresh store connection, and nothing
bounded how many of them ran at once. The audit measured the consequence —
batches without CPU/concurrency budgets — and this module is the budget.

Properties, all enforced here rather than trusted from the caller:

* **Bounded concurrency.** At most ``max_concurrency`` invocations are in flight
  (default 4) and at most ``per_target_concurrency`` per target (default 1), so
  a single host never receives a burst.
* **Backpressure.** The scheduler keeps one deque and one task per allowed
  slot; nothing is materialized ahead of the workers, so a 10 000-line job file
  costs the same memory as a 40-line one.
* **Every job accounted for.** Each job ends as ``completed``, ``failed`` or
  ``cancelled`` with its cause, and the report preserves negatives and failures
  instead of stopping at the first error.
* **Cancellation.** Setting ``cancel_event`` stops scheduling, lets the in-flight
  work finish (its evidence is already paid for) and marks the rest cancelled.

The runner schedules; it does not execute anything itself. The caller passes the
same governed entry point the CLI uses (``nexus_core.kernel.runtime.execute_tool``),
so a batched job is policy-checked, scoped, approved and audited exactly like a
single one.
"""

from __future__ import annotations

import asyncio
import time
from collections import Counter, deque
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Iterable, Sequence

#: Default global ceiling and per-target ceiling (V0-9).
DEFAULT_MAX_CONCURRENCY = 4
DEFAULT_PER_TARGET_CONCURRENCY = 1

#: Status vocabulary of a finished job. ``completed`` covers both a positive and
#: a determinate negative (V0-22): the call reached the target.
STATUS_COMPLETED = "completed"
STATUS_FAILED = "failed"
STATUS_CANCELLED = "cancelled"
JOB_STATUSES = (STATUS_COMPLETED, STATUS_FAILED, STATUS_CANCELLED)


@dataclass(frozen=True)
class BatchJob:
    """One governed invocation in a sweep.

    ``target`` groups jobs that must not run at the same time (default: one in
    flight per target). It is supplied by the caller — derived from the tool's
    ``scope_target_field`` — so the broker never guesses what identifies a host.

    ``index`` identifies the job in the report and must be unique.
    """

    index: int
    tool_id: str
    arguments: dict[str, Any] = field(default_factory=dict)
    engagement_id: str | None = None
    target: str = ""


@dataclass(frozen=True)
class JobOutcome:
    """What happened to one job, in a shape a report can serialize."""

    index: int
    tool_id: str
    target: str
    status: str
    outcome: str = ""
    error_type: str = ""
    error: str = ""
    duration_ms: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "tool_id": self.tool_id,
            "target": self.target,
            "status": self.status,
            "outcome": self.outcome,
            "error_type": self.error_type,
            "error": self.error,
            "duration_ms": round(self.duration_ms, 3),
        }


@dataclass
class BatchReport:
    total: int = 0
    completed: int = 0
    failed: int = 0
    cancelled: int = 0
    peak_concurrency: int = 0
    peak_per_target: int = 0
    wall_seconds: float = 0.0
    results: list[JobOutcome] = field(default_factory=list)

    @property
    def counts(self) -> dict[str, int]:
        return {status: sum(1 for item in self.results if item.status == status)
                for status in JOB_STATUSES}

    def to_dict(self) -> dict[str, Any]:
        return {
            "total": self.total,
            "completed": self.completed,
            "failed": self.failed,
            "cancelled": self.cancelled,
            "peak_concurrency": self.peak_concurrency,
            "peak_per_target": self.peak_per_target,
            "wall_seconds": round(self.wall_seconds, 3),
            "results": [item.to_dict() for item in self.results],
        }


def _classify(payload: Any) -> str:
    """Read the outcome of a successful invocation from its result envelope."""
    if isinstance(payload, dict):
        result = payload.get("output")
        if isinstance(result, dict):
            if result.get("success") is True:
                return "success"
            return str(result.get("outcome") or "")
    return ""


async def run_batch(
    jobs: Iterable[BatchJob],
    invoke: Callable[[BatchJob], Awaitable[Any]],
    *,
    max_concurrency: int = DEFAULT_MAX_CONCURRENCY,
    per_target_concurrency: int = DEFAULT_PER_TARGET_CONCURRENCY,
    cancel_event: asyncio.Event | None = None,
    on_result: Callable[[JobOutcome], None] | None = None,
) -> BatchReport:
    """Run ``jobs`` through ``invoke`` with bounded concurrency and backpressure.

    Returns in job order, so a resumable sweep can compare index by index.
    ``invoke`` raises normally: its exception is captured as a ``failed`` job
    with the error type, never swallowed and never masking the other jobs.
    """
    if max_concurrency < 1 or per_target_concurrency < 1:
        raise ValueError("concurrency budgets must be >= 1")
    queue: deque[BatchJob] = deque(jobs)
    report = BatchReport(total=len(queue))
    if not queue:
        # An empty sweep is a valid result: no facts invented, no error raised.
        return report
    in_flight_per_target: Counter[str] = Counter()
    running: dict[asyncio.Task, BatchJob] = {}
    outcomes: dict[int, JobOutcome] = {}
    started = time.monotonic()

    async def _one(job: BatchJob) -> JobOutcome:
        job_started = time.monotonic()
        try:
            payload = await invoke(job)
        except asyncio.CancelledError:
            raise
        except BaseException as exc:  # noqa: BLE001 - every job is accounted for
            return JobOutcome(
                index=job.index, tool_id=job.tool_id, target=job.target,
                status=STATUS_FAILED, error_type=type(exc).__name__,
                error=str(exc)[:500], duration_ms=(time.monotonic() - job_started) * 1000,
            )
        return JobOutcome(
            index=job.index, tool_id=job.tool_id, target=job.target,
            status=STATUS_COMPLETED, outcome=_classify(payload),
            duration_ms=(time.monotonic() - job_started) * 1000,
        )

    def _record(outcome: JobOutcome) -> None:
        outcomes[outcome.index] = outcome
        if outcome.status == STATUS_COMPLETED:
            report.completed += 1
        elif outcome.status == STATUS_FAILED:
            report.failed += 1
        else:
            report.cancelled += 1
        if on_result is not None:
            on_result(outcome)

    def _launch(job: BatchJob) -> None:
        in_flight_per_target[job.target] += 1
        report.peak_per_target = max(report.peak_per_target, in_flight_per_target[job.target])
        running[asyncio.create_task(_one(job))] = job
        report.peak_concurrency = max(report.peak_concurrency, len(running))

    def _stop_scheduling() -> bool:
        return cancel_event is not None and cancel_event.is_set()

    while queue or running:
        # Schedule greedily, past neither budget. Jobs whose target is busy are
        # deferred, not dropped: one host cannot be parallelized with itself.
        remaining: deque[BatchJob] = deque()
        candidates = len(queue)
        while (queue and not _stop_scheduling()
               and len(running) < max_concurrency and len(remaining) < candidates):
            job = queue.popleft()
            if in_flight_per_target[job.target] >= per_target_concurrency:
                remaining.append(job)
            else:
                _launch(job)
        queue.extendleft(reversed(remaining))
        if _stop_scheduling():
            while queue:
                job = queue.popleft()
                _record(JobOutcome(index=job.index, tool_id=job.tool_id, target=job.target,
                                   status=STATUS_CANCELLED))
        if not running:
            break
        done, _ = await asyncio.wait(running, return_when=asyncio.FIRST_COMPLETED)
        for task in done:
            job = running.pop(task)
            in_flight_per_target[job.target] -= 1
            _record(task.result())
    report.wall_seconds = time.monotonic() - started
    report.results = [outcomes[index] for index in sorted(outcomes)]
    return report


def jobs_from_records(records: Sequence[dict[str, Any]], *, target_field: str = "target") -> list[BatchJob]:
    """Build jobs from parsed NDJSON records (one governed call per line)."""
    jobs: list[BatchJob] = []
    for index, record in enumerate(records):
        tool_id = str(record.get("tool_id") or "")
        if not tool_id:
            raise ValueError(f"job {index} has no tool_id")
        arguments = record.get("arguments")
        if arguments is None:
            arguments = {}
        # ``[]``/``""`` must be rejected, not silently read as "no arguments".
        if not isinstance(arguments, dict):
            raise ValueError(f"job {index} arguments must be an object")
        target = str(record.get("target") or arguments.get(target_field) or "")
        jobs.append(BatchJob(index=index, tool_id=tool_id, arguments=arguments,
                             engagement_id=record.get("engagement"), target=target))
    return jobs
