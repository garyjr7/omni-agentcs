"""V0-9: forty jobs are one process with bounded concurrency.

The measured failure was a sweep that paid one CLI start per job and bounded
neither concurrency nor memory. These tests run the broker with a synthetic
governed entry point and require the budgets to hold, every job to be accounted
for (including failures and negatives) and nothing to be spawned.
"""

from __future__ import annotations

import asyncio
from unittest import mock

import pytest

from nexus_core.kernel.batch import (
    DEFAULT_MAX_CONCURRENCY,
    STATUS_CANCELLED,
    STATUS_COMPLETED,
    STATUS_FAILED,
    BatchJob,
    jobs_from_records,
    run_batch,
)

DELAY = 0.02
TARGETS = ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"]


class _Tracker:
    """Records real in-flight concurrency, globally and per target."""

    def __init__(self) -> None:
        self.in_flight = 0
        self.peak = 0
        self.per_target: dict[str, int] = {}
        self.peak_per_target = 0
        self.started = 0

    async def invoke(self, job: BatchJob):
        self.started += 1
        self.in_flight += 1
        self.peak = max(self.peak, self.in_flight)
        self.per_target[job.target] = self.per_target.get(job.target, 0) + 1
        self.peak_per_target = max(self.peak_per_target, self.per_target[job.target])
        try:
            await asyncio.sleep(DELAY)
        finally:
            self.in_flight -= 1
            self.per_target[job.target] -= 1
        return {"tool_id": job.tool_id, "output": {"success": True}}


def _jobs(count: int, targets: list[str]) -> list[BatchJob]:
    return [
        BatchJob(index=index, tool_id="nexus.recon.nmap",
                 arguments={"target": targets[index % len(targets)]},
                 target=targets[index % len(targets)])
        for index in range(count)
    ]


def test_batch_40_jobs_bounded_resources():
    tracker = _Tracker()
    jobs = _jobs(40, TARGETS)
    serial = len(jobs) * DELAY
    with mock.patch(
        "asyncio.create_subprocess_exec",
        side_effect=AssertionError("the batch runner must not spawn a process per job"),
    ):
        report = asyncio.run(run_batch(jobs, tracker.invoke))

    # One process, 40 governed invocations, every job accounted for exactly once.
    assert tracker.started == 40
    assert len(report.results) == 40
    assert report.total == 40
    assert [item.index for item in report.results] == list(range(40))
    assert report.completed == 40 and report.failed == 0 and report.cancelled == 0

    # Concurrency and per-target budgets hold, and the run is not serial.
    assert report.peak_concurrency <= DEFAULT_MAX_CONCURRENCY
    assert tracker.peak <= DEFAULT_MAX_CONCURRENCY
    assert report.peak_per_target == 1
    assert tracker.peak_per_target == 1
    assert report.wall_seconds < serial / 2


def test_jobs_on_the_same_target_never_overlap():
    tracker = _Tracker()
    jobs = _jobs(8, ["10.0.0.9"])
    report = asyncio.run(run_batch(jobs, tracker.invoke))
    assert report.completed == 8
    assert report.peak_concurrency == 1
    assert tracker.peak == 1


def test_failures_and_negatives_are_preserved_and_do_not_stop_the_sweep():
    async def invoke(job: BatchJob):
        if job.index == 1:
            raise RuntimeError("tool post-condition was not verified")
        if job.index == 2:
            return {"tool_id": job.tool_id, "output": {"success": False, "outcome": "denied"}}
        return {"tool_id": job.tool_id, "output": {"success": True}}

    report = asyncio.run(run_batch(_jobs(5, TARGETS), invoke))
    by_index = {item.index: item for item in report.results}
    assert (report.completed, report.failed) == (4, 1)
    assert by_index[1].status == STATUS_FAILED
    assert by_index[1].error_type == "RuntimeError"
    assert by_index[1].error
    # A determinate negative completed the call: it is not a failure (V0-22).
    assert by_index[2].status == STATUS_COMPLETED
    assert by_index[2].outcome == "denied"
    assert by_index[3].status == STATUS_COMPLETED and by_index[3].outcome == "success"


def test_cancellation_accounts_for_every_remaining_job():
    cancel = asyncio.Event()

    def on_result(_outcome) -> None:
        cancel.set()

    async def invoke(job: BatchJob):
        return {"tool_id": job.tool_id, "output": {"success": True}}

    report = asyncio.run(
        run_batch(_jobs(6, TARGETS), invoke, max_concurrency=1,
                  cancel_event=cancel, on_result=on_result)
    )
    assert len(report.results) == 6
    assert report.results[0].status == STATUS_COMPLETED
    assert [item.status for item in report.results[1:]] == [STATUS_CANCELLED] * 5
    assert report.cancelled == 5


def test_an_empty_sweep_completes_without_inventing_facts():
    async def invoke(job: BatchJob):  # pragma: no cover - never called
        raise AssertionError("no job to run")

    report = asyncio.run(run_batch([], invoke))
    assert report.total == 0 and report.results == []
    assert report.counts == {STATUS_COMPLETED: 0, STATUS_FAILED: 0, STATUS_CANCELLED: 0}
    assert report.to_dict()["results"] == []


def test_jobs_from_records_validates_the_lines():
    jobs = jobs_from_records(
        [
            {"tool_id": "nexus.recon.nmap", "arguments": {"target": "10.0.0.1"}},
            {"tool_id": "nexus.web.request", "arguments": {"url": "http://10.0.0.2/"}, "target": "10.0.0.2"},
        ]
    )
    assert [job.index for job in jobs] == [0, 1]
    assert jobs[0].target == "10.0.0.1"
    assert jobs[1].target == "10.0.0.2"
    with pytest.raises(ValueError, match="tool_id"):
        jobs_from_records([{"arguments": {}}])
    with pytest.raises(ValueError, match="arguments"):
        jobs_from_records([{"tool_id": "nexus.recon.nmap", "arguments": []}])


def test_concurrency_budgets_must_be_positive():
    async def invoke(job: BatchJob):  # pragma: no cover - never called
        raise AssertionError("no job to run")

    for kwargs in ({"max_concurrency": 0}, {"per_target_concurrency": 0}):
        with pytest.raises(ValueError, match="budgets"):
            asyncio.run(run_batch(_jobs(1, TARGETS), invoke, **kwargs))
