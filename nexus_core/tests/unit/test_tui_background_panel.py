"""The TUI row for a background job: alive, identifiable and not duplicated.

A long ``nmap -p-`` runs in its own task while the loop keeps working, so the
screen is the only thing telling the operator the engagement is not stalled. The
coordinator already publishes ``react.background_started`` / ``_finished`` /
``_delivered``; these tests pin that the projection turns them into one compact
row (``Background · bg-1 · nmap · running · 01:24``) and retires it once the
result is in the transcript card, so the dock never becomes a second copy.
"""

from __future__ import annotations

import time

import pytest

from nexus_core.cli.tui.session import TuiSession
from nexus_core.cli.tui.tasks import TaskPanel, elapsed_label

pytestmark = pytest.mark.unit


def _started(task_id="bg-1", *, tool_id="nexus.recon.nmap", label="nmap -p-") -> dict:
    return {
        "event_type": "react.background_started",
        "run_id": "r",
        "payload": {
            "task_id": task_id, "tool_id": tool_id, "label": label,
            "status": "running", "iteration": 3,
        },
    }


def _finished(task_id="bg-1", *, status="succeeded") -> dict:
    return {
        "event_type": "react.background_finished",
        "run_id": "r",
        "payload": {"task_id": task_id, "status": status, "iteration": 4},
    }


def _delivered(task_id="bg-1") -> dict:
    return {
        "event_type": "react.background_delivered",
        "run_id": "r",
        "payload": {"task_id": task_id, "status": "succeeded", "iteration": 5},
    }


def _text(panel: TaskPanel) -> str:
    return "".join(line for _, line in panel.render())


def test_a_background_job_names_its_id_tool_state_and_clock():
    panel = TaskPanel()
    panel.consume(_started())

    text = _text(panel)

    assert "Background · bg-1 · nmap · running · 00:00" in text
    assert "nmap -p-" in text
    assert panel.running is True
    # The row is not advertised as cancellable: F7 only owns fan-out children.
    assert "F7" not in text


def test_the_clock_counts_wall_time_and_past_an_hour_keeps_the_hours():
    started = time.monotonic() - 84
    assert elapsed_label(started) == "01:24"
    assert elapsed_label(time.monotonic() - 3725).startswith("1:02:")


def test_a_repeated_start_cannot_restart_the_clock():
    panel = TaskPanel()
    panel.consume(_started())
    first = panel.tasks["r:bg-1"]["started"]

    panel.consume(_started())

    assert panel.tasks["r:bg-1"]["started"] == first
    assert panel.tasks["r:bg-1"]["status"] == "running"


def test_finishing_freezes_the_state_and_delivery_retires_the_row():
    panel = TaskPanel()
    panel.consume(_started())
    panel.consume(_finished(status="succeeded"))
    assert panel.tasks["r:bg-1"]["status"] == "ok"
    assert panel.tasks["r:bg-1"]["finished"] is not None
    assert "ok · 00:00" in _text(panel)

    panel.consume(_delivered())

    assert panel.tasks == {}
    assert panel.render() == []
    # A late duplicate of the finish cannot bring a delivered job back.
    panel.consume(_finished())
    assert panel.tasks == {}


def test_a_failed_background_job_keeps_its_terminal_state():
    panel = TaskPanel()
    panel.consume(_started())
    panel.consume(_finished(status="failed"))

    assert panel.tasks["r:bg-1"]["status"] == "failed"
    assert "failed" in _text(panel)


def test_a_finish_whose_start_was_missed_never_invents_a_timer():
    panel = TaskPanel()
    panel.consume(_finished(task_id="bg-9"))

    assert panel.tasks == {}


def test_the_end_of_the_run_retires_background_rows_only():
    panel = TaskPanel()
    panel.consume({"event_type": "orchestrator.subagent", "run_id": "r", "sequence": 1,
                   "payload": {"subagent_id": "recon"}})
    panel.consume(_started())

    panel.consume({"event_type": "react.finished", "run_id": "r", "payload": {"status": "completed"}})

    assert "r:bg-1" not in panel.tasks
    assert panel.tasks["r:profile:recon:1"]["status"] == "ok"


def test_no_color_keeps_the_row_text_and_drops_the_style():
    panel = TaskPanel()
    panel.consume(_started())

    styled = panel.render()
    plain = panel.render(no_color=True)

    assert [text for _, text in styled] == [text for _, text in plain]
    assert {style for style, _ in plain} == {""}


def test_many_jobs_stay_bounded_and_route_through_the_session():
    ui = TuiSession(use_tui=False)
    for index in range(150):
        ui.task_event(_started(f"bg-{index}", label="scan"))
        ui.task_event(_finished(f"bg-{index}"))

    assert len(ui.task_panel.tasks) <= ui.task_panel.max_tasks
