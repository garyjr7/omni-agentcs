"""The event loop keeps serving the TUI while tools run.

The TUI owns its own prompt_toolkit loop on a dedicated thread, but every frame
it shows arrives through the agent's asyncio loop (``_dispatch`` ->
``call_soon_threadsafe``, the run-event streamer, the spinner). A tool launched
synchronously -or a handler that calls ``subprocess.run`` instead of awaiting
the sandbox- stops that traffic and the operator sees a frozen screen even
though the tool is fine.

These tests measure the loop itself: a heartbeat runs alongside the batch and the
largest gap between ticks is the freeze the operator would feel. They also fail
outright if anything calls blocking ``subprocess.run`` during a real sandboxed
batch, because that is the regression this guard exists for.
"""

from __future__ import annotations

import asyncio
import subprocess
import threading
import time

import pytest

from nexus_core.agent import parallel
from nexus_core.kernel import hardware
from nexus_core.kernel.sandbox import LocalSandbox

pytestmark = pytest.mark.unit

#: A gap this long between heartbeats means the loop was not running. The tools
#: below sleep much longer, so a blocked loop is impossible to miss.
MAX_LOOP_GAP_SECONDS = 0.2


async def _run_with_heartbeat(operation, *, interval: float = 0.02):
    """Await ``operation`` while ticking the loop; return (result, gaps)."""
    task = asyncio.ensure_future(operation)
    loop = asyncio.get_running_loop()
    gaps: list[float] = []
    last = loop.time()
    while not task.done():
        await asyncio.sleep(interval)
        now = loop.time()
        gaps.append(now - last)
        last = now
    return await task, gaps


def _many_cores(monkeypatch) -> None:
    profile = hardware.HardwareProfile(16, 8, 32 * hardware.GIB, 16 * hardware.GIB, "test")
    monkeypatch.setattr(hardware, "detect_hardware", lambda: profile)


def test_the_tui_bus_keeps_receiving_frames_during_a_parallel_batch(monkeypatch):
    """Frames dispatched from the TUI thread must not queue behind the tools."""
    _many_cores(monkeypatch)
    frames: list[float] = []

    async def scenario() -> list[parallel.CallExecution]:
        loop = asyncio.get_running_loop()
        stop = threading.Event()

        def ui_thread() -> None:
            # Same shape as the TUI's `_dispatch`: a foreign thread asks the
            # loop to run a callback, and the loop must get to it promptly.
            while not stop.is_set():
                loop.call_soon_threadsafe(frames.append, time.monotonic())
                time.sleep(0.02)

        thread = threading.Thread(target=ui_thread, daemon=True)
        thread.start()
        calls = [
            {
                "index": index,
                "tool_id": f"t{index}",
                "arguments": {},
                "payload": {"tool_id": f"t{index}"},
            }
            for index in range(3)
        ]

        async def execute(payload, timeout, cancel_event):
            await asyncio.sleep(0.6)
            return {"output": {"success": True, "outcome": "success"}}, False

        try:
            results, gaps = await _run_with_heartbeat(
                parallel.execute_calls(calls, execute=execute, limit=3, timeout=30)
            )
        finally:
            stop.set()
            thread.join(timeout=1)
        return results, gaps, len(frames)

    started = time.monotonic()
    results, gaps, delivered = asyncio.run(scenario())
    elapsed = time.monotonic() - started

    assert [entry.error for entry in results] == [None, None, None]
    assert elapsed >= 0.6, "the tools really were still running while we measured"
    assert max(gaps) < MAX_LOOP_GAP_SECONDS, f"the loop stalled {max(gaps):.2f}s during the batch"
    assert delivered >= 3, "the TUI kept receiving frames while the tools ran"


def test_real_sandboxed_tools_never_block_the_event_loop(tmp_path, monkeypatch):
    """The executor path, end to end: two real children, no blocking call."""
    _many_cores(monkeypatch)
    workspace = tmp_path / "ws"
    workspace.mkdir()
    sandbox = LocalSandbox(workspace, allowed_programs=("python3",))

    def forbidden(*args, **kwargs):
        raise AssertionError("blocking subprocess.run called on the event loop")

    monkeypatch.setattr(subprocess, "run", forbidden)

    async def execute(payload, timeout, cancel_event):
        result = await sandbox.run(
            payload["argv"], timeout_seconds=timeout, cancel_event=cancel_event
        )
        return {
            "output": {
                "success": result.exit_code == 0,
                "outcome": "success" if result.exit_code == 0 else "error",
                "output": result.stdout.strip(),
            }
        }, False

    calls = [
        {
            "index": index,
            "tool_id": f"scan{index}",
            "arguments": {},
            "payload": {
                "argv": ["python3", "-c", "import time;time.sleep(0.5);print('done')"]
            },
        }
        for index in range(2)
    ]

    results, gaps = asyncio.run(
        _run_with_heartbeat(
            parallel.execute_calls(calls, execute=execute, limit=2, timeout=30)
        )
    )

    assert [entry.error for entry in results] == [None, None]
    assert all(entry.invocation["output"]["output"] == "done" for entry in results)
    assert max(gaps) < MAX_LOOP_GAP_SECONDS, (
        f"the loop stalled {max(gaps):.2f}s while real tools ran"
    )
