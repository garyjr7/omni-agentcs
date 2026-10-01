"""Real cancellation for the local sandbox (audit finding #2).

The child runs in its own process group; a timeout or a set ``cancel_event``
sends SIGTERM, then SIGKILL after ``grace_seconds``, and never leaves an
orphaned descendant behind.
"""

from __future__ import annotations

import asyncio
import os
import subprocess

import pytest

from nexus_core.kernel import sandbox as sandbox_module
from nexus_core.kernel.sandbox import LocalSandbox

pytestmark = pytest.mark.unit

_GRACEFUL = "import signal,sys,time\nsignal.signal(signal.SIGTERM, lambda *a: sys.exit(0))\ntime.sleep(300)\n"
_STUBBORN = "import signal,time\nsignal.signal(signal.SIGTERM, signal.SIG_IGN)\ntime.sleep(300)\n"
_PARENT = (
    "import subprocess,sys,time\n"
    "child = subprocess.Popen(['sleep','300'])\n"
    "open(sys.argv[1],'w').write(str(child.pid))\n"
    "time.sleep(300)\n"
)


def _write(tmp_path, name: str, body: str):
    path = tmp_path / name
    path.write_text(body, encoding="utf-8")
    return str(path)


def _sandbox(tmp_path) -> LocalSandbox:
    return LocalSandbox(tmp_path, allowed_programs=("python3", "sleep"))


async def _cancel_soon(event: asyncio.Event, delay: float = 0.2) -> None:
    await asyncio.sleep(delay)
    event.set()


async def _run_cancelled(tmp_path, script, *, grace_seconds=3.0, extra=()):
    sandbox = _sandbox(tmp_path)
    event = asyncio.Event()
    task = asyncio.ensure_future(_cancel_soon(event))
    try:
        return await sandbox.run(
            ["python3", script, *extra],
            timeout_seconds=120,
            cancel_event=event,
            grace_seconds=grace_seconds,
        )
    finally:
        task.cancel()


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


async def test_cancel_event_sends_sigterm(tmp_path):
    script = _write(tmp_path, "graceful.py", _GRACEFUL)
    result = await _run_cancelled(tmp_path, script, grace_seconds=5.0)
    assert result.cancelled is True
    assert result.timed_out is False
    # The handler exited on SIGTERM, well before the grace deadline.
    assert result.exit_code == 0
    assert result.duration_seconds < 2.0


async def test_cancel_escalates_to_sigkill_after_grace(tmp_path):
    script = _write(tmp_path, "stubborn.py", _STUBBORN)
    result = await _run_cancelled(tmp_path, script, grace_seconds=0.5)
    assert result.cancelled is True
    assert result.timed_out is False
    # SIGTERM was ignored; the group was SIGKILLed after the grace period.
    assert result.exit_code == -9
    assert result.duration_seconds >= 0.5


async def test_cancel_kills_process_group(tmp_path):
    pid_file = tmp_path / "child.pid"
    script = _write(tmp_path, "parent.py", _PARENT)
    result = await _run_cancelled(
        tmp_path, script, grace_seconds=1.0, extra=(str(pid_file),)
    )
    assert result.cancelled is True
    assert result.orphans_detected == 0
    child_pid = int(pid_file.read_text(encoding="utf-8"))
    await asyncio.sleep(0.2)
    assert not _alive(child_pid)


async def test_no_orphans_after_cancel(tmp_path):
    pid_file = tmp_path / "child.pid"
    script = _write(tmp_path, "parent.py", _PARENT)
    result = await _run_cancelled(
        tmp_path, script, grace_seconds=1.0, extra=(str(pid_file),)
    )
    assert result.orphans_detected == 0


async def test_cancel_during_subprocess_with_children(tmp_path):
    """A grandchild in the same group must die with the group."""
    pid_file = tmp_path / "child.pid"
    script = _write(tmp_path, "parent.py", _PARENT)
    await _run_cancelled(tmp_path, script, grace_seconds=1.0, extra=(str(pid_file),))
    child_pid = int(pid_file.read_text(encoding="utf-8"))
    await asyncio.sleep(0.2)
    assert not _alive(child_pid)
    ping = subprocess.run(["pgrep", "-x", "sleep"], capture_output=True, text=True)
    assert child_pid not in {int(pid) for pid in ping.stdout.split()}


async def test_cancel_vs_timeout_distinguished(tmp_path):
    script = _write(tmp_path, "graceful.py", _GRACEFUL)
    cancelled = await _run_cancelled(tmp_path, script, grace_seconds=5.0)
    assert cancelled.cancelled is True and cancelled.timed_out is False

    sandbox = _sandbox(tmp_path)
    timed_out = await sandbox.run(
        ["python3", script], timeout_seconds=0.2, grace_seconds=1.0
    )
    assert timed_out.timed_out is True and timed_out.cancelled is False


async def test_cancel_event_not_set_completes_normally(tmp_path):
    sandbox = _sandbox(tmp_path)
    event = asyncio.Event()
    result = await sandbox.run(
        ["python3", "-c", "print('done')"],
        timeout_seconds=10,
        cancel_event=event,
    )
    assert result.cancelled is False
    assert result.timed_out is False
    assert result.exit_code == 0
    assert "done" in result.stdout


async def test_external_task_cancel_kills_process_group(tmp_path):
    """A raw ``task.cancel()`` must still tear down the group before raising."""
    pid_file = tmp_path / "child.pid"
    script = _write(tmp_path, "parent.py", _PARENT)
    sandbox = _sandbox(tmp_path)
    task = asyncio.create_task(
        sandbox.run(["python3", script, str(pid_file)], timeout_seconds=120)
    )
    await asyncio.sleep(0.4)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    child_pid = int(pid_file.read_text(encoding="utf-8"))
    await asyncio.sleep(0.3)
    assert not _alive(child_pid)


async def test_terminate_is_explicit_and_idempotent(tmp_path):
    sandbox = _sandbox(tmp_path)
    process = await asyncio.create_subprocess_exec(
        "sleep",
        "300",
        start_new_session=True,
        stdin=asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    communicate = asyncio.ensure_future(process.communicate())
    orphans = await sandbox.terminate(process, grace_seconds=1.0)
    assert orphans == 0
    await asyncio.wait_for(communicate, timeout=5)
    # Calling it again is a no-op, not an error.
    assert await sandbox.terminate(process, grace_seconds=0.1) == 0


def test_sandbox_result_has_three_states():
    completed = sandbox_module.SandboxResult(0, "", "")
    assert not completed.cancelled and not completed.timed_out
    assert completed.orphans_detected == 0
    assert completed.duration_seconds == 0.0
