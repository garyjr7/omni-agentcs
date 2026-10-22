"""Orphan process groups: register, verify, reap (DeadDrop campaign, 2026-10-22).

Measured: after killing two runs by hand, two ``nmap -p-`` sweeps kept attacking
``192.168.11.200`` for 1 h 04 min and 1 h 18 min, and two ``hydra`` sweeps did the
same against the login. The sandbox reaps the group on timeout/cancel, but a run
killed by a signal never gets there.

These tests use a real child in its own session, so the whole path -register,
read ``/proc``, ``killpg``- is exercised instead of mocked.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from nexus_core.kernel import process_registry as registry

pytestmark = pytest.mark.skipif(
    not Path("/proc").is_dir(), reason="/proc is required to verify a pid"
)


@pytest.fixture(autouse=True)
def _isolated_registry(tmp_path, monkeypatch):
    monkeypatch.setenv("NEXUS_PROC_REGISTRY", str(tmp_path / "procs"))
    yield
    # Never leave a child behind if an assertion fails mid-test.
    for path in registry.registry_root().glob("*.json"):
        record = json.loads(path.read_text(encoding="utf-8"))
        try:
            os.killpg(int(record["pid"]), 9)
        except (ProcessLookupError, PermissionError, ValueError, KeyError):
            pass


def _spawn(command: list[str]) -> subprocess.Popen:
    return subprocess.Popen(
        command,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )


def test_a_stale_group_is_killed_and_removed_from_the_registry():
    child = _spawn([sys.executable, "-c", "import time; time.sleep(120)"])
    try:
        registry.register(child.pid, [sys.executable, "-c", "sleep"])
        assert list(registry.registry_root().glob("*.json"))

        killed = registry.reap_stale(min_age_seconds=0)

        assert [entry["pid"] for entry in killed] == [child.pid]
        child.wait(timeout=5)
        assert child.poll() is not None
        assert not list(registry.registry_root().glob("*.json"))
    finally:
        if child.poll() is None:
            child.kill()


def test_a_recycled_pid_is_never_signalled():
    """The pid is alive, but its start time is not the recorded one."""
    child = _spawn([sys.executable, "-c", "import time; time.sleep(60)"])
    try:
        path = registry.register(child.pid, [sys.executable, "-c", "sleep"])
        assert path is not None
        record = json.loads(path.read_text(encoding="utf-8"))
        record["start_time"] = "1"
        path.write_text(json.dumps(record), encoding="utf-8")

        killed = registry.reap_stale(min_age_seconds=0)

        assert killed == []
        assert child.poll() is None
        assert not list(registry.registry_root().glob("*.json"))
    finally:
        child.kill()
        child.wait(timeout=5)


def test_a_fresh_group_is_left_alone():
    """A run starting next to another one must not kill its first tool."""
    child = _spawn([sys.executable, "-c", "import time; time.sleep(60)"])
    try:
        registry.register(child.pid, [sys.executable, "-c", "sleep"])
        killed = registry.reap_stale(min_age_seconds=120)
        assert killed == []
        assert child.poll() is None
    finally:
        child.kill()
        child.wait(timeout=5)
        registry.unregister(child.pid)


def test_unregister_removes_every_record_of_the_pid():
    child = _spawn([sys.executable, "-c", "import time; time.sleep(60)"])
    try:
        registry.register(child.pid, ["first"])
        registry.register(child.pid, ["second"])
        assert len(list(registry.registry_root().glob("*.json"))) == 2
        registry.unregister(child.pid)
        assert not list(registry.registry_root().glob("*.json"))
    finally:
        child.kill()
        child.wait(timeout=5)


def test_a_dead_group_is_cleaned_without_an_error():
    child = _spawn([sys.executable, "-c", "pass"])
    child.wait(timeout=10)
    registry.register(child.pid, [sys.executable, "-c", "pass"])
    assert registry.reap_stale(min_age_seconds=0) == []
    assert not list(registry.registry_root().glob("*.json"))


def test_the_sandbox_records_and_forgets_the_group(tmp_path, monkeypatch):
    """The wiring: a normal run leaves no record behind."""
    import asyncio

    from nexus_core.kernel import process_registry as registry_module
    from nexus_core.kernel.sandbox import LocalSandbox

    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(tmp_path))
    monkeypatch.setenv("NEXUS_PROC_REGISTRY", str(tmp_path / "procs"))
    seen: list[int] = []
    original = registry_module.register

    def spy(pid, argv, **kwargs):
        seen.append(pid)
        return original(pid, argv, **kwargs)

    monkeypatch.setattr("nexus_core.kernel.sandbox.register_process_group", spy)
    sandbox = LocalSandbox(str(tmp_path), allowed_programs=(sys.executable,))
    result = asyncio.run(sandbox.run([sys.executable, "-c", "print('ok')"], timeout_seconds=30))

    assert result.exit_code == 0 and "ok" in result.stdout
    assert seen, "the group must be registered while it runs"
    time.sleep(0.1)
    assert not list((tmp_path / "procs").glob("*.json"))


def test_a_wrapper_that_exited_still_gets_its_group_reaped():
    """The measured shape: `sh -c gobuster …` exits, gobuster keeps running.

    The leader's pid is gone, so the record can only be used through its *group*:
    a member whose binary matches is proof the group is still the original one.
    """
    leader = subprocess.Popen(
        ["bash", "-c", "sleep 120 & exit 0"], start_new_session=True
    )
    leader.wait(timeout=5)
    time.sleep(0.2)
    try:
        assert registry.group_members(leader.pid), "the child must share the group"
        registry.register(leader.pid, ["/usr/bin/sleep"])

        killed = registry.reap_stale(min_age_seconds=0)

        assert [entry["pid"] for entry in killed] == [leader.pid]
        time.sleep(0.3)
        assert registry.group_members(leader.pid) == []
    finally:
        for pid, _ in registry.group_members(leader.pid):
            try:
                os.kill(pid, 9)
            except OSError:
                pass


def test_a_group_whose_members_are_another_binary_is_left_alone():
    leader = subprocess.Popen(
        ["bash", "-c", "sleep 120 & exit 0"], start_new_session=True
    )
    leader.wait(timeout=5)
    time.sleep(0.2)
    try:
        registry.register(leader.pid, ["/usr/bin/gobuster"])
        assert registry.reap_stale(min_age_seconds=0) == []
        assert registry.group_members(leader.pid), "the unrelated member survives"
        assert not list(registry.registry_root().glob("*.json"))
    finally:
        for pid, _ in registry.group_members(leader.pid):
            try:
                os.kill(pid, 9)
            except OSError:
                pass
