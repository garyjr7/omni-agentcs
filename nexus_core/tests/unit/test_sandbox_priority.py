"""``nice``/``cpulimit`` injection at the one place every tool crosses: the sandbox.

Handlers build their own ``argv`` and must not care about scheduling, so the
prologue is added by :meth:`LocalSandbox.run` **after** the program allowlist
check. These tests run real children and read their actual niceness, because the
claim "the TUI gets priority" is only true if the kernel received it.
"""

from __future__ import annotations

import asyncio
import shutil
import stat
from pathlib import Path

import pytest

from nexus_core.kernel import hardware, sandbox as sandbox_module
from nexus_core.kernel.sandbox import LocalSandbox

pytestmark = pytest.mark.unit

_NICENESS = "import os;print(os.nice(0))"
_ENV_REPORT = (
    "import os,json;print(json.dumps({'nice': os.environ.get('NEXUS_TOOL_NICE'),"
    " 'cpu': os.environ.get('NEXUS_TOOL_CPU_LIMIT')}))"
)

#: A stand-in for ``cpulimit``: it announces itself, drops ``-l N --`` and then
#: becomes the real program, which is exactly what the wrapper does.
_FAKE_CPULIMIT = """#!/bin/sh
echo "cpulimit-wrapper"
shift 3
exec "$@"
"""


def _sandbox(tmp_path: Path, *programs: str) -> LocalSandbox:
    workspace = tmp_path / "ws"
    workspace.mkdir(exist_ok=True)
    return LocalSandbox(workspace, allowed_programs=programs or ("python3",))


def _run(tmp_path: Path, argv: list[str], *, sandbox: LocalSandbox | None = None):
    sandbox = sandbox or _sandbox(tmp_path)
    return asyncio.run(sandbox.run(argv, timeout_seconds=30))


def _fake_cpulimit(tmp_path: Path) -> Path:
    directory = tmp_path / "bin"
    directory.mkdir(exist_ok=True)
    path = directory / "cpulimit"
    path.write_text(_FAKE_CPULIMIT, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return directory


def _niceness(pid: int) -> int:
    """Field 19 of ``/proc/<pid>/stat`` -the child's real nice value."""
    stat_text = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8")
    fields = stat_text[stat_text.rfind(")") + 1 :].split()
    return int(fields[16])


def test_a_child_runs_niced_by_default(tmp_path, monkeypatch):
    monkeypatch.delenv(hardware.NICE_ENV, raising=False)

    result = _run(tmp_path, ["python3", "-c", _NICENESS])

    assert result.exit_code == 0
    assert result.stdout.strip() == "10", "the kernel must see the nice level, not just argv"
    assert result.priority[0].endswith("nice")
    assert result.priority[1:3] == ("-n", "10")


def test_the_operator_can_change_or_disable_the_increment(tmp_path, monkeypatch):
    monkeypatch.setenv(hardware.NICE_ENV, "5")
    assert _run(tmp_path, ["python3", "-c", _NICENESS]).stdout.strip() == "5"

    monkeypatch.setenv(hardware.NICE_ENV, "0")
    disabled = _run(tmp_path, ["python3", "-c", _NICENESS])
    assert disabled.stdout.strip() == "0"
    assert disabled.priority == (), "level 0 means no prologue at all"


def test_the_policy_travels_to_the_child_environment(tmp_path, monkeypatch):
    """The ``john`` client inside ``crack_hash`` reads these to cap itself."""
    monkeypatch.setenv(hardware.NICE_ENV, "12")
    monkeypatch.setenv(hardware.CPU_LIMIT_ENV, "65")

    result = _run(tmp_path, ["python3", "-c", _ENV_REPORT])

    assert '"nice": "12"' in result.stdout
    assert '"cpu": "65"' in result.stdout


def test_a_cpu_heavy_tool_gets_the_cpulimit_ceiling(tmp_path, monkeypatch):
    bin_dir = _fake_cpulimit(tmp_path)
    monkeypatch.setenv("NEXUS_TOOL_BIN_DIR", str(bin_dir))
    monkeypatch.setenv(hardware.CPU_HEAVY_ENV, "python3")
    monkeypatch.setenv(hardware.CPU_LIMIT_ENV, "80")

    result = _run(tmp_path, ["python3", "-c", "print('hello')"])

    assert result.exit_code == 0
    assert "cpulimit-wrapper" in result.stdout, "the wrapper really ran in front of the tool"
    assert "hello" in result.stdout, "the tool still ran and its output survived"
    assert "-l" in result.priority and "80" in result.priority
    assert result.priority[-1] == "--"


def test_a_heavy_command_inside_a_shell_gets_capped(tmp_path, monkeypatch):
    """``shell.exec`` runs ``bash -lc "<command>"``: the command word decides."""
    bin_dir = _fake_cpulimit(tmp_path)
    monkeypatch.setenv("NEXUS_TOOL_BIN_DIR", str(bin_dir))
    monkeypatch.setenv(hardware.CPU_HEAVY_ENV, "echo")
    sandbox = _sandbox(tmp_path, "python3", "bash")

    result = _run(tmp_path, ["bash", "-lc", "echo via-shell"], sandbox=sandbox)

    assert result.exit_code == 0 and "via-shell" in result.stdout
    assert "cpulimit-wrapper" in result.stdout
    assert "-l" in result.priority and "80" in result.priority


def test_a_tool_that_is_not_cpu_heavy_gets_no_ceiling(tmp_path, monkeypatch):
    bin_dir = _fake_cpulimit(tmp_path)
    monkeypatch.setenv("NEXUS_TOOL_BIN_DIR", str(bin_dir))
    monkeypatch.delenv(hardware.CPU_HEAVY_ENV, raising=False)

    result = _run(tmp_path, ["python3", "-c", "print('hello')"])

    assert "cpulimit-wrapper" not in result.stdout
    assert result.priority[-1] == "10", "only nice was prepended"


def test_a_missing_cpulimit_never_stops_the_tool(tmp_path, monkeypatch):
    """``cpulimit`` is optional on most distros; the tool must still run.

    The absence is simulated on **PATH**, not on ``NEXUS_TOOL_BIN_DIR``: the
    sandbox's base PATH is ``/usr/local/bin:/usr/bin:/bin``, so on a host that
    happens to ship ``cpulimit`` the guard would never be exercised.
    """
    path_dir = tmp_path / "path"
    path_dir.mkdir()
    for program in ("python3", "nice"):
        resolved = shutil.which(program)
        assert resolved is not None, f"the test needs a real {program} to run"
        (path_dir / program).symlink_to(resolved)
    monkeypatch.setitem(sandbox_module.SANDBOX_BASE_ENV, "PATH", str(path_dir))
    monkeypatch.setenv(hardware.CPU_HEAVY_ENV, "python3")
    monkeypatch.setenv("NEXUS_TOOL_BIN_DIR", str(tmp_path / "does-not-exist"))

    result = _run(tmp_path, ["python3", "-c", "print('hello')"])

    assert result.exit_code == 0 and "hello" in result.stdout
    # Compare basenames: ``tmp_path`` itself contains the test's name.
    assert all(Path(entry).name != "cpulimit" for entry in result.priority)


def test_the_allowlist_is_checked_before_the_prologue(tmp_path):
    """Injecting a wrapper must never become a way to run a forbidden program."""
    with pytest.raises(PermissionError):
        _run(tmp_path, ["sh", "-c", "echo hola"])


def test_open_stdio_also_starts_the_child_niced(tmp_path, monkeypatch):
    monkeypatch.delenv(hardware.NICE_ENV, raising=False)
    sandbox = _sandbox(tmp_path)

    async def scenario() -> int:
        async with sandbox.open_stdio(
            ["python3", "-c", "import time;time.sleep(5)"], cwd="."
        ) as process:
            await asyncio.sleep(0.3)
            return _niceness(process.pid)

    assert asyncio.run(scenario()) == 10
