"""V9 (Hijack): passive waits are refused before anything runs.

The measured defect: the agent executed ``sleep 170`` to wait for a reverse
shell. Nothing changed on the target, one turn and its tokens were gone, and
the run still had no session. These tests pin the *order* (the wait is refused
before the sandbox is even reached) and the *vocabulary* (``outcome="denied"``
with the replacement tools in the observation).
"""

from __future__ import annotations

import asyncio

import pytest

from nexus_core.cli.engage import build_scope
from nexus_core.kernel.control_store import ControlStore
from nexus_core.kernel.models import Identity, RunContext
from nexus_core.scope import EngagementStore
from nexus_core.tools.handlers import shell_exec_local as local_shell
from nexus_core.tools.handlers.shell_exec_local import shell_exec_handler
from nexus_core.tools.passive_wait import (
    PASSIVE_WAIT_GUIDANCE,
    duration_seconds,
    passive_wait_reason,
)

SECRET = "test-signing-secret"
TARGET = "10.10.10.5"


@pytest.fixture()
def context(tmp_path, monkeypatch):
    monkeypatch.setenv("NEXUS_SCOPE_SIGNING_SECRET", SECRET)
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(workspace))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    store = ControlStore(tmp_path / "control.db")
    store.initialize()
    scope = EngagementStore(store).create(build_scope("bench", f"{TARGET}/32", SECRET))
    return RunContext(
        "system",
        Identity("operator-1", "system", roles=("operator",)),
        store=store,
        scope=scope,
        project_root=str(workspace),
        run_id="run-passive-wait",
    )


# ------------------------------------------------------------------ detector
@pytest.mark.parametrize(
    "command,expected",
    [
        ("sleep 170", "sleep"),
        ("sleep 1", "sleep"),
        ("/bin/sleep 30", "sleep"),
        ("FOO=1 sleep 5", "sleep"),
        ("echo hola; sleep 10; id", "sleep"),
        ("wait", "wait"),
        ("bash -c 'sleep 170'", "sleep"),
        ("timeout 170 nc -lvnp 4444", "timeout 170"),
        ("timeout 10.5s id", "timeout 10.5s"),
        ("timeout 5 id", None),
        ("timeout 10 id", None),
        ("echo 'sleep 170'", None),
        ("grep sleep log.txt", None),
        ("nmap -p- -Pn 10.10.10.5", None),
        # A backgrounded wait returns at once with a PID (and a delayed callback
        # is a real technique), so it is not a passive wait.
        ("sleep 30 &", None),
        ("(sleep 30; curl http://x) &", None),
        ("nohup sleep 30", "sleep"),
    ],
)
def test_passive_wait_detection(command, expected):
    assert passive_wait_reason(command) == expected


def test_a_background_wait_is_allowed_but_a_foreground_one_is_not():
    assert passive_wait_reason("sleep 5 &") is None
    assert passive_wait_reason("sleep 5 && echo ok") == "sleep"
    assert passive_wait_reason("sleep 5") == "sleep"


def test_duration_units_are_seconds():
    assert duration_seconds("10") == 10
    assert duration_seconds("2m") == 120
    assert duration_seconds("1h") == 3600
    assert duration_seconds("nope") is None


# ------------------------------------------------------------------- handler
def test_shell_exec_refuses_a_wait_without_reaching_the_sandbox(context, monkeypatch):
    def _explode(*_args, **_kwargs):
        raise AssertionError("a passive wait must not reach the sandbox")

    monkeypatch.setattr(local_shell, "sandbox_for_environment", _explode)
    result = asyncio.run(shell_exec_handler({"command": "sleep 170"}, context))

    assert result.outcome == "denied"
    assert result.verification_method == "shell_passive_wait_denied"
    assert result.verified is False
    assert result.evidence["wait"] == "sleep"
    assert result.output["guidance"] == PASSIVE_WAIT_GUIDANCE
    assert "nexus.post.listener" in result.output["guidance"]


def test_shell_exec_still_allows_a_real_command(context):
    result = asyncio.run(shell_exec_handler({"command": "echo hola"}, context))
    assert result.verified is True
    assert result.outcome in ("", None)
