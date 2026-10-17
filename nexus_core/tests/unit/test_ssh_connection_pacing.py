"""Simple CTF fix: one SSH session at a time per target, then a quiet period.

Measured in Simple CTF: after ``user.txt`` the agent called ``enum_system`` and
then ``ssh_exec`` twice, seconds apart. Each handler opened its own session, the
server answered the second and third with ``Authentication failed``, and the
agent read that as a wrong password. The handlers now share a per-target gate:
the next connection waits for the previous one to finish *and* for
``SSH_CONNECT_COOLDOWN_SECONDS`` after it, so our own recon never arrives as a
burst of parallel logins.

These tests use the gate directly (fake sandbox, fake clock) so they stay
offline and do not spend a real second.
"""

from __future__ import annotations

import asyncio
import json
from unittest import mock

import pytest

from nexus_core.kernel.sandbox import SandboxResult
from nexus_core.tools.handlers import ssh_post as module

pytestmark = [pytest.mark.unit]

TARGET = "10.64.175.30"


class _RecordingSandbox:
    """Counts concurrent client runs and yields so overlap would be visible."""

    def __init__(self) -> None:
        self.calls = 0
        self.active = 0
        self.max_active = 0

    async def run(self, argv, *, timeout_seconds: float = 30):
        self.calls += 1
        self.active += 1
        self.max_active = max(self.max_active, self.active)
        try:
            await asyncio.sleep(0)
            return SandboxResult(
                0,
                json.dumps(
                    {"ok": True, "connected": True, "stdout": "", "stderr": "", "exit_status": 0}
                ) + "\n",
                "",
            )
        finally:
            self.active -= 1


def _client():
    return module._run_ssh_client(
        mode="exec",
        host=TARGET,
        port=22,
        username="lin",
        password="secret",
        payload={"command": "id", "command_timeout": 10},
        timeout_seconds=30,
    )


def _patched(sandbox):
    return mock.patch.object(module, "sandbox_for_environment", lambda *a, **k: sandbox)


def test_a_second_session_waits_the_cooldown(monkeypatch):
    sandbox = _RecordingSandbox()
    clock = [100.0]
    sleeps: list[float] = []

    async def fake_sleep(delay):
        if delay:
            sleeps.append(delay)
        clock[0] += delay

    monkeypatch.setattr(module, "SSH_CONNECT_COOLDOWN_SECONDS", 1.0)
    monkeypatch.setattr(module, "_now", lambda: clock[0])
    monkeypatch.setattr(module.asyncio, "sleep", fake_sleep)

    async def scenario():
        with _patched(sandbox):
            await _client()
            await _client()

    asyncio.run(scenario())

    assert sandbox.calls == 2
    # First connection: cold target, no wait. Second: exactly the quiet period.
    assert sleeps == [1.0]


def test_concurrent_sessions_to_the_same_target_are_serialized(monkeypatch):
    sandbox = _RecordingSandbox()
    monkeypatch.setattr(module, "SSH_CONNECT_COOLDOWN_SECONDS", 0.0)

    async def scenario():
        with _patched(sandbox):
            await asyncio.gather(_client(), _client())

    asyncio.run(scenario())

    assert sandbox.calls == 2
    assert sandbox.max_active == 1


def test_a_different_target_does_not_wait_for_another_ones_cooldown(monkeypatch):
    sandbox = _RecordingSandbox()
    clock = [100.0]
    sleeps: list[float] = []

    async def fake_sleep(delay):
        if delay:
            sleeps.append(delay)
        clock[0] += delay

    monkeypatch.setattr(module, "SSH_CONNECT_COOLDOWN_SECONDS", 1.0)
    monkeypatch.setattr(module, "_now", lambda: clock[0])
    monkeypatch.setattr(module.asyncio, "sleep", fake_sleep)

    async def scenario():
        with _patched(sandbox):
            await _client()
            await module._run_ssh_client(
                mode="exec", host="10.64.175.31", port=22, username="lin",
                password="secret", payload={"command": "id"}, timeout_seconds=30,
            )

    asyncio.run(scenario())

    assert sandbox.calls == 2
    assert sleeps == []
