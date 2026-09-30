"""Write/read primitives and ``run_in_session`` of the Metasploit client.

Every RPC goes through ``httpx.MockTransport``; ``asyncio.sleep`` is patched so
the polling loop is deterministic. Session RPCs are keyed by the numeric sid, so
the client resolves the uuid through ``session.list`` first.
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, patch

import httpx
import msgpack
import pytest

from nexus_core.integrations.metasploit import client as client_module
from nexus_core.integrations.metasploit.client import (
    MetasploitClient,
    MetasploitConfig,
    MetasploitError,
)

CREDENTIAL = "fixture-credential"
TOKEN = "fixture-token"
UUID = "sess-1"
SID = "3"


def session_list(*, kind: str = "shell", present: bool = True) -> dict:
    if not present:
        return {}
    return {SID: {"uuid": UUID, "type": kind, "session_host": "127.0.0.1"}}


def responder(**routes):
    """Bind ``method -> callable(params)``, allowing raw ``httpx.Response``."""

    def handler(request: httpx.Request) -> httpx.Response:
        args = msgpack.unpackb(request.content, raw=False)
        method = args[0]
        if method == "auth.login":
            return response({"result": "success", "token": TOKEN})
        assert args[1] == TOKEN, "session calls must carry the auth token"
        route = routes.get(method)
        if route is None:
            raise AssertionError(f"unexpected RPC method {method}")
        result = route(args[2:])
        return result if isinstance(result, httpx.Response) else response(result)

    return handler


def response(data, status: int = 200) -> httpx.Response:
    return httpx.Response(status, content=msgpack.packb(data, use_bin_type=True))


def make_client(handler) -> MetasploitClient:
    return MetasploitClient(
        MetasploitConfig("http://127.0.0.1:55552", "msf", CREDENTIAL),
        transport=httpx.MockTransport(handler),
    )


def test_write_meterpreter_appends_newline():
    seen = []

    async def run():
        routes = {
            "session.list": lambda p: session_list(kind="meterpreter"),
            "session.meterpreter_write": lambda p: seen.append(p) or {"result": "success"},
        }
        async with make_client(responder(**routes)) as rpc:
            assert await rpc.write_meterpreter(UUID, "sysinfo") is True

    asyncio.run(run())
    assert seen == [[SID, "sysinfo\n"]]


def test_write_meterpreter_idempotent_newline():
    seen = []

    async def run():
        routes = {
            "session.list": lambda p: session_list(kind="meterpreter"),
            "session.meterpreter_write": lambda p: seen.append(p) or {"result": "success"},
        }
        async with make_client(responder(**routes)) as rpc:
            await rpc.write_meterpreter(UUID, "sysinfo\n")

    asyncio.run(run())
    assert seen == [[SID, "sysinfo\n"]], "a single newline must be appended"


def test_write_meterpreter_session_not_found():
    calls = []

    async def run():
        routes = {"session.list": lambda p: calls.append(p) or session_list(present=False)}
        async with make_client(responder(**routes)) as rpc:
            with pytest.raises(MetasploitError):
                await rpc.write_meterpreter(UUID, "sysinfo")

    asyncio.run(run())
    assert len(calls) == 1


def test_read_meterpreter_returns_pending_output():
    async def run():
        routes = {
            "session.list": lambda p: session_list(kind="meterpreter"),
            "session.meterpreter_read": lambda p: {"data": "Computer: WIN-DC-01\n"},
        }
        async with make_client(responder(**routes)) as rpc:
            assert await rpc.read_meterpreter(UUID) == "Computer: WIN-DC-01\n"

    asyncio.run(run())


def test_read_meterpreter_empty_when_no_data():
    async def run():
        routes = {
            "session.list": lambda p: session_list(kind="meterpreter"),
            "session.meterpreter_read": lambda p: {"data": ""},
        }
        async with make_client(responder(**routes)) as rpc:
            assert await rpc.read_meterpreter(UUID) == ""

    asyncio.run(run())


def test_read_meterpreter_session_dead_raises():
    async def run():
        routes = {
            "session.list": lambda p: session_list(kind="meterpreter"),
            "session.meterpreter_read": lambda p: httpx.Response(500, content=b""),
        }
        async with make_client(responder(**routes)) as rpc:
            with pytest.raises(MetasploitError):
                await rpc.read_meterpreter(UUID)

    asyncio.run(run())


def test_write_shell_same_semantics():
    seen = []

    async def run():
        routes = {
            "session.list": lambda p: session_list(kind="shell"),
            "session.shell_write": lambda p: seen.append(p) or {"write_count": "4"},
        }
        async with make_client(responder(**routes)) as rpc:
            assert await rpc.write_shell(UUID, "id") is True
            assert await rpc.write_shell(UUID, "whoami\n") is True

    asyncio.run(run())
    assert seen == [[SID, "id\n"], [SID, "whoami\n"]]


def test_read_shell_returns_pending_output():
    reads = {"n": 0}

    def shell_read(params):
        reads["n"] += 1
        return {"seq": 0, "data": "uid=0(root) gid=0(root)\n" if reads["n"] == 1 else ""}

    async def run():
        routes = {
            "session.list": lambda p: session_list(kind="shell"),
            "session.shell_read": shell_read,
        }
        async with make_client(responder(**routes)) as rpc:
            assert "uid=0" in await rpc.read_shell(UUID)
            assert await rpc.read_shell(UUID) == ""

    asyncio.run(run())


def test_run_in_session_collects_output_until_quiet():
    reads = []

    def shell_read(params):
        reads.append(1)
        return {"seq": 0, "data": "uid=1000(x) gid=1000(x)\n" if len(reads) == 1 else ""}

    async def run():
        routes = {
            "session.list": lambda p: session_list(kind="shell"),
            "session.shell_write": lambda p: {"write_count": "3"},
            "session.shell_read": shell_read,
        }
        async with make_client(responder(**routes)) as rpc:
            with patch.object(client_module.asyncio, "sleep", new=AsyncMock()) as sleep:
                result = await rpc.run_in_session(UUID, "id")
        assert result["status"] == "ok"
        assert "uid=1000" in result["output"]
        assert result["bytes"] == len(result["output"].encode())
        assert result["duration_seconds"] >= 0
        assert sleep.await_count == 8  # ceil(1.5 / 0.2) quiet polls

    asyncio.run(run())


def test_run_in_session_timeout_returns_partial_output():
    counter = {"n": 0}

    def shell_read(params):
        counter["n"] += 1
        return {"seq": 0, "data": f"chunk{counter['n']}\n"}

    async def run():
        routes = {
            "session.list": lambda p: session_list(kind="shell"),
            "session.shell_write": lambda p: {"write_count": "3"},
            "session.shell_read": shell_read,
        }
        async with make_client(responder(**routes)) as rpc:
            with patch.object(client_module.asyncio, "sleep", new=AsyncMock()):
                result = await rpc.run_in_session(
                    UUID, "cat huge.log", max_wait_seconds=2, poll_interval_seconds=0.2
                )
        assert result["status"] == "timeout"
        assert result["output"].startswith("chunk1\n")
        assert counter["n"] == 10  # ceil(2 / 0.2) attempts

    asyncio.run(run())


def test_run_in_session_detects_session_death_during_polling():
    calls = {"n": 0}

    def listing(params):
        calls["n"] += 1
        return session_list(present=calls["n"] <= 2)

    async def run():
        routes = {
            "session.list": listing,
            "session.shell_write": lambda p: {"write_count": "3"},
            "session.shell_read": lambda p: {"seq": 0, "data": "late\n"},
        }
        async with make_client(responder(**routes)) as rpc:
            with patch.object(client_module.asyncio, "sleep", new=AsyncMock()):
                result = await rpc.run_in_session(UUID, "id")
        assert result["status"] == "session_dead"

    asyncio.run(run())


def test_run_in_session_session_gone_before_write():
    """A session that vanished before the write is reported, not raised."""

    async def run():
        routes = {"session.list": lambda p: session_list(present=False)}
        async with make_client(responder(**routes)) as rpc:
            result = await rpc.run_in_session(UUID, "id")
        assert result["status"] == "session_dead"
        assert result["output"] == ""

    asyncio.run(run())


def test_run_in_session_write_failure_is_session_dead():
    async def run():
        routes = {
            "session.list": lambda p: session_list(kind="shell"),
            "session.shell_write": lambda p: httpx.Response(500, content=b""),
        }
        async with make_client(responder(**routes)) as rpc:
            result = await rpc.run_in_session(UUID, "id")
        assert result["status"] == "session_dead"

    asyncio.run(run())


def test_run_in_session_respects_max_wait():
    async def run():
        routes = {
            "session.list": lambda p: session_list(kind="shell"),
            "session.shell_write": lambda p: {"write_count": "3"},
            "session.shell_read": lambda p: {"seq": 0, "data": ""},
        }
        async with make_client(responder(**routes)) as rpc:
            with patch.object(client_module.asyncio, "sleep", new=AsyncMock()) as sleep:
                result = await rpc.run_in_session(
                    UUID, "sleep 300", max_wait_seconds=1, poll_interval_seconds=0.5
                )
        assert result["status"] == "timeout"
        assert len(sleep.await_args_list) == 1  # ceil(1 / 0.5) attempts, one sleep

    asyncio.run(run())


def test_run_in_session_cancellable_via_asyncio_cancel():
    async def run():
        routes = {
            "session.list": lambda p: session_list(kind="shell"),
            "session.shell_write": lambda p: {"write_count": "3"},
            "session.shell_read": lambda p: {"seq": 0, "data": ""},
        }
        async with make_client(responder(**routes)) as rpc:
            task = asyncio.create_task(
                rpc.run_in_session(
                    UUID, "sleep 300", max_wait_seconds=30, poll_interval_seconds=0.05
                )
            )
            await asyncio.sleep(0.02)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task

    asyncio.run(run())


@pytest.mark.parametrize(
    "kind,expected",
    [("shell", "shell"), ("powershell", "shell"), ("meterpreter", "meterpreter")],
)
def test_run_in_session_determines_session_type_from_list(kind, expected):
    seen: list[str] = []
    reads = {"n": 0}

    def make_read(prefix: str):
        def read(_params):
            reads["n"] += 1
            seen.append(f"{prefix}_read")
            return {"seq": 0, "data": "x\n"} if reads["n"] == 1 else {"seq": 0, "data": ""}

        return read

    async def run():
        routes = {
            "session.list": lambda p: session_list(kind=kind),
            "session.shell_write": lambda p: seen.append("shell_write") or {"write_count": "3"},
            "session.shell_read": make_read("shell"),
            "session.meterpreter_write": lambda p: (
                seen.append("meterpreter_write") or {"result": "success"}
            ),
            "session.meterpreter_read": make_read("meterpreter"),
        }
        async with make_client(responder(**routes)) as rpc:
            with patch.object(client_module.asyncio, "sleep", new=AsyncMock()):
                result = await rpc.run_in_session(UUID, "id")
        assert result["status"] == "ok"
        assert seen[0] == f"{expected}_write", seen
        assert f"{expected}_read" in seen
        other = "meterpreter" if expected == "shell" else "shell"
        assert f"{other}_write" not in seen and f"{other}_read" not in seen

    asyncio.run(run())


@pytest.mark.parametrize(
    "kwargs",
    [
        {"quiet_seconds": 0},
        {"quiet_seconds": 61},
        {"max_wait_seconds": 0},
        {"poll_interval_seconds": 0},
        {"poll_interval_seconds": 11},
    ],
)
def test_run_in_session_rejects_bad_bounds(kwargs):
    async def run():
        async with make_client(responder()) as rpc:
            with pytest.raises(ValueError):
                await rpc.run_in_session(UUID, "id", **kwargs)

    asyncio.run(run())


@pytest.mark.parametrize("command", ["", None, 5])
def test_write_rejects_empty_command(command):
    async def run():
        async with make_client(responder(**{"session.list": lambda p: session_list()})) as rpc:
            with pytest.raises(ValueError):
                await rpc.write_shell(UUID, command)

    asyncio.run(run())
