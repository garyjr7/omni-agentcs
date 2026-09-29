"""Session lifecycle and exploit polling of the Metasploit RPC client.

Every RPC goes through ``httpx.MockTransport``; ``session.list`` must be called
with an empty *list* of params (a dict there dies before reaching the daemon).
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
    MetasploitUnavailable,
)

CREDENTIAL = "fixture-credential"
TOKEN = "fixture-token"

METERPRETER = {
    "type": "meterpreter",
    "tunnel_local": "203.0.113.10:4444",
    "tunnel_peer": "203.0.113.10:41234",
    "via_exploit": "exploit/windows/smb/ms17_010_eternalblue",
    "via_payload": "windows/x64/meterpreter/reverse_tcp",
    "session_host": "203.0.113.10",
    "session_port": 445,
    "target_host": "203.0.113.10",
    "username": "NT AUTHORITY\\SYSTEM",
    "info": "Windows 7 x64",
    "uuid": "sess-1",
}
SHELL = {
    "type": "shell",
    "tunnel_local": "203.0.113.10:4444",
    "tunnel_peer": "203.0.113.11:51234",
    "via_exploit": "exploit/multi/script/web_delivery",
    "via_payload": "cmd/unix/reverse",
    "session_host": "203.0.113.11",
    "session_port": 8080,
    "target_host": "203.0.113.11",
    "username": "www-data",
    "info": "Unix shell",
    "uuid": "sess-2",
}


def responder(**routes):
    """Build a MockTransport bound to ``method -> callable(params)``."""
    def handler(request: httpx.Request) -> httpx.Response:
        args = msgpack.unpackb(request.content, raw=False)
        method = args[0]
        if method == "auth.login":
            assert args[1:] == ["msf", CREDENTIAL]
            return payload({"result": "success", "token": TOKEN})
        assert args[1] == TOKEN, "session calls must carry the auth token"
        route = routes.get(method)
        if route is None:
            raise AssertionError(f"unexpected RPC method {method}")
        return payload(route(args[2:]))

    return handler


def payload(data, status: int = 200) -> httpx.Response:
    return httpx.Response(status, content=msgpack.packb(data, use_bin_type=True))


def make_client(handler) -> MetasploitClient:
    return MetasploitClient(
        MetasploitConfig("http://127.0.0.1:55552", "msf", CREDENTIAL),
        transport=httpx.MockTransport(handler),
    )


def test_list_sessions_empty():
    seen = []

    async def run():
        async with make_client(responder(**{"session.list": lambda p: seen.append(p) or {}})) as rpc:
            assert await rpc.list_sessions() == {}

    asyncio.run(run())
    assert seen == [[]], "session.list must be called with an empty params list"


def test_list_sessions_with_meterpreter():
    found = {}

    async def run():
        routes = {"session.list": lambda p: {"1": METERPRETER}}
        async with make_client(responder(**routes)) as rpc:
            found.update(await rpc.list_sessions())

    asyncio.run(run())
    assert set(found) == {"1"}
    assert found["1"]["type"] == "meterpreter"
    assert found["1"]["via_payload"] == "windows/x64/meterpreter/reverse_tcp"


def test_list_sessions_with_shell():
    found = {}

    async def run():
        async with make_client(responder(**{"session.list": lambda p: {"2": SHELL}})) as rpc:
            found.update(await rpc.list_sessions())

    asyncio.run(run())
    assert found["2"]["type"] == "shell"
    assert found["2"]["session_port"] == 8080


def test_stop_session_success():
    seen = []

    async def run():
        routes = {"session.stop": lambda params: seen.append(params) or {"result": "success"}}
        async with make_client(responder(**routes)) as rpc:
            assert await rpc.stop_session("sess-1") == {"result": "success"}

    asyncio.run(run())
    assert seen == [["sess-1"]]


@pytest.mark.parametrize("uuid", ["", "a b", "x" * 65, "sess;drop", None])
def test_stop_session_invalid_uuid(uuid):
    calls = []

    async def run():
        async with make_client(responder()) as rpc:
            with pytest.raises(ValueError):
                await rpc.stop_session(uuid)

    asyncio.run(run())
    assert calls == []


def test_execute_exploit_opens_session():
    state = {"sessions": 0}

    def session_list(params):
        state["sessions"] += 1
        # baseline, then one empty poll, then the new session.
        return {} if state["sessions"] < 3 else {"sess-9": METERPRETER}

    async def run():
        routes = {
            "module.execute": lambda p: {"job_id": 7, "uuid": "job-uuid"},
            "module.results": lambda p: {"status": "running"},
            "session.list": session_list,
        }
        async with make_client(responder(**routes)) as rpc:
            with patch.object(client_module.asyncio, "sleep", new=AsyncMock()) as sleep:
                result = await rpc.execute_exploit(
                    "exploit/windows/smb/ms17_010_eternalblue", {"RPORT": 445}
                )
        assert result["status"] == "session_opened"
        assert result["session_uuid"] == "sess-9"
        assert result["session"]["type"] == "meterpreter"
        assert result["job_uuid"] == "job-uuid"
        assert result["duration_seconds"] >= 0
        assert sleep.await_count == 1

    asyncio.run(run())


def test_execute_exploit_timeout():
    async def run():
        routes = {
            "module.execute": lambda p: {"job_id": 7, "uuid": "job-uuid"},
            "module.results": lambda p: {"status": "running"},
            "session.list": lambda p: {},
        }
        async with make_client(responder(**routes)) as rpc:
            with patch.object(client_module.asyncio, "sleep", new=AsyncMock()):
                result = await rpc.execute_exploit(
                    "exploit/windows/smb/ms17_010_eternalblue",
                    {"RPORT": 445},
                    wait_for_session_seconds=1,
                    poll_interval_seconds=0.5,
                )
        assert result["status"] == "timeout"
        assert result["job_id"] == 7 and result["job_uuid"] == "job-uuid"

    asyncio.run(run())


def test_execute_exploit_job_fails():
    async def run():
        routes = {
            "module.execute": lambda p: {"job_id": 7, "uuid": "job-uuid"},
            "module.results": lambda p: {"status": "errored", "error": "exploit failed"},
            "session.list": lambda p: {},
        }
        async with make_client(responder(**routes)) as rpc:
            with patch.object(client_module.asyncio, "sleep", new=AsyncMock()):
                result = await rpc.execute_exploit(
                    "exploit/windows/smb/ms17_010_eternalblue", {"RPORT": 445}
                )
        assert result["status"] == "failed"
        assert "exploit failed" in result["error"]

    asyncio.run(run())


@pytest.mark.parametrize(
    "kwargs",
    [
        {"wait_for_session_seconds": 0},
        {"wait_for_session_seconds": 3601},
        {"poll_interval_seconds": 0},
        {"poll_interval_seconds": 61},
    ],
)
def test_execute_exploit_rejects_bad_bounds(kwargs):
    async def run():
        async with make_client(responder()) as rpc:
            with pytest.raises(ValueError):
                await rpc.execute_exploit("exploit/multi/handler", {}, **kwargs)

    asyncio.run(run())


def test_execute_exploit_polls_at_interval():
    sleeps = []

    async def fake_sleep(seconds):
        sleeps.append(seconds)

    async def run():
        routes = {
            "module.execute": lambda p: {"job_id": 7, "uuid": "job-uuid"},
            "module.results": lambda p: {"status": "running"},
            "session.list": lambda p: {},
        }
        async with make_client(responder(**routes)) as rpc:
            with patch.object(client_module.asyncio, "sleep", new=fake_sleep):
                result = await rpc.execute_exploit(
                    "exploit/multi/handler",
                    {"PAYLOAD": "generic/shell_reverse_tcp"},
                    wait_for_session_seconds=2,
                    poll_interval_seconds=2,
                )
        assert result["status"] == "timeout"

    asyncio.run(run())
    assert sleeps == [2.0]


def test_execute_exploit_propagates_transport_failure():
    async def run():
        def boom(request):
            raise httpx.ConnectError("daemon down")

        with pytest.raises(MetasploitUnavailable):
            async with make_client(boom) as rpc:
                await rpc.execute_exploit("exploit/multi/handler", {})

    asyncio.run(run())
