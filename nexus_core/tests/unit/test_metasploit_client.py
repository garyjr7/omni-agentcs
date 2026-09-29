import asyncio
import json

import httpx
import msgpack
import pytest

from nexus_core.integrations.metasploit.client import (
    MetasploitAuthError,
    MetasploitClient,
    MetasploitConfig,
    MetasploitError,
    MetasploitUnavailable,
)


def client(handler, transport="msgpack"):
    return MetasploitClient(
        MetasploitConfig(
            "http://127.0.0.1:55552", "msf", "fixture-credential", transport=transport
        ),
        transport=httpx.MockTransport(handler),
    )


def response(data, status=200):
    return httpx.Response(status, content=msgpack.packb(data, use_bin_type=True))


def login(request):
    assert request.url.path == "/api/"
    assert request.headers["Content-Type"] == "binary/message-pack"
    assert msgpack.unpackb(request.content, raw=False) == [
        "auth.login",
        "msf",
        "fixture-credential",
    ]
    return response({b"result": b"success", b"token": b"fixture-token"})


def test_config_defaults(monkeypatch):
    for key in ("URL", "USER", "PASSWORD", "TRANSPORT"):
        monkeypatch.delenv("MSF_RPC_" + key, raising=False)
    config = MetasploitConfig.from_env()
    assert (config.url, config.user, config.password, config.transport) == (
        "http://127.0.0.1:55552",
        "msf",
        "",
        "msgpack",
    )


def test_config_overrides(monkeypatch):
    for key, value in {
        "URL": "https://localhost:1234",
        "USER": "operator",
        "PASSWORD": "fixture-credential",
        "TRANSPORT": "JSON",
    }.items():
        monkeypatch.setenv("MSF_RPC_" + key, value)
    config = MetasploitConfig.from_env()
    assert config.url == "https://localhost:1234" and config.transport == "json"
    assert config.user == "operator" and config.password == "fixture-credential"
    assert config.password not in repr(config)


def test_auth_success_binary_strings():
    async def run():
        async with client(login) as rpc:
            assert rpc._token == "fixture-token"
        assert rpc._client.is_closed

    asyncio.run(run())


@pytest.mark.parametrize("data", [{"result": "failure"}, {"result": "success"}])
def test_auth_failure_closes_client(data):
    rpc = client(lambda request: response(data))

    async def run():
        with pytest.raises(MetasploitAuthError):
            async with rpc:
                pass
        assert rpc._client.is_closed

    asyncio.run(run())


def test_unavailable_no_retry():
    calls = []

    def handler(request):
        calls.append(request)
        raise httpx.ConnectError("fixture-credential")

    async def run():
        with pytest.raises(MetasploitUnavailable, match="unavailable") as error:
            async with client(handler):
                pass
        assert "fixture-credential" not in str(error.value)

    asyncio.run(run())
    assert len(calls) == 1


@pytest.mark.parametrize("status,exc", [(503, MetasploitError), (401, MetasploitAuthError)])
def test_http_error(status, exc):
    async def run():
        with pytest.raises(exc):
            async with client(lambda request: response({}, status)):
                pass

    asyncio.run(run())


def test_rpc_error_sanitized():
    async def run():
        with pytest.raises(MetasploitError) as error:
            async with client(
                lambda r: response({"error": True, "error_message": "fixture-credential"})
            ):
                pass
        assert "fixture-credential" not in str(error.value)

    asyncio.run(run())


@pytest.mark.parametrize("limit,expected", [(50, 3), (1, 1)])
def test_search_and_truncation(limit, expected):
    def handler(request):
        args = msgpack.unpackb(request.content, raw=False)
        if args[0] == "auth.login":
            return login(request)
        assert args == [
            "module.search",
            "fixture-token",
            "smb type:auxiliary platform:windows cve:CVE-2017-0144",
        ]
        return response([{"fullname": "auxiliary/scanner/smb/smb_version"}] * 3)

    async def run():
        async with client(handler) as rpc:
            result = await rpc.search_modules(
                "smb", module_type="auxiliary", platform="windows", cve="CVE-2017-0144", limit=limit
            )
            assert len(result) == expected

    asyncio.run(run())


def test_execute_strips_type_and_results_preserve_completed_payload():
    def handler(request):
        args = msgpack.unpackb(request.content, raw=False)
        if args[0] == "auth.login":
            return login(request)
        if args[0] == "module.execute":
            assert args[2:] == ["auxiliary", "scanner/smb/smb_version", {"RHOSTS": "203.0.113.1"}]
            return response({"job_id": 1, "uuid": "u"})
        assert args == ["module.results", "fixture-token", "u"]
        return response({"status": "completed", "result": None})

    async def run():
        async with client(handler) as rpc:
            assert (
                await rpc.execute_module(
                    "auxiliary/scanner/smb/smb_version", {"RHOSTS": "203.0.113.1"}
                )
            )["uuid"] == "u"
            assert (await rpc.get_module_results("u"))["status"] == "completed"

    asyncio.run(run())


def test_availability_false():
    def handler(request):
        raise httpx.ReadTimeout("timed out")

    async def run():
        rpc = client(handler)
        try:
            assert await rpc.is_available() is False
        finally:
            await rpc.aclose()

    asyncio.run(run())


def test_module_type():
    assert MetasploitClient._module_type("auxiliary/scanner/smb/smb_version") == "auxiliary"
    assert MetasploitClient._module_type("exploit/windows/smb/example") == "exploit"
    for name in ("smb", "unknown/foo", "auxiliary/../foo", "auxiliary/foo;cmd"):
        with pytest.raises(MetasploitError):
            MetasploitClient._module_type(name)


def test_json_bearer_transport():
    def handler(request):
        assert request.headers["Authorization"] == "Bearer fixture-credential"
        assert request.url.path == "/api/v1/json-rpc"
        data = json.loads(request.content)
        assert data["params"] == []
        return httpx.Response(
            200, json={"jsonrpc": "2.0", "id": data["id"], "result": {"version": "6.5"}}
        )

    async def run():
        async with client(handler, "json") as rpc:
            assert await rpc.is_available()

    asyncio.run(run())


def test_malformed_response():
    async def run():
        with pytest.raises(MetasploitError):
            async with client(lambda r: httpx.Response(200, content=b"not msgpack")):
                pass

    asyncio.run(run())
