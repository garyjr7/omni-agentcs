import asyncio
from unittest.mock import patch

import pytest

from nexus_core.integrations.metasploit.client import MetasploitUnavailable
from nexus_core.tests.msf_support import context, fake_client, gateway
from nexus_core.tools.handlers import msf_search as module


def run(args=None):
    return asyncio.run(module.msf_search_handler(args or {}, context()))


def test_missing_credentials(monkeypatch):
    monkeypatch.delenv("MSF_RPC_PASSWORD", raising=False)
    assert run().verification_method == "msf_credentials_missing"


def test_daemon_down(monkeypatch):
    client = fake_client(monkeypatch, module)
    client.authenticate.side_effect = MetasploitUnavailable("unavailable")
    assert not run().success
    client.search_modules.assert_not_awaited()
    assert client.authenticate.await_count == 1


def test_success(monkeypatch):
    client = fake_client(monkeypatch, module)
    result = run({"query": "ms17-010"})
    assert result.success and result.output["count"] == 1
    client.search_modules.assert_awaited_once_with(query="ms17-010")


def test_gateway_does_not_require_scope(tmp_path, monkeypatch):
    fake_client(monkeypatch, module)
    gw, audit = gateway(tmp_path)
    result = asyncio.run(gw.invoke("nexus.exploit.msf_search", {}, context()))
    assert result["verified"]
    assert not module.msf_search_definition().scope_required
    assert any(event["action"] == "tool.complete" for event in audit.export("system"))


@pytest.mark.parametrize("limit", [0, 101, True])
def test_limit_rejected_before_rpc(monkeypatch, limit):
    client = fake_client(monkeypatch, module)
    with pytest.raises(ValueError):
        run({"limit": limit})
    client.authenticate.assert_not_awaited()


def test_no_shell(monkeypatch):
    fake_client(monkeypatch, module)
    with (
        patch("subprocess.Popen", side_effect=AssertionError("no subprocess")),
        patch("asyncio.create_subprocess_exec", side_effect=AssertionError("no process")),
    ):
        assert run({"query": "smb; arbitrary catalog text"}).success


def test_credentials_redacted_from_output(monkeypatch):
    client = fake_client(monkeypatch, module)
    client.search_modules.return_value = [
        {"fullname": "auxiliary/a", "name": client._config.password}
    ]
    assert client._config.password not in str(run().to_dict())


def test_invalid_cve(monkeypatch):
    client = fake_client(monkeypatch, module)
    with pytest.raises(ValueError):
        run({"cve": "wrong"})
    client.authenticate.assert_not_awaited()
