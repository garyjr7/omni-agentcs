import asyncio
from unittest.mock import patch

import pytest

from nexus_core.integrations.metasploit.client import MetasploitUnavailable
from nexus_core.scope import ScopeViolation
from nexus_core.tests.msf_support import context, fake_client, gateway, scope
from nexus_core.tools.handlers import msf_auxiliary as module

ARGS = {"module": "auxiliary/scanner/smb/smb_version", "target": "203.0.113.10"}


def run(args=None):
    return asyncio.run(module.msf_auxiliary_handler(args or ARGS, context(scope())))


def test_requires_scope(tmp_path, monkeypatch):
    client = fake_client(monkeypatch, module)
    gw, audit = gateway(tmp_path)
    with pytest.raises(PermissionError):
        asyncio.run(gw.invoke("nexus.exploit.msf_auxiliary", ARGS, context()))
    assert module.msf_auxiliary_definition().scope_target_field == "target"
    client.execute_module.assert_not_awaited()
    assert any(e["action"] == "scope.denied" for e in audit.export("system"))


def test_out_of_scope_denied_and_audited(tmp_path, monkeypatch):
    client = fake_client(monkeypatch, module)
    gw, audit = gateway(tmp_path)
    with pytest.raises(ScopeViolation):
        asyncio.run(
            gw.invoke(
                "nexus.exploit.msf_auxiliary", {**ARGS, "target": "8.8.8.8"}, context(scope())
            )
        )
    client.authenticate.assert_not_awaited()
    assert any(
        e["action"] == "scope.denied" and e["decision"] == "deny" for e in audit.export("system")
    )


@pytest.mark.parametrize("name", ["exploit/windows/smb/x", "auxiliary/../exploit/x"])
def test_reject_non_auxiliary(monkeypatch, name):
    client = fake_client(monkeypatch, module)
    with pytest.raises(ValueError):
        run({**ARGS, "module": name})
    client.authenticate.assert_not_awaited()


@pytest.mark.parametrize("value", ["a;b", "a|b", "a&b", "`cmd`", "$(cmd)", {"nested": "a;b"}])
def test_reject_injection(monkeypatch, value):
    client = fake_client(monkeypatch, module)
    with pytest.raises(ValueError):
        run({**ARGS, "options": {"SMBUser": value}})
    client.execute_module.assert_not_awaited()


def test_threads_default_and_target_pinned(monkeypatch):
    client = fake_client(monkeypatch, module)
    assert run().success
    opts = client.execute_module.call_args.args[1]
    assert opts["THREADS"] == 1
    assert opts["RHOSTS"] == opts["RHOST"] == ARGS["target"]


@pytest.mark.parametrize(
    "options", [{"THREADS": 33}, {"THREADS": True}, {"RPORT": 0}, {"RPORT": 65536}]
)
def test_invalid_bounds(monkeypatch, options):
    client = fake_client(monkeypatch, module)
    with pytest.raises(ValueError):
        run({**ARGS, "options": options})
    client.execute_module.assert_not_awaited()


@pytest.mark.parametrize(
    "key", ["PROXIES", "Proxies", "LHOST", "LPORT", "rhosts", "RHOST", "SESSION"]
)
def test_forbidden_option_overrides(monkeypatch, key):
    client = fake_client(monkeypatch, module)
    with pytest.raises(ValueError):
        run({**ARGS, "options": {key: "203.0.113.200"}})
    client.execute_module.assert_not_awaited()


def test_polling_timeout_stops_job(monkeypatch):
    client = fake_client(monkeypatch, module)
    client.get_module_results.return_value = {"status": "running"}
    result = run({**ARGS, "timeout_seconds": 1})
    assert result.timed_out and not result.success
    client.stop_job.assert_awaited_once_with(42)
    client.aclose.assert_awaited_once()


def test_polling_success(monkeypatch):
    client = fake_client(monkeypatch, module)
    client.get_module_results.side_effect = [
        {"status": "running"},
        {"status": "completed", "result": None},
    ]
    with patch.object(module.asyncio, "sleep") as sleep:
        result = run()
    assert result.success and result.output["uuid"] == "fixture-uuid"
    sleep.assert_awaited_once_with(2)


def test_password_not_in_results_or_audit(tmp_path, monkeypatch, caplog):
    client = fake_client(monkeypatch, module)
    client.get_module_results.return_value = {
        "status": "completed",
        "result": client._config.password,
    }
    gw, audit = gateway(tmp_path)
    result = asyncio.run(gw.invoke("nexus.exploit.msf_auxiliary", ARGS, context(scope())))
    assert client._config.password not in str(result) + str(audit.export("system")) + caplog.text


def test_no_shell(monkeypatch):
    fake_client(monkeypatch, module)
    with (
        patch("subprocess.Popen", side_effect=AssertionError("no subprocess")),
        patch("asyncio.create_subprocess_exec", side_effect=AssertionError("no process")),
    ):
        assert run().success


def test_rpc_failure_no_poll_retry(monkeypatch):
    client = fake_client(monkeypatch, module)
    client.get_module_results.side_effect = MetasploitUnavailable("unavailable")
    assert not run().success
    client.get_module_results.assert_awaited_once()
    client.stop_job.assert_not_awaited()


def test_direct_handler_also_denies_scope(monkeypatch):
    client = fake_client(monkeypatch, module)
    with pytest.raises(ScopeViolation):
        run({**ARGS, "target": "8.8.8.8"})
    client.authenticate.assert_not_awaited()


def test_authentication_timeout(monkeypatch):
    client = fake_client(monkeypatch, module)

    async def slow_auth():
        await asyncio.sleep(10)

    client.authenticate.side_effect = slow_auth
    result = run({**ARGS, "timeout_seconds": 1})
    assert result.timed_out
    client.execute_module.assert_not_awaited()
    client.aclose.assert_awaited_once()


# This module's unsigned scopes exercise targeting/session behavior. Authentication
# is covered separately in test_scope_governed_mode with the governed default.
pytestmark = globals().get("pytestmark", [])
if not isinstance(pytestmark, list):
    pytestmark = [pytestmark]
pytestmark.append(pytest.mark.usefixtures("lab_scope"))
