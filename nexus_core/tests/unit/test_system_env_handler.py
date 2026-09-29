import asyncio
from unittest.mock import patch
import pytest

from nexus_core.provisioner.detector import ToolStatus
from nexus_core.tests.msf_support import context
from nexus_core.tools.handlers import system_env as module
from nexus_core.tools.registry import durable_tool_definitions

pytestmark = pytest.mark.usefixtures("onboarding_env")


def run(arguments=None):
    return asyncio.run(module.check_env_handler(arguments or {}, context()))


def test_check_env_returns_os_and_managers():
    result = run()
    assert result.verified and "os" in result.output and "managers" in result.output


def test_check_env_checks_specific_tools_only():
    status = ToolStatus("nmap", True, "/bin/nmap", "7", ("apt",))
    with patch.object(module, "check_tool", return_value=status) as check:
        result = run({"tools": ["nmap"]})
    check.assert_called_once_with("nmap")
    assert list(result.output["tools"]) == ["nmap"]


def test_check_env_includes_version_when_present(onboarding_env):
    onboarding_env.which.return_value = "/bin/nmap"
    assert run({"tools": ["nmap"]}).output["tools"]["nmap"]["version"] == "tool 1.2.3"


def test_check_env_handles_tool_absent():
    assert not run({"tools": ["nmap"]}).output["tools"]["nmap"]["present"]


def test_check_env_never_executes_shell(onboarding_env):
    onboarding_env.which.return_value = "/bin/nmap"
    run({"tools": ["nmap"]})
    assert all(call.kwargs["shell"] is False for call in onboarding_env.run.call_args_list)


def test_check_env_registered_in_catalog():
    catalog = durable_tool_definitions()
    assert "nexus.system.check_env" in catalog
    assert {
        "nexus.exploit.msf_exploit",
        "nexus.session.list",
        "nexus.session.kill",
    } <= set(catalog)
    assert len(catalog) == 14
