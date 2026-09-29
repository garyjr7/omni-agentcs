import asyncio
from unittest.mock import patch
import pytest

from nexus_core.kernel.approvals import ApprovalService
from nexus_core.kernel.models import RiskLevel
from nexus_core.provisioner.installer import approval_action, plan_install
from nexus_core.tests.msf_support import context, gateway
from nexus_core.tools.handlers import system_install as module

pytestmark = pytest.mark.usefixtures("onboarding_env")


@pytest.fixture
def setup(onboarding_env, tmp_path):
    onboarding_env.which.side_effect = lambda name: (
        "/usr/bin/" + name if name in {"apt", "go", "sudo", "env"} else None
    )
    gw, audit = gateway(tmp_path)
    gw.approvals = ApprovalService(audit.store)
    return gw, context()


def authorized(setup, arguments):
    gw, ctx = setup
    plan = plan_install(arguments["tool_name"], arguments.get("manager"))
    row = gw.approvals.request(ctx, approval_action(plan, dry_run=arguments.get("dry_run", False)))
    gw.approvals.decide(row["id"], ctx.tenant_id, "separate-human", True)
    return asyncio.run(
        gw.invoke("nexus.system.install_tool", arguments, ctx, approval_id=row["id"])
    )


def test_install_tool_requires_approval(setup, onboarding_env):
    gw, ctx = setup
    assert module.install_tool_definition().risk == RiskLevel.HIGH
    with pytest.raises(PermissionError):
        asyncio.run(gw.invoke("nexus.system.install_tool", {"tool_name": "nmap"}, ctx))
    onboarding_env.run.assert_not_called()


def test_install_tool_dry_run_returns_plan(setup, onboarding_env):
    result = authorized(setup, {"tool_name": "nmap", "dry_run": True})
    assert result["verified"] and result["output"]["tool_name"] == "nmap"
    onboarding_env.run.assert_not_called()


def test_install_tool_builds_command_from_recipe(setup):
    result = authorized(setup, {"tool_name": "nmap"})
    assert result["evidence"]["command"][-1] == "nmap"


def test_install_tool_rejects_unknown_tool(setup):
    with pytest.raises(ValueError):
        authorized(setup, {"tool_name": "missing"})


def test_install_tool_rejects_manager_not_available(setup):
    with pytest.raises(ValueError):
        authorized(setup, {"tool_name": "nmap", "manager": "brew"})


def test_install_tool_verifies_after_install(setup):
    assert authorized(setup, {"tool_name": "nmap"})["evidence"]["verify_passed"]


def test_install_tool_updates_shell_path_if_needed(setup):
    with patch.object(module, "update_shell_path", return_value=True) as update:
        result = authorized(setup, {"tool_name": "ffuf", "manager": "go"})
    update.assert_called_once()
    assert result["output"]["path_updated"]


def test_install_tool_never_accepts_command_from_llm(setup):
    assert "command" not in module.install_tool_definition().input_schema["properties"]
    gw, ctx = setup
    with pytest.raises(ValueError):
        asyncio.run(
            gw.invoke(
                "nexus.system.install_tool", {"tool_name": "nmap", "command": "anything"}, ctx
            )
        )


def test_approval_cannot_authorize_different_plan(setup, onboarding_env):
    gw, ctx = setup
    row = gw.approvals.request(ctx, approval_action(plan_install("nmap")))
    gw.approvals.decide(row["id"], ctx.tenant_id, "human", True)
    with pytest.raises(PermissionError):
        asyncio.run(
            gw.invoke(
                "nexus.system.install_tool", {"tool_name": "ffuf"}, ctx, approval_id=row["id"]
            )
        )
    onboarding_env.run.assert_not_called()


def test_direct_handler_cannot_install_without_gateway(setup, onboarding_env):
    with pytest.raises(PermissionError):
        asyncio.run(module.install_tool_handler({"tool_name": "nmap"}, context()))
    onboarding_env.run.assert_not_called()


def test_dry_run_approval_cannot_install(setup):
    gw, ctx = setup
    row = gw.approvals.request(ctx, approval_action(plan_install("nmap"), dry_run=True))
    gw.approvals.decide(row["id"], ctx.tenant_id, "human", True)
    with pytest.raises(PermissionError):
        asyncio.run(
            gw.invoke(
                "nexus.system.install_tool", {"tool_name": "nmap"}, ctx, approval_id=row["id"]
            )
        )


def test_cli_displays_exact_plan_before_approval(setup, capsys):
    from types import SimpleNamespace
    from nexus_core.cli.approval import make_approval_callback
    from nexus_core.kernel.models import PolicyDecision

    gw, ctx = setup

    def reader(prompt):
        assert "/usr/bin/sudo -n /usr/bin/apt install -y nmap" in capsys.readouterr().out
        return "y"

    session = SimpleNamespace(
        input_reader=reader, operator_id="separate-human", build_run_context=lambda run_id: ctx
    )
    callback = make_approval_callback(session, gw.audit.store, ctx.tenant_id, ctx.run_id)
    decision = callback(
        "nexus.system.install_tool",
        {"tool_name": "nmap"},
        PolicyDecision(True, "test", "test", requires_approval=True),
    )
    assert decision.approved
    assert gw.approvals.verify(decision.approval_id, ctx, approval_action(plan_install("nmap")))
