from dataclasses import replace
from types import SimpleNamespace
import subprocess
import pytest

from nexus_core.provisioner.installer import execute_install, plan_install, update_shell_path

pytestmark = pytest.mark.usefixtures("onboarding_env")


@pytest.fixture
def managers(onboarding_env):
    onboarding_env.which.side_effect = lambda name: (
        "/usr/bin/" + name if name in {"apt", "go", "sudo", "env"} else None
    )
    return onboarding_env


def test_plan_install_builds_command_for_apt(managers):
    assert plan_install("nmap", "apt").command[-4:] == ("/usr/bin/apt", "install", "-y", "nmap")


def test_plan_install_sets_sudo_true_for_apt(managers):
    plan = plan_install("nmap", "apt")
    assert plan.requires_sudo and plan.command[:2] == ("/usr/bin/sudo", "-n")


def test_plan_install_prefers_go_when_user_install(managers):
    plan = plan_install("ffuf")
    assert plan.manager == "go"
    assert str(managers.home / ".local/bin") in plan.command[1]


def test_plan_install_rejects_unknown_tool(managers):
    with pytest.raises(ValueError):
        plan_install("nmap;cmd")


def test_plan_install_rejects_manager_not_supported(managers):
    with pytest.raises(ValueError):
        plan_install("nmap", "go")


def test_execute_install_dry_run_does_not_execute(managers):
    result = execute_install(plan_install("nmap"), dry_run=True)
    assert result.success and not result.verify_passed
    managers.run.assert_not_called()


def test_execute_install_runs_subprocess_with_timeout(managers):
    execute_install(plan_install("nmap"))
    kwargs = managers.run.call_args_list[0].kwargs
    assert kwargs["timeout"] == 600 and kwargs["shell"] is False


def test_execute_install_captures_stdout_stderr(managers):
    managers.run.return_value = SimpleNamespace(returncode=0, stdout="installed", stderr="notice")
    result = execute_install(plan_install("nmap"))
    assert (result.stdout, result.stderr) == ("installed", "notice")


def test_execute_install_verifies_after_success(managers):
    plan = plan_install("nmap")
    assert execute_install(plan).verify_passed
    assert managers.run.call_args_list[1].args[0] == list(plan.verify_command)


def test_execute_install_returns_failure_on_nonzero_exit(managers):
    managers.run.return_value.returncode = 1
    assert not execute_install(plan_install("nmap")).success
    assert managers.run.call_count == 1


def test_execute_install_timeout_returns_failure(managers):
    managers.run.side_effect = subprocess.TimeoutExpired("apt", 600)
    result = execute_install(plan_install("nmap"))
    assert not result.success and result.exit_code == 124


def test_update_shell_path_idempotent(managers):
    path = str(managers.home / "bin with space/nmap")
    assert update_shell_path(path, home=managers.home, shell="/bin/bash")
    assert not update_shell_path(path, home=managers.home, shell="/bin/bash")
    assert (managers.home / ".bashrc").read_text().count("omni provisioner") == 1


def test_update_shell_path_targets_zshrc_for_zsh(managers):
    # The rc file follows the login shell; pinning $SHELL keeps this deterministic.
    path = str(managers.home / "bin/nmap")
    assert update_shell_path(path, home=managers.home, shell="/usr/bin/zsh")
    assert (managers.home / ".zshrc").read_text().count("omni provisioner") == 1
    assert not (managers.home / ".bashrc").exists()


def test_update_shell_path_rejects_control_characters(managers):
    # The control character must live in a directory component, not the basename.
    with pytest.raises(ValueError):
        update_shell_path("/tmp/bad\ndir/nmap", home=managers.home, shell="/bin/bash")


def test_manufactured_plan_cannot_execute(managers):
    plan = replace(plan_install("nmap"), command=("sh", "-c", "anything"))
    with pytest.raises(ValueError):
        execute_install(plan)
    managers.run.assert_not_called()
