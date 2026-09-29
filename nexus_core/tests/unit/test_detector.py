from unittest.mock import patch
from types import SimpleNamespace
import pytest
from nexus_core.provisioner import detector as d
from nexus_core.provisioner.recipes import load_recipes

pytestmark = pytest.mark.usefixtures("onboarding_env")


def test_detect_os_returns_linux_on_linux():
    with patch.object(d.platform, "system", return_value="Linux"):
        assert d.detect_os().system == "Linux"


def test_detect_managers_includes_apt_when_present(onboarding_env):
    onboarding_env.which.side_effect = lambda name: "/bin/apt" if name == "apt" else None
    with patch.object(d.platform, "system", return_value="Linux"):
        assert d.detect_managers() == ("apt",)


def test_check_tool_present(onboarding_env):
    onboarding_env.which.return_value = "/bin/nmap"
    assert d.check_tool("nmap").present


def test_check_tool_absent(onboarding_env):
    assert not d.check_tool("nmap").present
    onboarding_env.run.assert_not_called()


def test_check_tool_version_parse(onboarding_env):
    onboarding_env.which.return_value = "/bin/nmap"
    onboarding_env.run.return_value.stdout = "nmap 7.94\nsecond line"
    assert d.check_tool("nmap").version == "nmap 7.94"


def test_check_tool_version_failure_no_crash(onboarding_env):
    onboarding_env.which.return_value = "/bin/nmap"
    onboarding_env.run.side_effect = OSError()
    assert d.check_tool("nmap").version is None


def test_check_all_tools_returns_all_from_recipes():
    assert set(d.check_all_tools()) == set(load_recipes())


def test_detect_managers_order_of_preference(onboarding_env):
    onboarding_env.which.return_value = "/bin/tool"
    with patch.object(d.platform, "system", return_value="Linux"):
        assert d.detect_managers()[:3] == ("apt", "dnf", "yum")


def test_detect_os_distro_parsing():
    with (
        patch.object(d.platform, "system", return_value="Linux"),
        patch.object(
            d.platform, "freedesktop_os_release", return_value={"ID": "fedora", "VERSION_ID": "42"}
        ),
    ):
        assert (d.detect_os().distro, d.detect_os().version) == ("fedora", "42")


def test_check_tool_recipes_available_only_supported():
    assert set(d.check_tool("nmap").recipes_available) == set(load_recipes()["nmap"]["recipes"])


def test_httpx_python_collision_is_not_present(onboarding_env):
    onboarding_env.which.return_value = "/bin/httpx"
    onboarding_env.run.return_value = SimpleNamespace(
        returncode=2, stdout="", stderr="unknown option"
    )
    assert not d.check_tool("httpx").present


def test_version_ignores_banner_and_reads_stderr(onboarding_env):
    onboarding_env.which.return_value = "/bin/httpx"
    onboarding_env.run.return_value = SimpleNamespace(
        returncode=0, stdout="ASCII banner\n", stderr="[INF] Current Version: v1.2.3\n"
    )
    assert d.check_tool("httpx").version == "[INF] Current Version: v1.2.3"


def test_macos_manager_order(onboarding_env):
    onboarding_env.which.return_value = "/bin/tool"
    with patch.object(d.platform, "system", return_value="Darwin"):
        assert d.detect_managers()[:2] == ("brew", "port")
