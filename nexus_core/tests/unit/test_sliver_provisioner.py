"""Unit tests for the verified Sliver provisioner (no network, no processes)."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from nexus_core.provisioner import sliver

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def _isolated_xdg(tmp_path, monkeypatch):
    """Never let a test write to the real ~/.config/systemd/user."""
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))


# --------------------------------------------------------------- platform/urls
def test_platform_tag_maps_common_arches():
    assert sliver.platform_tag("x86_64", "Linux") == "linux-amd64"
    assert sliver.platform_tag("aarch64", "Linux") == "linux-arm64"
    assert sliver.platform_tag("arm64", "Darwin") == "darwin-arm64"


def test_platform_tag_unsupported_returns_none():
    assert sliver.platform_tag("riscv64", "Linux") is None
    assert sliver.platform_tag("x86_64", "Windows") is None


def test_sliver_urls_point_at_pinned_release():
    binary, signature = sliver.sliver_urls("v1.7.7", "linux-amd64")
    assert binary.endswith("/v1.7.7/sliver-server_linux-amd64")
    assert signature == binary + ".minisig"


def test_install_plan_text_is_reproducible_and_names_minisign():
    text = sliver.install_plan_text()
    assert sliver.SLIVER_MINISIGN_PUB_KEY in text
    assert "sliver-server" in text


# ------------------------------------------------------------------- install
def _which(minisign=True, sliver_present=None):
    def _lookup(name):
        if name == "sliver-server":
            return sliver_present
        if name == "minisign":
            return "/usr/bin/minisign" if minisign else None
        return None

    return _lookup


def _downloader(content=b"SLIVER-BINARY"):
    def _download(url, destination, *, timeout):
        Path(destination).write_bytes(content)

    return _download


def test_install_unsupported_platform(tmp_path):
    result = sliver.install_sliver_verified(
        target_dir=tmp_path, machine="riscv64", system="Linux", which=_which()
    )
    assert result.ok is False and result.status == sliver.STATUS_UNSUPPORTED


def test_install_already_present(tmp_path):
    result = sliver.install_sliver_verified(
        target_dir=tmp_path, which=_which(sliver_present="/usr/bin/sliver-server")
    )
    assert result.ok is True and result.status == sliver.STATUS_ALREADY


def test_install_requires_minisign(tmp_path):
    result = sliver.install_sliver_verified(
        target_dir=tmp_path, which=_which(minisign=False)
    )
    assert result.ok is False and result.status == sliver.STATUS_NO_MINISIGN


def test_install_download_failure(tmp_path):
    def _boom(url, destination, *, timeout):
        raise OSError("no route")

    result = sliver.install_sliver_verified(
        target_dir=tmp_path, which=_which(), download=_boom
    )
    assert result.ok is False and result.status == sliver.STATUS_DOWNLOAD_FAILED


def test_install_rejects_bad_signature(tmp_path):
    result = sliver.install_sliver_verified(
        target_dir=tmp_path, which=_which(), download=_downloader(),
        run=lambda *a, **k: SimpleNamespace(returncode=1, stdout="", stderr="bad sig"),
    )
    assert result.ok is False and result.status == sliver.STATUS_SIGNATURE_INVALID
    assert not (tmp_path / "sliver-server").exists()


def test_install_success_verifies_then_installs(tmp_path):
    calls = []

    def _run(argv, **kwargs):
        calls.append(argv)
        return SimpleNamespace(returncode=0, stdout="Signature verified", stderr="")

    result = sliver.install_sliver_verified(
        target_dir=tmp_path, which=_which(), download=_downloader(), run=_run
    )
    assert result.ok is True and result.status == sliver.STATUS_INSTALLED
    target = tmp_path / "sliver-server"
    assert target.read_bytes() == b"SLIVER-BINARY"
    assert target.stat().st_mode & 0o777 == 0o755
    assert len(result.sha256) == 64
    # minisign was invoked with the official public key.
    assert calls and sliver.SLIVER_MINISIGN_PUB_KEY in calls[0]


# --------------------------------------------------------------- team server
def test_team_server_already_running():
    assert sliver.start_team_server(
        binary="/x/sliver-server", port_open=lambda *a: True
    ) is True


def test_team_server_starts_and_waits_for_port():
    state = {"open": False}

    def _spawn(argv):
        state["argv"] = argv
        state["open"] = True

    ok = sliver.start_team_server(
        binary="/x/sliver-server",
        port_open=lambda *a: state["open"],
        spawn=_spawn,
        service_installer=lambda **k: False,  # no user systemd in the test
        attempts=3,
        sleep=lambda *_: None,
    )
    assert ok is True
    assert state["argv"] == ["/x/sliver-server", "daemon"]


def test_team_server_never_opens_reports_false():
    ok = sliver.start_team_server(
        binary="/x/sliver-server",
        port_open=lambda *a: False,
        spawn=lambda argv: None,
        service_installer=lambda **k: False,  # never touch the real user systemd
        attempts=2,
        sleep=lambda *_: None,
    )
    assert ok is False


def test_team_server_without_binary_returns_false():
    assert sliver.start_team_server(
        binary=None, spawn=lambda a: None, which=lambda n: None
    ) is False


def test_team_server_prefers_user_service():
    used = {"service": False, "spawn": False}
    state = {"open": False}

    def _port_open(*a):
        return state["open"]

    def _installer_opens(**kwargs):
        used["service"] = True
        state["open"] = True
        return True

    ok = sliver.start_team_server(
        binary="/x/sliver-server",
        port_open=_port_open,
        spawn=lambda a: used.__setitem__("spawn", True),
        service_installer=_installer_opens,
        attempts=2,
        sleep=lambda *_: None,
    )
    assert ok is True and used["service"] is True and used["spawn"] is False


# ------------------------------------------------------------ user service
def test_user_unit_text_is_a_user_service():
    text = sliver.user_unit_text("/home/operator/.local/bin/sliver-server")
    assert "ExecStart=/home/operator/.local/bin/sliver-server daemon" in text
    assert "WantedBy=default.target" in text
    assert "User=" not in text  # it is a --user unit


def test_install_user_service_writes_and_enables(tmp_path):
    unit = tmp_path / "omni-sliver.service"
    calls = []

    def _run(argv, **kwargs):
        calls.append(argv)
        if argv[:3] == ["systemctl", "--user", "is-system-running"]:
            return SimpleNamespace(returncode=0, stdout="running\n", stderr="")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    ok = sliver.install_user_service(
        binary="/home/operator/.local/bin/sliver-server", path=unit, run=_run
    )
    assert ok is True
    assert unit.exists() and "sliver-server daemon" in unit.read_text()
    flat = [" ".join(c) for c in calls]
    assert any("enable --now " + sliver.USER_SERVICE_NAME in line for line in flat)
    assert any(line.startswith("loginctl enable-linger") for line in flat)


def test_install_user_service_without_systemd(tmp_path):
    def _run(argv, **kwargs):
        return SimpleNamespace(returncode=1, stdout="offline\n", stderr="")

    assert sliver.install_user_service(
        binary="/x/sliver-server", path=tmp_path / "u.service", run=_run
    ) is False


# ----------------------------------------------------------- operator config
def test_ensure_operator_config_existing_returns_true(tmp_path):
    path = tmp_path / "operator.cfg"
    path.write_text("{}")
    assert sliver.ensure_operator_config(path=path, binary="/x/sliver-server") is True


def test_ensure_operator_config_generates(tmp_path):
    path = tmp_path / "sub" / "operator.cfg"

    def _run(argv, **kwargs):
        # Emulate sliver-server writing the config file.
        Path(argv[argv.index("--save") + 1]).write_text("{\"lhost\": \"127.0.0.1\"}")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    assert sliver.ensure_operator_config(
        path=path, binary="/x/sliver-server", lhost="127.0.0.1", run=_run
    ) is True
    assert path.exists()


def test_ensure_operator_config_without_binary(tmp_path):
    assert sliver.ensure_operator_config(
        path=tmp_path / "operator.cfg", binary=None, which=lambda n: None
    ) is False
