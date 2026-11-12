"""``omni update``: version check, upgrade steps and the config that must survive."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from nexus_core.cli import update as update_module
from nexus_core.cli.update import (
    Release,
    check_for_update,
    config_fingerprint,
    fetch_latest_release,
    parse_version,
    run_update_command,
    update_notice,
    update_steps,
)


def _completed(code=0, stdout="", stderr=""):
    return SimpleNamespace(returncode=code, stdout=stdout, stderr=stderr)


# --- versiones ----------------------------------------------------------------


def test_versions_compare_numerically_not_as_text():
    assert parse_version("3.10.0") > parse_version("3.9.9")
    assert parse_version("v3.0.1") == (3, 0, 1)
    assert parse_version("sin numeros") == ()


def test_check_for_update_offers_only_a_newer_version():
    newer = Release("3.1.0")
    assert check_for_update("3.0.0", fetch=lambda timeout: newer) == newer
    assert check_for_update("3.1.0", fetch=lambda timeout: newer) is None
    assert check_for_update("3.2.0", fetch=lambda timeout: newer) is None
    assert check_for_update("3.0.0", fetch=lambda timeout: None) is None


def test_fetch_reads_the_releases_api():
    payload = json.dumps({"tag_name": "v3.4.5", "html_url": "https://x/rel"})
    release = fetch_latest_release(2.0, getter=lambda url, timeout: payload)
    assert release == Release(version="3.4.5", url="https://x/rel")


def test_fetch_falls_back_to_the_remote_pyproject():
    def getter(url, timeout):
        if url == update_module.RELEASES_URL:
            raise OSError("404")
        return '[project]\nname = "omniagentcs"\nversion = "4.2.0"\n'

    release = fetch_latest_release(2.0, getter=getter)
    assert release is not None
    assert release.version == "4.2.0"
    assert release.source == "pyproject"


def test_fetch_can_point_at_a_local_manifest(tmp_path, monkeypatch):
    manifest = tmp_path / "release.json"
    manifest.write_text(json.dumps({"tag_name": "v5.0.0"}), encoding="utf-8")
    monkeypatch.setenv(update_module.RELEASES_URL_ENV, manifest.as_uri())
    release = fetch_latest_release(2.0)
    assert release is not None and release.version == "5.0.0"


def test_an_explicit_manifest_has_no_pyproject_fallback(tmp_path, monkeypatch):
    manifest = tmp_path / "release.json"
    manifest.write_text("not json", encoding="utf-8")
    monkeypatch.setenv(update_module.RELEASES_URL_ENV, manifest.as_uri())
    assert fetch_latest_release(2.0) is None


def test_fetch_is_none_when_nothing_answers():
    def getter(url, timeout):
        raise TimeoutError("slow")

    assert fetch_latest_release(2.0, getter=getter) is None


# --- pasos --------------------------------------------------------------------


def test_steps_pull_first_and_then_install_into_the_current_env(tmp_path):
    (tmp_path / ".git").mkdir()
    (tmp_path / "requirements-prod.in").write_text("openai\n", encoding="utf-8")
    steps = update_steps(tmp_path, python="/opt/venv/bin/python", prefix="/opt/venv")
    assert steps[0] == ["git", "-C", str(tmp_path), "pull", "--ff-only"]
    assert steps[1] == [
        "/opt/venv/bin/python", "-m", "pip", "install", "--upgrade",
        "-r", str(tmp_path / "requirements-prod.in"),
    ]


def test_pipx_installs_upgrade_through_pipx(tmp_path):
    steps = update_steps(tmp_path, prefix="/home/x/.local/pipx/venvs/omniagentcs")
    assert steps == [["pipx", "upgrade", "omniagentcs"]]


def test_a_non_git_checkout_installs_the_tree(tmp_path):
    steps = update_steps(tmp_path, python="/v/bin/python", prefix="/v")
    assert steps == [["/v/bin/python", "-m", "pip", "install", "--upgrade", str(tmp_path)]]


# --- omni update --------------------------------------------------------------


def _config(tmp_path: Path) -> Path:
    config = tmp_path / "config" / "omni"
    config.mkdir(parents=True)
    (config / "secrets.json").write_text('{"OPENAI_API_KEY": "stored"}', encoding="utf-8")
    (config / "config.toml").write_text("schema_version = 1\n", encoding="utf-8")
    return config


def test_up_to_date_says_so_and_runs_nothing(tmp_path):
    lines: list[str] = []
    code = run_update_command(
        [], current="3.0.0", fetch=lambda timeout: Release("3.0.0"),
        out=lines.append, runner=pytest.fail, root=tmp_path, config_dir=tmp_path,
    )
    assert code == 0
    assert "última versión" in "\n".join(lines)


def test_unreachable_github_is_reported_without_failing_the_install(tmp_path):
    lines: list[str] = []
    code = run_update_command(
        [], current="3.0.0", fetch=lambda timeout: None, out=lines.append,
        runner=pytest.fail, root=tmp_path, config_dir=tmp_path,
    )
    assert code == 1
    assert "no se pudo consultar" in "\n".join(lines)


def test_check_only_reports_without_touching_anything(tmp_path):
    lines: list[str] = []
    code = run_update_command(
        ["--check"], current="3.0.0", fetch=lambda timeout: Release("3.2.1"),
        out=lines.append, runner=pytest.fail, root=tmp_path, config_dir=tmp_path,
    )
    assert code == 0
    assert "3.2.1" in "\n".join(lines)
    assert any("--check" in line for line in lines)


def test_declining_the_prompt_changes_nothing(tmp_path):
    lines: list[str] = []
    code = run_update_command(
        [], current="3.0.0", fetch=lambda timeout: Release("3.2.1"),
        prompt=lambda text: "n", out=lines.append, runner=pytest.fail,
        root=tmp_path, config_dir=tmp_path,
    )
    assert code == 0
    assert "cancelada" in "\n".join(lines)


def test_the_prompt_is_the_documented_sentence(tmp_path):
    seen: list[str] = []
    run_update_command(
        [], current="3.0.0", fetch=lambda timeout: Release("3.2.1"),
        prompt=lambda text: seen.append(text) or "n", out=lambda line: None,
        runner=pytest.fail, root=tmp_path, config_dir=tmp_path,
    )
    assert seen == [
        "Nueva versión v3.2.1 disponible. ¿Deseas actualizar ahora? [y/N] "
    ]


def test_update_runs_the_steps_and_preserves_the_operator_config(tmp_path):
    config = _config(tmp_path)
    secrets = (config / "secrets.json").read_bytes()
    before = config_fingerprint(config)
    calls: list[list[str]] = []

    def runner(argv):
        calls.append(list(argv))
        return _completed()

    code = run_update_command(
        [], current="3.0.0", fetch=lambda timeout: Release("3.1.0"),
        prompt=lambda text: "y", out=lambda line: None, runner=runner,
        root=tmp_path, config_dir=config,
    )

    assert code == 0
    assert calls
    # CI runs the suite with the system interpreter (``python3``), a pipx venv
    # with the pipx launcher; neither name is part of the contract.
    executable = Path(calls[0][0]).name
    assert executable == "pipx" or executable.startswith("python")
    assert (config / "secrets.json").read_bytes() == secrets
    assert config_fingerprint(config) == before
    assert sorted(path.name for path in config.iterdir()) == ["config.toml", "secrets.json"]


def test_a_failing_step_still_leaves_the_config_alone(tmp_path):
    config = _config(tmp_path)
    secrets = (config / "secrets.json").read_bytes()
    lines: list[str] = []

    code = run_update_command(
        [], current="3.0.0", fetch=lambda timeout: Release("3.1.0"),
        prompt=lambda text: "s", out=lines.append,
        runner=lambda argv: _completed(1, "", "fatal: not possible to fast-forward"),
        root=tmp_path, config_dir=config,
    )
    assert code == 1
    assert "not possible to fast-forward" in "\n".join(lines)
    assert (config / "secrets.json").read_bytes() == secrets


def test_a_step_that_writes_into_the_config_dir_is_detected(tmp_path):
    config = _config(tmp_path)
    lines: list[str] = []

    def meddling(argv):
        (config / "secrets.json").write_text('{"OPENAI_API_KEY": "clobbered"}')
        return _completed()

    code = run_update_command(
        [], current="3.0.0", fetch=lambda timeout: Release("3.1.0"),
        prompt=lambda text: "y", out=lines.append, runner=meddling,
        root=tmp_path, config_dir=config,
    )
    assert code == 3
    assert "ALERTA" in "\n".join(lines)
    assert "secrets.json" in "\n".join(lines)


def test_refuses_to_update_a_tree_inside_the_config_dir(tmp_path):
    config = _config(tmp_path)
    nested = config / "src"
    nested.mkdir()
    lines: list[str] = []
    code = run_update_command(
        [], current="3.0.0", fetch=lambda timeout: Release("3.1.0"),
        prompt=lambda text: "y", out=lines.append, runner=pytest.fail,
        root=nested, config_dir=config,
    )
    assert code == 2
    assert "me niego" in "\n".join(lines)


def test_unknown_argument_is_a_usage_error(tmp_path):
    lines: list[str] = []
    code = run_update_command(
        ["--force"], out=lines.append, runner=pytest.fail, root=tmp_path, config_dir=tmp_path
    )
    assert code == 2
    assert "argumento desconocido" in "\n".join(lines)


# --- banner de la TUI ---------------------------------------------------------


def test_update_notice_is_the_documented_line():
    assert update_notice(Release("3.4.0")) == (
        "[!] Actualización disponible: v3.4.0. Ejecuta 'omni update' para instalar."
    )


class _Output:
    def __init__(self):
        self.written: list[str] = []

    def write(self, text, *, end="\n"):
        self.written.append(text)


def _announce(monkeypatch, release):
    from nexus_core.cli.session import OmniSession

    output = _Output()
    stub = SimpleNamespace(_output=output)
    monkeypatch.setattr(
        update_module, "check_for_update", lambda *a, **k: release
    )
    OmniSession._announce_update_in_background(stub)
    for _ in range(100):
        if output.written or release is None:
            break
        time.sleep(0.01)
    return output.written


def test_background_check_prints_the_yellow_notice(monkeypatch):
    written = _announce(monkeypatch, Release("9.9.9"))
    assert written and "9.9.9" in written[0]
    assert "omni update" in written[0]


def test_background_check_is_silent_when_up_to_date(monkeypatch):
    assert _announce(monkeypatch, None) == []


def test_background_check_honours_the_opt_out(monkeypatch):
    from nexus_core.cli.session import OmniSession

    output = _Output()
    monkeypatch.setenv("OMNI_NO_UPDATE_CHECK", "1")
    monkeypatch.setattr(
        update_module, "check_for_update", pytest.fail
    )
    OmniSession._announce_update_in_background(SimpleNamespace(_output=output))
    assert output.written == []


# --- wiring -------------------------------------------------------------------


# --- install.sh ---------------------------------------------------------------

REPO_ROOT = Path(__file__).resolve().parents[3]
INSTALL_SH = REPO_ROOT / "install.sh"


def test_the_installer_lives_where_the_one_liner_fetches_it():
    """The curl URL points at ``/main/install.sh``; it has to exist at the root."""
    assert INSTALL_SH.is_file()
    assert os.access(INSTALL_SH, os.X_OK)
    assert (
        "raw.githubusercontent.com/garyjr7/omni-agentcs/main/install.sh"
        in INSTALL_SH.read_text(encoding="utf-8")
    )


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash no disponible")
def test_installer_dry_run_creates_no_configuration(tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    env = {**os.environ, "HOME": str(home), "XDG_CONFIG_HOME": str(home / ".config")}
    env.pop("OMNI_SOURCE", None)

    syntax = subprocess.run(["bash", "-n", str(INSTALL_SH)], capture_output=True, text=True)
    assert syntax.returncode == 0, syntax.stderr

    completed = subprocess.run(
        ["bash", str(INSTALL_SH), "--dry-run"],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
        env=env,
        timeout=120,
    )
    assert completed.returncode == 0, completed.stderr
    assert "no se instala nada" in completed.stdout
    # The whole point: no config, no keys, no ~/.config/omni during install.
    assert not (home / ".config").exists()


def test_omni_update_check_through_a_local_manifest(tmp_path, monkeypatch, capsys):
    """Real network path (file:// manifest), real argparse wiring, no internet."""
    from nexus_core.cli.main import main

    manifest = tmp_path / "release.json"
    manifest.write_text(json.dumps({"tag_name": "v9.1.0"}), encoding="utf-8")
    monkeypatch.setenv(update_module.RELEASES_URL_ENV, manifest.as_uri())
    assert main(["update", "--check"]) == 0
    output = capsys.readouterr().out
    assert "9.1.0" in output
    assert "--check" in output


def test_omni_update_check_end_to_end(tmp_path, monkeypatch, capsys):
    from nexus_core.cli.main import main

    monkeypatch.setattr(
        update_module, "fetch_latest_release", lambda *a, **k: Release("3.0.0")
    )
    assert main(["update", "--check"]) == 0
    assert "última versión" in capsys.readouterr().out
