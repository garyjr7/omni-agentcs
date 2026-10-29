import json
from unittest.mock import patch
import pytest

from nexus_core.cli import doctor as d
from nexus_core.config.schema import OmniConfig

pytestmark = pytest.mark.usefixtures("onboarding_env")


@pytest.fixture(autouse=True)
def no_network():
    with patch.object(d.socket, "create_connection", side_effect=OSError):
        yield


def test_doctor_returns_zero(onboarding_env):
    assert d.run_doctor(onboarding_env.paths, OmniConfig()) == 0


def test_doctor_human_output_contains_sections(onboarding_env, capsys):
    d.run_doctor(onboarding_env.paths, OmniConfig())
    output = capsys.readouterr().out
    assert all(
        section in output
        for section in (
            "Sistema",
            "Hardware",
            "Rutas XDG",
            "Config",
            "Base de datos",
            "Herramientas",
            "Auditoría",
        )
    )


def test_doctor_json_output_valid(onboarding_env, capsys):
    d.run_doctor(onboarding_env.paths, OmniConfig(), as_json=True)
    assert "tools" in json.loads(capsys.readouterr().out)


def test_doctor_handles_missing_db(onboarding_env, capsys):
    d.run_doctor(onboarding_env.paths, OmniConfig(), as_json=True)
    report = json.loads(capsys.readouterr().out)
    assert not report["db"]["exists"] and report["audit"] == []
    assert not onboarding_env.paths.db_file.exists()


def test_doctor_masks_api_keys(onboarding_env, capsys, monkeypatch):
    config = OmniConfig()
    config.llm.api_keys["groq"] = "private-fixture-key"
    monkeypatch.setenv("OPENAI_API_KEY", "another-private-key")
    d.run_doctor(onboarding_env.paths, config, as_json=True)
    output = capsys.readouterr().out
    assert "private-fixture-key" not in output and "another-private-key" not in output
    assert json.loads(output)["config"]["api_keys"]["groq"] is True


def test_json_valid_even_if_secret_matches_boolean_text(onboarding_env, capsys):
    config = OmniConfig()
    config.llm.api_keys["groq"] = "true"
    d.run_doctor(onboarding_env.paths, config, as_json=True)
    assert json.loads(capsys.readouterr().out)["config"]["api_keys"]["groq"] is True


def test_doctor_reports_effective_provider_model(onboarding_env, capsys, monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "fake")
    monkeypatch.delenv("FAKE_LLM_MODEL", raising=False)
    d.run_doctor(onboarding_env.paths, OmniConfig(), as_json=True)
    assert json.loads(capsys.readouterr().out)["config"]["default_model"] == "nexus-fake-v1"


def test_doctor_warns_when_sshpass_is_missing(onboarding_env, capsys):
    """The plan B of ``ssh_exec`` needs the binary, and the operator must know.

    Measured in Simple CTF: the credential was valid, the paramiko login was
    refused and the fallback could not run -the run read that as a wrong
    password. The doctor says it *before* the run, never with a secret.
    """
    with patch.object(d, "_sshpass_available", return_value=False):
        d.run_doctor(onboarding_env.paths, OmniConfig(), as_json=True)
    report = json.loads(capsys.readouterr().out)
    entry = next(
        item for item in report["runtime_preconditions"] if item["service"] == "sshpass"
    )
    assert entry["severity"] == "warning"
    assert entry["missing_env"] == []
    assert "sudo apt install sshpass" in entry["action"]


def test_doctor_is_quiet_when_sshpass_is_installed(onboarding_env, capsys):
    with patch.object(d, "_sshpass_available", return_value=True):
        d.run_doctor(onboarding_env.paths, OmniConfig(), as_json=True)
    report = json.loads(capsys.readouterr().out)
    assert "sshpass" not in {item["service"] for item in report["runtime_preconditions"]}


def test_sshpass_probe_uses_the_sandbox_path():
    """The binary is probed on the same PATH the sandbox hands its children."""
    seen: dict[str, object] = {}

    def fake_which(name, path=None):
        seen["name"], seen["path"] = name, path
        return "/usr/bin/sshpass"

    with patch.object(d.shutil, "which", fake_which):
        assert d._sshpass_available() is True
    assert seen["name"] == "sshpass"
    assert seen["path"] == d.sandbox_path()


def test_doctor_does_not_inspect_sqlite_for_postgres(onboarding_env, capsys, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "postgresql://user:private@localhost/db")
    with patch.object(d, "_audit") as audit:
        d.run_doctor(onboarding_env.paths, OmniConfig(), as_json=True)
    output = capsys.readouterr().out
    assert "private" not in output
    assert json.loads(output)["db"]["backend"] == "postgres"
    assert json.loads(output)["db"]["path"] is None
    audit.assert_not_called()
