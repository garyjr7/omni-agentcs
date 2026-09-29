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


def test_doctor_does_not_inspect_sqlite_for_postgres(onboarding_env, capsys, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "postgresql://user:private@localhost/db")
    with patch.object(d, "_audit") as audit:
        d.run_doctor(onboarding_env.paths, OmniConfig(), as_json=True)
    output = capsys.readouterr().out
    assert "private" not in output
    assert json.loads(output)["db"]["backend"] == "postgres"
    assert json.loads(output)["db"]["path"] is None
    audit.assert_not_called()
