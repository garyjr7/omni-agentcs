"""``omni doctor`` verifies the local key file exists and is not world-readable."""

import json
import os
from unittest.mock import patch

import pytest

from nexus_core.cli import doctor as d
from nexus_core.config.schema import OmniConfig
from nexus_core.config.secrets import default_secrets_path

pytestmark = pytest.mark.usefixtures("onboarding_env")


@pytest.fixture(autouse=True)
def no_network():
    with patch.object(d.socket, "create_connection", side_effect=OSError):
        yield


def _store_file(mode):
    path = default_secrets_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text('{"OPENAI_API_KEY": "never-printed"}', encoding="utf-8")
    os.chmod(path, mode)
    return path


def test_doctor_lists_the_store_path_when_absent(onboarding_env, capsys):
    d.run_doctor(onboarding_env.paths, OmniConfig(), as_json=True)
    report = json.loads(capsys.readouterr().out)
    assert report["secrets"]["path"] == str(default_secrets_path())
    assert report["secrets"]["exists"] is False
    assert "secretos" not in {item["service"] for item in report["runtime_preconditions"]}


def test_doctor_accepts_0600_silently(onboarding_env, capsys):
    path = _store_file(0o600)
    d.run_doctor(onboarding_env.paths, OmniConfig(), as_json=True)
    report = json.loads(capsys.readouterr().out)
    assert report["secrets"]["exists"] is True
    assert report["secrets"]["mode"] == "0600"
    assert report["secrets"]["secure"] is True
    assert report["secrets"]["path"] == str(path)
    assert "secretos" not in {item["service"] for item in report["runtime_preconditions"]}


def test_doctor_warns_when_the_store_is_world_readable(onboarding_env, capsys):
    _store_file(0o644)
    d.run_doctor(onboarding_env.paths, OmniConfig(), as_json=True)
    report = json.loads(capsys.readouterr().out)
    entry = next(
        item for item in report["runtime_preconditions"] if item["service"] == "secretos"
    )
    assert entry["severity"] == "warning"
    assert entry["observed"] == "mode=0644"
    assert "chmod 600" in entry["action"]
    # The value itself never reaches the report.
    assert "never-printed" not in json.dumps(report)


def test_doctor_human_output_shows_the_permission_verdict(onboarding_env, capsys):
    _store_file(0o644)
    d.run_doctor(onboarding_env.paths, OmniConfig())
    output = capsys.readouterr().out
    assert "Secretos (gestor local)" in output
    assert "INSEGUROS" in output
    assert "chmod 600" in output
