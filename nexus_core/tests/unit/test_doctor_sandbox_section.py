"""``/doctor`` reports the active sandbox mode and its guarantees (finding #3)."""

from __future__ import annotations

import json
from unittest.mock import patch

import pytest

from nexus_core.cli import doctor as doctor_module
from nexus_core.config.schema import OmniConfig
from nexus_core.kernel.sandbox_modes import active_mode, guarantees_for

pytestmark = pytest.mark.usefixtures("onboarding_env")


@pytest.fixture(autouse=True)
def no_network():
    with patch.object(doctor_module.socket, "create_connection", side_effect=OSError):
        yield


def _run(onboarding_env, **kwargs):
    with patch.object(doctor_module, "check_all_tools", return_value={}):
        return doctor_module.run_doctor(onboarding_env.paths, OmniConfig(), **kwargs)


def test_doctor_shows_sandbox_mode(onboarding_env, capsys):
    _run(onboarding_env)
    output = capsys.readouterr().out
    assert "Sandbox" in output
    assert active_mode().value in output


def test_doctor_shows_guarantees(onboarding_env, capsys):
    _run(onboarding_env)
    output = capsys.readouterr().out
    assert "process isolation" in output
    assert "aislamiento red" in output
    assert "tools network" in output


def test_doctor_json_reports_sandbox(onboarding_env, capsys):
    _run(onboarding_env, as_json=True)
    report = json.loads(capsys.readouterr().out)
    assert report["sandbox"]["mode"] == active_mode().value
    assert report["sandbox"]["process_isolation"] is guarantees_for().process_isolation
