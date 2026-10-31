"""The autonomy benchmark must stay honest, offline and reproducible."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

from nexus_core.kernel.fact_verification import derive_assertions
from nexus_core.kernel.models import Identity, RunContext, ToolResult

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[3]
RUNNER = ROOT / "bench" / "autonomy" / "run.py"
SCENARIOS = ROOT / "bench" / "autonomy" / "scenarios.json"


def _runner():
    spec = importlib.util.spec_from_file_location("autonomy_bench", RUNNER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    # Dataclasses resolve their module through ``sys.modules`` while the file
    # executes; registering it first is what makes the dynamic import behave
    # like a normal import.
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_the_benchmark_has_calibration_and_reserved_scenarios() -> None:
    payload = json.loads(SCENARIOS.read_text(encoding="utf-8"))
    splits = {scenario.get("split") for scenario in payload["scenarios"]}
    assert {"calibration", "reserved"} <= splits
    ids = [scenario["id"] for scenario in payload["scenarios"]]
    assert len(ids) == len(set(ids))
    # No room-specific naming or real-looking secret in the fixtures.
    text = SCENARIOS.read_text(encoding="utf-8").lower()
    assert "thm" not in text and "tryhackme" not in text


def test_no_scenario_needs_network_or_a_model() -> None:
    text = RUNNER.read_text(encoding="utf-8")
    assert "import httpx" not in text
    assert "import requests" not in text
    assert "import socket" not in text
    assert "llm_client" not in text


def test_the_benchmark_passes_with_reserved_metrics_separate() -> None:
    report = _runner().run_benchmark()
    assert report["total"]["passed"] == report["total"]["scenarios"]
    assert report["by_split"]["calibration"]["success_rate"] >= report["target_rate"]
    assert report["by_split"]["reserved"]["passed"] == report["by_split"]["reserved"]["scenarios"]
    assert report["total"]["provenance_precision"] == 1.0
    # The negative SMB-style answer is information and must not be a failure.
    assert not any("tool_failure" in item for item in report["total"]["failures"])
    assert report["total"]["repeated_without_progress"] >= 1  # the background dedup case


def test_the_terminal_max_iterations_scenario_reports_the_surface() -> None:
    report = _runner().run_benchmark()
    scenario = next(
        item for item in report["scenarios"] if item["id"] == "max_iterations_summary_is_honest"
    )
    assert scenario["passed"] is True


def test_an_nmap_listing_through_the_generic_shell_is_not_a_verified_fact() -> None:
    """Only a reliable parser may promote raw shell text into board facts."""
    result = ToolResult(
        verified=True,
        verification_method="shell_exit_code",
        output={
            "exit_code": 0,
            "stdout": (
                "PORT     STATE SERVICE   VERSION\n"
                "445/tcp  open  smb       Samba 4.13\n"
                "3389/tcp open  ms-wbt    Microsoft Terminal Services\n"
            ),
        },
        exit_code=0,
    )
    context = RunContext(
        tenant_id="system",
        identity=Identity("operator", "system", roles=("operator",)),
        run_id="run-shell",
        invocation_id="inv-shell",
    )
    assertions = derive_assertions(
        "nexus.shell.exec",
        {"command": "nmap -sV 203.0.113.47"},
        result,
        context,
    )
    assert assertions == []
