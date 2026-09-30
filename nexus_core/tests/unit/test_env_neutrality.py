"""Verify the color tests under inherited terminal preferences."""

import os
from pathlib import Path
import subprocess
import sys

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]


@pytest.mark.parametrize("no_color_value", [None, "1", "true", ""])
def test_suite_passes_regardless_of_no_color(no_color_value):
    env = os.environ.copy()
    if no_color_value is None:
        env.pop("NO_COLOR", None)
    else:
        env["NO_COLOR"] = no_color_value
    tests = (
        "test_cli_banner.py::test_banner_with_color_emits_ansi_but_keeps_plain_tokens",
        "test_cli_prompt_polish.py::test_prompt_no_color_strips_ansi",
        "test_cli_spinner.py::test_spinner_enabled_requires_both_ttys",
    )
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", *(
            "nexus_core/tests/unit/" + test for test in tests
        )],
        cwd=REPO_ROOT, env=env, capture_output=True, text=True, timeout=60,
    )
    assert result.returncode == 0, (
        f"NO_COLOR={no_color_value!r}\n{result.stdout}\n{result.stderr}"
    )
