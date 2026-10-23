"""F2: a pipeline through ``head`` no longer reports the producer's failure as 0.

Measured in DeadDrop (2026-10-23, iteration 71): ``proxychains4 … | head -60``
answered ``outcome: success`` for a command that never reached the DC -the exit
code was ``head``'s- and the run read that as "the tunnel works once". These
tests pin the fix in both halves: the detector, and the exit code the handler
really sees.
"""

from __future__ import annotations

import asyncio

import pytest

from nexus_core.cli.engage import build_scope
from nexus_core.kernel.control_store import ControlStore
from nexus_core.kernel.models import Identity, RunContext
from nexus_core.scope import EngagementStore
from nexus_core.tools.handlers.shell_exec_local import (
    PIPELINE_STATUS_NOTE,
    needs_pipefail,
    pipeline_consumer,
    shell_exec_handler,
    shell_script,
)

pytestmark = pytest.mark.unit

SECRET = "test-signing-secret"
TARGET = "10.10.10.5"


@pytest.fixture()
def context(tmp_path, monkeypatch):
    """A signed engagement and an isolated workspace (the handler needs both)."""
    monkeypatch.setenv("NEXUS_SCOPE_SIGNING_SECRET", SECRET)
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(workspace))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    store = ControlStore(tmp_path / "control.db")
    store.initialize()
    scope = EngagementStore(store).create(build_scope("bench", f"{TARGET}/32", SECRET))
    return RunContext(
        "system",
        Identity("operator-1", "system", roles=("operator",)),
        store=store,
        scope=scope,
        project_root=str(workspace),
        run_id="run-pipe-test",
    )


def _run(context, arguments: dict):
    return asyncio.run(shell_exec_handler(arguments, context))


@pytest.mark.parametrize(
    "command,consumer",
    [
        ("nmap -sV 10.0.0.5 | head -n 10", "head"),
        ("cmd|head", "head"),
        ("nc 10.0.0.5 80 < req | tail -5", "tail"),
        ("proxychains4 nxc smb 10.0.0.5 | head -60", "head"),
        ("cat a | tee out", "tee"),
        ("cat a | grep open", "grep"),
        ("echo hola", ""),
        ("echo 'a | head'", ""),
        ("cmd || echo fallo", ""),
    ],
)
def test_the_last_stage_of_the_pipeline_is_named(command, consumer):
    assert pipeline_consumer(command) == consumer


def test_a_truncating_consumer_asks_for_pipefail_but_a_predicate_does_not():
    assert needs_pipefail("nxc smb 10.0.0.5 | head -n 5") is True
    # ``grep``'s own exit status is a real answer about the filter: making it
    # inherit the producer's failure would turn "no match" into a broken command.
    assert needs_pipefail("cat a | grep open") is False
    assert shell_script("x | head", pipefail=False) == "x | head"
    assert shell_script("x | head", pipefail=True) == "set -o pipefail; x | head"


def test_a_head_after_a_failing_command_reports_the_failure(context):
    """Acceptance F2: ``| head`` used to answer 0 for a command that exited 7."""
    result = _run(context, {"command": "(exit 7) | head -n 10"})
    assert result.exit_code == 7
    assert result.verified is False
    assert result.outcome == "command_failed"
    assert result.output["pipeline"] == {"consumer": "head", "pipefail": True}
    assert result.evidence["pipeline"] == {"consumer": "head", "pipefail": True}


def test_a_head_after_a_successful_command_still_succeeds(context):
    result = _run(context, {"command": "printf 'a\\nb\\n' | head -n 1"})
    assert result.exit_code == 0
    assert result.verified is True
    assert "a" in result.output["summary"]


def test_a_predicate_pipeline_keeps_its_own_status_and_says_so(context):
    result = _run(context, {"command": "printf 'a\\n' | grep zzz"})
    # grep's 1 is the filter's answer, not a broken producer: the handler keeps
    # the exit code and hands the model the rule instead of changing semantics.
    assert result.exit_code == 1
    assert result.output["pipeline"] == {
        "consumer": "grep", "pipefail": False, "note": PIPELINE_STATUS_NOTE,
    }


def test_a_command_without_a_pipeline_pays_nothing(context):
    result = _run(context, {"command": "echo hola"})
    assert "pipeline" not in result.output
    assert "pipeline" not in result.evidence
