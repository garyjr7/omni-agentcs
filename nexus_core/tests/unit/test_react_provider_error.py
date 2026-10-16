"""B8.2: a provider failure during the model call must close the run cleanly.

Before this fix the LLM call in ``_request_action`` re-raised ``ProviderFailure``
out of ``ReActCoordinator.run()``, so the process died without a terminal result
and no ``run.complete`` was emitted (the Bounty Hacker RUN #6 abort). These tests
pin the new contract: the run returns a terminal ``provider_error`` result, the
status is never ``null``, and the headless entry point still emits
``run.complete`` with that status.
"""
from __future__ import annotations

import asyncio
import io
import json
from types import SimpleNamespace

import pytest

from nexus_core.agent.react import ReActConfig, run_react_loop
from nexus_core.kernel.errors import ProviderFailure
from nexus_core.kernel.runtime import ExecutionContext
from nexus_core.tests.unit.test_hooks_lifecycle import context


class FailingProvider:
    """A client whose model call always fails, without touching the network."""

    supports_streaming = False

    def __init__(self, exc: BaseException) -> None:
        self.exc = exc

    async def complete(self, messages, **kwargs):
        raise self.exc


def _loop_context(tmp_path, monkeypatch) -> ExecutionContext:
    """A durable ExecutionContext for one engagement-free ReAct run."""
    ctx = context(tmp_path, monkeypatch)
    run = ctx.store.create_run("system", {})
    payload = {"objective": "recon", "identity": {"subject_id": "op", "roles": ["operator"]}}
    task = {"id": "t", "tenant_id": "system", "run_id": run["id"],
            "task_type": "react.run", "payload": payload}
    return ExecutionContext(ctx.store, task, "worker-test")


@pytest.mark.parametrize(
    "exc, marker",
    [
        (ProviderFailure("daily quota exhausted"), "daily quota exhausted"),
        # Any other failure of the model call is wrapped by type name, exactly as
        # the pre-fix code did before re-raising it.
        (RuntimeError("provider down"), "RuntimeError"),
    ],
)
def test_model_call_failure_returns_terminal_provider_error(tmp_path, monkeypatch, exc, marker):
    exec_ctx = _loop_context(tmp_path, monkeypatch)
    result = asyncio.run(run_react_loop(
        context=exec_ctx, objective="recon", engagement_id=None,
        llm_client=FailingProvider(exc),
        config=ReActConfig(max_iterations=3, enforce_completion_gates=False),
    ))
    # The failure is reported, not raised: status is typed and non-null.
    assert result.status == "provider_error"
    assert result.status is not None
    assert result.iterations >= 1
    assert marker in result.final_summary
    # The turn that failed carries the same terminal outcome.
    assert result.turns and result.turns[-1]["outcome"] == "provider_error"


def test_headless_emits_run_complete_on_provider_failure(tmp_path, monkeypatch):
    """The headless NDJSON still closes with a ``run.complete`` line."""
    from nexus_core.cli import headless
    from nexus_core.cli.session import OmniSession
    from nexus_core.kernel.control_store import ControlStore

    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("NEXUS_SANDBOX_MODE", "local_strict")

    store = ControlStore(tmp_path / "headless.db")
    store.initialize()
    session = OmniSession(
        store=store, tenant_id="system", engagement=None, use_tui=False,
        operator_id="tester",
        llm_client=FailingProvider(ProviderFailure("daily quota exhausted")),
    )
    output = io.StringIO()
    exit_code = headless.run_headless(
        session, "recon", stream=output,
        preflight=SimpleNamespace(ok=True, problems=[]),
    )

    payload = json.loads(output.getvalue().strip().splitlines()[-1])
    assert payload["type"] == "run.complete"
    assert payload["status"] == "provider_error"
    assert payload["iterations"] >= 1
    assert payload["completion_verified"] is False
    assert exit_code == 3
