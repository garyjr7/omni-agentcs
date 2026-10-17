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
from nexus_core.agent.react_types import (
    INVALID_JSON_CORRECTION,
    INVALID_JSON_EVENT_TYPE,
    MAX_INVALID_JSON_TURNS,
)
from nexus_core.kernel.errors import ProviderFailure
from nexus_core.kernel.runtime import ExecutionContext
from nexus_core.llm.abstraction import (
    LLMConfig,
    LLMInvalidJSONError,
    LLMProvider,
    LLMResponse,
    NexusLLM,
    NexusLLMError,
)
from nexus_core.tests.unit.test_hooks_lifecycle import context


class FailingProvider:
    """A client whose model call always fails, without touching the network."""

    supports_streaming = False

    def __init__(self, exc: BaseException) -> None:
        self.exc = exc

    async def complete(self, messages, **kwargs):
        raise self.exc


class ScriptedAnswerProvider:
    """Fails the first ``failures`` turns with a malformed JSON answer.

    The exception is wrapped exactly like ``NexusLLM.complete`` does when no
    fallback client is configured, so the test exercises the same cause chain
    the run measured in Simple CTF Run 3.
    """

    supports_streaming = False

    def __init__(self, failures: int, answer: str) -> None:
        self.failures = failures
        self.answer = answer
        self.calls: list[list[dict[str, str]]] = []

    async def complete(self, messages, **kwargs):
        self.calls.append([{"role": m.role, "content": m.content} for m in messages])
        if len(self.calls) <= self.failures:
            error = NexusLLMError("Primary LLM provider failed and no fallback is configured.")
            error.__cause__ = LLMInvalidJSONError("DeepSeek returned invalid JSON")
            raise error
        return LLMResponse(
            content=self.answer,
            model="scripted-test",
            provider=LLMProvider.FAKE,
        )


_CLARIFY = json.dumps(
    {"thought": "Pido contexto.", "action": "request_clarification", "question": "¿Sigo?"}
)


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


def test_invalid_json_answer_is_retried_with_a_correction(tmp_path, monkeypatch):
    """Run 3: a malformed answer becomes a correction, not a dead run."""
    exec_ctx = _loop_context(tmp_path, monkeypatch)
    provider = ScriptedAnswerProvider(failures=1, answer=_CLARIFY)

    result = asyncio.run(run_react_loop(
        context=exec_ctx, objective="recon", engagement_id=None,
        llm_client=provider,
        config=ReActConfig(max_iterations=3, enforce_completion_gates=False),
    ))

    assert result.status != "provider_error"
    assert len(provider.calls) == 2, "one failed turn plus the corrected retry"
    # The retry carries the exact instruction the contract promises the model.
    retry = "\n".join(message["content"] for message in provider.calls[1])
    assert INVALID_JSON_CORRECTION in retry
    # The failed turn is audited with its attempt number, not silently dropped.
    events = [
        event for event in exec_ctx.store.list_run_events("system", exec_ctx.run_id)
        if event["event_type"] == INVALID_JSON_EVENT_TYPE
    ]
    assert len(events) == 1
    assert events[0]["payload"]["attempt"] == 1


class _TypedInvalidJSONPrimary:
    """A real provider client that answers malformed JSON once, then correctly."""

    supports_streaming = False
    config = LLMConfig(provider=LLMProvider.DEEPSEEK, model="deepseek-flash")

    def __init__(self) -> None:
        self.calls = 0

    async def complete(self, messages, **kwargs):
        self.calls += 1
        if self.calls == 1:
            raise LLMInvalidJSONError("DeepSeek returned invalid JSON")
        return LLMResponse(content=_CLARIFY, model="deepseek-flash", provider=LLMProvider.DEEPSEEK)


def test_the_real_wrapper_keeps_a_bad_answer_retryable(tmp_path, monkeypatch):
    """The production path: ``NexusLLM`` wraps the typed error, the loop retries."""
    exec_ctx = _loop_context(tmp_path, monkeypatch)
    primary = _TypedInvalidJSONPrimary()

    result = asyncio.run(run_react_loop(
        context=exec_ctx, objective="recon", engagement_id=None,
        llm_client=NexusLLM(primary=primary),
        config=ReActConfig(max_iterations=3, enforce_completion_gates=False),
    ))

    assert result.status != "provider_error"
    assert primary.calls == 2


def test_a_provider_that_only_returns_garbage_still_fails_closed(tmp_path, monkeypatch):
    """Three corrections are the budget; a fourth malformed turn ends the run."""
    exec_ctx = _loop_context(tmp_path, monkeypatch)
    provider = ScriptedAnswerProvider(failures=99, answer=_CLARIFY)

    result = asyncio.run(run_react_loop(
        context=exec_ctx, objective="recon", engagement_id=None,
        llm_client=provider,
        config=ReActConfig(max_iterations=8, enforce_completion_gates=False),
    ))

    assert result.status == "provider_error"
    assert "invalid JSON" in result.final_summary
    assert len(provider.calls) == MAX_INVALID_JSON_TURNS + 1
    # The last attempt carries one correction per failed turn (the history
    # accumulates them), proving each retry was budgeted and asked again.
    final_call = provider.calls[-1]
    corrections = [
        message for message in final_call
        if message["content"] == INVALID_JSON_CORRECTION
    ]
    assert len(corrections) == MAX_INVALID_JSON_TURNS


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
