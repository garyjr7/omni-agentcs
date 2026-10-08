"""Headless mode: one objective, machine-readable output, never a TUI.

The contract a CI consumer depends on: one JSON object per line, parseable
independently, carrying the ``subagent_id`` of the phase that produced it, and a
final ``run.complete`` object whose ``status`` maps to the process exit code.
"""

from __future__ import annotations

import io
import json
import threading

import pytest

from nexus_core.cli.headless import (
    STREAMED_AUDIT_ACTIONS,
    _EventEmitter,
    result_payload,
    run_headless,
    write_line,
)
from nexus_core.llm.abstraction import LLMProvider, LLMResponse

TENANT = "system"


class _ScriptedLLM:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls: list[list[dict[str, str]]] = []

    async def complete(self, messages, **kwargs):
        self.calls.append([{"role": m.role, "content": m.content} for m in messages])
        index = min(len(self.calls) - 1, max(0, len(self.responses) - 1))
        return LLMResponse(
            content=self.responses[index], model="scripted", provider=LLMProvider.FAKE
        )


def _timeline():
    return json.dumps(
        {"thought": "hecho", "action": "task_complete", "summary": "ok", "findings": []}
    )


@pytest.fixture(autouse=True)
def _disable_binaries_preflight(monkeypatch):
    # These are hermetic loop tests: the binary-identity preflight would probe
    # the host PATH (and abort on the Python httpx), so it is disabled here.
    monkeypatch.setenv("NEXUS_PREFLIGHT_BINARIES", "0")


@pytest.fixture()
def store(tmp_path):
    from nexus_core.kernel.control_store import ControlStore

    value = ControlStore(tmp_path / "headless.db")
    value.initialize()
    return value


@pytest.fixture()
def session(store):
    from nexus_core.cli.session import OmniSession

    return OmniSession(
        store=store,
        tenant_id=TENANT,
        engagement=None,
        llm_client=_ScriptedLLM([_timeline()]),
        use_tui=False,
        operator_id="operator:tester",
    )


def _lines(buffer: io.StringIO) -> list[dict]:
    text = buffer.getvalue()
    assert text.endswith("\n") or text == ""
    return [json.loads(line) for line in text.splitlines()]


# --------------------------------------------------------------- write_line


def test_write_line_emits_one_flushed_json_object():
    buffer = io.StringIO()
    write_line(buffer, {"type": "x", "value": 1})
    text = buffer.getvalue()
    assert text.endswith("\n")
    assert len(text.splitlines()) == 1
    payload = json.loads(text)
    assert payload["type"] == "x" and payload["value"] == 1
    assert "ts" in payload


def test_write_line_stringifies_unserialisable_values():
    buffer = io.StringIO()
    write_line(buffer, {"type": "x", "value": object()})
    assert json.loads(buffer.getvalue())["type"] == "x"


def test_result_payload_carries_the_subagent_attribution():
    from types import SimpleNamespace

    result = SimpleNamespace(
        status="completed",
        iterations=2,
        final_summary="ok",
        findings=[],
        subagent_id="recon",
        conversation_id="conv-1",
        plan=None,
    )
    payload = result_payload(result, "run-1")
    assert payload["type"] == "run.complete"
    assert payload["status"] == "completed"
    assert payload["subagent_id"] == "recon"


# --------------------------------------------------------------- json mode


def test_json_mode_without_evidence_is_incomplete(session):
    buffer = io.StringIO()
    code = run_headless(session, "Escanea 10.0.0.5", mode="json", stream=buffer)
    assert code == 1
    lines = _lines(buffer)
    assert len(lines) == 1
    assert lines[0]["type"] == "run.complete"
    assert lines[0]["status"] == "completed"
    assert "\x1b[" not in buffer.getvalue()  # no ANSI escapes in machine output


def test_empty_objective_is_a_usage_error_without_running_anything(session):
    buffer = io.StringIO()
    assert run_headless(session, "   ", mode="json", stream=buffer) == 1
    assert _lines(buffer)[0]["type"] == "run.complete"


# -------------------------------------------------------------- stream mode


def test_stream_mode_is_line_delimited_and_carries_subagent_id(session):
    buffer = io.StringIO()
    code = run_headless(session, "Escanea 10.0.0.5", mode="stream", stream=buffer)
    assert code == 1
    lines = _lines(buffer)  # every line parses on its own
    assert lines[-1]["type"] == "run.complete"
    assert lines[-1]["status"] == "completed"
    # The ReAct loop tags every step with the active subagent; the stream keeps it.
    assert any(line.get("subagent_id") for line in lines)


def test_stream_and_json_agree_on_the_final_status(session):
    json_buffer, stream_buffer = io.StringIO(), io.StringIO()
    run_headless(session, "Escanea 10.0.0.5", mode="json", stream=json_buffer)
    run_headless(session, "Escanea 10.0.0.5", mode="stream", stream=stream_buffer)
    final_json = _lines(json_buffer)[-1]
    final_stream = _lines(stream_buffer)[-1]
    assert final_json["status"] == final_stream["status"] == "completed"


# ----------------------------------------------------------------- emitter


def test_emitter_streams_run_events_and_audit_rows_once(session, store):
    from nexus_core.kernel.audit import AuditWriter

    run_id = str(store.create_run(TENANT, {"source": "test"})["id"])
    session.run_id = run_id
    store.append_run_event(
        TENANT, run_id, "orchestrator.subagent", {"subagent_id": "recon"}
    )
    AuditWriter(store).append(
        tenant_id=TENANT,
        trace_id=run_id,
        actor_id="omni",
        action="react.step",
        resource_type="run",
        resource_id=run_id,
        payload={"subagent_id": "recon", "iteration": 1},
        decision="allow",
    )
    AuditWriter(store).append(
        tenant_id=TENANT,
        trace_id=run_id,
        actor_id="omni",
        action="noise.ignored",
        resource_type="run",
        resource_id=run_id,
        payload={},
        decision="allow",
    )
    buffer = io.StringIO()
    emitter = _EventEmitter(session, threading.Event(), buffer)
    emitter.emit_new()  # first pass only latches the run id
    emitter.emit_new()  # second pass emits everything

    lines = _lines(buffer)
    types = [line["type"] for line in lines]
    assert "orchestrator.subagent" in types
    assert "react.step" in types
    assert "noise.ignored" not in types
    step = next(line for line in lines if line["type"] == "react.step")
    assert step["subagent_id"] == "recon"
    assert emitter.error is None

    # Re-polling must not duplicate what was already streamed.
    before = len(_lines(buffer))
    emitter.emit_new()
    assert len(_lines(buffer)) == before


def test_emitter_never_raises_on_a_broken_store(session):
    session.run_id = "run-x"

    class _Broken:
        def list_run_events(self, *args, **kwargs):
            raise RuntimeError("db gone")

    session.store = _Broken()
    emitter = _EventEmitter(session, threading.Event(), io.StringIO())
    emitter.emit_new()  # latches the run id
    emitter.emit_new()  # must swallow the failure, never raise
    assert emitter.error is not None
    assert "db gone" in emitter.error


def test_streamed_audit_actions_cover_the_governance_denials():
    assert {"mcp.tool_denied", "mcp.timeout", "scope.denied", "roe.denied"} <= set(
        STREAMED_AUDIT_ACTIONS
    )
