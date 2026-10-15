"""Fase 3g fixes: a repeat is corrected, and a tool timeout is a tool failure.

Measured in the rerun #7 (``docs/missions/diag/diag_rerun7_2026-10-15.md``):

* **Bug A / V1-26** - after ``msf_exploit`` failed (``method=msf_exploit_failed``,
  60 s, "No session created"), the model proposed the byte-identical invocation in
  the next iteration. The gateway keeps a failed invocation journaled as
  ``unknown`` -its effect may have happened-, so the repeat demanded a human
  approval that the ``--trust-mode`` run does not hold: the loop closed with
  ``termination_reason="blocked"``, ``friction=["repeated_action",
  "governance_denial"]`` and ``summary="unknown invocation requires human
  approval"``, with the ``exploit`` profile 10 iterations and ~17k tokens short of
  its budget. In the rerun #6 the same failure produced a *correction* and the
  model pivoted to ``psexec``, which opened the session. The behaviour of the gate
  was inconsistent between runs; this module pins the correct one: an identical
  repeat of an action that just failed gets a correction and the run continues.
* **Bug B / V1-27** - the first attempt of the rerun #7 ran ``nmap -p-`` with
  ``timeout_seconds=600`` against a slow target. The gateway's ``asyncio.wait_for``
  fired, the bare ``TimeoutError`` escaped the tool layer and the whole run closed
  as ``provider_error`` / ``summary="TimeoutError"`` (exit 3) from iteration 1. A
  *tool* running out of time is a tool failure; only the *provider* (LLM) timeout
  keeps the ``provider_error`` path.
"""

from __future__ import annotations

import asyncio
import copy
import json
from typing import Any

import pytest

from nexus_core.agent.react import (
    TOOL_UNAVAILABLE_EVENT_TYPE,
    STATUS_COMPLETED,
    run_react_loop,
)
from nexus_core.kernel import runtime as runtime_module
from nexus_core.kernel.audit import AuditWriter
from nexus_core.kernel.control_store import ControlStore
from nexus_core.kernel.invocation_journal import InvocationJournal
from nexus_core.kernel.models import Identity, RiskLevel, RunContext, ToolDefinition, ToolResult
from nexus_core.kernel.policy import PolicyEngine
from nexus_core.kernel.runtime import ExecutionContext
from nexus_core.kernel.tool_gateway import ToolGateway
from nexus_core.tests.unit.test_phase3b_fixes import (
    ScriptedLLM,
    ToolSpy,
    _config,
    _create_scope,
    _observations,
)

pytestmark = [pytest.mark.usefixtures("lab_scope")]

#: The measured tool: the one whose identical repeat blocked the rerun #7.
FAILING_TOOL = "nexus.recon.nmap"


def _call(tool_id: str = FAILING_TOOL, **arguments: Any) -> str:
    """One ``tool_call`` action, with the arguments the test needs."""
    return json.dumps(
        {
            "thought": "Siguiente paso del reconocimiento.",
            "action": "tool_call",
            "tool_id": tool_id,
            "arguments": arguments or {"target": "10.0.0.5", "flags": ["-Pn"]},
            "expected_outcome": "puertos abiertos",
        }
    )


def _task_complete() -> str:
    return json.dumps({"thought": "listo", "action": "task_complete", "summary": "ok", "findings": []})


def _timeout_payload(tool_id: str) -> dict:
    """What the gateway returns for a handler it had to cut off (V1-27)."""
    return {
        "tool_id": tool_id,
        "output": {
            "success": False,
            "outcome": "timeout",
            "verification_method": f"{tool_id}_timeout",
            "evidence": {"timeout_seconds": 600, "tool_id": tool_id},
            "output": {"status": "timeout"},
            "assertions": [],
        },
    }


def _success_payload(tool_id: str) -> dict:
    return {
        "tool_id": tool_id,
        "output": {
            "success": True,
            "outcome": "success",
            "verification_method": "nmap_xml_parsed",
            "evidence": {},
            "output": {"hosts": ["10.0.0.5"]},
            "assertions": [],
        },
    }


def _dedup_payload(tool_id: str) -> dict:
    """What the *gateway's* dedup answers for a repeat that already succeeded."""
    return {
        "tool_id": tool_id,
        "output": {
            "success": True,
            "outcome": "success",
            "verification_method": "tool_already_invoked",
            "evidence": {"previous_invocation_id": "inv-1", "previous_outcome": "succeeded"},
            "output": {
                "deduplicated": True,
                "message": (
                    "Esta misma invocación ya se ejecutó con éxito en este run "
                    "(invocación previa inv-1): devuelve los mismos datos y no aporta "
                    "información nueva. Considera cambiar de estrategia."
                ),
            },
            "assertions": [],
        },
    }


@pytest.fixture()
def harness(tmp_path):
    """A live store, scope and execution context for one ReAct run.

    The same shape the Phase 3b/3c suites script: the real loop over a real store
    with the tool layer spied out, so no host, provider or network is touched.
    """
    store = ControlStore(tmp_path / "react3g.db")
    store.initialize()
    _create_scope(store, "eng-1")
    run = store.create_run("system", {})
    task = {
        "id": "task-react-3g",
        "tenant_id": "system",
        "run_id": run["id"],
        "task_type": "react.run",
        "payload": {
            "objective": "Escanea 10.0.0.5 en los puertos 22 y 80",
            "engagement_id": "eng-1",
            "identity": {"subject_id": "operator-1", "roles": ["operator"]},
            "permissions": ["execute:tool:nexus.recon.nmap"],
        },
    }
    return store, ExecutionContext(store, task, "worker-test")


def _timeout_events(store, run_id: str) -> list[dict]:
    return [
        event
        for event in store.list_run_events("system", run_id)
        if event.get("event_type") == TOOL_UNAVAILABLE_EVENT_TYPE
    ]


# ------------------------------------------------------------------ Bug A / V1-26
# The identical repeat of a failed action is corrected, never blocked.


async def test_repeated_failed_action_injects_correction_not_block(harness):
    """The measured iteration: the same failed call twice gets text, not ``blocked``.

    In the rerun #7 the second identical ``msf_exploit`` reached the gateway and the
    run died asking for an approval the trust-mode run does not hold. The repeat must
    instead be answered with the correction the model needs, and the run must go on.
    """
    store, context_ = harness
    same = _call(target="10.0.0.5", flags=["-Pn"])
    llm = ScriptedLLM([same, same, _task_complete()])
    spy = ToolSpy(error=RuntimeError("tool post-condition was not verified"))

    with mock_execute_tool(spy):
        result = await run_react_loop(
            context=context_,
            objective="Escanea 10.0.0.5",
            engagement_id="eng-1",
            llm_client=llm,
            config=_config(max_iterations=6),
        )

    # The run is not closed as ``blocked`` and no approval sentence is involved.
    assert result.status == STATUS_COMPLETED
    assert result.status != "blocked"
    assert "requires human approval" not in result.final_summary
    # The identical repeat never reached the tool layer (the gateway, and with it the
    # approval gate, was never consulted), and the turn was consumed like any other.
    assert len(spy.payloads) == 1
    assert len(result.turns) >= 2

    correction = [
        item for item in _observations(store, result.conversation_id)
        if "Repetiste la invocación" in item
    ]
    assert correction, "the model must read the correction on the next prompt"
    assert FAILING_TOOL in correction[0]
    assert "Propón UNA acción NUEVA" in correction[0]
    assert '"outcome":"repeated_action"' in correction[0]


async def test_repeated_successful_action_still_uses_dedup(harness):
    """Regression (V1-14): only a repeat of a *failed* action is intercepted.

    A repeat of an invocation that already succeeded keeps its own answer: it reaches
    the executor, the gateway's dedup marks it (``tool_already_invoked``) and the model
    reads the data it asked for with the strategy warning.
    """
    store, context_ = harness
    same = _call(target="10.0.0.5", flags=["-Pn"])
    llm = ScriptedLLM([same, same, _task_complete()])
    spy = _DedupSpy()

    with mock_execute_tool(spy):
        result = await run_react_loop(
            context=context_,
            objective="Escanea 10.0.0.5",
            engagement_id="eng-1",
            llm_client=llm,
            config=_config(max_iterations=6),
        )

    assert result.status == STATUS_COMPLETED
    assert len(spy.payloads) == 2, "a successful repeat is the gateway's business"
    observations = _observations(store, result.conversation_id)
    assert any("ya se ejecutó con éxito" in item for item in observations)
    assert not any("Repetiste la invocación" in item for item in observations)


async def test_repeated_failed_action_does_not_consume_human_approval(harness):
    """No approval is requested, and none is consumed, for a repeated failure.

    The correction happens before the gateway, so the ``retry:invocation:...``
    approval the journal asks for an unknown outcome is never reached. The turn's own
    approval hook stays untouched too -this tool never needs one and the repeat must
    not change that- and the run finishes on its own instead of ``blocked``.
    """
    store, context_ = harness
    same = _call(target="10.0.0.5", flags=["-Pn"])
    llm = ScriptedLLM([same, same, _task_complete()])
    spy = ToolSpy(error=RuntimeError("tool post-condition was not verified"))
    asked: list[tuple] = []

    def _on_approval_needed(*args: Any) -> None:
        asked.append(args)
        return None

    with mock_execute_tool(spy):
        result = await run_react_loop(
            context=context_,
            objective="Escanea 10.0.0.5",
            engagement_id="eng-1",
            llm_client=llm,
            config=_config(max_iterations=6, on_approval_needed=_on_approval_needed),
        )

    assert asked == [], "the repeat must never reach the approval gate"
    assert result.status == STATUS_COMPLETED
    assert len(spy.payloads) == 1
    # Nothing was left pending in the store either.
    assert _pending_approvals(store) == []


async def test_two_different_failed_actions_do_not_trigger_correction(harness):
    """Two failures in a row are not a repetition when the invocation differs.

    The trigger is (same tool *and* same canonical arguments *and* adjacent), so a
    second attempt with another target is a new attempt: it really runs, and no
    correction is injected.
    """
    store, context_ = harness
    llm = ScriptedLLM(
        [
            _call(target="10.0.0.5", flags=["-Pn"]),
            _call(target="10.0.0.6", flags=["-Pn"]),
            _task_complete(),
        ]
    )
    spy = ToolSpy(error=RuntimeError("tool post-condition was not verified"))

    with mock_execute_tool(spy):
        result = await run_react_loop(
            context=context_,
            objective="Escanea la red",
            engagement_id="eng-1",
            llm_client=llm,
            config=_config(max_iterations=6),
        )

    assert result.status == STATUS_COMPLETED
    assert len(spy.payloads) == 2, "both attempts must be executed"
    assert not any(
        "Repetiste la invocación" in item
        for item in _observations(store, result.conversation_id)
    )


# ------------------------------------------------------------------ Bug B / V1-27
# A tool that runs out of time is a tool failure, never a provider error.


def test_sleeping_handler_is_cut_off_by_its_own_timeout_seconds(tmp_path):
    """The real gateway converts a handler's overrun into ``outcome="timeout"``.

    Reproduces the rerun #7 attempt 1 at the level it happened: a handler that sleeps
    past ``timeout_seconds``. The call completes as a determinate ``timeout`` -with its
    own method and evidence, and deriving no assertion- instead of raising the bare
    ``TimeoutError`` that used to end the whole run as ``provider_error``.
    """
    store = ControlStore(tmp_path / "timeout.db")
    store.initialize()
    audit = AuditWriter(store)
    gateway = ToolGateway(PolicyEngine(store), audit)
    tool_id = "nexus.recon.slow"

    async def handler(arguments: dict[str, Any], context: RunContext) -> ToolResult:
        await asyncio.sleep(5)
        return ToolResult(output={}, verified=True, verification_method="never_reached")

    gateway.register(
        ToolDefinition(
            "slow",
            "system",
            {"type": "object", "properties": {"target": {"type": "string"}}},
            tool_id=tool_id,
            risk=RiskLevel.READ_ONLY,
            effect="read_only",
            timeout_seconds=0.05,
        ),
        handler,
    )
    run_context = RunContext(
        "system", Identity("operator-1", "system", roles=("operator",)), run_id="run-1"
    )

    returned = asyncio.run(gateway.invoke(tool_id, {"target": "10.0.0.5"}, run_context))

    assert returned["success"] is False
    assert returned["verified"] is False
    assert returned["outcome"] == "timeout"
    assert returned["verification_method"] == f"{tool_id}_timeout"
    assert returned["evidence"] == {"timeout_seconds": 0.05, "tool_id": tool_id}
    # Nothing was observed about the target, so nothing is derived from it.
    assert returned["assertions"] == []

    trail = audit.export("system")
    assert [row for row in trail if row["action"] == "tool.failed"] == []
    completed = next(row for row in trail if row["action"] == "tool.complete")
    assert completed["payload"]["outcome"] == "timeout"
    # The effect is not confirmed: the invocation stays retryable by policy instead of
    # being answered later as data this run never obtained.
    assert InvocationJournal(store).get(returned["invocation_id"], "system")["state"] == "unknown"


async def test_tool_timeout_returns_failed_not_provider_error(harness):
    """A tool timeout is counted as a tool failure and the run survives it.

    This is the loop-side half of the measured defect: the per-call ceiling used to
    close the engagement as ``provider_error``. It must now be an observation with
    ``outcome="timeout"`` that names the tool and tells the model what to do.
    """
    store, context_ = harness
    llm = ScriptedLLM([_call(target="10.0.0.5", flags=["-Pn"]), _task_complete()])
    spy = ToolSpy(error=TimeoutError("tool call exceeded its 600s budget"))

    with mock_execute_tool(spy):
        result = await run_react_loop(
            context=context_,
            objective="Escanea 10.0.0.5",
            engagement_id="eng-1",
            llm_client=llm,
            config=_config(max_iterations=4),
        )

    assert result.status == STATUS_COMPLETED
    assert result.status != "provider_error"
    assert result.final_summary != "TimeoutError"

    timeout = [
        item for item in _observations(store, result.conversation_id)
        if '"outcome":"timeout"' in item
    ]
    assert timeout, "the timeout must reach the model as a determinate observation"
    assert FAILING_TOOL in timeout[0]
    assert "exceeded its time budget" in timeout[0]


async def test_llm_timeout_still_returns_provider_error(harness):
    """Regression: a *provider* timeout keeps its own terminal status.

    Only the tool layer changed. A model call that times out is not a tool failure and
    must still close the run with ``provider_error`` (the B8.2 fix), never be counted
    as a tool that failed.
    """
    store, context_ = harness
    llm = _TimingOutLLM()

    with mock_execute_tool(ToolSpy(error=RuntimeError("must not be reached"))):
        result = await run_react_loop(
            context=context_,
            objective="Escanea 10.0.0.5",
            engagement_id="eng-1",
            llm_client=llm,
            config=_config(max_iterations=4),
        )

    assert result.status == "provider_error"
    assert "TimeoutError" in result.final_summary
    assert _timeout_events(store, context_.run_id) == []


async def test_three_consecutive_tool_timeouts_retire_the_tool(harness):
    """Three timeouts retire the tool, exactly like any other tool failure (B3).

    The point of the previous fix: the timeout has to be *counted* so the agent stops
    insisting on a route that keeps running out of time. Each attempt uses different
    arguments on purpose -an identical repeat is the corrected case of V1-26- so what
    is exercised here is the retirement path itself.
    """
    store, context_ = harness
    llm = ScriptedLLM(
        [
            _call(target="10.0.0.5", flags=["-Pn"]),
            _call(target="10.0.0.6", flags=["-Pn"]),
            _call(target="10.0.0.7", flags=["-Pn"]),
            _task_complete(),
        ]
    )
    spy = _PayloadSpy({FAILING_TOOL: _timeout_payload})

    with mock_execute_tool(spy):
        result = await run_react_loop(
            context=context_,
            objective="Escanea la red",
            engagement_id="eng-1",
            llm_client=llm,
            config=_config(max_iterations=8),
        )

    assert result.status != "provider_error"
    assert len(spy.payloads) == 3
    retired = _timeout_events(store, context_.run_id)
    assert len(retired) == 1
    assert retired[0]["payload"]["tool_id"] == FAILING_TOOL
    assert retired[0]["payload"]["failures"] == 3


# --------------------------------------------------------------------- harness


def mock_execute_tool(spy: Any):
    """Patch the tool executor the loop calls (never the real gateway, never a host)."""
    from unittest import mock

    return mock.patch.object(runtime_module, "execute_tool", spy)


class _PayloadSpy:
    """Returns the scripted payload of each tool (or a plain success)."""

    def __init__(self, payloads: dict[str, Any]) -> None:
        self.payloads: list[dict] = []
        self._payloads = payloads

    async def __call__(self, payload, context):
        self.payloads.append(payload)
        tool_id = str(payload["tool_id"])
        factory = self._payloads.get(tool_id)
        return copy.deepcopy(factory(tool_id) if factory else _success_payload(tool_id))


class _DedupSpy(_PayloadSpy):
    """Succeeds once, then answers the way the gateway's dedup does (V1-14)."""

    def __init__(self) -> None:
        super().__init__({})

    async def __call__(self, payload, context):
        self.payloads.append(payload)
        tool_id = str(payload["tool_id"])
        if len(self.payloads) == 1:
            return copy.deepcopy(_success_payload(tool_id))
        return copy.deepcopy(_dedup_payload(tool_id))


class _TimingOutLLM:
    """A provider that never answers: the model call times out."""

    async def complete(self, messages, **kwargs):
        raise TimeoutError("provider call timed out")


def _pending_approvals(store: ControlStore) -> list[dict]:
    """Approval rows still pending (never requested here, which is the point)."""
    from nexus_core.kernel.approvals import ApprovalService

    return list(ApprovalService(store).list_pending("system"))
