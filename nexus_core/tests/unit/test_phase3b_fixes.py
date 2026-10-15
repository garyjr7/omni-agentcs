"""Fase 3b fixes: the hidden contract published, the dead backend survived.

Measured in run_434f5eeadb104b11ba0c80bce16f8d08 (10.65.175.32): iteration 6
proposed ``nexus.exploit.msf_auxiliary`` with ``options.RHOSTS`` -a key the
handler refuses although the JSON Schema accepts it, and the catalog never
said so- and the following call found ``msfrpcd`` not listening, which raised
``ProviderFailure`` and ended the whole run (exit 3, ``provider_error``) with
five other routes still in the phase.

Two fixes, one commit:

* 5A/V1-15: ``ToolDefinition.forbidden_argument_values`` publishes the values
  the handler rejects, and the catalog line carries them (``options ∉
  {RHOSTS, LHOST, ...}``), so the model knows before it tries. The rejection
  message names the offending key instead of a generic sentence.
* 5C/V1-16: a backend that is not serving does not end the mission. The tool
  answers ``outcome="unavailable"`` (never ``negative``: nothing was observed),
  the loop counts it like any other tool failure, retires the tool after
  repeated attempts and pivots to the rest of the phase- while a genuine fatal
  provider failure still aborts the run.
"""

from __future__ import annotations

import asyncio
import copy
import json
from datetime import datetime, timedelta, timezone
from unittest import mock

import pytest

from nexus_core.agent.prompts import render_tool_catalog
from nexus_core.agent.react import ReActConfig, STATUS_MAX_ITERATIONS, run_react_loop
from nexus_core.integrations.metasploit.client import MetasploitUnavailable
from nexus_core.kernel import runtime as runtime_module
from nexus_core.kernel.control_store import ControlStore
from nexus_core.kernel.errors import ProviderFailure
from nexus_core.kernel.invocation_journal import InvocationJournal
from nexus_core.kernel.runtime import ExecutionContext
from nexus_core.llm.abstraction import LLMProvider, LLMResponse
from nexus_core.scope import EngagementScope, EngagementStore
from nexus_core.tests.msf_support import context, fake_client, gateway, scope
from nexus_core.tools.handlers import msf_auxiliary as msf_auxiliary_module
from nexus_core.tools.handlers import msf_exploit as msf_exploit_module
from nexus_core.tools.registry import durable_tool_definitions

MSF_ARGS = {"module": "auxiliary/scanner/smb/smb_version", "target": "203.0.113.10"}

FORBIDDEN_TOOLS = (
    ("nexus.exploit.msf_auxiliary", msf_auxiliary_module),
    ("nexus.exploit.msf_exploit", msf_exploit_module),
)


# ------------------------------------------------------------------ 5A / V1-15


@pytest.mark.parametrize(
    "tool_id,module", FORBIDDEN_TOOLS, ids=["msf_auxiliary", "msf_exploit"]
)
def test_catalog_exposes_forbidden_options(tool_id, module):
    """The catalog publishes the handler's vetting, and the refusal names the key.

    The schema stays permissive on purpose (any datastore key is a scalar for
    Metasploit), so the hand-written validator is the real contract. It used to
    be invisible: the model could only learn ``RHOSTS`` was refused by being
    refused, and the message it got back ("forbidden or duplicate auxiliary
    option") did not even say which key was the problem.
    """
    catalog = durable_tool_definitions("system")
    rendered = render_tool_catalog(catalog)
    line = next(item for item in rendered.splitlines() if item.startswith(f"- {tool_id}:"))

    assert "options:object ∉ {" in line
    assert "RHOSTS" in line and "LHOST" in line
    # Same one-pass shape as an enum: the constraint travels with the argument.
    assert "LPORT" in line and "PROXIES" in line

    # The handler keeps enforcing it, and now says *which* option is forbidden
    # and what is still allowed- not just that something was wrong.
    with pytest.raises(ValueError) as refusal:
        module.validated_options({"RHOSTS": "203.0.113.10", "RPORT": 445})
    message = str(refusal.value)
    assert "'RHOSTS'" in message
    assert "forbidden" in message
    assert "RPORT" in message


# ------------------------------------------------------------------ 5C / V1-16


def test_msf_auxiliary_returns_unavailable_when_rpc_down(tmp_path, monkeypatch):
    """``msfrpcd`` down is a determinate ``unavailable``, not a fatal error.

    Reproduces the measured iteration: the RPC bridge fails, the handler answers
    ``msf_rpc_failed`` and the gateway used to raise ``ProviderFailure``, which
    the loop turned into ``run.complete status=provider_error``. No ``msfrpcd``
    is contacted: the bridge is mocked.
    """
    client = fake_client(monkeypatch, msf_auxiliary_module)
    client.execute_module.side_effect = MetasploitUnavailable("msfrpcd is not listening")
    gw, audit = gateway(tmp_path)
    context_ = context(scope())

    payload = asyncio.run(gw.invoke("nexus.exploit.msf_auxiliary", MSF_ARGS, context_))

    assert payload["success"] is False
    assert payload["outcome"] == "unavailable"
    assert payload["verification_method"] == "nexus.exploit.msf_auxiliary_provider_unavailable"
    assert payload["evidence"]["provider"] == "msf_rpc"
    assert payload["evidence"]["cause"]["error_type"] == "MetasploitUnavailable"
    # Nothing was observed against the target: no fact may be derived from it.
    assert payload["assertions"] == []
    invocation = InvocationJournal(ControlStore(tmp_path / "control.db")).get(
        payload["invocation_id"], "system"
    )
    assert invocation["state"] == "succeeded"
    trail = audit.export("system")
    assert [row for row in trail if row["action"] == "tool.failed"] == []
    completed = next(row for row in trail if row["action"] == "tool.complete")
    assert completed["payload"]["outcome"] == "unavailable"


# ------------------------------------------------------------- the ReAct loop
#
# These drive the real loop with a scripted model and a spied tool layer, so the
# signal that matters is exercised end to end: does the run survive, does it
# retire the tool, and does the model read why.


def _iso(delta: timedelta) -> str:
    return (datetime.now(timezone.utc) + delta).isoformat()


def _create_scope(store, engagement_id: str = "eng-1") -> None:
    EngagementStore(store).create(
        EngagementScope(
            engagement_id=engagement_id,
            tenant_id="system",
            name=f"engagement-{engagement_id}",
            client="acme",
            owner_id="owner-1",
            valid_from=_iso(-timedelta(days=1)),
            valid_until=_iso(timedelta(days=1)),
            cidrs=("10.0.0.0/24",),
            domains=(),
            urls=(),
            exclusions=(),
            created_at=_iso(timedelta(0)),
        )
    )


class ScriptedLLM:
    """Replays scripted responses, repeating the last one when exhausted."""

    def __init__(self, responses: list[str]) -> None:
        self.responses = list(responses)
        self.calls: list[list[dict[str, str]]] = []

    async def complete(self, messages, **kwargs):
        self.calls.append([{"role": m.role, "content": m.content} for m in messages])
        index = min(len(self.calls) - 1, max(0, len(self.responses) - 1))
        return LLMResponse(
            content=self.responses[index] if self.responses else "",
            model="scripted-test",
            provider=LLMProvider.FAKE,
        )


def _tool_call(tool_id: str = "nexus.recon.nmap") -> str:
    return json.dumps(
        {
            "thought": "Insisto con la misma herramienta de reconocimiento.",
            "action": "tool_call",
            "tool_id": tool_id,
            "arguments": {"target": "10.0.0.5", "flags": ["-Pn"]},
            "expected_outcome": "puertos abiertos",
        }
    )


def _unavailable_payload(tool_id: str, provider: str = "nmap_rpc") -> dict:
    """What the gateway now returns when a tool's backend is not serving."""
    return {
        "tool_id": tool_id,
        "output": {
            "success": False,
            "outcome": "unavailable",
            "verification_method": f"{tool_id}_provider_unavailable",
            "evidence": {"provider": provider, "detail": "backend is not serving"},
            "output": {},
            "assertions": [],
        },
    }


class ToolSpy:
    """Stands in for ``execute_tool``: returns an unavailable result, or raises."""

    def __init__(self, result: dict | None = None, error: BaseException | None = None) -> None:
        self.result = result
        self.error = error
        self.payloads: list[dict] = []

    async def __call__(self, payload, context):
        self.payloads.append(payload)
        if self.error is not None:
            raise self.error
        return copy.deepcopy(self.result or _unavailable_payload(str(payload["tool_id"])))


@pytest.fixture()
def harness(tmp_path):
    store = ControlStore(tmp_path / "react.db")
    store.initialize()
    _create_scope(store, "eng-1")
    run = store.create_run("system", {})
    task = {
        "id": "task-react-3b",
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


def _config(**kwargs) -> ReActConfig:
    kwargs.setdefault("enforce_completion_gates", False)
    return ReActConfig(**kwargs)


def _observations(store, conversation_id: str) -> list[str]:
    return [
        message["content"]
        for message in store.list_messages("system", conversation_id)
        if message["metadata"].get("kind") == "react.observation"
    ]


async def test_unavailable_tool_is_retired_after_three_failures(harness):
    """Three consecutive ``unavailable`` outcomes retire the tool, not the run."""
    store, context_ = harness
    spy = ToolSpy(_unavailable_payload("nexus.recon.nmap"))

    with mock.patch.object(runtime_module, "execute_tool", spy):
        result = await run_react_loop(
            context=context_,
            objective="objetivo",
            engagement_id="eng-1",
            llm_client=ScriptedLLM([_tool_call()]),
            config=_config(max_iterations=6),
        )

    assert result.status == STATUS_MAX_ITERATIONS
    assert result.status != "provider_error"
    # The backend answered every time, so the loop kept iterating all six turns.
    assert result.iterations == 6
    events = [
        event
        for event in store.list_run_events("system", context_.run_id)
        if event.get("event_type") == "react.tool_unavailable"
    ]
    assert events and events[0]["payload"]["tool_id"] == "nexus.recon.nmap"
    assert events[0]["payload"]["failures"] == 3
    # The refusal that follows points the model at what remains.
    assert any("unavailable after repeated failures" in item for item in _observations(
        store, result.conversation_id
    ))


async def test_loop_suggests_alternative_when_tool_unavailable(harness):
    """The model reads *which* tool is out, *why*, and that it should pivot."""
    store, context_ = harness
    spy = ToolSpy(_unavailable_payload("nexus.recon.nmap", provider="nmap_rpc"))

    with mock.patch.object(runtime_module, "execute_tool", spy):
        result = await run_react_loop(
            context=context_,
            objective="objetivo",
            engagement_id="eng-1",
            llm_client=ScriptedLLM([_tool_call()]),
            config=_config(max_iterations=4),
        )

    guidance = [item for item in _observations(store, result.conversation_id) if "alternative" in item]
    assert guidance, "the unavailable observation must tell the model what to do next"
    first = guidance[0]
    assert "nexus.recon.nmap" in first
    assert "nmap_rpc" in first
    assert "temporarily unavailable" in first
    # Unavailable is never reported as "we looked and found nothing".
    assert '"outcome":"unavailable"' in first
    assert '"outcome":"negative"' not in first
    assert '"assertions":[]' in first


async def test_fatal_provider_failure_still_aborts(harness):
    """A genuine fatal provider failure keeps ending the run with ``provider_error``.

    The exception, pinned on purpose: classifying *every* provider failure as
    recoverable would hide a real protocol/invariant break behind a retry.
    """
    _, context_ = harness
    spy = ToolSpy(error=ProviderFailure("msf protocol is corrupt", kind="fatal"))

    with mock.patch.object(runtime_module, "execute_tool", spy):
        result = await run_react_loop(
            context=context_,
            objective="objetivo",
            engagement_id="eng-1",
            llm_client=ScriptedLLM([_tool_call()]),
            config=_config(max_iterations=6),
        )

    assert result.status == "provider_error"
    assert result.iterations == 1
    assert result.final_summary == "ProviderFailure"


async def test_unavailable_provider_failure_does_not_abort_the_run(harness):
    """The same raise declared ``unavailable`` degrades instead of ending the run."""
    store, context_ = harness
    spy = ToolSpy(
        error=ProviderFailure("msfrpcd is not listening", kind="unavailable")
    )

    with mock.patch.object(runtime_module, "execute_tool", spy):
        result = await run_react_loop(
            context=context_,
            objective="objetivo",
            engagement_id="eng-1",
            llm_client=ScriptedLLM([_tool_call()]),
            config=_config(max_iterations=6),
        )

    assert result.status == STATUS_MAX_ITERATIONS
    assert result.iterations == 6
    assert any(
        event.get("event_type") == "react.tool_unavailable"
        for event in store.list_run_events("system", context_.run_id)
    )
    assert any(
        "msfrpcd is not listening" in item for item in _observations(store, result.conversation_id)
    )


# This module's unsigned scope exercises targeting/backend behavior. Authentication
# is covered separately in test_scope_governed_mode with the governed default.
pytestmark = globals().get("pytestmark", [])
if not isinstance(pytestmark, list):
    pytestmark = [pytestmark]
pytestmark.append(pytest.mark.usefixtures("lab_scope"))
