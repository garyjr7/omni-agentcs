"""End-to-end (in-process) credential redaction in the ReAct loop.

The loop must persist a redacted history while still handing the real
credentials to the tool executor.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from unittest import mock

import pytest

from nexus_core.agent.react import ReActConfig, run_react_loop
from nexus_core.kernel import runtime as runtime_module
from nexus_core.kernel.control_store import ControlStore
from nexus_core.kernel.runtime import ExecutionContext
from nexus_core.llm.abstraction import LLMProvider, LLMResponse
from nexus_core.scope import EngagementScope, EngagementStore

pytestmark = pytest.mark.unit

PASSWORD = "secret123"
NTLM_HASH = "a" * 32


def _iso(delta: timedelta) -> str:
    return (datetime.now(timezone.utc) + delta).isoformat()


def _create_scope(store) -> None:
    EngagementStore(store).create(
        EngagementScope(
            engagement_id="eng-1",
            tenant_id="system",
            name="engagement-eng-1",
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


def _credential_tool_call() -> str:
    return json.dumps(
        {
            "thought": "Autentico con las credenciales del engagement.",
            "action": "tool_call",
            "tool_id": "nexus.recon.nmap",
            "arguments": {
                "target": "10.0.0.5",
                "flags": ["-Pn", "-p", "22"],
                "password": PASSWORD,
                "hash": NTLM_HASH,
                "content_sha256": "integrity-digest",
            },
            "expected_outcome": "puerto abierto",
        }
    )


def _task_complete() -> str:
    return json.dumps(
        {
            "thought": "Terminado.",
            "action": "task_complete",
            "summary": "hecho",
            "findings": [],
        }
    )


class ScriptedLLM:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    async def complete(self, messages, **kwargs):
        self.calls.append(messages)
        index = min(len(self.calls) - 1, max(0, len(self.responses) - 1))
        return LLMResponse(
            content=self.responses[index],
            model="scripted-test",
            provider=LLMProvider.FAKE,
        )


class ToolSpy:
    def __init__(self):
        self.payloads = []

    async def __call__(self, payload, context):
        self.payloads.append(payload)
        return {
            "tool_id": payload["tool_id"],
            "output": {
                "success": True,
                "verified": True,
                "verification_method": "test",
                "evidence": {},
                "output": {},
            },
        }


@pytest.fixture()
def harness(tmp_path):
    store = ControlStore(tmp_path / "react.db")
    store.initialize()
    _create_scope(store)
    run = store.create_run("system", {})
    task = {
        "id": "task-react-creds",
        "tenant_id": "system",
        "run_id": run["id"],
        "task_type": "react.run",
        "payload": {
            "objective": "Prueba de redacción",
            "engagement_id": "eng-1",
            "identity": {"subject_id": "operator-1", "roles": ["operator"]},
            "permissions": ["execute:tool:nexus.recon.nmap"],
        },
    }
    return store, ExecutionContext(store, task, "worker-test")


async def _run(harness):
    store, context = harness
    llm = ScriptedLLM([_credential_tool_call(), _task_complete()])
    spy = ToolSpy()
    with mock.patch.object(runtime_module, "execute_tool", spy):
        result = await run_react_loop(
            context=context,
            objective="Prueba de redacción",
            engagement_id="eng-1",
            llm_client=llm,
            config=_loop_config(max_iterations=4),
        )
    return store, result, spy


async def test_react_loop_redacts_credentials_in_persisted_arguments(harness):
    store, result, _ = await _run(harness)
    messages = store.list_messages("system", result.conversation_id)
    serialized = json.dumps(messages, ensure_ascii=False, default=str)
    assert PASSWORD not in serialized
    assert NTLM_HASH not in serialized

    actions = [m for m in messages if m["metadata"].get("kind") == "react.action"]
    assert actions, "the action step must be persisted"
    arguments = actions[0]["metadata"]["arguments"]
    assert arguments["password"] == "[REDACTED]"
    assert arguments["hash"] == "[REDACTED]"
    # Integrity digests must survive redaction.
    assert arguments["content_sha256"] == "integrity-digest"
    # The persisted raw JSON assistant turn is redacted too.
    assert PASSWORD not in actions[0]["content"]
    assert NTLM_HASH not in actions[0]["content"]


async def test_react_loop_passes_original_arguments_to_tool(harness):
    _, _, spy = await _run(harness)
    assert spy.payloads, "the tool must have been invoked"
    arguments = spy.payloads[0]["arguments"]
    assert arguments["password"] == PASSWORD
    assert arguments["hash"] == NTLM_HASH


def test_redact_content_preserves_plain_prose():
    from nexus_core.agent.memory import _redact_content

    assert _redact_content("hola mundo") == "hola mundo"
    assert _redact_content("") == ""


def test_redact_arguments_none_passthrough():
    from nexus_core.agent.memory import _redact_arguments

    assert _redact_arguments(None) is None
    assert _redact_arguments({}) == {}


def _loop_config(**kwargs):
    """Loop config for tests that exercise mechanics, not the completion gates.

    ``require_plan_completion=False`` disables the B8.2.2/B8.2.3 gate on purpose:
    these tests script a ``task_complete`` (or need the loop to keep proposing
    recon tools) while the blackboard is empty, which production must refuse. The
    gate itself is covered by ``test_react_frame.py``. The host-binary preflight
    (B6) is disabled too so the tool catalog never depends on the CI machine.
    """
    kwargs.setdefault("enforce_completion_gates", False)
    return ReActConfig(**kwargs)


# This module's unsigned scopes exercise targeting/session behavior. Authentication
# is covered separately in test_scope_governed_mode with the governed default.
pytestmark = globals().get("pytestmark", [])
if not isinstance(pytestmark, list):
    pytestmark = [pytestmark]
pytestmark.append(pytest.mark.usefixtures("lab_scope"))
