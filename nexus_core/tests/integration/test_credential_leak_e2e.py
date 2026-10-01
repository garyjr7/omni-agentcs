"""Hermetic DB-level check: no cleartext credential reaches ``kernel_messages``.

This does not need the network or a real model: a scripted LLM requests a tool
call carrying ``password`` and ``hash``. The loop must persist a redacted
history while the executor still receives the original values.
"""

from __future__ import annotations

import asyncio
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

pytestmark = pytest.mark.integration

PASSWORD = "secret123"
NTLM_HASH = "deadbeef" * 4


def _iso(delta: timedelta) -> str:
    return (datetime.now(timezone.utc) + delta).isoformat()


class ScriptedLLM:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = 0

    async def complete(self, messages, **kwargs):
        self.calls += 1
        index = min(self.calls - 1, max(0, len(self.responses) - 1))
        return LLMResponse(
            content=self.responses[index], model="scripted", provider=LLMProvider.FAKE
        )


@pytest.mark.parametrize("wrapper", ["{}", "```json\n{}\n```", "Acción:\n{}\nFin."])
@pytest.mark.parametrize("malformed", [False, True])
def test_e2e_credentials_never_persisted_to_kernel_messages(tmp_path, wrapper, malformed):
    store = ControlStore(tmp_path / "control.db")
    store.initialize()
    EngagementStore(store).create(
        EngagementScope(
            engagement_id="eng-1",
            tenant_id="system",
            name="eng-1",
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
    run = store.create_run("system", {})
    context = ExecutionContext(
        store,
        {
            "id": "task-leak-e2e",
            "tenant_id": "system",
            "run_id": run["id"],
            "task_type": "react.run",
            "payload": {
                "objective": "e2e leak",
                "engagement_id": "eng-1",
                "identity": {"subject_id": "operator-1", "roles": ["operator"]},
                "permissions": ["execute:tool:nexus.recon.nmap"],
            },
        },
        "worker-e2e",
    )
    tool_call = json.dumps(
        {
            "thought": "auth",
            "action": "tool_call",
            "tool_id": "nexus.recon.nmap",
            "arguments": {
                "target": "10.0.0.5",
                "flags": ["-Pn"],
                "password": PASSWORD,
                "hash": NTLM_HASH,
            },
        }
    )
    done = json.dumps(
        {"thought": "ok", "action": "task_complete", "summary": "done", "findings": []}
    )
    received = {}

    async def fake_execute_tool(payload, ctx):
        received.update(payload["arguments"])
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

    with mock.patch.object(runtime_module, "execute_tool", fake_execute_tool):
        outcome = asyncio.run(
            run_react_loop(
                context=context,
                objective="e2e leak",
                engagement_id="eng-1",
                llm_client=ScriptedLLM([wrapper.format(tool_call[:-2] if malformed else tool_call), done]),
                config=ReActConfig(max_iterations=3),
            )
        )

    with store.connect() as conn:
        rows = conn.execute("SELECT content, metadata FROM kernel_messages").fetchall()
    blob = "\n".join(f"{row['content']}\n{row['metadata']}" for row in rows)
    assert PASSWORD not in blob
    assert NTLM_HASH not in blob
    # The handler still got the real credentials.
    if malformed:
        assert received == {}, "malformed requests must never execute"
    else:
        assert received["password"] == PASSWORD
        assert received["hash"] == NTLM_HASH
    with store.connect() as conn:
        audit_rows = conn.execute("SELECT payload FROM kernel_audit_events").fetchall()
    audit_blob = "\n".join(row["payload"] for row in audit_rows)
    assert PASSWORD not in audit_blob and NTLM_HASH not in audit_blob
    event_blob = json.dumps(store.list_run_events("system", run["id"]))
    assert PASSWORD not in event_blob and NTLM_HASH not in event_blob
    from nexus_core.kernel.audit import AuditWriter
    assert AuditWriter(store).verify_chain()[0]
    assert outcome.conversation_id
