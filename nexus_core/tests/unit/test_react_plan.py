"""The ReAct loop embeds the phased plan and audits phase transitions."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from unittest import mock

import pytest

from nexus_core.agent.react import ReActConfig, STATUS_COMPLETED, run_react_loop
from nexus_core.kernel import runtime as runtime_module
from nexus_core.kernel.blackboard import Blackboard
from nexus_core.kernel.control_store import ControlStore
from nexus_core.kernel.runtime import ExecutionContext
from nexus_core.llm.abstraction import LLMProvider, LLMResponse
from nexus_core.scope import EngagementScope, EngagementStore

pytestmark = pytest.mark.unit

TENANT = "system"
ENGAGEMENT = "eng-plan"


def _iso(delta: timedelta) -> str:
    return (datetime.now(timezone.utc) + delta).isoformat()


def _scope() -> EngagementScope:
    return EngagementScope(
        engagement_id=ENGAGEMENT,
        tenant_id=TENANT,
        name="plan",
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


class _LLM:
    def __init__(self) -> None:
        self.calls: list[str] = []

    async def complete(self, messages, **kwargs):
        self.calls.append("\n".join(m.content for m in messages))
        return LLMResponse(
            content=json.dumps(
                {"thought": "fin", "action": "task_complete", "summary": "hecho", "findings": []}
            ),
            model="test",
            provider=LLMProvider.FAKE,
        )


def _context(store: ControlStore) -> ExecutionContext:
    run = store.create_run(TENANT, {})
    task = {
        "id": f"task-{run['id']}",
        "tenant_id": TENANT,
        "run_id": run["id"],
        "task_type": "react.run",
        "payload": {"objective": "objetivo", "engagement_id": ENGAGEMENT},
    }
    return ExecutionContext(store, task, "worker")


@pytest.fixture()
def harness(tmp_path):
    store = ControlStore(tmp_path / "plan.db")
    store.initialize()
    EngagementStore(store).create(_scope())
    return store


async def test_prompt_includes_phased_plan(harness):
    store = harness
    context = _context(store)
    llm = _LLM()
    with mock.patch.object(runtime_module, "execute_tool", mock.AsyncMock()):
        result = await run_react_loop(
                config=_loop_config(),
            context=context,
            objective="objetivo",
            engagement_id=ENGAGEMENT,
            llm_client=llm,
        )
    assert result.status == STATUS_COMPLETED
    assert "PLAN DE ENGAGEMENT" in llm.calls[0]
    assert "fase actual: Reconocimiento" in llm.calls[0]


async def test_plan_reflects_blackboard_facts(harness):
    store = harness
    Blackboard(store).record(
        tenant_id=TENANT,
        engagement_id=ENGAGEMENT,
        fact_type="service",
        key="10.0.0.5:21/tcp",
        value={"product": "vsftpd"},
        source="nexus.recon.nmap",
        verified=True, asserted_by="verifier", verification_method="nmap_xml_parsed", invocation_id="fixture-invocation",
        created_by="operator-1",
    )
    context = _context(store)
    llm = _LLM()
    with mock.patch.object(runtime_module, "execute_tool", mock.AsyncMock()):
        result = await run_react_loop(
                config=_loop_config(),
            context=context,
            objective="objetivo",
            engagement_id=ENGAGEMENT,
            llm_client=llm,
        )
    assert "fase actual: Enumeración" in llm.calls[0]
    assert result.plan is not None
    assert result.plan["current"] == "enumeration"
    assert result.plan["counts"]["service"] == 1


async def test_phase_transition_is_audited_as_run_event(harness):
    store = harness
    context = _context(store)
    with mock.patch.object(runtime_module, "execute_tool", mock.AsyncMock()):
        await run_react_loop(
                config=_loop_config(),
            context=context,
            objective="objetivo",
            engagement_id=ENGAGEMENT,
            llm_client=_LLM(),
        )
    events = store.list_run_events(TENANT, context.run_id)
    plan_events = [event for event in events if event.get("event_type") == "orchestrator.plan"]
    assert plan_events
    assert plan_events[0]["payload"]["phase"] == "recon"
    assert plan_events[0]["payload"]["previous"] is None


def _loop_config(**kwargs):
    """Loop config for tests that exercise mechanics, not the completion gates.

    ``require_plan_completion=False`` disables the B8.2.2/B8.2.3 gate on purpose:
    these tests script a ``task_complete`` (or need the loop to keep proposing
    recon tools) while the blackboard is empty, which production must refuse. The
    gate itself is covered by ``test_react_frame.py``.
    """
    kwargs.setdefault("enforce_completion_gates", False)
    return ReActConfig(**kwargs)


# This module's unsigned scopes exercise targeting/session behavior. Authentication
# is covered separately in test_scope_governed_mode with the governed default.
pytestmark = globals().get("pytestmark", [])
if not isinstance(pytestmark, list):
    pytestmark = [pytestmark]
pytestmark.append(pytest.mark.usefixtures("lab_scope"))
