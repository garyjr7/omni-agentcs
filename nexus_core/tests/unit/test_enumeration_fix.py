"""Regression tests for the Fase 3.7 enumeration fixes (P0/P1/P2/P3).

The E2E #3 blocked on a *system* defect, not on the model: the planner closes
``recon`` with the first ``service`` fact, and ``enumeration`` mapped to the
web-only profile, so a target whose first service was FTP had no reachable
subset (``docs/missions/TEST_E2E_BOUNTY_HACKER_RUN3.md`` §5). These tests pin the
fix end to end: the profile that wins, the tools it offers, the grace window and
the operator pin.
"""

from __future__ import annotations

import io
import json
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest import mock

import pytest

from nexus_core.agent.react import STATUS_COMPLETED, ReActConfig, run_react_loop
from nexus_core.kernel import runtime as runtime_module
from nexus_core.kernel.audit import AuditWriter
from nexus_core.kernel.blackboard import Blackboard
from nexus_core.kernel.control_store import ControlStore
from nexus_core.kernel.runtime import ExecutionContext
from nexus_core.llm.abstraction import LLMProvider, LLMResponse
from nexus_core.scope import EngagementScope, EngagementStore

pytestmark = pytest.mark.unit

TENANT = "system"
ENGAGEMENT = "eng-enum"


def _iso(delta: timedelta) -> str:
    return (datetime.now(timezone.utc) + delta).isoformat()


def _loop_config(**kwargs) -> ReActConfig:
    """Mechanics config: the completion gates are covered by ``test_react_frame``."""
    kwargs.setdefault("enforce_completion_gates", False)
    return ReActConfig(**kwargs)


def _tool_call(tool_id: str, arguments: dict | None = None) -> str:
    return json.dumps(
        {
            "thought": "voy a usarla",
            "action": "tool_call",
            "tool_id": tool_id,
            "arguments": arguments or {"target": "10.0.0.5"},
            "expected_outcome": "algo",
        }
    )


def _record_ftp_service() -> str:
    return _tool_call(
        "nexus.knowledge.record_fact",
        {
            "fact_type": "service",
            "key": "10.0.0.5:21/tcp",
            "value": {"service": "ftp", "product": "vsftpd"},
            "source": "nexus.recon.nmap",
            "verified": True,
        },
    )


def _task_complete() -> str:
    return json.dumps(
        {"thought": "listo", "action": "task_complete", "summary": "ok", "findings": []}
    )


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


def _result_for(tool_id: str) -> dict:
    return {
        "tool_id": tool_id,
        "output": {
            "success": True,
            "verified": True,
            "verification_method": "deterministic_check",
            "evidence": {"ok": True},
            "output": {"note": "ran"},
        },
    }


def _harness(tmp_path, **payload_extra):
    store = ControlStore(tmp_path / "enum.db")
    store.initialize()
    EngagementStore(store).create(
        EngagementScope(
            engagement_id=ENGAGEMENT,
            tenant_id=TENANT,
            name="enum",
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
    run = store.create_run(TENANT, {})
    task = {
        "id": "task-enum",
        "tenant_id": TENANT,
        "run_id": run["id"],
        "task_type": "react.run",
        "payload": {
            "objective": "Enumera 10.0.0.5",
            "engagement_id": ENGAGEMENT,
            "identity": {"subject_id": "operator-1", "roles": ["operator"]},
            **payload_extra,
        },
    }
    return store, ExecutionContext(store, task, "worker-enum"), run["id"]


def _spy(store, *, record_facts: bool):
    """Stand-in for the gateway: it records the fact the model asked for.

    Wiring the blackboard write back into the fake is what lets one run *cross*
    the ``recon`` → ``enumeration`` boundary, which is the whole point.
    """
    executed: list[str] = []
    board = Blackboard(store)

    async def _call(payload, context):
        executed.append(payload["tool_id"])
        if record_facts and payload["tool_id"] == "nexus.recon.nmap":
            arguments = payload.get("arguments") or {}
            board.record(
                tenant_id=TENANT,
                engagement_id=ENGAGEMENT,
                fact_type=str(arguments.get("fact_type") or "service"),
                key=str(arguments.get("key") or "10.0.0.5:21/tcp"),
                value=arguments.get("value") or {},
                source="test",
                verified=True, asserted_by="verifier", verification_method="nmap_xml_parsed", invocation_id="fixture-invocation",
                created_by="tester",
            )
        return _result_for(payload["tool_id"])

    return _call, executed


def _denials(store, run_id):
    return [
        row
        for row in AuditWriter(store).export(TENANT, trace_id=run_id)
        if row["action"] == "react.step"
        and row["payload"].get("reason") == "subagent_tool_denied"
    ]


# ------------------------------------------------------------------ P0 + P1


async def test_first_service_fact_keeps_the_tools_that_enumerate_it(tmp_path):
    """P0+P1: the FTP subset survives the ``recon`` → ``enumeration`` hop.

    Iterations 2-3 are the grace window (the previous profile's read-only tools),
    iteration 4 is past it, so the same tool is then refused by the subset.
    """
    store, context, run_id = _harness(tmp_path)
    spy, executed = _spy(store, record_facts=True)
    llm = _ScriptedLLM(
        [
            _tool_call("nexus.recon.nmap"),  # 1: recon -> the first ``service`` fact
            _tool_call("nexus.recon.nmap"),  # 2: enumeration, grace
            _tool_call("nexus.recon.nmap"),  # 3: enumeration, grace
            _tool_call("nexus.recon.nmap"),  # 4: enumeration, grace expired
            _task_complete(),  # 5
        ]
    )

    with mock.patch.object(runtime_module, "execute_tool", spy):
        result = await run_react_loop(
            context=context,
            objective="Enumera 10.0.0.5",
            engagement_id=ENGAGEMENT,
            llm_client=llm,
            config=_loop_config(max_iterations=6),
        )

    assert result.status == STATUS_COMPLETED
    # P0: enumeration no longer falls back to the web-only profile.
    assert result.subagent_id == "services"
    # The service profile itself offers the FTP enumeration tool.
    assert "nexus.recon.ftp" in llm.calls[1][0]["content"]
    # P1: nmap (only reachable through the grace) ran twice, then was refused.
    assert executed.count("nexus.recon.nmap") == 3
    assert "nexus.recon.nmap" in llm.calls[1][0]["content"]
    assert "nexus.recon.nmap" in llm.calls[2][0]["content"]
    assert "nexus.recon.nmap" not in llm.calls[3][0]["content"]
    assert len(_denials(store, run_id)) == 1
    assert AuditWriter(store).verify_chain() == (True, None)


async def test_service_profile_is_announced_with_its_effective_subset(tmp_path):
    """P3: ``orchestrator.subagent`` carries ``tools``, so P1-style locks show up."""
    store, context, _ = _harness(tmp_path)
    spy, _ = _spy(store, record_facts=True)
    llm = _ScriptedLLM([_tool_call("nexus.recon.nmap"), _task_complete()])

    with mock.patch.object(runtime_module, "execute_tool", spy):
        await run_react_loop(
            context=context,
            objective="Enumera 10.0.0.5",
            engagement_id=ENGAGEMENT,
            llm_client=llm,
            config=_loop_config(max_iterations=2),
        )

    events = [
        event
        for event in store.list_run_events(TENANT, context.run_id)
        if event["event_type"] == "orchestrator.subagent"
    ]
    assert [event["payload"]["subagent_id"] for event in events] == ["recon", "services"]
    assert events[1]["payload"]["previous"] == "recon"
    assert "nexus.recon.ftp" in events[1]["payload"]["tools"]
    # The announced subset is exactly the one the loop enforces in that iteration.
    assert "nexus.recon.nmap" in events[1]["payload"]["tools"]


# ------------------------------------------------------------------ P2 (CLI)


def test_subagent_flag_is_exposed_and_validated():
    from nexus_core.cli.main import build_parser

    parser = build_parser()
    assert parser.parse_args(["--subagent", "services"]).subagent == "services"
    assert parser.parse_args([]).subagent is None
    with pytest.raises(SystemExit):
        parser.parse_args(["--subagent", "no-existe"])


def test_operator_pin_reaches_the_headless_payload(tmp_path, monkeypatch):
    from nexus_core.cli import headless as headless_module
    from nexus_core.cli.session import OmniSession

    store = ControlStore(tmp_path / "headless.db")
    store.initialize()
    captured: list[dict] = []

    async def _fake_loop(*, context, **kwargs):
        captured.append(dict(context.task["payload"]))
        return SimpleNamespace(
            status="completed",
            iterations=1,
            final_summary="ok",
            findings=[],
            subagent_id="services",
            conversation_id="conversation-x",
            plan=None,
        )

    monkeypatch.setattr(headless_module, "run_react_loop", _fake_loop)
    session = OmniSession(
        store=store,
        tenant_id=TENANT,
        engagement=None,
        llm_client=None,
        use_tui=False,
        subagent="services",
    )
    buffer = io.StringIO()
    code = headless_module.run_headless(session, "Enumera 10.0.0.5", mode="json", stream=buffer)

    assert code == 1
    assert captured and captured[0]["subagent"] == "services"
    assert json.loads(buffer.getvalue().splitlines()[-1])["status"] == "completed"


def test_repl_subagent_command_sets_and_clears_the_pin():
    from nexus_core.cli import commands

    session = SimpleNamespace(subagent_override=None)
    commands.cmd_subagent(session, ["services"])
    assert session.subagent_override == "services"
    commands.cmd_subagent(session, ["auto"])
    assert session.subagent_override is None
    # An unknown id never reaches the run: the command refuses it.
    commands.cmd_subagent(session, ["web"])
    assert session.subagent_override == "web"
    commands.cmd_subagent(session, ["nope"])
    assert session.subagent_override == "web"


# This module's unsigned scopes exercise targeting/session behavior. Authentication
# is covered separately in test_scope_governed_mode with the governed default.
pytestmark = globals().get("pytestmark", [])
if not isinstance(pytestmark, list):
    pytestmark = [pytestmark]
pytestmark.append(pytest.mark.usefixtures("lab_scope"))
