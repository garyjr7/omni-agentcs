"""Hardening of the agent frame (B8.2.1, B8.2.2, B8.2.3) and the rg preflight (B6).

The E2E run #2 ended "completed" after a single recon action, citing ports and
users that only the *previous* runs of the shared work session had observed. The
three defences pinned here are deliberately independent of the model:

* a run only ever reads its own turns (B8.2.1);
* a ``task_complete`` is refused while the plan is unfinished (B8.2.2);
* a finding whose evidence no observation of this run supports is marked
  ``stale_evidence`` and cannot close the engagement (B8.2.3).
"""

from __future__ import annotations

import copy
import json
from datetime import datetime, timedelta, timezone
from unittest import mock

import pytest

from nexus_core.agent import memory
from nexus_core.agent import react as react_module
from nexus_core.agent.evidence import annotate_findings, fabricated_evidence
from nexus_core.agent.planner import PHASES
from nexus_core.agent.react import (
    FINAL_PHASE_ID,
    MAX_PREMATURE_COMPLETIONS,
    PREMATURE_COMPLETION_EVENT_TYPE,
    STATUS_COMPLETED,
    STATUS_PREMATURE_COMPLETION,
    ReActConfig,
    run_react_loop,
)
from nexus_core.kernel import runtime as runtime_module
from nexus_core.kernel.blackboard import Blackboard
from nexus_core.kernel.control_store import ControlStore
from nexus_core.kernel.runtime import ExecutionContext
from nexus_core.llm.abstraction import LLMProvider, LLMResponse
from nexus_core.scope import EngagementScope, EngagementStore

CURRENT_TARGET = "10.67.177.81"
STALE_TARGET = "10.65.163.65"
STALE_FILE = "locks.txt"

#: A fact-query observation: what a *reporting-phase* profile can still obtain
#: (``nexus.knowledge.query_facts`` is a common tool), used when a test needs the
#: plan to be on ``reporting`` and this run to have its own evidence.
QUERY_OK = {
    "tool_id": "nexus.knowledge.query_facts",
    "output": {
        "success": True,
        "verified": True,
        "verification_method": "blackboard_read",
        "evidence": {"facts": 1},
        "output": {
            "facts": [
                {
                    "fact_type": "service",
                    "key": "ftp",
                    "value": {"host": CURRENT_TARGET, "port": 21},
                }
            ]
        },
    },
}

NMAP_OK = {
    "tool_id": "nexus.recon.nmap",
    "output": {
        "success": True,
        "verified": True,
        "verification_method": "nmap_xml_parsed",
        "evidence": {"hosts_up": 1, "ports_open_total": 2},
        "output": {
            "target": CURRENT_TARGET,
            "scan": {
                "hosts": [
                    {
                        "ip": CURRENT_TARGET,
                        "ports": [
                            {"port": 21, "state": "open", "service": "ftp"},
                            {"port": 22, "state": "open", "service": "ssh"},
                        ],
                    }
                ]
            },
        },
    },
}


def _iso(delta: timedelta) -> str:
    return (datetime.now(timezone.utc) + delta).isoformat()


def _tool_call(tool_id: str, **arguments) -> str:
    return json.dumps(
        {
            "thought": "siguiente paso",
            "action": "tool_call",
            "tool_id": tool_id,
            "arguments": arguments,
            "expected_outcome": "evidencia",
        }
    )


def _complete(*findings) -> str:
    return json.dumps(
        {
            "thought": "listo",
            "action": "task_complete",
            "summary": "engagement cerrado",
            "findings": list(findings),
        }
    )


class ScriptedLLM:
    """Replays the scripted answers, repeating the last one forever."""

    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = 0
        self.prompts: list[str] = []

    async def complete(self, messages, **kwargs):
        self.calls += 1
        index = min(self.calls - 1, max(0, len(self.responses) - 1))
        self.prompts.append("\n".join(str(m.content) for m in messages))
        return LLMResponse(
            content=self.responses[index] if self.responses else "",
            model="scripted-test",
            provider=LLMProvider.FAKE,
        )


class ToolSpy:
    """Returns a successful nmap observation (and records the payloads)."""

    def __init__(self, payload: dict | None = None):
        self.payloads: list[dict] = []
        self.response = payload or NMAP_OK

    async def __call__(self, payload, context):
        self.payloads.append(payload)
        result = copy.deepcopy(self.response)
        result["tool_id"] = payload["tool_id"]
        result["output"]["assertions"] = [dict(invocation_id="test-invocation",run_id=context.run_id,
            target=CURRENT_TARGET,fact_type="service",verified=True,verification_method="test-parser")]
        return result


def _make_harness(tmp_path, name: str):
    store = ControlStore(tmp_path / name)
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
    return store


def _context(store) -> ExecutionContext:
    run = store.create_run("system", {})
    task = {
        "id": f"task-{run['id']}",
        "tenant_id": "system",
        "run_id": run["id"],
        "task_type": "react.run",
        "payload": {
            "objective": "comprometer 10.67.177.81",
            "engagement_id": "eng-1",
            "identity": {"subject_id": "operator-1", "roles": ["operator"]},
            "permissions": [],
        },
    }
    return ExecutionContext(store, task, "worker-test")


@pytest.fixture()
def harness(tmp_path):
    store = _make_harness(tmp_path, "frame.db")
    return store, _context(store)


def _events(store, run_id, event_type):
    return [
        event
        for event in store.list_run_events("system", run_id)
        if event.get("event_type") == event_type
    ]


def _seed_completed_plan(store, engagement_id: str = "eng-1") -> None:
    """One verified fact per phase so the plan reaches ``reporting``."""
    board = Blackboard(store)
    for fact_type in ("host", "user", "access", "privilege", "loot"):
        board.record(
            tenant_id="system",
            engagement_id=engagement_id,
            fact_type=fact_type,
            key=f"k-{fact_type}",
            value={"note": fact_type},
            source="test-parser",
            verified=True, asserted_by="verifier", verification_method="test-parser", invocation_id="fixture-invocation",
            created_by="operator-1",
        )


# --------------------------------------------------------------- frame constants
def test_final_phase_id_matches_the_planner():
    assert FINAL_PHASE_ID == PHASES[-1].id


# --------------------------------------------------- B8.2.2 premature completion
async def test_premature_task_complete_is_refused_and_the_loop_keeps_working(harness):
    store, context = harness
    llm = ScriptedLLM(
        [_complete(), _tool_call("nexus.recon.nmap", target=CURRENT_TARGET), _complete()]
    )
    spy = ToolSpy()

    with mock.patch.object(runtime_module, "execute_tool", spy):
        result = await run_react_loop(
            context=context,
            objective="comprometer 10.67.177.81",
            engagement_id="eng-1",
            llm_client=llm,
            config=ReActConfig(max_iterations=5),
        )

    assert result.status == STATUS_PREMATURE_COMPLETION
    assert result.completion_objections
    assert "fase" in result.completion_objections[0]
    # The refusal does not count as a tool failure: the run kept working.
    assert [p["tool_id"] for p in spy.payloads] == ["nexus.recon.nmap"]
    rejections = _events(store, context.run_id, PREMATURE_COMPLETION_EVENT_TYPE)
    assert len(rejections) == MAX_PREMATURE_COMPLETIONS
    assert rejections[0]["payload"]["phase"] == "recon"
    # The correction is durably injected, so a resumed run sees it too.
    messages = memory.load_history(store, "system", result.conversation_id, limit=100)
    corrections = [
        m for m in messages if memory.message_kind(m) == "react.correction"
    ]
    assert corrections and "RECHAZADO" in corrections[0]["content"]


async def test_task_complete_is_accepted_on_the_reporting_phase(harness):
    store, context = harness
    _seed_completed_plan(store)
    llm = ScriptedLLM([_complete()])

    with mock.patch.object(runtime_module, "execute_tool", ToolSpy()):
        result = await run_react_loop(
            context=context,
            objective="cerrar el engagement",
            engagement_id="eng-1",
            llm_client=llm,
            config=ReActConfig(max_iterations=4),
        )

    assert result.status == STATUS_COMPLETED
    assert result.iterations == 1
    assert result.completion_objections == []
    assert _events(store, context.run_id, PREMATURE_COMPLETION_EVENT_TYPE) == []


async def test_a_run_without_an_engagement_may_complete(harness):
    """No signed scope means no kill chain to complete (documented scoping)."""
    store, context = harness
    llm = ScriptedLLM([_complete()])

    with mock.patch.object(runtime_module, "execute_tool", ToolSpy()):
        result = await run_react_loop(
            context=context,
            objective="resume el estado del engagement",
            engagement_id=None,
            llm_client=llm,
            config=ReActConfig(max_iterations=4),
        )

    assert result.status == STATUS_COMPLETED


# --------------------------------------------------------- B8.2.3 stale evidence
async def test_findings_citing_another_runs_evidence_are_marked_stale(harness):
    store, context = harness
    llm = ScriptedLLM(
        [
            _tool_call("nexus.recon.nmap", target=CURRENT_TARGET),
            _complete(
                {
                    "severity": "high",
                    "title": f"Credenciales de {STALE_TARGET}",
                    "evidence": f"{STALE_TARGET} usuario harry {STALE_FILE}",
                }
            ),
        ]
    )

    with mock.patch.object(runtime_module, "execute_tool", ToolSpy()):
        result = await run_react_loop(
            context=context,
            objective="comprometer 10.67.177.81",
            engagement_id="eng-1",
            llm_client=llm,
            config=ReActConfig(max_iterations=5),
        )

    assert result.status == STATUS_PREMATURE_COMPLETION
    assert result.findings and result.findings[0]["stale_evidence"] is True
    assert result.findings[0]["evidence_source"] == "stale_evidence"
    assert result.evidence_stats["grounded"] == 0
    assert any("stale_evidence" in item for item in result.completion_objections)


async def test_findings_grounded_in_this_runs_observation_survive(harness):
    store, context = harness
    _seed_completed_plan(store)
    llm = ScriptedLLM(
        [
            _tool_call("nexus.knowledge.query_facts", query="ftp"),
            _complete(
                {
                    "severity": "high",
                    "title": f"FTP observado en {CURRENT_TARGET}",
                    "invocation_id": "test-invocation", "target": CURRENT_TARGET, "fact_type": "service",
                    "evidence": f"21/tcp open ftp en {CURRENT_TARGET}",
                }
            ),
        ]
    )

    with mock.patch.object(runtime_module, "execute_tool", ToolSpy(QUERY_OK)):
        result = await run_react_loop(
            context=context,
            objective="cerrar el engagement",
            engagement_id="eng-1",
            llm_client=llm,
            config=ReActConfig(max_iterations=5),
        )

    assert result.status == STATUS_COMPLETED
    assert result.findings[0]["evidence_source"] == "current_run"
    assert "stale_evidence" not in result.findings[0]
    assert result.evidence_stats["grounded"] == 1


# ---------------------------------------------------------- B8.2.1 run isolation
async def test_a_run_does_not_inherit_another_runs_transcript(harness):
    store, context = harness
    conversation_id = memory.ensure_work_conversation(store, "system", "omni", "eng-1")
    first = ScriptedLLM(
        [
            _tool_call("nexus.recon.nmap", target=CURRENT_TARGET),
            _complete({"severity": "info", "title": f"FTP en {CURRENT_TARGET}", "evidence": "21/tcp ftp"}),
        ]
    )
    _seed_completed_plan(store)
    with mock.patch.object(runtime_module, "execute_tool", ToolSpy()):
        await run_react_loop(
            context=context,
            objective="recon del engagement",
            engagement_id="eng-1",
            llm_client=first,
            conversation_id=conversation_id,
            config=ReActConfig(max_iterations=4),
        )

    second = ScriptedLLM([_complete()])
    with mock.patch.object(runtime_module, "execute_tool", ToolSpy()):
        await run_react_loop(
            context=_context(store),
            objective="segundo objetivo",
            engagement_id="eng-1",
            llm_client=second,
            conversation_id=conversation_id,
            config=ReActConfig(max_iterations=4),
        )

    prompt = second.prompts[0]
    # The earlier objective survives as *session context* ...
    assert "recon del engagement" in prompt
    assert "segundo objetivo" in prompt
    # ... but the earlier run's tool output does not reach this run's model.
    assert "nmap_xml_parsed" not in prompt
    assert "21/tcp" not in prompt


async def test_stale_evidence_from_a_previous_run_never_closes_the_new_run(harness):
    """The exact E2E run #2 bug: a finding citing what an *earlier* run observed."""
    store, context = harness
    conversation_id = memory.ensure_work_conversation(store, "system", "omni", "eng-1")
    stale_observation = copy.deepcopy(NMAP_OK)
    stale_observation["output"]["output"]["target"] = STALE_TARGET
    stale_observation["output"]["output"]["scan"]["hosts"][0]["ip"] = STALE_TARGET

    # Run 1 observed the OLD address (the room was re-addressed between runs).
    first = ScriptedLLM([_tool_call("nexus.recon.nmap", target=STALE_TARGET), _complete()])
    with mock.patch.object(runtime_module, "execute_tool", ToolSpy(stale_observation)):
        await run_react_loop(
            context=context,
            objective="primer objetivo",
            engagement_id="eng-1",
            llm_client=first,
            conversation_id=conversation_id,
            config=ReActConfig(max_iterations=4),
        )

    # Run 2 observes the CURRENT address only, yet its finding cites run 1's.
    second = ScriptedLLM(
        [
            _tool_call("nexus.recon.nmap", target=CURRENT_TARGET),
            _complete(
                {
                    "severity": "high",
                    "title": f"SSH en {STALE_TARGET}",
                    "evidence": f"22/tcp open ssh en {STALE_TARGET}",
                }
            ),
        ]
    )
    with mock.patch.object(runtime_module, "execute_tool", ToolSpy()):
        result = await run_react_loop(
            context=_context(store),
            objective="segundo objetivo",
            engagement_id="eng-1",
            llm_client=second,
            conversation_id=conversation_id,
            # 3 refusals then the stop: the run needs room to insist.
            config=ReActConfig(max_iterations=8),
        )

    assert result.status == STATUS_PREMATURE_COMPLETION
    assert result.evidence_stats["corpus_tokens"] > 0
    assert result.findings[0]["evidence_source"] == "stale_evidence"
    assert any("stale_evidence" in item for item in result.completion_objections)
    # The earlier run's observation never reached this run's model (B8.2.1).
    assert STALE_TARGET not in second.prompts[0]


# --------------------------------------------------------------- B6 rg preflight
async def test_a_tool_whose_binary_is_missing_starts_retired(harness, monkeypatch):
    store, context = harness
    monkeypatch.setattr(
        react_module, "unavailable_tools_from_env", lambda: {"nexus.workspace.search"}
    )
    llm = ScriptedLLM(
        [
            _tool_call("nexus.workspace.search", query="lin"),
            _tool_call("nexus.recon.nmap", target=CURRENT_TARGET),
        ]
    )
    spy = ToolSpy()

    with mock.patch.object(runtime_module, "execute_tool", spy):
        await run_react_loop(
            context=context,
            objective="comprometer 10.67.177.81",
            engagement_id="eng-1",
            llm_client=llm,
            config=ReActConfig(max_iterations=4),
        )

    # The tool never ran: it is refused with a pointer to what is still usable.
    executed = [p["tool_id"] for p in spy.payloads]
    assert "nexus.workspace.search" not in executed
    assert executed and executed[0] == "nexus.recon.nmap"
    retired = _events(store, context.run_id, react_module.TOOL_UNAVAILABLE_EVENT_TYPE)
    assert [e["payload"]["reason"] for e in retired] == ["binary_missing"]
    # The retired tool is gone from the model's tool catalog (the rules mention it
    # by name, so only the catalog block is inspected).
    catalog_block = (
        llm.prompts[0].split("HERRAMIENTAS DISPONIBLES")[1].split("REGLAS:")[0]
    )
    assert "nexus.workspace.search" not in catalog_block
    assert "nexus.workspace.read" in catalog_block


# ------------------------------------------------------------ evidence module
def test_annotate_findings_marks_unsupported_and_stale():
    observations = [dict(invocation_id="i1",run_id="r1",target=CURRENT_TARGET,
                         fact_type="service",verified=True,verification_method="test-parser")]
    findings, stats = annotate_findings(
        [dict(title="FTP",invocation_id="i1",target=CURRENT_TARGET,fact_type="service"),
         {"title":"SSH", "evidence":f"ssh en {STALE_TARGET}"}, {"title":""}],
        observations=observations,run_id="r1")
    assert [item["evidence_source"] for item in findings] == ["current_run","stale_evidence","no_evidence"]
    assert stats['grounded'] == stats['stale'] == stats['unsupported'] == 1
    assert fabricated_evidence(stats) is True


def test_fabricated_evidence_without_observations_still_blocks():
    findings, stats = annotate_findings([{"title":f"algo en {STALE_TARGET}"}],observations=[])
    assert findings[0]['evidence_source'] == 'stale_evidence'
    assert fabricated_evidence(stats) is True


# This module's unsigned scopes exercise targeting/session behavior. Authentication
# is covered separately in test_scope_governed_mode with the governed default.
pytestmark = globals().get("pytestmark", [])
if not isinstance(pytestmark, list):
    pytestmark = [pytestmark]
pytestmark.append(pytest.mark.usefixtures("lab_scope"))
