"""Generic autonomy semantics: answers vs failures, progress, families, dedup.

Every test pins behaviour that must hold for any engagement; no room, address,
credential or flag is hard-coded.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from unittest import mock

import pytest

from nexus_core.agent.coverage import (
    STATUS_CLOSED,
    STATUS_PENDING,
    build_coverage,
    render_coverage,
)
from nexus_core.agent.react import run_react_loop
from nexus_core.agent.react_support import termination_summary
from nexus_core.agent.react_types import TOOL_UNAVAILABLE_EVENT_TYPE
from nexus_core.agent.task_manager import invocation_signature
from nexus_core.agent.turn_telemetry import FrictionFlag, TurnTelemetryRecorder
from nexus_core.integrations.metasploit.client import (
    MetasploitAuthError,
    MetasploitRPCError,
    MetasploitUnavailable,
)
from nexus_core.kernel import runtime as runtime_module
from nexus_core.kernel.blackboard import Blackboard
from nexus_core.kernel.invocation_journal import InvocationJournal
from nexus_core.kernel.step_signature import semantic_signature
from nexus_core.kernel.tool_gateway import ToolGateway
from nexus_core.tests.unit.test_phase3_fixes import (
    ENGAGEMENT,
    TENANT,
    ScriptedLLM,
    _events,
    _harness,
    _loop_config,
    tool_call,
)
from nexus_core.tools.handlers._msf import msf_failure_result

pytestmark = [pytest.mark.unit, pytest.mark.usefixtures("lab_scope")]


# ---------------------------------------------------------------------------
# A determinate "no" is an answer, not a broken tool
# ---------------------------------------------------------------------------
def test_a_verified_negative_still_derives_no_positive_fact() -> None:
    from nexus_core.kernel.fact_verification import derive_assertions
    from nexus_core.kernel.models import Identity, RunContext, ToolResult

    negative = ToolResult(
        verified=True,
        outcome="negative",
        verification_method="nmap_xml_parsed",
        output={
            "scan": {
                "hosts": [
                    {
                        "ip": "203.0.113.39",
                        "state": "up",
                        "ports": [{"port": 445, "protocol": "tcp", "state": "open"}],
                    }
                ]
            }
        },
    )
    context = RunContext(
        tenant_id=TENANT,
        identity=Identity("operator", TENANT, roles=("operator",)),
        run_id="run-negative",
        invocation_id="inv-negative",
    )
    assert derive_assertions("nexus.recon.nmap", {"target": "203.0.113.39"}, negative, context) == []


def test_negative_is_flagged_as_an_answer_in_telemetry() -> None:
    recorder = TurnTelemetryRecorder(emit=False)
    recorder.begin_turn(iteration=1, phase="enumeration", subagent_id=None)
    recorder.note_tool(duration_ms=900, success=False, outcome="negative")
    record = recorder.finish(outcome="negative")
    assert record is not None
    assert FrictionFlag.TOOL_NEGATIVE.value in record.friction
    assert FrictionFlag.TOOL_FAILURE.value not in record.friction


def test_in_flight_is_neither_an_answer_nor_a_failure() -> None:
    recorder = TurnTelemetryRecorder(emit=False)
    recorder.begin_turn(iteration=1, phase="enumeration", subagent_id=None)
    recorder.note_tool(duration_ms=1, success=False, outcome="in_flight")
    record = recorder.finish(outcome="in_flight")
    assert record is not None
    assert record.friction == (FrictionFlag.TOOL_IN_FLIGHT.value,)


@pytest.mark.parametrize("outcome", ["unavailable", "timeout", "error"])
def test_unavailable_timeout_and_error_stay_failures(outcome: str) -> None:
    recorder = TurnTelemetryRecorder(emit=False)
    recorder.begin_turn(iteration=1, phase="enumeration", subagent_id=None)
    recorder.note_tool(duration_ms=10, success=False, outcome=outcome)
    record = recorder.finish(outcome=outcome)
    assert record is not None
    assert FrictionFlag.TOOL_FAILURE.value in record.friction


async def test_negative_turns_never_retire_the_tool(tmp_path) -> None:
    """Three determinate SMB-style negatives are information, not a broken tool."""
    store, context = _harness(tmp_path)
    llm = ScriptedLLM(
        [tool_call(ports=str(port)) for port in (445, 3389, 5985, 49152)]
    )

    negative = {
        "tool_id": "nexus.recon.nmap",
        "output": {
            "success": False,
            "outcome": "negative",
            "verified": False,
            "verification_method": "smb_shares_empty",
            "output": {"count": 0, "error": "NT_STATUS_RESOURCE_NAME_NOT_FOUND"},
            "assertions": [],
        },
    }

    async def fake_tool(payload, run_context):
        return dict(negative)

    with mock.patch.object(runtime_module, "execute_tool", fake_tool):
        result = await run_react_loop(
            context=context,
            objective="Enumera el objetivo autorizado",
            engagement_id=ENGAGEMENT,
            llm_client=llm,
            config=_loop_config(max_iterations=4),
        )

    assert [turn["friction"] for turn in result.turns] == [
        ["tool_negative"],
        ["tool_negative"],
        ["tool_negative"],
        ["tool_negative"],
    ]
    assert _events(store, context, TOOL_UNAVAILABLE_EVENT_TYPE) == []
    assert result.status == "max_iterations"


# ---------------------------------------------------------------------------
# Progress is actionable, and a barrier does not buy a new margin
# ---------------------------------------------------------------------------
async def test_a_barrier_without_evidence_does_not_reset_the_streak(tmp_path) -> None:
    store, context = _harness(tmp_path)
    llm = ScriptedLLM(
        [tool_call(ports=str(port)) for port in (445, 3389, 5985, 49152)]
    )
    board = Blackboard(store)
    calls = {"count": 0}

    async def fake_tool(payload, run_context):
        calls["count"] += 1
        board.record(
            tenant_id=TENANT,
            engagement_id=ENGAGEMENT,
            fact_type="barrier",
            key=f"203.0.113.40:{440 + calls['count']}",
            value={"reason": "sin vector", "sweep_attempted": False},
            source="agent",
            created_by="agent",
            verified=False,
        )
        return dict(
            {
                "tool_id": "nexus.recon.nmap",
                "output": {
                    "success": True,
                    "verified": True,
                    "verification_method": "nmap_xml_parsed",
                    "output": {"scan": {"hosts": []}},
                    "assertions": [],
                },
            }
        )

    with mock.patch.object(runtime_module, "execute_tool", fake_tool):
        result = await run_react_loop(
            context=context,
            objective="Enumera el objetivo autorizado",
            engagement_id=ENGAGEMENT,
            llm_client=llm,
            config=_loop_config(max_iterations=4),
        )

    # Four barriers in a row are four turns without actionable progress.
    assert [turn["consecutive_no_progress"] for turn in result.turns] == [1, 2, 3, 4]


def test_only_a_conclusive_barrier_counts_as_branch_progress() -> None:
    from nexus_core.agent.react_coordinator import ReActCoordinator

    coordinator = ReActCoordinator.__new__(ReActCoordinator)
    coordinator.closed_branches = set()
    coordinator.observation = {"success": True}
    with mock.patch.object(
        ReActCoordinator, "_blackboard_counts", lambda self: {"barrier": 5, "service": 2}
    ):
        coordinator.action = SimpleNamespace(
            tool_id="nexus.knowledge.record_fact",
            arguments={
                "fact_type": "barrier",
                "key": "203.0.113.41:80",
                "value": {"reason": "probado", "sweep_attempted": False},
            },
        )
        assert coordinator._actionable_progress() == (2, 0)

        coordinator.action = SimpleNamespace(
            tool_id="nexus.knowledge.record_fact",
            arguments={
                "fact_type": "barrier",
                "key": "203.0.113.41:80",
                "value": {
                    "reason": "el barrido se ejecutó y no hay vector",
                    "sweep_attempted": True,
                },
            },
        )
        assert coordinator._actionable_progress() == (2, 1)


# ---------------------------------------------------------------------------
# Dynamic RPC ports are one campaign, not one branch per port
# ---------------------------------------------------------------------------
def _service(port: int, service: str, host: str = "203.0.113.42") -> dict:
    return {
        "fact_type": "service",
        "key": f"{host}:{port}:tcp",
        "value": {"state": "open", "service": service},
        "verified": True,
    }


def test_dynamic_rpc_ports_share_one_family_and_one_representative() -> None:
    host = "203.0.113.42"
    facts = [
        _service(3389, "ms-wbt-server", host),
        _service(445, "microsoft-ds", host),
        _service(49152, "msrpc", host),
        _service(49153, "msrpc", host),
        _service(49154, "rpcbind", host),
        _service(49155, "msrpc", host),
    ]
    coverage = build_coverage(facts)

    assert len(coverage.entries) == 6  # no open port is discarded
    assert len(coverage.families) == 1
    representative = coverage.family_representative(host, "rpc")
    assert representative is not None and representative.ref == f"{host}:49152"
    assert len(coverage.open_work) == 6
    deferred = coverage.deferred_family_members(representative)
    assert {entry.port for entry in deferred} == {49153, 49154, 49155}
    assert all(entry.status == STATUS_PENDING for entry in deferred)
    rendered = render_coverage(coverage)
    assert "familia RPC" in rendered
    assert "APLAZADOS" in rendered


def test_a_family_barrier_closes_the_whole_campaign() -> None:
    host = "203.0.113.43"
    facts = [
        _service(49152, "msrpc", host),
        _service(49153, "msrpc", host),
        {
            "fact_type": "barrier",
            "key": f"{host}:rpc",
            "value": {"reason": "el endpoint mapper no expone vector", "sweep_attempted": True},
            "verified": False,
        },
    ]
    coverage = build_coverage(facts)
    assert [entry.status for entry in coverage.entries] == [STATUS_CLOSED, STATUS_CLOSED]


def test_an_unknown_high_port_is_not_folded_into_a_family() -> None:
    coverage = build_coverage([_service(54321, "")])
    assert coverage.families == {}
    first = coverage.first_open()
    assert first is not None
    assert first.port == 54321


# ---------------------------------------------------------------------------
# One semantic signature for direct, background and retried scans
# ---------------------------------------------------------------------------
def test_timeout_only_differences_are_the_same_scan_in_every_layer() -> None:
    base = {"target": "203.0.113.44", "profile": "full_tcp"}
    with_timeout = {**base, "timeout_seconds": 300}
    background = {**base, "background": True}

    assert semantic_signature("nexus.recon.nmap", base) == semantic_signature(
        "nexus.recon.nmap", with_timeout
    )
    assert invocation_signature("nexus.recon.nmap", base) == invocation_signature(
        "nexus.recon.nmap", background
    )
    assert InvocationJournal.step_key(
        "nexus.recon.nmap", base, phase="enumeration"
    ) == InvocationJournal.step_key(
        "nexus.recon.nmap", with_timeout, phase="enumeration"
    )


def test_real_differences_are_still_different_intents() -> None:
    base = {"target": "203.0.113.44", "profile": "full_tcp"}
    assert semantic_signature("nexus.recon.nmap", base) != semantic_signature(
        "nexus.recon.nmap", {**base, "profile": "top_1000"}
    )
    assert semantic_signature("nexus.recon.nmap", base) != semantic_signature(
        "nexus.recon.nmap", {**base, "target": "203.0.113.45"}
    )
    assert InvocationJournal.step_key(
        "nexus.recon.nmap", base, phase="enumeration"
    ) != InvocationJournal.step_key("nexus.recon.nmap", base, phase="exploitation")


# ---------------------------------------------------------------------------
# Metasploit failures carry a concrete, safe cause
# ---------------------------------------------------------------------------
def test_msf_failure_causes_are_distinct_and_never_leak_secrets() -> None:
    cases = [
        (MetasploitAuthError("rejected password=hunter2"), "authentication_failed", "auth_failed"),
        (MetasploitUnavailable("cannot connect"), "rpc_unreachable", "unavailable"),
        (
            MetasploitRPCError("RPC error", method="module.execute"),
            "module_unavailable",
            "module_unavailable",
        ),
        (MetasploitRPCError("RPC error", method="job.stop"), "rpc_error", "rpc_failed"),
    ]
    for error, cause, method_fragment in cases:
        result = msf_failure_result("nexus.exploit.msf_auxiliary", error)
        # The handler states the specific cause; the gateway turns the shape into
        # the established ``*_provider_unavailable`` method (see the next test).
        assert result.completed is False
        assert result.output["cause"] == cause
        assert method_fragment in result.verification_method
        assert "hunter2" not in str(result.to_dict())


def test_the_gateway_preserves_the_specific_msf_cause(tmp_path) -> None:
    from nexus_core.kernel.control_store import ControlStore
    from nexus_core.kernel.audit import AuditWriter
    from nexus_core.kernel.models import Identity, RunContext, ToolDefinition
    from nexus_core.kernel.policy import PolicyEngine

    store = ControlStore(tmp_path / "msf.db")
    store.initialize()
    gateway = ToolGateway(PolicyEngine(store), AuditWriter(store))
    gateway.register(
        ToolDefinition("msf_probe", TENANT, {}, tool_id="msf_probe", effect="read_only"),
        lambda arguments, context: msf_failure_result(
            "nexus.exploit.msf_auxiliary", MetasploitAuthError("rejected")
        ),
    )
    context = RunContext(
        tenant_id=TENANT,
        identity=Identity("operator", TENANT, roles=("operator",)),
        run_id="run-msf",
    )
    returned = asyncio.run(gateway.invoke("msf_probe", {}, context))
    assert returned["outcome"] == "unavailable"
    assert returned["evidence"]["cause_code"] == "authentication_failed"
    assert returned["output"]["cause"] == "authentication_failed"


# ---------------------------------------------------------------------------
# Terminal summary shows the proven surface, not only the missing findings
# ---------------------------------------------------------------------------
def test_the_terminal_summary_lists_verified_facts_with_zero_findings() -> None:
    summary = termination_summary(
        reason="iteration budget exhausted without task_complete",
        max_iterations=12,
        counts={"service": 3, "host": 1, "barrier": 2},
        findings=0,
        closed_branches=1,
        open_labels=["203.0.113.46:445/tcp microsoft-ds"],
        report_line="informe PENDIENTE",
    )
    assert "verified facts: service=3" in summary
    assert "host=" not in summary  # inventory noise, not actionable progress
    assert "findings=0" in summary
    assert "closed branches=1" in summary
    assert "203.0.113.46:445/tcp" in summary
    assert "informe PENDIENTE" in summary
    assert "termination_reason=" in summary
