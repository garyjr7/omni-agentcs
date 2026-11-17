"""Generic autonomy contracts measured in Bounty Hacker v2 and Blue (2026-10-31).

Each test pins one defect that is *not* about those rooms: an SMB answer the
handler could not classify, a job id that belongs to another registry, an
identical invocation still in flight, a duplicated background scan, and a report
whose reference data was missing from the installed package.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import tomllib
from pathlib import Path
from typing import Any
from unittest import mock

import pytest

from nexus_core.agent.task_manager import FAILED, TaskManager
from nexus_core.kernel.audit import AuditWriter
from nexus_core.kernel.control_store import ControlStore
from nexus_core.kernel.invocation_journal import InvocationJournal
from nexus_core.kernel.models import Identity, RunContext, ToolDefinition, ToolResult
from nexus_core.kernel.policy import PolicyEngine
from nexus_core.kernel.sandbox import SandboxResult
from nexus_core.kernel.tool_gateway import ToolGateway
from nexus_core.report import cvss4 as cvss4_module
from nexus_core.report import mitre as mitre_module
from nexus_core.tools.handlers import jobs, smb as smb_module
from nexus_core.tools.handlers.smb import smb_handler

pytestmark = pytest.mark.unit

TENANT = "system"
TARGET = "203.0.113.10"
SMB_BINARY = "/usr/bin/smbclient"
_CLARIFY = json.dumps(
    {"thought": "sigo", "action": "request_clarification", "question": "¿Continúo?"}
)


class _FakeSandbox:
    def __init__(self, result: SandboxResult) -> None:
        self.result = result
        self.calls: list[list[str]] = []

    async def run(self, argv, *, timeout_seconds: float = 30) -> SandboxResult:
        self.calls.append(list(argv))
        return self.result


@contextlib.contextmanager
def _stubbed_smb(result: SandboxResult):
    sandbox = _FakeSandbox(result)
    with mock.patch.object(smb_module, "ad_sandbox", lambda *args, **kwargs: sandbox):
        with mock.patch.object(
            smb_module, "resolve_ad_binary", lambda *args, **kwargs: SMB_BINARY
        ):
            yield sandbox


def _context(**overrides: Any) -> RunContext:
    values: dict[str, Any] = {
        "tenant_id": TENANT,
        "identity": Identity("operator", TENANT, roles=("operator",)),
        "run_id": "run-autonomy",
    }
    values.update(overrides)
    return RunContext(**values)


def _probe_gateway(tmp_path, result: ToolResult):
    """A gateway whose one tool answers exactly *result* (never touches a target)."""
    store = ControlStore(tmp_path / "gateway.db")
    store.initialize()
    gateway = ToolGateway(PolicyEngine(store), AuditWriter(store))
    gateway.register(
        ToolDefinition("probe", TENANT, {}, tool_id="probe", effect="read_only"),
        lambda arguments, context: result,
    )
    return store, gateway


# --------------------------------------------------------------------------
# SMB: "there is no such share" is an answer, not a broken post-condition
# --------------------------------------------------------------------------
def test_smb_share_listing_with_a_resource_answer_completes_as_negative(tmp_path):
    """Blue: anonymous ``shares`` answered NT_STATUS_RESOURCE_NAME_NOT_FOUND.

    The token is the server's answer to the question ("no such share here"), not
    an I/O failure, so the call must complete with ``negative`` and derive no
    positive fact. Before this it reached the loop as ``tool post-condition was
    not verified`` and the agent read an empty share list as a broken check.
    """
    with _stubbed_smb(
        SandboxResult(0, "session setup failed: NT_STATUS_RESOURCE_NAME_NOT_FOUND\n", "")
    ):
        result = asyncio.run(smb_handler({"target": TARGET, "action": "shares"}, _context()))

    assert result.success is False
    assert result.completed is True
    assert result.outcome == "negative"
    assert result.verification_method == "smb_shares_empty"
    assert result.output["count"] == 0
    assert result.output["error"] == "NT_STATUS_RESOURCE_NAME_NOT_FOUND"

    store, gateway = _probe_gateway(tmp_path, result)
    returned = asyncio.run(gateway.invoke("probe", {"case": "blue"}, _context()))
    assert returned["outcome"] == "negative"
    assert returned["assertions"] == []
    trail = AuditWriter(store).export(TENANT)
    assert [row for row in trail if row["action"] == "tool.failed"] == []


def test_smb_io_tokens_still_fail_closed(tmp_path):
    """The rule is per token: an I/O answer is not an observation about the target."""
    with _stubbed_smb(SandboxResult(1, "", "NT_STATUS_IO_TIMEOUT\n")):
        result = asyncio.run(smb_handler({"target": TARGET, "action": "shares"}, _context()))
    assert result.outcome == ""
    assert result.completed is False


# --------------------------------------------------------------------------
# nexus.post.job: an id from the coordinator's registry is not a durable job
# --------------------------------------------------------------------------
async def test_job_status_rejects_coordinator_ids_without_a_raise(tmp_path, monkeypatch):
    monkeypatch.setattr(jobs, "validate_session_scope", lambda context: None)
    store = ControlStore(tmp_path / "jobs.db")
    store.initialize()
    store.create_tenant("tenant", tenant_id="t")
    run = store.create_run("t", {})
    context = RunContext(
        "t", Identity("owner", "t", roles=("operator",)), run_id=run["id"], store=store
    )

    result = await jobs.jobs_handler({"action": "status", "job_id": "bg-1"}, context)

    assert result.verified is False
    assert result.outcome == "negative"
    assert result.completed is True
    assert result.verification_method == "job_not_found"
    assert result.output["reason"] == "coordinator_task_id"
    assert result.output["registry"] == "nexus.post.job"
    assert "coordinador ReAct" in result.output["hint"]
    assert "nexus.post.job" in result.output["hint"]


def test_job_status_is_a_determinate_result_at_the_gateway(tmp_path):
    result = ToolResult(
        output={"status": "job_not_found"},
        outcome="negative",
        verification_method="job_not_found",
    )
    store, gateway = _probe_gateway(tmp_path, result)
    returned = asyncio.run(gateway.invoke("probe", {"case": "job"}, _context()))
    assert returned["outcome"] == "negative"
    assert returned["assertions"] == []
    assert [row for row in AuditWriter(store).export(TENANT) if row["action"] == "tool.failed"] == []


# --------------------------------------------------------------------------
# Gateway: the identical invocation is still in flight
# --------------------------------------------------------------------------
def test_an_identical_in_flight_invocation_is_reconciled_not_raised(tmp_path):
    """Bounty Hacker: a second ``nmap full_tcp`` while the first was running.

    The journal must not execute it twice; it also must not answer with a broken
    post-condition. The call completes as ``in_flight`` and names the running
    invocation so the loop can wait for the result that is already on its way.
    """
    store = ControlStore(tmp_path / "inflight.db")
    store.initialize()
    gateway = ToolGateway(PolicyEngine(store), AuditWriter(store))
    calls: list[dict] = []

    def handler(arguments, context):
        calls.append(dict(arguments))
        return ToolResult(output={"ok": True}, verified=True, verification_method="probe_ok")

    gateway.register(
        ToolDefinition("probe", TENANT, {}, tool_id="probe", effect="read_only"), handler
    )
    journal = InvocationJournal(store)
    arguments = {"target": TARGET, "profile": "full_tcp"}
    first = _context(phase="recon", objective="own the host", invocation_id="inv-first")
    journal.prepare(
        first,
        "probe",
        arguments,
        "",
        step_key=InvocationJournal.step_key(
            "probe", arguments, phase="recon", objective="own the host"
        ),
    )
    journal.start("inv-first", TENANT)

    second = _context(phase="recon", objective="own the host", invocation_id="inv-second")
    returned = asyncio.run(gateway.invoke("probe", dict(arguments), second))

    assert calls == [], "the identical effect never ran twice"
    assert returned["outcome"] == "in_flight"
    assert returned["success"] is False
    assert returned["verification_method"] == "tool_in_flight"
    assert returned["output"]["in_flight_invocation_id"] == "inv-first"
    assert returned["evidence"]["state"] == "running"
    assert returned["assertions"] == []
    assert "no se ha lanzado otra" in returned["output"]["message"]
    actions = [row["action"] for row in AuditWriter(store).export(TENANT)]
    assert "invocation.in_flight" in actions
    assert "tool.failed" not in actions


def test_a_different_argument_set_still_runs(tmp_path):
    """A changed target/profile is a different intent and must execute."""
    store = ControlStore(tmp_path / "different.db")
    store.initialize()
    gateway = ToolGateway(PolicyEngine(store), AuditWriter(store))
    calls: list[dict] = []

    def handler(arguments, context):
        calls.append(dict(arguments))
        return ToolResult(output={"ok": True}, verified=True, verification_method="probe_ok")

    gateway.register(
        ToolDefinition("probe", TENANT, {}, tool_id="probe", effect="read_only"), handler
    )
    journal = InvocationJournal(store)
    first_args = {"target": TARGET, "profile": "full_tcp"}
    first = _context(phase="recon", objective="own the host", invocation_id="inv-first")
    journal.prepare(
        first,
        "probe",
        first_args,
        "",
        step_key=InvocationJournal.step_key(
            "probe", first_args, phase="recon", objective="own the host"
        ),
    )
    journal.start("inv-first", TENANT)

    second = _context(phase="recon", objective="own the host", invocation_id="inv-second")
    returned = asyncio.run(
        gateway.invoke("probe", {"target": TARGET, "profile": "service"}, second)
    )

    assert calls == [{"target": TARGET, "profile": "service"}]
    assert returned["success"] is True


# --------------------------------------------------------------------------
# Background tasks: an identical call is reconciled, not spawned twice
# --------------------------------------------------------------------------
def _manager() -> TaskManager:
    async def runner(payload, cancel_event):
        return {"success": True, "outcome": "success"}

    return TaskManager(runner=runner)


def test_equivalent_background_signature_ignores_only_tuning():
    manager = _manager()

    async def scenario():
        record = await manager.spawn_task(
            tool_id="nexus.recon.nmap",
            arguments={"target": TARGET, "profile": "full_tcp", "timeout_seconds": 300},
        )
        try:
            same = manager.find_equivalent(
                "nexus.recon.nmap", {"target": TARGET, "profile": "full_tcp"}
            )
            other_profile = manager.find_equivalent(
                "nexus.recon.nmap", {"target": TARGET, "profile": "service"}
            )
            other_target = manager.find_equivalent(
                "nexus.recon.nmap", {"target": "198.51.100.9", "profile": "full_tcp"}
            )
            return record, same, other_profile, other_target
        finally:
            await manager.cancel_all()

    record, same, other_profile, other_target = asyncio.run(scenario())
    assert same is record, "same scan, different timeout => same task"
    assert other_profile is None, "a different profile is a different scan"
    assert other_target is None, "a different target is a different scan"


def test_a_failed_background_task_is_not_reconciled():
    """Retrying a scan that did not complete is a legitimate new attempt."""
    manager = TaskManager()

    async def scenario():
        async def runner(payload, cancel_event):
            raise RuntimeError("sandbox died")

        manager.runner = runner
        record = await manager.spawn_task(
            tool_id="nexus.recon.nmap", arguments={"target": TARGET}
        )
        await record.handle
        return record, manager.find_equivalent("nexus.recon.nmap", {"target": TARGET})

    record, found = asyncio.run(scenario())
    assert record.status == FAILED
    assert found is None


# --------------------------------------------------------------------------
# A refusal is the model's answer, not an Omni failure
# --------------------------------------------------------------------------
def test_a_refusal_is_recognised_in_the_models_own_words():
    from nexus_core.agent.react_coordinator import _refusal_kind

    assert _refusal_kind(
        "No puedo ayudar a explotar el host, obtener una shell ni extraer flags."
    ) == "model_declined"
    assert _refusal_kind("I can't help with exploiting that host.") == "model_declined"
    # A conditional question is a clarification, not a refusal.
    assert _refusal_kind("¿No puedo continuar sin credenciales? ¿Me las das?") == ""
    assert _refusal_kind("¿Quieres que continúe con una evaluación no intrusiva?") == ""


async def test_a_refusal_stop_keeps_the_verified_findings_and_names_what_is_owed(
    tmp_path, monkeypatch
):
    """Blue (2026-10-31): ``clarification`` published ``findings: []`` over a full board.

    The stop stays a clarification (the operator still answers), but the record
    now says the model declined -distinct from an Omni/tool failure or a barren
    loop- and carries the facts the verifier had already proved.
    """
    from types import SimpleNamespace

    from nexus_core.kernel.blackboard import Blackboard
    from nexus_core.tests.unit.test_parallel_tools import (
        FakeService,
        ScriptedLLM,
        _coordinator,
        _loop_context,
    )

    exec_ctx = _loop_context(tmp_path, monkeypatch)
    coordinator = _coordinator(exec_ctx, ScriptedLLM(_CLARIFY), ("local.one",), FakeService())
    await coordinator._initialize()
    coordinator.engagement_id = "eng-refusal"
    Blackboard(exec_ctx.store).record(
        tenant_id=TENANT,
        engagement_id="eng-refusal",
        fact_type="service",
        key=f"{TARGET}:445:tcp",
        value={"port": "445", "service": "microsoft-ds", "state": "open"},
        source="nexus.recon.nmap",
        created_by="deterministic-verifier",
        verified=True,
        asserted_by="verifier",
        verification_method="nmap_xml_parsed",
        invocation_id="inv-nmap-blue",
    )
    coordinator.iteration = 7
    coordinator.action = SimpleNamespace(
        action="request_clarification",
        thought="No puedo ayudar a explotar el host, obtener una shell ni extraer flags.",
        question="¿Quieres que continúe con una evaluación no intrusiva?",
        warnings=[],
    )

    coordinator._clarify()
    result = coordinator._result()

    assert result.status == "clarification", "the operator still owns the decision"
    assert result.termination_reason == "provider_refusal"
    assert result.completion_verified is False
    assert result.question == "¿Quieres que continúe con una evaluación no intrusiva?"
    [finding] = result.findings
    assert finding["fact_type"] == "service"
    assert finding["invocation_id"] == "inv-nmap-blue"
    assert finding["verification_method"] == "nmap_xml_parsed"
    assert "Negativa del modelo/proveedor" in result.final_summary
    assert "fallo de Omni" in result.final_summary
    assert "informe PENDIENTE" in result.final_summary

    events = exec_ctx.store.list_run_events(TENANT, exec_ctx.run_id)
    kinds = [str(event.get("event_type")) for event in events]
    assert "react.provider_refusal" in kinds
    refusal = next(e for e in events if e.get("event_type") == "react.provider_refusal")
    assert refusal["payload"]["refusal"] == "model_declined"
    assert refusal["payload"]["findings_count"] == 1


# --------------------------------------------------------------------------
# A barren loop gets a next action, not just telemetry or another run
# --------------------------------------------------------------------------
async def test_a_barren_repeat_is_answered_with_a_next_action(tmp_path, monkeypatch):
    """Blue (2026-10-31): identical plan/fact queries while nothing changed.

    The guard has to *answer* the repeat with what to do next (change the
    arguments, pivot to an open branch, or record a barrier) and never reach the
    gateway. A call whose arguments differ is a new attempt and stays untouched.
    """
    from nexus_core.agent.react_coordinator import FAST_REPEAT_MIN_NO_PROGRESS
    from nexus_core.agent.react_support import _invocation_signature, barren_repeat_correction
    from nexus_core.kernel.domain_dto import ToolCall
    from nexus_core.tests.unit.test_parallel_tools import (
        FakeService,
        ScriptedLLM,
        _coordinator,
        _loop_context,
    )

    exec_ctx = _loop_context(tmp_path, monkeypatch)
    coordinator = _coordinator(exec_ctx, ScriptedLLM([]), ("local.one",), FakeService())
    await coordinator._initialize()
    coordinator.iteration = 9
    coordinator.consecutive_no_progress = FAST_REPEAT_MIN_NO_PROGRESS
    tool_id = "nexus.orchestrator.get_plan_status"
    signature = _invocation_signature(tool_id, {})
    coordinator.actions = [
        {
            "invocation_signature": signature,
            "tool_result": {"success": True, "outcome": "success"},
        }
    ]

    coordinator.action = ToolCall(tool_id=tool_id, arguments={})
    assert coordinator._repeated_barren_action() == tool_id

    correction = barren_repeat_correction(tool_id, 3)
    assert "Cambia los argumentos" in correction
    assert "barrier" in correction, "the exhausted route must be closeable"

    coordinator.action = ToolCall(tool_id=tool_id, arguments={"scope": "web"})
    assert coordinator._repeated_barren_action() is None, "a new intent must still run"


# --------------------------------------------------------------------------
# The chain that worked, protected with fictional data
# --------------------------------------------------------------------------
def test_the_hint_chain_registers_proven_access_and_loot_on_the_host(monkeypatch, tmp_path):
    """FTP hints -> crossed password -> SSH access/loot, without any real room.

    The chain has to keep working: a validated credential is keyed on the host
    (no plaintext in the fact), and the shell that proves root and prints the
    flag registers ``access``/``privilege``/``loot`` with the *host* as target
    and the flag only as the loot's key/value.
    """
    from types import SimpleNamespace

    from nexus_core.kernel.fact_verification import derive_assertions

    monkeypatch.setenv("NEXUS_VAULT_ROOT", str(tmp_path / "vault"))
    context = SimpleNamespace(invocation_id="inv-chain", run_id="run-chain", tenant_id=TENANT)

    sweep = ToolResult(
        output={
            "target": TARGET,
            "service": "ssh",
            "username": "hintuser",
            "valid_credentials": [{"username": "hintuser", "password": "from-hints"}],
        },
        verified=True,
        verification_method="cred_bruteforce_completed",
    )
    credential = next(
        row
        for row in derive_assertions("nexus.cred.bruteforce", {}, sweep, context)
        if row["fact_type"] == "credential"
    )
    assert credential["target"] == TARGET
    assert credential["key"] == f"cred:ssh:hintuser@{TARGET}"
    assert credential["value"]["secret_ref"].startswith("vault:")
    assert "from-hints" not in json.dumps(credential)

    shell = ToolResult(
        output={
            "target": TARGET,
            "username": "hintuser",
            "command": "id; cat /home/hintuser/flag.txt",
            "stdout": "uid=0(root) gid=0(root) groups=0(root)\nflag{fake_flag}",
            "exit_status": 0,
        },
        verified=True,
        verification_method="ssh_exec_completed",
    )
    rows = derive_assertions("nexus.post.ssh_exec", {}, shell, context)
    assert {"access", "privilege", "loot"} <= {row["fact_type"] for row in rows}
    loot = next(row for row in rows if row["fact_type"] == "loot")
    assert loot["target"] == TARGET, "the capture belongs to the host, never to the flag"
    assert loot["key"] == "flag{fake_flag}"
    assert loot["value"]["flag"] == "flag{fake_flag}"
    assert all(row["invocation_id"] == "inv-chain" for row in rows)


# --------------------------------------------------------------------------
# Report reference data: packaged, and never able to destroy the report
# --------------------------------------------------------------------------
def test_report_reference_data_is_declared_as_package_data():
    """Measured in the pipx install: ``report/data`` never reached site-packages."""
    root = Path(__file__).resolve().parents[3]
    data = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    package_data = data["tool"]["setuptools"]["package-data"]
    assert "data/*.json" in package_data["nexus_core.report"]
    for name in ("mitre_techniques.json", "tool_ttp_map.json", "cvss4_lookup.json"):
        assert (root / "nexus_core" / "report" / "data" / name).is_file()


def test_a_missing_attack_dataset_degrades_instead_of_crashing(tmp_path, monkeypatch):
    missing = tmp_path / "missing.json"
    monkeypatch.setattr(mitre_module, "TECHNIQUES_FILE", missing)
    monkeypatch.setattr(mitre_module, "TOOL_MAP_FILE", missing / "child.json")
    mitre_module.techniques.cache_clear()
    mitre_module.tool_map.cache_clear()
    try:
        assert mitre_module.dataset_available() is False
        assert mitre_module.tool_map() == {}
        assert mitre_module.techniques() == {}
        assert mitre_module.techniques_for_tool("nexus.recon.nmap") == ()
        assert mitre_module.technique_name("T1059") == "T1059"
    finally:
        mitre_module.techniques.cache_clear()
        mitre_module.tool_map.cache_clear()


def test_a_missing_cvss4_table_degrades_without_fabricating_a_score(tmp_path, monkeypatch):
    monkeypatch.setattr(cvss4_module, "DATA_FILE", tmp_path / "missing.json")
    cvss4_module.lookup_table.cache_clear()
    try:
        assert cvss4_module.lookup_table() == {}
        assert (
            cvss4_module.parse_cvss4_vector(
                "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N"
            )
            is None
        )
    finally:
        cvss4_module.lookup_table.cache_clear()


def test_a_malformed_dataset_is_still_a_failure(tmp_path, monkeypatch):
    """Missing data is an install detail; corrupt data is a bug and stays loud."""
    broken = tmp_path / "broken.json"
    broken.write_text(json.dumps(["not", "an", "object"]), encoding="utf-8")
    monkeypatch.setattr(mitre_module, "TOOL_MAP_FILE", broken)
    mitre_module.tool_map.cache_clear()
    try:
        with pytest.raises(ValueError, match="must be an object"):
            mitre_module.tool_map()
    finally:
        mitre_module.tool_map.cache_clear()
