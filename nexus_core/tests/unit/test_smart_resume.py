"""V1-54: a timeout is a determinate result, and a trusted run may resume.

Measured in the Simple CTF run of 2026-10-18 15:49 UTC:

* iteration 27 ran ``enum_system`` and the SSH client answered
  ``TimeoutError: timed out``;
* the journal kept the invocation ``unknown`` (the effect is never confirmed);
* iteration 29 retried it and the gateway raised
  ``unknown invocation requires human approval``, so a ``--trust-mode`` bench
  closed as ``blocked`` (exit 2) with the target still reachable.

What this module pins:

* the handler declares ``outcome="timeout"`` instead of raising, so the loop
  receives a determinate tool failure and the journal never pretends the call
  succeeded (a retry is not answered with data this run never obtained);
* a declared timeout is handled exactly like the engine's own
  ``tool_timeout_result``: no assertion, journal ``unknown``;
* ``--resume-policy approve`` inside ``--trust-mode`` records the durable,
  audited approval the gateway would otherwise demand, so the retry really
  happens instead of ending the run;
* ``skip`` records the operator's no-effect decision and re-runs the call;
* without a policy the gateway keeps failing closed.
"""

from __future__ import annotations

import asyncio
import json
from unittest import mock

import pytest

from nexus_core.cli.session import OmniSession
from nexus_core.kernel.approvals import ApprovalService
from nexus_core.kernel.audit import AuditWriter
from nexus_core.kernel.control_store import ControlStore
from nexus_core.kernel.errors import ApprovalRequired
from nexus_core.kernel.invocation_journal import InvocationJournal
from nexus_core.kernel.models import Identity, RunContext, ToolDefinition, ToolResult
from nexus_core.kernel.policy import PolicyEngine
from nexus_core.kernel.sandbox import SandboxResult
from nexus_core.kernel.tool_gateway import ToolGateway
from nexus_core.tools.handlers import ssh_post as ssh_module
from nexus_core.tools.handlers.ssh_post import enum_system_handler, ssh_exec_handler

#: ``lab_scope`` is what the loop harness of ``test_phase3b_fixes`` expects for a
#: fixture engagement; the gateway tests build their own signed-free contexts.
pytestmark = [pytest.mark.unit, pytest.mark.usefixtures("lab_scope")]

TENANT = "system"
TARGET = "10.0.0.5"
OPERATOR = "cli:operator:kali"


@pytest.fixture(autouse=True)
def _no_connect_cooldown(monkeypatch):
    monkeypatch.setattr(ssh_module, "SSH_CONNECT_COOLDOWN_SECONDS", 0.0)


class _FakeSandbox:
    def __init__(self, payload: dict) -> None:
        self.result = SandboxResult(0, json.dumps(payload) + "\n", "")

    async def run(self, argv, *, timeout_seconds: float = 30):
        return self.result


def _ssh_context() -> RunContext:
    return RunContext(TENANT, Identity("agent:omni", TENANT, kind="agent"))


def _ssh_run(handler, arguments: dict, payload: dict):
    sandbox = _FakeSandbox(payload)
    with mock.patch.object(
        ssh_module, "sandbox_for_environment", lambda *args, **kwargs: sandbox
    ):
        return asyncio.run(handler(arguments, _ssh_context()))


# ------------------------------------------------------ the SSH client timeout
def test_enum_system_client_timeout_is_a_declared_timeout() -> None:
    """The measured payload: ``TimeoutError: timed out`` from the client."""
    result = _ssh_run(
        enum_system_handler,
        {"target": TARGET, "username": "mitch", "password": "secret"},
        {"ok": False, "connected": False, "error": "TimeoutError: timed out",
         "error_kind": "connect_failed"},
    )

    assert result.verified is False
    assert result.timed_out is True
    assert result.outcome == "timeout"
    assert result.success is False
    assert result.verification_method == "enum_system_timeout"
    assert "timed out" in result.output["error"]
    assert result.evidence["error_detail"] == "TimeoutError: timed out"


def test_ssh_exec_client_timeout_is_a_declared_timeout() -> None:
    result = _ssh_run(
        ssh_exec_handler,
        {"target": TARGET, "username": "mitch", "password": "secret",
         "command": "ip addr"},
        {"ok": False, "connected": True, "command": "ip addr",
         "error": "TimeoutError: timed out"},
    )

    assert result.verified is False
    assert result.timed_out is True
    assert result.outcome == "timeout"
    assert result.success is False
    assert result.verification_method == "ssh_exec_timeout"


def test_a_command_that_mentions_timeout_in_stderr_is_not_a_timeout() -> None:
    """Only the client's own ``error`` counts: a real answer is a real answer."""
    result = _ssh_run(
        ssh_exec_handler,
        {"target": TARGET, "username": "mitch", "password": "secret",
         "command": "cat /var/log/syslog"},
        {"ok": True, "connected": True, "command": "cat /var/log/syslog",
         "stdout": "", "stderr": "connection timed out\n", "exit_status": 1},
    )

    assert result.timed_out is False
    assert result.outcome == "command_failed"


# --------------------------------------------------- the gateway's classification
def _gateway(tmp_path, result: ToolResult):
    store = ControlStore(tmp_path / "control.db")
    store.initialize()
    calls: list[dict] = []

    def handler(arguments, context):
        calls.append(dict(arguments))
        return result

    gateway = ToolGateway(
        PolicyEngine(store), AuditWriter(store), ApprovalService(store)
    )
    gateway.register(
        ToolDefinition("probe", TENANT, {}, tool_id="probe", effect="active"), handler
    )
    return store, gateway, calls


def _context(*, policy: str = "", run_id: str = "run-smart-resume") -> RunContext:
    return RunContext(
        TENANT,
        Identity("agent:omni", TENANT, kind="agent", roles=("operator",)),
        run_id=run_id,
        worker_id=OPERATOR,
        phase="post_exploitation",
        objective="Compromete el sistema",
        resume_policy=policy,
    )


def _unknown(store, context: RunContext) -> str:
    """Leave a failed ``probe`` call where the gateway really left the SSH one."""
    journal = InvocationJournal(store)
    key = journal.step_key(
        "probe", {}, phase=context.phase, objective=context.objective
    )
    item = journal.prepare(context, "probe", {}, "", step_key=key)
    journal.start(item["invocation_id"], TENANT)
    journal.unknown(item["invocation_id"], TENANT)
    return item["invocation_id"]


def test_a_declared_timeout_completes_without_assertions_and_is_not_reused(tmp_path):
    """Same contract as ``tool_timeout_result``: determinate, no fact, retryable."""
    result = ToolResult(
        {"error": "timed out"}, False, "probe_timeout", outcome="timeout", timed_out=True
    )
    store, gateway, calls = _gateway(tmp_path, result)
    context = _context()

    returned = asyncio.run(gateway.invoke("probe", {}, context))

    assert returned["outcome"] == "timeout"
    assert returned["success"] is False
    assert returned["assertions"] == []
    # The effect is not confirmed, so the retry is never answered with old data.
    assert InvocationJournal(store).get(
        returned["invocation_id"], TENANT
    )["state"] == "unknown"
    trail = AuditWriter(store).export(TENANT)
    assert [row for row in trail if row["action"] == "tool.failed"] == []
    completed = next(row for row in trail if row["action"] == "tool.complete")
    assert completed["payload"]["outcome"] == "timeout"

    # A second identical call is the journal's unknown-retry gate, not a dedup.
    with pytest.raises(ApprovalRequired, match="retry:invocation"):
        asyncio.run(gateway.invoke("probe", {}, context))
    assert calls == [{}], "the second call must not reach the handler unauthorized"


def test_trust_mode_approve_resumes_the_unknown_retry(tmp_path):
    """The measured block: the retry now runs, durably approved and audited."""
    store, gateway, calls = _gateway(tmp_path, ToolResult({"ok": True}, True, "probe_ok"))
    invocation_id = _unknown(store, _context())
    context = _context(policy="approve")

    returned = asyncio.run(gateway.invoke("probe", {}, context))

    assert returned["success"] is True
    assert calls == [{}]
    trail = AuditWriter(store).export(TENANT)
    auto = [row for row in trail if row["action"] == "invocation.retry_auto_approved"]
    assert len(auto) == 1
    assert auto[0]["resource_id"] == invocation_id
    assert auto[0]["payload"]["trust_mode"] is True
    assert auto[0]["payload"]["policy"] == "approve"
    # A durable row really exists, and it was consumed by the retry.
    approval = ApprovalService(store).get(auto[0]["payload"]["approval_id"], TENANT)
    assert approval["action"] == f"retry:invocation:{invocation_id}"
    assert approval["status"] == "approved"
    assert approval["consumed_at"]
    # The requester is the run, the decider the operator: no self-approval.
    assert approval["requested_by"] != approval["decided_by"] == OPERATOR
    assert InvocationJournal(store).get(
        returned["invocation_id"], TENANT
    )["retry_of"] == invocation_id


def test_skip_marks_the_unknown_step_without_effect_and_reruns_it(tmp_path):
    store, gateway, calls = _gateway(tmp_path, ToolResult({"ok": True}, True, "probe_ok"))
    invocation_id = _unknown(store, _context())

    returned = asyncio.run(gateway.invoke("probe", {}, _context(policy="skip")))

    assert returned["success"] is True
    assert calls == [{}]
    assert InvocationJournal(store).get(invocation_id, TENANT)["state"] == "failed"
    trail = AuditWriter(store).export(TENANT)
    assert [row for row in trail if row["action"] == "invocation.retry_skipped"]
    assert InvocationJournal(store).get(returned["invocation_id"], TENANT)["retry_of"] is None


def test_without_a_policy_the_retry_still_fails_closed(tmp_path):
    store, gateway, calls = _gateway(tmp_path, ToolResult({"ok": True}, True, "probe_ok"))
    _unknown(store, _context())

    with pytest.raises(ApprovalRequired, match="unknown invocation requires human approval"):
        asyncio.run(gateway.invoke("probe", {}, _context()))
    assert calls == []
    assert [
        row for row in AuditWriter(store).export(TENANT)
        if row["action"] == "invocation.retry_auto_approved"
    ] == []


def test_a_pre_existing_durable_approval_still_wins(tmp_path):
    """``resume-policy`` never bypasses a human decision that already exists."""
    store, gateway, calls = _gateway(tmp_path, ToolResult({"ok": True}, True, "probe_ok"))
    invocation_id = _unknown(store, _context())
    context = _context()
    approvals = ApprovalService(store)
    approval = approvals.request(context, f"retry:invocation:{invocation_id}")
    approvals.decide(approval["id"], TENANT, "operator:human", True, "reviewed")

    returned = asyncio.run(
        gateway.invoke("probe", {}, context, retry_approval_id=approval["id"])
    )

    assert returned["success"] is True
    assert calls == [{}]
    trail = AuditWriter(store).export(TENANT)
    assert [row for row in trail if row["action"] == "invocation.retry_auto_approved"] == []


def test_execute_tool_forwards_the_engine_policy_to_the_gateway(tmp_path, monkeypatch):
    """End to end through the runtime: payload → RunContext → journal gate.

    The coordinator writes ``resume_policy`` into the tool payload and the
    runtime turns it into an engine-owned ``RunContext`` field. This drives the
    real ``execute_tool`` executor, so a break anywhere in that chain shows up
    as the measured ``ApprovalRequired`` block.
    """
    from nexus_core.kernel.models import Identity as KernelIdentity
    from nexus_core.kernel.runtime import ExecutionContext, execute_tool
    import nexus_core.tools.registry as registry

    store = ControlStore(tmp_path / "control.db")
    store.initialize()
    seen: list[str] = []

    def handler(arguments, context):
        seen.append(context.resume_policy)
        return ToolResult({"ok": True}, True, "probe_ok")

    definition = ToolDefinition("probe", TENANT, {}, tool_id="probe", effect="active")
    monkeypatch.setattr(
        registry, "durable_tool_definitions", lambda tenant: {"probe": (definition, handler)}
    )
    payload = {
        "tool_id": "probe",
        "arguments": {},
        "identity": {"subject_id": "agent:omni", "kind": "agent", "roles": ["operator"]},
        "phase": "post_exploitation",
        "objective": "Compromete el sistema",
        "resume_policy": "approve",
        "trace_id": "run-smart-resume",
    }
    task = {
        "id": "task-smart-resume", "tenant_id": TENANT, "run_id": "run-smart-resume",
        "task_type": "tool.invoke", "payload": payload,
    }
    context = ExecutionContext(store, task, OPERATOR)
    journal_context = RunContext(
        TENANT, KernelIdentity("agent:omni", TENANT, kind="agent"),
        run_id="run-smart-resume", phase="post_exploitation",
        objective="Compromete el sistema",
    )
    _unknown(store, journal_context)

    returned = asyncio.run(execute_tool(payload, context))

    assert returned["output"]["success"] is True
    assert seen == ["approve"]
    trail = AuditWriter(store).export(TENANT)
    assert [row for row in trail if row["action"] == "invocation.retry_auto_approved"]


@pytest.fixture()
def loop_harness(tmp_path):
    """The ReAct harness of ``test_phase3b_fixes`` (store + engagement + run)."""
    from nexus_core.tests.unit.test_phase3b_fixes import harness

    return harness.__wrapped__(tmp_path)


async def test_the_loop_forwards_the_resume_policy_to_the_executor(loop_harness):
    """The coordinator writes it into the engine half of the tool payload."""
    from nexus_core.agent.react import STATUS_COMPLETED, run_react_loop
    from nexus_core.tests.unit.test_phase3b_fixes import ScriptedLLM, _config, _tool_call
    from nexus_core.tests.unit.test_phase3g_fixes import ToolSpy, _task_complete, mock_execute_tool

    store, context = loop_harness
    llm = ScriptedLLM([_tool_call(), _task_complete()])
    spy = ToolSpy()

    with mock_execute_tool(spy):
        result = await run_react_loop(
            context=context,
            objective="Compromete el sistema",
            engagement_id="eng-1",
            llm_client=llm,
            config=_config(max_iterations=4, resume_policy="approve"),
        )

    assert result.status == STATUS_COMPLETED
    assert spy.payloads, "the scripted tool call must reach the executor"
    assert spy.payloads[0]["resume_policy"] == "approve"


# --------------------------------------------------------------- the CLI gate
def test_resume_policy_is_only_effective_under_trust_mode():
    session = object.__new__(OmniSession)
    session.resume_policy = "approve"
    session.trust_mode = True
    assert session.effective_resume_policy == "approve"
    session.trust_mode = False
    assert session.effective_resume_policy == ""
