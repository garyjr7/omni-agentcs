"""Fase 3c fixes: the operator's MSF config, visible before and after it bites.

Measured in the Fase 3 reruns:

* ``run_434f5eeadb104b11ba0c80bce16f8d08`` (rerun 2): ``msfrpcd`` was down, the
  provider failure aborted the run. 5C degraded it to ``unavailable`` (996e6aa),
  but ``omni --doctor`` still said nothing *before* the run started.
* ``run_02f8b99a5753469aa024905af4a25d7c`` (rerun 3, ``8de386b``): ``MSF_LHOST``
  was absent from ``.env``, so MS17-010 ran 46.6 s without a callback, the
  ``exploit`` subagent burned its budget retrying MSF and the run ended as
  ``subagent_budget_exceeded``. The doctor reported ``msfrpcd`` OK because it
  never validated ``MSF_LHOST``.
* rerun 3, 7th finding: the enumeration→exploitation hand-off left the plan with
  ``enumeration`` *pending* while ``exploitation`` was *current*, a state the
  completion gate can never close.

Four fixes, one commit:

1. ``MSF_LHOST``/``MSF_LPORT`` are in ``.env.example``, the first-run wizard
   auto-detects the ``tun0`` address and persists it, and the README explains it.
2. ``omni --doctor`` validates the runtime preconditions of the tools that
   depend on config and reports them (block ``runtime_preconditions``) as
   *warnings* with one actionable line.
3. Every deliberate hand-off marks the phase it leaves ``done`` (V1-18).
4. A missing operator variable is an ``unavailable`` outcome with
   ``verification_method=<tool>_config_missing`` (never ``input_rejected``), so
   the model pivots instead of retrying MSF in a loop (V1-19).
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import pytest

from nexus_core.agent.planner import (
    ENUMERATION_EXHAUSTED_REASON,
    PHASE_IDS,
    EnumerationEscalation,
    build_plan,
    escalate_enumeration,
    hand_over_phase,
)
from nexus_core.agent.react import STATUS_MAX_ITERATIONS, run_react_loop
from nexus_core.cli import doctor as doctor_module
from nexus_core.cli import wizard as wizard_module
from nexus_core.config.schema import OmniConfig
from nexus_core.kernel import runtime as runtime_module
from nexus_core.kernel.control_store import ControlStore
from nexus_core.kernel.models import config_missing_result
from nexus_core.kernel.runtime import ExecutionContext
from nexus_core.scope import ScopeViolation
from nexus_core.tests.msf_support import context, fake_client, scope
from nexus_core.tests.unit.test_phase3b_fixes import (
    ScriptedLLM,
    ToolSpy,
    _config,
    _create_scope,
    _observations,
    _tool_call,
)
from nexus_core.tools.handlers import msf_auxiliary as msf_auxiliary_module
from nexus_core.tools.handlers import msf_exploit as msf_exploit_module

pytestmark = [
    pytest.mark.usefixtures("onboarding_env"),
    # The unsigned fixtures of the scope/session behavior; governed stays the
    # default everywhere else (same convention as the Phase 3/3b suites).
    pytest.mark.usefixtures("lab_scope"),
]

#: The repository's example environment file, shipped with the code.
ENV_EXAMPLE = Path(__file__).resolve().parents[3] / ".env.example"

EXPLOIT_ARGS = {
    "module": "exploit/windows/smb/ms17_010_eternalblue",
    "target": "203.0.113.10",
}
REVERSE_PAYLOAD = "windows/x64/meterpreter/reverse_tcp"

#: Hand-offs of the kill chain: (previous, target, the evidence that had already
#: closed everything before *previous*, phases closed after the hand-off).
HAND_OFFS = (
    ("recon", "enumeration", {}, 1),
    ("enumeration", "exploitation", {"host": 1}, 2),
    ("exploitation", "privilege_escalation", {"host": 1, "user": 1}, 3),
    (
        "privilege_escalation",
        "post_exploitation",
        {"host": 1, "user": 1, "access": 1},
        4,
    ),
)


# ------------------------------------------------------------------ 1 · V1-17


def test_env_example_has_msf_lhost():
    """``.env.example`` ships the callback as an *active* line, explained.

    The rerun measured the failure the absence causes: an unset ``MSF_LHOST``
    makes every reverse payload dead, so the operator has to find the variable
    without reading the handler.
    """
    text = ENV_EXAMPLE.read_text(encoding="utf-8")
    lines = [line.strip() for line in text.splitlines()]
    assert "MSF_LHOST=" in lines, "MSF_LHOST must be set in the example env"
    assert "MSF_LPORT=4444" in lines
    # Active assignments, not commented-out documentation.
    assert "# MSF_LHOST=" not in lines
    # The comment above says what it is and where the value comes from (tun0).
    block = text.split("MSF_LHOST=")[0].rsplit("\n\n", 1)[-1]
    assert "tun0" in block
    assert "reverse" in block.lower()
    assert "IP" in block


def test_wizard_detects_tun0_ip(tmp_path, monkeypatch, capsys):
    """The wizard reads the VPN address from ``ip`` and persists it in ``.env``.

    Sub-process is mocked: no real interface is queried, and the test pins the
    exact command the detection runs.
    """
    calls: list[list[str]] = []

    def fake_ip(argv, **kwargs):
        calls.append(list(argv))
        return SimpleNamespace(
            returncode=0, stdout="1: tun0    inet 10.10.14.7/23 scope global tun0\n", stderr=""
        )

    monkeypatch.setattr(wizard_module.subprocess, "run", fake_ip)
    assert wizard_module.detect_tun0_ip() == "10.10.14.7"
    assert calls[0] == ["ip", "-o", "-4", "addr", "show", "tun0"]

    # Accepted as-is (empty answer) and written to the project ``.env``, the
    # file the runtime loads.
    monkeypatch.setattr("builtins.input", lambda prompt="": "")
    assert wizard_module._configure_msf_callback(tmp_path) == "10.10.14.7"
    written = (tmp_path / ".env").read_text(encoding="utf-8")
    assert "MSF_LHOST=10.10.14.7" in written
    assert "MSF_LPORT=4444" in written

    # No tun0 (no VPN / interface named differently): warn and leave it empty.
    monkeypatch.setattr(
        wizard_module.subprocess,
        "run",
        lambda argv, **kwargs: SimpleNamespace(returncode=1, stdout="", stderr="Device not found"),
    )
    empty_root = tmp_path / "sin-tun0"
    empty_root.mkdir()
    assert wizard_module.detect_tun0_ip() is None
    assert wizard_module._configure_msf_callback(empty_root) is None
    assert "AVISO" in capsys.readouterr().out
    assert not (empty_root / ".env").exists()


# ------------------------------------------------------------------ 2 · V1-17


def _rpcd_listening() -> dict:
    return {
        "host": "127.0.0.1",
        "port": 55552,
        "listening": True,
        "systemd_active": True,
        "transport": "msgpack",
    }


def test_doctor_reports_missing_msf_lhost(onboarding_env, monkeypatch, capsys):
    """A listening ``msfrpcd`` with no callback is a WARNING with an action.

    Not an error: running only the MSF auxiliaries that need no callback is a
    legitimate choice, so the run is not refused -the operator is told what to
    export.
    """
    monkeypatch.delenv("MSF_LHOST", raising=False)
    monkeypatch.delenv("MSF_LPORT", raising=False)
    with (
        mock.patch.object(doctor_module, "_rpc_status", _rpcd_listening),
        mock.patch.object(doctor_module.socket, "create_connection", side_effect=OSError),
    ):
        code = doctor_module.run_doctor(onboarding_env.paths, OmniConfig())

    output = capsys.readouterr().out
    line = next(
        item for item in output.splitlines() if "msfrpcd:" in item and "MSF_LHOST" in item
    )
    assert "listening=true" in line
    assert "MSF_LHOST=unset" in line
    assert "WARNING" in line and "ERROR" not in line
    assert "exporta MSF_LHOST=" in line
    # A warning never fails the diagnostic.
    assert code == 0


def test_doctor_json_includes_runtime_preconditions(onboarding_env, monkeypatch, capsys):
    """``--doctor --json`` carries the preconditions as a per-service block."""
    monkeypatch.delenv("MSF_LHOST", raising=False)
    monkeypatch.delenv("MSF_LPORT", raising=False)
    monkeypatch.delenv("SLIVER_OPERATOR_CONFIG", raising=False)
    with (
        mock.patch.object(doctor_module, "_rpc_status", _rpcd_listening),
        mock.patch.object(doctor_module.socket, "create_connection", side_effect=OSError),
    ):
        doctor_module.run_doctor(onboarding_env.paths, OmniConfig(), as_json=True)
        report = json.loads(capsys.readouterr().out)
        entries = report["runtime_preconditions"]
        msf = next(item for item in entries if item["service"] == "msfrpcd")
        assert msf["missing_env"] == ["MSF_LHOST", "MSF_LPORT"]
        assert msf["severity"] == "warning"
        assert msf["observed"] == "listening=true"
        assert "MSF_LHOST" in msf["action"] and msf["action"]

        # Positive control: with the callback configured there is nothing to
        # report, so the block is not noise.
        monkeypatch.setenv("MSF_LHOST", "10.10.14.7")
        monkeypatch.setenv("MSF_LPORT", "4444")
        doctor_module.run_doctor(onboarding_env.paths, OmniConfig(), as_json=True)
        report = json.loads(capsys.readouterr().out)
    assert "msfrpcd" not in {item["service"] for item in report["runtime_preconditions"]}


# ------------------------------------------------------------------ 3 · V1-18


@pytest.mark.parametrize(
    "previous,target,counts,closed",
    HAND_OFFS,
    ids=[f"{previous}->{target}" for previous, target, _, _ in HAND_OFFS],
)
def test_plan_marks_previous_phase_done_on_handoff(previous, target, counts, closed):
    """Every hand-off closes the phase it leaves, over every transition.

    Each case starts from the plan the board of that moment yields -the earlier
    phases already closed by evidence, ``previous`` current- and then hands over
    once, so the assertion covers every transition of the kill chain and not
    only the measured enumeration→exploitation step. The hand-off the loop
    actually performs goes through :func:`escalate_enumeration`; the others use
    the shared helper, and both entry points are exercised here.
    """
    plan = build_plan("objetivo", counts=counts)
    assert plan.current == previous, "the case must start in the phase it leaves"

    if previous == "enumeration":
        plan = escalate_enumeration(
            plan,
            EnumerationEscalation(
                phase=target, subagent="exploit", reason=ENUMERATION_EXHAUSTED_REASON
            ),
        )
    else:
        plan = hand_over_phase(plan, phase=target)

    assert plan.current == target
    statuses = {item.id: item.status for item in plan.phases}
    assert statuses[target] == "current"
    assert statuses[previous] == "done", "the phase left behind must not stay pending"
    # Nothing mandatory may be left pending *before* the current phase: that is
    # the plan the completion gate can never close (the measured finding).
    for phase_id in PHASE_IDS[: PHASE_IDS.index(target)]:
        if phase_id != "lateral_movement":
            assert statuses[phase_id] != "pending"
    # The payload the loop audits: from enumeration it is [2, 6] (was [1, 6]).
    assert plan.progress == (closed, 6)
    assert plan.to_dict()["done"] == closed
    assert plan.done_required == closed
    assert plan.next_hint


# ------------------------------------------------------------------ 4 · V1-19


def _msf_context(tmp_path, engagement=None):
    """RunContext with a control store: the session registry of a call that
    actually runs needs one (same shape as the MSF handler suite)."""
    from dataclasses import replace

    store = ControlStore(tmp_path / "msf-control.db")
    store.initialize()
    return replace(context(engagement or scope()), store=store)


def test_msf_exploit_returns_unavailable_when_lhost_missing(monkeypatch, tmp_path):
    """A missing operator variable is ``unavailable``, not invalid input.

    Reproduces rerun 3: the reverse payload has no callback, so the call cannot
    work however many times the model retries it. The result is *determinate*
    (never ``negative``: nothing was observed) and names the variable.
    """
    client = fake_client(monkeypatch, msf_exploit_module)
    monkeypatch.delenv("MSF_LHOST", raising=False)

    result = asyncio.run(
        msf_exploit_module.msf_exploit_handler(
            {**EXPLOIT_ARGS, "payload": REVERSE_PAYLOAD}, _msf_context(tmp_path)
        )
    )

    assert result.success is False
    assert result.verified is False
    assert result.outcome == "unavailable"
    assert result.verification_method == "nexus.exploit.msf_exploit_config_missing"
    assert result.evidence["missing_env"] == ["MSF_LHOST"]
    assert result.evidence["tool_id"] == "nexus.exploit.msf_exploit"
    assert "MSF_LHOST" in str(result.output)
    # Determinate for the gateway: it does not raise a post-condition error.
    assert result.completed is True
    assert result.to_dict()["outcome"] == "unavailable"
    # No RPC was attempted: the precondition is checked before any call.
    client.authenticate.assert_not_awaited()
    client.execute_exploit.assert_not_awaited()

    # Control: a payload with no callback need (no ``reverse``) still runs with
    # ``MSF_LHOST`` unset -the check is not a blanket MSF block.
    plain = asyncio.run(
        msf_exploit_module.msf_exploit_handler(EXPLOIT_ARGS, _msf_context(tmp_path))
    )
    assert plain.outcome != "unavailable"
    client.execute_exploit.assert_awaited()


def test_msf_auxiliary_returns_unavailable_when_callback_lhost_missing(monkeypatch):
    """Same contract for the auxiliaries that need a callback, and only those."""
    client = fake_client(monkeypatch, msf_auxiliary_module)
    monkeypatch.delenv("MSF_LHOST", raising=False)
    callback_args = {"module": "auxiliary/server/capture/smb", "target": "203.0.113.10"}

    result = asyncio.run(
        msf_auxiliary_module.msf_auxiliary_handler(callback_args, context(scope()))
    )

    assert result.outcome == "unavailable"
    assert result.verification_method == "nexus.exploit.msf_auxiliary_config_missing"
    assert result.evidence["missing_env"] == ["MSF_LHOST"]
    assert result.completed is True
    client.execute_module.assert_not_awaited()

    # Governance still comes first: an out-of-scope target is denied, not
    # reported as a config problem.
    with pytest.raises(ScopeViolation):
        asyncio.run(
            msf_auxiliary_module.msf_auxiliary_handler(
                {**callback_args, "target": "8.8.8.8"}, context(scope())
            )
        )

    # A scanner needs no callback and keeps working with MSF_LHOST unset.
    scanner = {"module": "auxiliary/scanner/smb/smb_version", "target": "203.0.113.10"}
    scanned = asyncio.run(
        msf_auxiliary_module.msf_auxiliary_handler(scanner, context(scope()))
    )
    assert scanned.success and scanned.outcome != "unavailable"
    client.execute_module.assert_awaited()


def _config_missing_payload(tool_id: str, missing: tuple[str, ...] = ("MSF_LHOST",)) -> dict:
    """The payload the gateway hands back for a config-missing tool result."""
    result = config_missing_result(
        tool_id, list(missing), detail="MSF_LHOST is required for a reverse payload"
    )
    assert result.completed, "the gateway re-classifies/completes this outcome"
    return {
        "tool_id": tool_id,
        "output": {
            "success": False,
            "outcome": result.outcome,
            "verification_method": result.verification_method,
            "evidence": result.evidence,
            "output": result.output,
            "assertions": [],
        },
    }


@pytest.fixture()
def exploit_harness(tmp_path):
    """A loop whose active profile is ``exploit`` (the measured iteration)."""
    store = ControlStore(tmp_path / "react-3c.db")
    store.initialize()
    _create_scope(store, "eng-1")
    run = store.create_run("system", {})
    task = {
        "id": "task-react-3c",
        "tenant_id": "system",
        "run_id": run["id"],
        "task_type": "react.run",
        "payload": {
            "objective": "Explota 10.0.0.5 con MS17-010",
            "engagement_id": "eng-1",
            "subagent": "exploit",
            "identity": {"subject_id": "operator-1", "roles": ["operator"]},
            "permissions": ["execute:tool:nexus.exploit.msf_exploit"],
        },
    }
    return store, ExecutionContext(store, task, "worker-test")


async def test_loop_suggests_alternative_on_config_missing(exploit_harness):
    """The model reads *why* MSF could not run and what is left in the profile.

    The run survives (no ``subagent_budget_exceeded``), the tool is retired
    after repeated attempts, and the message the model gets back names the
    missing variable plus the alternatives of the *same* subagent.
    """
    store, context_ = exploit_harness
    spy = ToolSpy(_config_missing_payload("nexus.exploit.msf_exploit"))

    with mock.patch.object(runtime_module, "execute_tool", spy):
        result = await run_react_loop(
            context=context_,
            objective="Explota 10.0.0.5 con MS17-010",
            engagement_id="eng-1",
            llm_client=ScriptedLLM([_tool_call("nexus.exploit.msf_exploit")]),
            config=_config(max_iterations=6),
        )

    assert result.status == STATUS_MAX_ITERATIONS
    assert result.status != "provider_error"
    observations = _observations(store, result.conversation_id)
    guidance = [item for item in observations if "alternative" in item]
    assert guidance, "a config-missing observation must tell the model what to do next"
    first = guidance[0]
    assert "nexus.exploit.msf_exploit" in first
    assert '"outcome":"unavailable"' in first
    assert "config_missing" in first
    assert "MSF_LHOST" in first
    # Nothing was observed against the target: no fact may be derived.
    assert '"assertions":[]' in first

    retired = [item for item in observations if '"tool_retired":true' in item]
    assert retired, "the tool is retired after repeated config-missing attempts"
    assert "nexus.exploit.searchsploit" in retired[0]
    assert "nexus.exploit.msf_auxiliary" in retired[0]
    # Alternatives come from the active profile, not from the global catalog.
    assert "nexus.recon.nmap" not in retired[0]
