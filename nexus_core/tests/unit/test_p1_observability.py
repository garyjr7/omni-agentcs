"""Regression tests for the P1 observability items of the E2E report."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from nexus_core.cli.tui.pricing import default_rates
from nexus_core.cli.tui.usage import response_usage
from nexus_core.kernel.audit import AuditWriter
from nexus_core.kernel.control_store import ControlStore
from nexus_core.kernel.models import Identity, RiskLevel, RunContext, ToolDefinition, ToolResult
from nexus_core.kernel.policy import PolicyEngine
from nexus_core.kernel.tool_gateway import ToolGateway


def _response(provider: str, model: str, tokens_in: int, tokens_out: int):
    return SimpleNamespace(
        provider=provider,
        model=model,
        tokens_input=tokens_in,
        tokens_output=tokens_out,
    )


def test_reference_rates_make_cost_known_without_env(monkeypatch):
    monkeypatch.delenv("NEXUS_TUI_INPUT_USD_PER_MTOK", raising=False)
    monkeypatch.delenv("NEXUS_TUI_OUTPUT_USD_PER_MTOK", raising=False)
    incoming, outgoing, cost = response_usage(
        _response("groq", "openai/gpt-oss-120b", 1_000_000, 1_000_000)
    )
    assert (incoming, outgoing) == (1_000_000, 1_000_000)
    assert cost == pytest.approx(0.75)


def test_env_rates_override_the_reference_table(monkeypatch):
    monkeypatch.setenv("NEXUS_TUI_INPUT_USD_PER_MTOK", "1.0")
    monkeypatch.setenv("NEXUS_TUI_OUTPUT_USD_PER_MTOK", "2.0")
    _, _, cost = response_usage(_response("groq", "openai/gpt-oss-120b", 1_000_000, 1_000_000))
    assert cost == pytest.approx(3.0)


def test_unknown_model_stays_cost_unknown(monkeypatch):
    monkeypatch.delenv("NEXUS_TUI_INPUT_USD_PER_MTOK", raising=False)
    monkeypatch.delenv("NEXUS_TUI_OUTPUT_USD_PER_MTOK", raising=False)
    _, _, cost = response_usage(_response("mystery", "mystery-model", 10, 10))
    assert cost is None


def test_longest_model_key_wins():
    assert default_rates("openai/gpt-4o-mini") == (0.15, 0.60)
    assert default_rates("gpt-4o") == (2.50, 10.00)


def _definition() -> ToolDefinition:
    return ToolDefinition(
        tool_id="nexus.test.audit_args",
        name="Audit args echo",
        tenant_id="system",
        description="test",
        input_schema={
            "type": "object",
            "properties": {
                "target": {"type": "string"},
                "password": {"type": "string"},
            },
            "required": ["target"],
            "additionalProperties": False,
        },
        risk=RiskLevel.LOW,
        required_permissions=(),
        scope_required=False,
    )


async def _handler(arguments, context):
    return ToolResult(
        output={"target": arguments.get("target")},
        verified=True,
        verification_method="echo",
    )


async def test_tool_invoke_audit_records_redacted_arguments(tmp_path):
    store = ControlStore(Path(tmp_path) / "audit.db")
    store.initialize()
    gateway = ToolGateway(PolicyEngine(store), AuditWriter(store))
    gateway.register(_definition(), _handler)
    context = RunContext(
        "system",
        Identity("operator-1", "system", roles=("operator",)),
        run_id="run-1",
        trace_id="run-1",
    )
    await gateway.invoke(
        "nexus.test.audit_args",
        {"target": "10.0.0.5", "password": "s3cr3t"},
        context,
    )
    rows = AuditWriter(store).export("system")
    invoke = next(row for row in rows if row["action"] == "tool.invoke")
    assert invoke["trace_id"] == "run-1"
    assert invoke["payload"]["argument_keys"] == ["password", "target"]
    # The target is visible (the transcript is self-contained) but the secret is
    # never written in the clear.
    assert invoke["payload"]["arguments"]["target"] == "10.0.0.5"
    assert invoke["payload"]["arguments"]["password"] != "s3cr3t"
    assert invoke["payload"]["run_id"] == "run-1"
