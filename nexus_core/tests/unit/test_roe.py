"""Rules of Engagement: windows, forbidden targets, rate limits and kill switch."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from nexus_core.cli.roe_cli import run_roe_action
from nexus_core.kernel.audit import AuditWriter
from nexus_core.kernel.control_store import ControlStore
from nexus_core.kernel.models import Identity, RunContext, ToolDefinition
from nexus_core.kernel.policy import PolicyEngine
from nexus_core.kernel.tool_gateway import ToolGateway
from nexus_core.scope.roe import (
    RoEEnforcer,
    RoEKillSwitch,
    RoEViolation,
    RulesOfEngagement,
    TimeWindow,
    kill_switch_path,
    load_enforcer,
    load_roe,
    make_roe_validator,
    save_roe,
)

MONDAY_10AM = datetime(2026, 10, 5, 10, 0, tzinfo=timezone.utc)  # a Monday


# ------------------------------------------------------------------ time window


def test_window_allows_inside_and_rejects_outside():
    window = TimeWindow("09:00", "18:00")
    assert window.allows(datetime(2026, 10, 5, 9, 0))
    assert window.allows(datetime(2026, 10, 5, 18, 0))
    assert not window.allows(datetime(2026, 10, 5, 8, 59))
    assert not window.allows(datetime(2026, 10, 5, 18, 1))


def test_window_wraps_midnight():
    window = TimeWindow("22:00", "02:00")
    assert window.allows(datetime(2026, 10, 5, 23, 30))
    assert window.allows(datetime(2026, 10, 5, 1, 0))
    assert not window.allows(datetime(2026, 10, 5, 3, 0))


def test_window_respects_weekdays():
    friday = TimeWindow("09:00", "18:00", days=(4,))  # 0=Monday .. 4=Friday
    assert friday.allows(datetime(2026, 10, 9, 10, 0))  # a Friday
    assert not friday.allows(datetime(2026, 10, 5, 10, 0))  # a Monday


def test_invalid_time_is_rejected():
    with pytest.raises(ValueError):
        TimeWindow("9:00", "18:00").allows(MONDAY_10AM)


# --------------------------------------------------------------------- signing


def test_signature_round_trip():
    roe = RulesOfEngagement("eng-1", "system", name="acme", notes="ok")
    signed = roe.sign("secret")
    assert signed.signature
    assert signed.signature_valid("secret")
    assert not signed.signature_valid("other")
    # The signature itself is never part of the signed bytes.
    assert "signature" not in signed.canonical_form()


def test_from_dict_round_trips():
    roe = RulesOfEngagement(
        "eng-1", "system", windows=(TimeWindow("09:00", "18:00", (0, 1)),),
        max_actions_per_minute=5, forbidden_categories=("scada",),
  )
    again = RulesOfEngagement.from_dict(roe.to_dict())
    assert again == roe


# ------------------------------------------------------------------- enforcer


def test_kill_switch_event_halts_everything():
    enforcer = RoEEnforcer(RulesOfEngagement("eng-1", "system"))
    assert enforcer.check() is None
    enforcer.trigger_kill_switch()
    assert enforcer.stopped
    with pytest.raises(RoEKillSwitch):
        enforcer.check()
    enforcer.reset()
    assert not enforcer.stopped


def test_kill_switch_sentinel_file_halts(tmp_path):
    sentinel = tmp_path / "stop"
    enforcer = RoEEnforcer(
        RulesOfEngagement("eng-1", "system", kill_switch_file=str(sentinel))
    )
    assert enforcer.stopped is False
    sentinel.write_text("stop\n")
    assert enforcer.stopped is True
    with pytest.raises(RoEKillSwitch):
        enforcer.ensure_alive()


def test_window_is_enforced_at_runtime():
    roe = RulesOfEngagement("eng-1", "system", windows=(TimeWindow("09:00", "18:00"),))
    enforcer = RoEEnforcer(roe)
    enforcer.check(now=MONDAY_10AM)
    with pytest.raises(RoEViolation):
        enforcer.check(now=datetime(2026, 10, 5, 20, 0))


def test_forbidden_target_patterns():
    roe = RulesOfEngagement(
        "eng-1", "system", forbidden_targets=("10.0.0.5", "*.payments.example")
    )
    enforcer = RoEEnforcer(roe)
    enforcer.check(targets=("10.0.0.9",))
    with pytest.raises(RoEViolation):
        enforcer.check(targets=("10.0.0.5",))
    with pytest.raises(RoEViolation):
        enforcer.check(targets=("api.payments.example",))


def test_forbidden_category():
    roe = RulesOfEngagement("eng-1", "system", forbidden_categories=("scada",))
    enforcer = RoEEnforcer(roe)
    enforcer.check(category="web")
    with pytest.raises(RoEViolation):
        enforcer.check(category="SCADA")


def test_rate_limit_slides_over_a_minute():
    clock = {"now": 0.0}
    roe = RulesOfEngagement("eng-1", "system", max_actions_per_minute=2)
    enforcer = RoEEnforcer(roe, clock=lambda: clock["now"])
    enforcer.check()
    enforcer.check()
    with pytest.raises(RoEViolation):
        enforcer.check()
    clock["now"] = 61.0  # the window slides
    enforcer.check()


def test_concurrency_slot_bounds_active_actions():
    roe = RulesOfEngagement("eng-1", "system", max_concurrent_actions=1)
    enforcer = RoEEnforcer(roe)
    with enforcer.slot():
        assert enforcer.snapshot()["active"] == 1
        with pytest.raises(RoEViolation):
            with enforcer.slot():
                pass
    assert enforcer.snapshot()["active"] == 0


def test_snapshot_reports_state():
    roe = RulesOfEngagement("eng-1", "system", windows=(TimeWindow("09:00", "18:00"),))
    enforcer = RoEEnforcer(roe)
    snapshot = enforcer.snapshot(now=MONDAY_10AM)
    assert snapshot == {
        "engagement_id": "eng-1",
        "stopped": False,
        "window_open": True,
        "actions_last_minute": 0,
        "active": 0,
        "max_actions_per_minute": 0,
        "max_concurrent_actions": 0,
    }


# -------------------------------------------------------------- gateway validator


def test_validator_checks_kill_switch_even_for_non_offensive_tools():
    enforcer = RoEEnforcer(RulesOfEngagement("eng-1", "system"))
    enforcer.trigger_kill_switch()
    validate = make_roe_validator(enforcer)
    definition = ToolDefinition("record", "system", {"type": "object"})
    with pytest.raises(RoEKillSwitch):
        validate(None, definition, {})


def test_validator_only_applies_windows_to_target_tools():
    roe = RulesOfEngagement("eng-1", "system", windows=(TimeWindow("09:00", "18:00"),))
    enforcer = RoEEnforcer(roe, wall_clock=lambda: datetime(2026, 10, 5, 20, 0, tzinfo=timezone.utc))
    validate = make_roe_validator(enforcer)
    passive = ToolDefinition("status", "system", {"type": "object"})
    validate(None, passive, {})  # bookkeeping is allowed at any hour
    scan = ToolDefinition(
        "scan", "system",
        {"type": "object", "properties": {"target": {"type": "string"}}},
        scope_target_field="target",
    )
    with pytest.raises(RoEViolation):
        validate(None, scan, {"target": "10.0.0.5"})


def test_validator_accepts_a_list_of_targets():
    roe = RulesOfEngagement("eng-1", "system", forbidden_targets=("10.0.0.5",))
    validate = make_roe_validator(RoEEnforcer(roe))
    scan = ToolDefinition(
        "scan-batch", "system",
        {"type": "object", "properties": {"targets": {"type": "array"}}},
        scope_target_field="targets",
    )
    with pytest.raises(RoEViolation):
        validate(None, scan, {"targets": ["10.0.0.9", "10.0.0.5"]})


async def test_gateway_denies_a_forbidden_target_and_audits(tmp_path):
    store = ControlStore(tmp_path / "roe.db")
    store.initialize()
    roe = RulesOfEngagement("eng-1", "system", forbidden_targets=("10.0.0.5",))
    gateway = ToolGateway(
        PolicyEngine(), AuditWriter(store), roe_validator=make_roe_validator(RoEEnforcer(roe))
    )
    definition = ToolDefinition(
        "scan", "system",
        {"type": "object", "properties": {"target": {"type": "string"}}},
        tool_id="scan",
        scope_target_field="target",
    )
    called = False

    async def handler(args, ctx):
        nonlocal called
        called = True
        raise AssertionError("the handler must never run behind a RoE denial")

    gateway.register(definition, handler)
    context = RunContext("system", Identity("operator-1", "system", roles=("operator",)))
    with pytest.raises(RoEViolation):
        await gateway.invoke("scan", {"target": "10.0.0.5"}, context)
    assert called is False
    actions = [row["action"] for row in AuditWriter(store).export("system")]
    assert "roe.denied" in actions
    assert AuditWriter(store).verify_chain() == (True, None)


# ------------------------------------------------------------------ persistence


def test_save_load_delete_round_trip(tmp_path):
    roe = RulesOfEngagement("eng-1", "system", notes="hello")
    save_roe(roe, paths=tmp_path)
    assert load_roe("eng-1", paths=tmp_path) == roe
    assert load_enforcer("eng-1", paths=tmp_path) is not None
    assert load_enforcer("missing", paths=tmp_path) is None
    assert load_enforcer(None, paths=tmp_path) is None
    assert kill_switch_path("eng-1", paths=tmp_path).parent == tmp_path / "roe"


def test_corrupt_roe_file_loads_as_none(tmp_path):
    path = tmp_path / "roe" / "eng-1.json"
    path.parent.mkdir(parents=True)
    path.write_text("{not json")
    assert load_roe("eng-1", paths=tmp_path) is None


# -------------------------------------------------------------------------- CLI


def test_cli_show_without_roe_is_a_clear_message(tmp_path):
    code, lines = run_roe_action("show", "eng-1", paths=tmp_path)
    assert code == 0
    assert any("sin RoE" in line for line in lines)


def test_cli_kill_and_arm_toggle_the_sentinel(tmp_path):
    code, lines = run_roe_action("kill", "eng-1", paths=tmp_path)
    assert code == 0 and any("kill switch activado" in line for line in lines)
    assert kill_switch_path("eng-1", paths=tmp_path).exists()
    code, lines = run_roe_action("arm", "eng-1", paths=tmp_path)
    assert code == 0 and not kill_switch_path("eng-1", paths=tmp_path).exists()


def test_cli_show_reports_a_configured_roe(tmp_path):
    save_roe(RulesOfEngagement("eng-1", "system", max_actions_per_minute=3), paths=tmp_path)
    code, lines = run_roe_action("show", "eng-1", paths=tmp_path)
    assert code == 0
    assert any("acciones/min" in line for line in lines)


def test_cli_requires_an_engagement_and_valid_action(tmp_path):
    assert run_roe_action("show", None, paths=tmp_path)[0] == 2
    assert run_roe_action("frobnicate", "eng-1", paths=tmp_path)[0] == 2


def test_cli_path_lists_the_files(tmp_path):
    code, lines = run_roe_action("path", "eng-1", paths=tmp_path)
    assert code == 0 and len(lines) == 2


def test_cli_kill_switch_reaches_the_runtime_enforcer(tmp_path):
    """Regression: the CLI sentinel and the enforcer must be the same file.

    The signed RoE left ``kill_switch_file`` empty, so an enforcer that only
    watched that field would ignore ``omni --roe kill`` entirely.
    """
    save_roe(RulesOfEngagement("eng-1", "system"), paths=tmp_path)
    enforcer = load_enforcer("eng-1", paths=tmp_path)
    assert enforcer.stopped is False
    run_roe_action("kill", "eng-1", paths=tmp_path)
    assert enforcer.stopped is True
    with pytest.raises(RoEKillSwitch):
        enforcer.ensure_alive()
    run_roe_action("arm", "eng-1", paths=tmp_path)
    assert enforcer.stopped is False


def test_cli_kill_switch_is_reported_by_show(tmp_path):
    save_roe(RulesOfEngagement("eng-1", "system"), paths=tmp_path)
    run_roe_action("kill", "eng-1", paths=tmp_path)
    code, lines = run_roe_action("show", "eng-1", paths=tmp_path)
    assert code == 0
    assert any("DETENIDA" in line for line in lines)


async def test_execute_tool_honours_the_cli_kill_switch(monkeypatch, tmp_path):
    """End-to-end: create engagement \u2192 RoE \u2192 CLI kill \u2192 tool denied + audited."""
    from nexus_core.cli.engage import build_scope
    from nexus_core.kernel.runtime import ExecutionContext, execute_tool
    from nexus_core.scope import EngagementStore

    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))
    monkeypatch.setenv("NEXUS_SCOPE_SIGNING_SECRET", "e2e-secret")
    store = ControlStore(tmp_path / "e2e.db")
    store.initialize()
    scope = build_scope("e2e", "127.0.0.1/32", "e2e-secret", hours=1)
    EngagementStore(store).create(scope)
    engagement_id = scope.engagement_id

    save_roe(RulesOfEngagement(engagement_id, "system"))
    run_roe_action("kill", engagement_id)

    run_id = store.create_run("system", {})["id"]
    task = {
        "id": "task-roe-e2e",
        "tenant_id": "system",
        "run_id": run_id,
        "task_type": "tool.invoke",
        "payload": {"engagement_id": engagement_id},
    }
    context = ExecutionContext(store, task, "worker-roe")
    payload = {
        "tool_id": "nexus.knowledge.record_fact",
        "arguments": {"fact_type": "service", "key": "k", "value": {"port": 80}},
        "identity": {"subject_id": "operator-1", "roles": ["operator"]},
        "permissions": [],
        "engagement_id": engagement_id,
        "trace_id": run_id,
    }
    with pytest.raises(RoEKillSwitch):
        await execute_tool(payload, context)

    actions = [row["action"] for row in AuditWriter(store).export("system", trace_id=run_id)]
    assert "roe.denied" in actions
    assert "tool.complete" not in actions  # the handler never ran

    # Re-arm and the same call goes through the gateway normally.
    run_roe_action("arm", engagement_id)
    result = await execute_tool(payload, context)
    assert result["output"]["success"] is True


# ------------------------------------------------------------------ REPL /roe


def test_slash_roe_is_registered():
    from nexus_core.cli import commands

    assert "/roe" in commands.COMMANDS


def test_cmd_roe_renders_the_status(monkeypatch, tmp_path, capsys):
    from types import SimpleNamespace

    from nexus_core.cli import commands

    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))
    commands.cmd_roe(SimpleNamespace(engagement_id="eng-1"), ["show"])
    assert "sin RoE" in capsys.readouterr().out


def test_cmd_roe_without_an_engagement_errors(monkeypatch, tmp_path, capsys):
    from types import SimpleNamespace

    from nexus_core.cli import commands

    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))
    commands.cmd_roe(SimpleNamespace(engagement_id=None), ["show"])
    assert "ro" in capsys.readouterr().out.lower()
