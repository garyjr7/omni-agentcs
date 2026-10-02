"""Unit tests for the deterministic multi-phase engagement planner."""

from __future__ import annotations

import pytest

from nexus_core.agent.planner import (
    PHASE_IDS,
    STATUS_CURRENT,
    STATUS_DONE,
    STATUS_PENDING,
    active_phase,
    build_plan,
    normalize_counts,
    plan_from_summary,
)

pytestmark = pytest.mark.unit


def test_empty_blackboard_starts_at_recon():
    plan = build_plan()
    assert plan.current == "recon"
    assert plan.progress == (0, 6)


def test_services_close_recon_and_open_enumeration():
    plan = build_plan(counts={"service": 3, "host": 1})
    assert plan.current == "enumeration"
    assert plan.progress == (1, 6)
    statuses = {item.id: item.status for item in plan.phases}
    assert statuses["recon"] == STATUS_DONE
    assert statuses["enumeration"] == STATUS_CURRENT


def test_users_and_credentials_close_enumeration():
    plan = build_plan(counts={"service": 1, "user": 1, "credential": 1})
    assert plan.current == "exploitation"


def test_access_closes_exploitation():
    plan = build_plan(counts={"service": 1, "user": 1, "access": 1})
    assert plan.current == "privilege_escalation"


def test_privilege_closes_escalation():
    plan = build_plan(counts={"service": 1, "user": 1, "access": 1, "privilege": 1})
    assert plan.current == "post_exploitation"


def test_loot_closes_post_exploitation_and_reaches_reporting():
    plan = build_plan(
        counts={"service": 1, "user": 1, "access": 1, "privilege": 1, "loot": 1}
    )
    assert plan.current == "reporting"
    assert plan.progress == (5, 6)


def test_reporting_is_never_auto_completed():
    for phase in PHASE_IDS:
        plan = build_plan(counts={phase: 5})
        reporting = next(item for item in plan.phases if item.id == "reporting")
        assert reporting.status != STATUS_DONE


def test_lateral_movement_is_optional_and_never_current():
    # Two sessions satisfy the optional lateral phase, but it is never current.
    plan = build_plan(
        counts={"service": 1, "user": 1, "access": 1, "privilege": 1, "loot": 1, "session": 2}
    )
    assert plan.current == "reporting"
    lateral = next(item for item in plan.phases if item.id == "lateral_movement")
    assert lateral.optional is True
    assert lateral.status == STATUS_DONE


def test_single_session_does_not_close_lateral():
    plan = build_plan(counts={"service": 1, "user": 1, "access": 1, "privilege": 1, "loot": 1, "session": 1})
    lateral = next(item for item in plan.phases if item.id == "lateral_movement")
    assert lateral.status == STATUS_PENDING


def test_render_marks_current_phase_and_hint():
    plan = build_plan(counts={"service": 1})
    text = plan.render()
    assert "PLAN DE ENGAGEMENT" in text
    assert "fase actual: Enumeración" in text
    assert "[>] Enumeración" in text
    assert "SIGUIENTE PASO DEL PLAN:" in text


def test_pipeline_is_single_line():
    plan = build_plan(counts={"service": 1})
    assert "\n" not in plan.pipeline()
    assert "Enumeración ▶" in plan.pipeline()


def test_to_dict_roundtrip_fields():
    plan = build_plan(counts={"service": 2}, engagement_id="eng-1")
    payload = plan.to_dict()
    assert payload["current"] == "enumeration"
    assert payload["current_label"] == "Enumeración"
    assert payload["done"] == 1 and payload["total"] == 6
    assert payload["counts"] == {"service": 2}
    assert len(payload["phases"]) == len(PHASE_IDS)


def test_normalize_counts_from_fact_records():
    counts = normalize_counts(
        facts=[{"fact_type": "service"}, {"fact_type": "service"}, {"type": "user"}]
    )
    assert counts == {"service": 2, "user": 1}


def test_normalize_ignores_bad_values():
    assert normalize_counts(counts={"service": "x", "user": 3, "host": 0}) == {"user": 3}


def test_plan_from_summary_uses_blackboard_summary():
    plan = plan_from_summary(
        {"engagement_id": "eng-1", "total": 4, "counts": {"service": 2, "user": 1, "credential": 1}},
        engagement_id="eng-1",
    )
    assert plan.current == "exploitation"
    assert plan.facts_total == 4


def test_active_phase_matches_build_plan():
    counts = {"service": 1, "user": 1}
    assert active_phase(counts) == build_plan(counts=counts).current
