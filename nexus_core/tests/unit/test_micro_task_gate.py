"""Fase 1: una micro-tarea cierra sin arrastrar el plan del engagement."""

from types import SimpleNamespace

from nexus_core.agent.react_support import _completion_objections, objective_is_micro_task


def _plan() -> SimpleNamespace:
    return SimpleNamespace(current="enumeration", phases=[], progress=(1, 7), phase=None)


def _engagement_plan() -> SimpleNamespace:
    return SimpleNamespace(
        pending=(SimpleNamespace(id="root", description="Escalar a root"),)
    )


def test_a_limiter_marks_the_objective_as_a_micro_task() -> None:
    assert objective_is_micro_task("solo escanea los puertos de 10.0.0.1")
    assert objective_is_micro_task("Only scan the top 100 ports")
    assert not objective_is_micro_task("compromete el DC y captura ambas flags")


def test_pending_todos_do_not_block_a_micro_task() -> None:
    common = dict(
        plan=_plan(),
        enforce_completion_gates=True,
        engagement_id="eng",
        engagement_plan=_engagement_plan(),
        require_plan_first=True,
    )
    assert _completion_objections(**common, micro_task=False)
    assert _completion_objections(**common, micro_task=True) == []


def test_the_evidence_gate_still_applies_to_a_micro_task(monkeypatch) -> None:
    from nexus_core.agent import react_support

    monkeypatch.setattr(react_support, "fabricated_evidence", lambda stats: True)
    objections = _completion_objections(
        plan=_plan(),
        enforce_completion_gates=True,
        evidence_stats={"stale": 1, "unsupported": 0},
        engagement_id="eng",
        engagement_plan=_engagement_plan(),
        require_plan_first=True,
        micro_task=True,
    )
    assert objections and "stale_evidence" in objections[0]
