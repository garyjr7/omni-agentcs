"""``Sí, siempre en este engagement`` skips the question, never the control.

The menu answer may cover later identical calls for the rest of the run. Every
covered call still registers and consumes its own durable, single-use approval,
and the automatic authorization is audited on its own so the trail never claims
the operator answered that particular call.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from nexus_core.cli import approval as module
from nexus_core.cli import render
from nexus_core.kernel.control_store import ControlStore
from nexus_core.kernel.models import Identity, RunContext

pytestmark = pytest.mark.unit

TENANT = "system"


class _Session:
    """The slice of ``OmniSession`` the approval callback actually uses."""

    operator_id = "operator:tester"
    input_reader = None
    _tui = SimpleNamespace(use_tui=False)

    def __init__(self, store: ControlStore) -> None:
        self.store = store

    def build_run_context(self, run_id: str) -> RunContext:
        return RunContext(
            tenant_id=TENANT,
            # The agent requests; the operator decides. Never the same subject.
            identity=Identity("agent", TENANT, roles=("operator",)),
            run_id=run_id,
        )


def _decision() -> SimpleNamespace:
    return SimpleNamespace(reason="requiere aprobación", requires_approval=True)


def _callback(tmp_path, monkeypatch, answers, *, risk="high"):
    store = ControlStore(tmp_path / "approvals.db")
    store.initialize()
    monkeypatch.setattr(module, "_risk_of", lambda *_: risk)
    prompts: list[str] = []

    def prompt(tool_id, arguments, decision, reader=None, risk="", **kwargs):
        prompts.append(tool_id)
        return answers.pop(0)

    monkeypatch.setattr(render, "render_approval_prompt", prompt)
    monkeypatch.setattr(render, "render_status", lambda *args, **kwargs: None)
    monkeypatch.setattr(render, "render_error", lambda *args, **kwargs: None)
    session = _Session(store)
    callback = module.make_approval_callback(session, store, TENANT, "run-1")
    return store, callback, prompts


def _rows(store: ControlStore) -> list[dict]:
    with store.connect() as conn:
        return [
            dict(row)
            for row in conn.execute(
                "SELECT action,status,decided_by,reason FROM kernel_approvals ORDER BY created_at"
            ).fetchall()
        ]


def test_always_covers_later_identical_calls_but_still_registers_each_row(tmp_path, monkeypatch):
    store, callback, prompts = _callback(tmp_path, monkeypatch, ["a"])
    first = callback("nexus.recon.nmap", {"target": "203.0.113.9"}, _decision())
    second = callback("nexus.recon.nmap", {"target": "203.0.113.9"}, _decision())

    assert first.approved is True and second.approved is True
    assert prompts == ["nexus.recon.nmap"]  # the operator answered once
    rows = _rows(store)
    assert len(rows) == 2  # but each call has its own durable approval
    assert {row["status"] for row in rows} == {"approved"}
    assert {row["decided_by"] for row in rows} == {"operator:tester"}


def test_a_different_target_is_asked_again(tmp_path, monkeypatch):
    _store, callback, prompts = _callback(
        tmp_path, monkeypatch, ["a", "y"]
    )
    callback("nexus.recon.nmap", {"target": "203.0.113.9"}, _decision())
    callback("nexus.recon.nmap", {"target": "203.0.113.10"}, _decision())
    assert prompts == ["nexus.recon.nmap", "nexus.recon.nmap"]


def test_a_destructive_action_is_never_covered_for_the_engagement(tmp_path, monkeypatch):
    _store, callback, prompts = _callback(
        tmp_path, monkeypatch, ["a", "n"], risk="destructive"
    )
    result = callback("nexus.post.exfil", {"path": "/tmp/x"}, _decision())
    assert result.approved is False
    # The engagement-wide answer was refused and the menu asked again.
    assert prompts == ["nexus.post.exfil", "nexus.post.exfil"]


def test_an_unresolvable_risk_is_never_covered_for_the_engagement(tmp_path, monkeypatch):
    _store, callback, prompts = _callback(tmp_path, monkeypatch, ["a", "n"], risk="")
    result = callback("nexus.recon.nmap", {"target": "203.0.113.9"}, _decision())
    assert result.approved is False
    assert prompts == ["nexus.recon.nmap", "nexus.recon.nmap"]
