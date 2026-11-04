"""The transcript's reading surfaces: purpose line, Markdown structure, summary.

Three texts reach the operator and none of them is the same kind of content:

* the ``thought`` of a ``react.action`` is the model's own note, and the durable
  metadata carries no structured ``expected_outcome``, so the collapsed row can
  only quote its opening sentence (the limitation is documented on
  ``thought_purpose``);
* a Markdown answer is a document -headings, lists (nested), tables, fences- and
  its structure must survive the terminal;
* the terminal summary of a run is a single long sentence whose tail carries the
  facts, the findings and the open branches, so the box has to wrap it, never
  clip it.
"""

from __future__ import annotations

from unittest import mock

import pytest

from nexus_core.agent.react import ReActConfig, run_react_loop
from nexus_core.agent.react_support import termination_summary
from nexus_core.cli import render
from nexus_core.cli.tui.markdown import render_markdown
from nexus_core.cli.tui.presentation import thinking, thought_purpose
from nexus_core.cli.tui.stream import render_thought
from nexus_core.kernel import runtime as runtime_module
from nexus_core.kernel.control_store import ControlStore
from nexus_core.kernel.runtime import ExecutionContext
from nexus_core.scope import EngagementStore
from nexus_core.tests.unit.test_engagement_plan import (
    ScriptedLLM_loop,
    _complete,
    _context,
)
from nexus_core.tests.unit.test_plan_status_polling import OBJECTIVE, _poll

pytestmark = [pytest.mark.unit, pytest.mark.usefixtures("lab_scope")]

TENANT = "system"
ENGAGEMENT = "eng-summary"
#: The box is ``│ `` + 66 columns + `` │``: the widest row any summary may have.
BOX_ROW_WIDTH = 70

LONG_NOTE = (
    "Enumero el 445 porque el SMB puede estar abierto. Después probaré "
    "credenciales por defecto, revisaré los shares y, si hay acceso, intentaré "
    "el pase lateral hacia el DC."
)


# --------------------------------------------------------------- the purpose
def test_collapsed_thought_reads_as_a_card_with_a_footer() -> None:
    plain = thinking("Reviso el 445.\nProbaré credenciales por defecto.").plain
    # A finished turn costs exactly one row: the arrow is the toggle, not a
    # duplicated preview plus footer.
    assert plain == "  ▸ Razonamiento"
    assert "• Thinking..." not in plain
    expanded = thinking("Reviso el 445.\nProbaré credenciales por defecto.",
                        expanded=True).plain.splitlines()
    assert expanded[0] == "  ▾ Razonamiento"
    assert expanded[1].startswith("  Reviso el 445.")
    assert expanded[-1].startswith("  ctrl+t colapsar")


def test_a_long_note_collapses_to_its_last_five_lines_with_an_ellipsis() -> None:
    # Collapsed there is no body at all; expanded the whole note is there in
    # order, with no ellipsis row and nothing dropped.
    assert thinking("palabra " * 60, width=40).plain == "  ▸ Razonamiento"
    lines = thinking("palabra " * 60, expanded=True, width=40).plain.splitlines()
    assert lines[0] == "  ▾ Razonamiento"
    body = [line for line in lines[1:-1] if line.strip()]
    assert len(body) > 5
    assert "  …" not in "\n".join(lines)


def test_expanded_thought_keeps_the_whole_note_once() -> None:
    plain = thinking(LONG_NOTE, expanded=True, width=100).plain
    assert plain.splitlines()[0] == "  ▾ Razonamiento"
    assert plain.count("Enumero el 445 porque el SMB puede estar abierto.") == 1
    assert "Después probaré" in plain
    # Strong assertion restored: expanded there is no ellipsis anywhere, not
    # just outside the footer. Nothing of the note was dropped.
    assert "…" not in plain, "expandido no recorta"
    assert "ctrl+t colapsar" in plain


def test_thought_purpose_is_capped_and_single_line() -> None:
    purpose = thought_purpose("palabra " * 60)
    assert len(purpose) == 101 and purpose.endswith("…")
    assert "\n" not in purpose
    assert thought_purpose("") == ""


def test_the_collapsed_card_stays_five_lines_at_a_normal_width() -> None:
    # One row at any width; expanding never exceeds the width it was given.
    assert thinking(LONG_NOTE, width=200).plain.splitlines() == ["  ▸ Razonamiento"]
    lines = thinking(LONG_NOTE, expanded=True, width=200).plain.splitlines()
    assert "Razonamiento" in lines[0]
    assert "ctrl+t colapsar" in lines[-1]
    assert max(len(line) for line in lines) <= 200
    assert render_thought(LONG_NOTE, width=200).strip()


# -------------------------------------------------------------- the Markdown
def test_nested_list_keeps_its_depth() -> None:
    rendered = render_markdown("- one\n  - two\n    - three", no_color=True, max_width=40)
    lines = rendered.splitlines()
    assert lines[0] == "  • one"
    assert lines[1].startswith("    • two")
    assert lines[2].startswith("      • three")
    assert all(len(line) <= 40 for line in lines)


def test_a_nested_item_wraps_under_its_own_indent() -> None:
    rendered = render_markdown(
        "- top\n  - " + "palabra " * 20, no_color=True, max_width=40
    )
    lines = rendered.splitlines()
    assert lines[1].startswith("    • palabra")
    assert lines[2].startswith("      palabra")
    assert all(len(line) <= 40 for line in lines)


def test_a_pathological_indent_falls_back_to_the_first_level() -> None:
    rendered = render_markdown(" " * 60 + "- deep", no_color=True, max_width=40)
    assert rendered.splitlines()[0] == "  • deep"


# --------------------------------------------------------------- the summary
def test_the_summary_wraps_instead_of_clipping_its_tail() -> None:
    summary = termination_summary(
        reason="límite de iteraciones alcanzado; trabajo incompleto",
        termination_reason="max_iterations",
        max_iterations=12,
        counts={"service": 2},
        findings=0,
        closed_branches=1,
        open_labels=["203.0.113.80:445/tcp microsoft-ds", "203.0.113.80:3389/tcp ms-wbt-server"],
        report_line="informe PENDIENTE",
    )
    rows = render._summary_rows(summary, 68)
    assert len(rows) > 1, "la frase terminal es más larga que el ancho del cajón"
    assert all(len(row) <= 68 for row in rows)
    joined = " ".join(rows)
    for expected in (
        "trabajo incompleto",
        "termination_reason=max_iterations",
        "verified facts: service=2",
        "findings=0",
        "203.0.113.80:3389/tcp ms-wbt-server",
        "informe PENDIENTE",
    ):
        assert expected in joined, f"el cajón perdió {expected!r}"


def test_the_summary_box_keeps_every_field_and_its_geometry(capsys) -> None:
    render.set_color_enabled(False)
    summary = termination_summary(
        reason="límite de iteraciones alcanzado; trabajo incompleto",
        termination_reason="max_iterations",
        max_iterations=12,
        counts={"service": 2},
        findings=0,
        closed_branches=1,
        open_labels=["203.0.113.80:445/tcp microsoft-ds"],
        report_line="informe PENDIENTE",
    )
    render.render_summary(summary, width=BOX_ROW_WIDTH)
    out = capsys.readouterr().out
    lines = [line for line in out.splitlines() if line.strip()]
    assert all(len(line) <= BOX_ROW_WIDTH for line in lines)
    box = [line for line in lines if line.startswith(("┌", "│", "├", "└"))]
    assert box[0].startswith("┌") and box[-1].startswith("└")
    compact = " ".join(lines)
    assert "findings=0" in compact and "informe PENDIENTE" in compact
    render.set_color_enabled(True)


# ------------------------------------------------- the deterministic agent run
@pytest.fixture()
def harness(tmp_path, monkeypatch):
    monkeypatch.setenv("NEXUS_WORKSPACE_ROOT", str(tmp_path))
    store = ControlStore(tmp_path / "summary.db")
    store.initialize()
    EngagementStore(store).create(_context(engagement_id=ENGAGEMENT).scope)
    run = store.create_run(TENANT, {})
    task = {
        "id": f"task-{run['id']}",
        "tenant_id": TENANT,
        "run_id": run["id"],
        "task_type": "react.run",
        "payload": {
            "objective": OBJECTIVE,
            "engagement_id": ENGAGEMENT,
            "identity": {"subject_id": "operator-1", "roles": ["operator"]},
            "permissions": [],
        },
    }
    return store, ExecutionContext(store, task, "worker-test"), tmp_path


def _loop_config(*, max_iterations: int, gates: bool) -> ReActConfig:
    return ReActConfig(
        max_iterations=max_iterations,
        enforce_completion_gates=gates,
        require_plan_first=False,
    )


async def _fake_tool(payload, context):
    return {"tool_id": payload["tool_id"], "output": {"success": True, "verified": True, "output": {}}}


async def test_a_finished_run_reads_as_finished_and_an_unfinished_one_does_not(harness, capsys):
    """Both terminal texts are rendered by the same box; only the status differs."""
    store, context, _workspace = harness
    render.set_color_enabled(False)

    done = await run_react_loop(
        context=context,
        objective=OBJECTIVE,
        engagement_id=ENGAGEMENT,
        llm_client=ScriptedLLM_loop([_complete()]),
        config=_loop_config(max_iterations=1, gates=False),
    )
    render.render_summary(done.final_summary, done.findings, width=BOX_ROW_WIDTH)
    finished = capsys.readouterr().out
    assert done.status == "completed"
    assert "hecho" in finished
    assert "trabajo incompleto" not in finished

    with mock.patch.object(runtime_module, "execute_tool", _fake_tool):
        pending = await run_react_loop(
            context=context,
            objective=OBJECTIVE,
            engagement_id=ENGAGEMENT,
            llm_client=ScriptedLLM_loop([_poll()]),
            config=_loop_config(max_iterations=2, gates=False),
        )
    render.render_summary(pending.final_summary, pending.findings, width=BOX_ROW_WIDTH)
    unfinished = capsys.readouterr().out
    assert pending.status == "max_iterations"
    assert "límite de iteraciones alcanzado; trabajo incompleto" in unfinished
    assert "termination_reason=max_iterations" in unfinished
    assert "findings=0" in unfinished
    assert "informe" in unfinished
    rows = [line for line in unfinished.splitlines() if line.strip()]
    assert all(len(line) <= BOX_ROW_WIDTH for line in rows)
    render.set_color_enabled(True)
