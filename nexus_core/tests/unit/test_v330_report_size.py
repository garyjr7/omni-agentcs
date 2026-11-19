"""V0-32: the deliverable bounds run ids instead of printing the whole list."""

from __future__ import annotations

import asyncio
from dataclasses import replace

from nexus_core.report.extractor import build_report
from nexus_core.report.markdown import MAX_REPORT_RUN_IDS, render_markdown
from nexus_core.tests import report_support as support


def _report(tmp_path):
    store, _engagement, _run_id = support.seed_full_engagement(tmp_path)
    return asyncio.run(build_report(store, support.TENANT, "eng-lab"))


def test_a_hundred_run_ids_do_not_flood_the_scope_line(tmp_path):
    report = _report(tmp_path)
    run_ids = tuple(f"run_{index:04d}" for index in range(120))
    report = replace(report, run_ids=run_ids)

    text = render_markdown(report)

    assert f"`{run_ids[0]}`" in text
    assert f"`{run_ids[MAX_REPORT_RUN_IDS - 1]}`" in text
    assert f"`{run_ids[MAX_REPORT_RUN_IDS]}`" not in text
    assert "y 108 más (ver JSON)" in text
    # The line is bounded even before the surrounding report is considered.
    scope_line = next(line for line in text.splitlines() if line.startswith("- Runs:"))
    assert len(scope_line) < 500


def test_run_ids_are_attributed_to_the_finding_that_produced_them(tmp_path):
    report = _report(tmp_path)
    finding = report.findings[0]
    report = replace(
        report,
        findings=(replace(finding, run_ids=tuple(f"run_{index}" for index in range(10))),),
        run_ids=(),
    )

    text = render_markdown(report)

    assert "**Runs:** `run_0`, `run_1`, `run_2`, `run_3`, `run_4`, `run_5`" in text
    assert "… y 4 más (ver JSON)" in text
    assert "`run_10`" not in text
