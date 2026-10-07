#!/usr/bin/env python3
"""Turn ReAct NDJSON traces into ``run_report.json`` files (Fase 4.0).

Every ``omni.py --stream-json`` run leaves an NDJSON trace. This script folds one
trace into a compact, machine-readable report so the Run → Trace → Diagnose →
Evolve loop has a stable input: which tools ran, in what order, which failed and
why, the phase reached and the status.

Usage:

    .venv/bin/python scripts/analyze_runs.py                      # all examples
    .venv/bin/python scripts/analyze_runs.py path/to/trace.ndjson
    .venv/bin/python scripts/analyze_runs.py --json-summary out.json trace.ndjson

Each trace gets a sibling ``<trace>.report.json``; a combined
``run_reports.json`` is written next to the traces unless ``--no-combined``.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

DEFAULT_GLOB = "docs/missions/examples/*.ndjson"


def _load_events(path: Path) -> list[dict]:
    events: list[dict] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            # A trace may interleave non-JSON stderr; skip it, never abort.
            continue
    return events


def _steps(events: list[dict]) -> list[dict]:
    steps: list[dict] = []
    for event in events:
        if event.get("type") != "react.step":
            continue
        payload = event.get("payload") or {}
        steps.append(
            {
                "iteration": payload.get("iteration"),
                "tool_id": payload.get("tool_id"),
                "action": payload.get("action"),
                "success": payload.get("success"),
                "error": payload.get("error"),
                "consecutive_failures": payload.get("consecutive_failures"),
            }
        )
    return steps


def build_report(path: Path) -> dict:
    """Fold one trace into a report (never raises on a malformed trace)."""
    events = _load_events(path)
    steps = _steps(events)
    final = next(
        (e for e in reversed(events) if e.get("type") == "run.complete"), None
    )
    plan = (final or {}).get("plan") or {}
    if not plan:
        # A run aborted by a provider limit (e.g. daily tokens) never writes
        # ``run.complete``. Fall back to the newest orchestrator.plan so the
        # report still records how far the agent got.
        last_plan = next(
            (e for e in reversed(events) if e.get("type") == "orchestrator.plan"), None
        )
        fallback = (last_plan or {}).get("payload") or {}
        if fallback:
            plan = {
                "engagement_id": fallback.get("engagement_id"),
                "current": fallback.get("phase"),
                "done": (fallback.get("progress") or [None, None])[0],
                "total": (fallback.get("progress") or [None, None])[1],
                "facts_total": fallback.get("facts_total"),
            }

    blockers = [
        {"iteration": s["iteration"], "tool_id": s["tool_id"], "error": s["error"]}
        for s in steps
        if s.get("success") is False
    ]

    return {
        "source": str(path),
        "run_id": (final or {}).get("run_id")
        or next((e.get("run_id") for e in events if e.get("run_id")), None),
        "engagement": plan.get("engagement_id"),
        "provider": (final or {}).get("provider"),
        "model": (final or {}).get("model"),
        "status": (final or {}).get("status"),
        "iterations": (final or {}).get("iterations", len(steps)),
        "duration_seconds": (final or {}).get("duration_seconds"),
        "summary": (final or {}).get("summary"),
        "phase_reached": {
            "current": plan.get("current"),
            "label": plan.get("current_label"),
            "done": plan.get("done"),
            "total": plan.get("total"),
        },
        "facts_total": plan.get("facts_total"),
        "facts_recorded": plan.get("counts") or {},
        "tools_used": [
            {"iteration": s["iteration"], "tool_id": s["tool_id"], "success": s["success"]}
            for s in steps
        ],
        "blockers": blockers,
        "failed_tool_calls": len(blockers),
    }


def _trace_paths(raw: list[str]) -> list[Path]:
    if raw:
        return [Path(p) for p in raw]
    return sorted(Path(".").glob(DEFAULT_GLOB))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("traces", nargs="*", help="NDJSON traces (default: examples)")
    parser.add_argument("--no-combined", action="store_true", help="skip run_reports.json")
    parser.add_argument("--json-summary", metavar="PATH", help="write the summary array here")
    args = parser.parse_args(argv)

    traces = [p for p in _trace_paths(args.traces) if p.is_file()]
    if not traces:
        print("no traces found", file=sys.stderr)
        return 1

    reports: list[dict] = []
    for trace in traces:
        report = build_report(trace)
        reports.append(report)
        out = trace.with_suffix(trace.suffix + ".report.json")
        out.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
        print(
            f"{trace.name}: status={report['status']} "
            f"phase={report['phase_reached']['current']} "
            f"iters={report['iterations']} failed={report['failed_tool_calls']} "
            f"-> {out.name}"
        )

    if not args.no_combined:
        combined = traces[0].parent / "run_reports.json"
        combined.write_text(json.dumps(reports, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"combined -> {combined}")
    if args.json_summary:
        Path(args.json_summary).write_text(
            json.dumps(reports, indent=2, ensure_ascii=False), encoding="utf-8"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
