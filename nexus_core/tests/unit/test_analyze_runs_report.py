"""Fase 4.0: ``scripts/analyze_runs.py`` folds a trace into a run report."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

_SCRIPT = Path(__file__).resolve().parents[3] / "scripts" / "analyze_runs.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("analyze_runs", _SCRIPT)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def _trace(tmp_path: Path) -> Path:
    events = [
        {"type": "react.step", "run_id": "r1", "payload": {"iteration": 1, "tool_id": "nexus.recon.nmap", "success": True, "error": None}},
        {"type": "react.step", "run_id": "r1", "payload": {"iteration": 2, "tool_id": "nexus.web.ffuf", "success": False, "error": "boom"}},
        {
            "type": "run.complete",
            "run_id": "r1",
            "status": "subagent_budget_exceeded",
            "iterations": 2,
            "provider": "groq",
            "model": "qwen/qwen3.8-27b",
            "plan": {"engagement_id": "eng-1", "current": "enumeration", "done": 1, "total": 6, "facts_total": 2, "counts": {"service": 2}},
        },
    ]
    path = tmp_path / "trace.ndjson"
    path.write_text("\n".join(json.dumps(e) for e in events), encoding="utf-8")
    return path


def test_report_captures_status_phase_model_and_blockers(tmp_path):
    module = _load_module()
    report = module.build_report(_trace(tmp_path))

    assert report["run_id"] == "r1"
    assert report["engagement"] == "eng-1"
    assert report["provider"] == "groq"
    assert report["model"] == "qwen/qwen3.8-27b"
    assert report["status"] == "subagent_budget_exceeded"
    assert report["phase_reached"]["current"] == "enumeration"
    assert report["facts_recorded"] == {"service": 2}
    assert report["failed_tool_calls"] == 1
    assert report["blockers"][0]["tool_id"] == "nexus.web.ffuf"
    assert report["blockers"][0]["error"] == "boom"


def test_aborted_run_still_reports_the_phase_from_plan_events(tmp_path):
    module = _load_module()
    events = [
        {"type": "react.step", "payload": {"iteration": 1, "tool_id": "nexus.recon.nmap", "success": True}},
        {
            "type": "orchestrator.plan",
            "payload": {"iteration": 1, "phase": "exploitation", "progress": [2, 6], "facts_total": 4, "engagement_id": "eng-9"},
        },
    ]
    path = tmp_path / "aborted.ndjson"
    path.write_text("\n".join(json.dumps(e) for e in events), encoding="utf-8")

    report = module.build_report(path)

    assert report["status"] is None
    assert report["engagement"] == "eng-9"
    assert report["phase_reached"]["current"] == "exploitation"
    assert report["phase_reached"]["done"] == 2


def test_report_tolerates_non_json_lines(tmp_path):
    module = _load_module()
    path = tmp_path / "trace.ndjson"
    path.write_text('{"type": "react.step", "payload": {"iteration": 1}}\nnot json\n', encoding="utf-8")

    report = module.build_report(path)

    assert report["iterations"] == 1
    assert report["status"] is None
