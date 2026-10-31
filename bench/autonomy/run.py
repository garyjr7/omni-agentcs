#!/usr/bin/env python3
"""Offline autonomy benchmark over synthetic traces.

This is *not* a room benchmark: it never opens a socket, never calls a model and
never executes a tool. Each scenario is a fictitious trace (tool results, board
facts, model exchange) evaluated with the production predicates the loop uses:

* ``ToolResult`` outcome/completion classification;
* :func:`nexus_core.kernel.fact_verification.derive_assertions` (negatives and
  unavailable results must never derive a positive fact);
* :class:`nexus_core.agent.turn_telemetry.TurnTelemetryRecorder` (a negative is
  ``tool_negative``, not ``tool_failure``);
* the coverage ledger (families, barriers, open/closed branches);
* the shared semantic signature (direct/background/retried dedup);
* :func:`nexus_core.agent.react_support.termination_summary`.

The scenarios are split into ``calibration`` and ``reserved``: rules may only be
tuned against calibration, and the report keeps reserved metrics separate. That
is the only way this number means anything beyond the traces it was written
with. ``90%`` is a target for the declared category/condition, never a promise
about an arbitrary engagement.

Usage::

    python bench/autonomy/run.py                    # human summary
    python bench/autonomy/run.py --json out.json    # machine-readable report
    python bench/autonomy/run.py --baseline old.json
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from nexus_core.agent.coverage import build_coverage  # noqa: E402
from nexus_core.agent.react_support import termination_summary  # noqa: E402
from nexus_core.agent.task_manager import invocation_signature  # noqa: E402
from nexus_core.agent.turn_telemetry import (  # noqa: E402
    DETERMINATE_NEGATIVE_OUTCOMES,
    FrictionFlag,
    TurnTelemetryRecorder,
)
from nexus_core.kernel.fact_verification import derive_assertions  # noqa: E402
from nexus_core.kernel.invocation_journal import InvocationJournal  # noqa: E402
from nexus_core.kernel.models import Identity, RunContext, ToolResult  # noqa: E402
from nexus_core.kernel.step_signature import semantic_signature  # noqa: E402

TENANT = "system"
CALIBRATION = "calibration"
RESERVED = "reserved"
SUCCESS = "success"

#: Target for the *declared* condition (a scenario's ``objective_complete`` with
#: verifiable evidence), never a guarantee for any room.
TARGET_RATE = 0.9


@dataclass
class ScenarioResult:
    scenario_id: str
    split: str
    category: str
    tokens: int = 0
    ms: int = 0
    open_branches: int = 0
    closed_branches: int = 0
    families: int = 0
    verified_facts: int = 0
    unverified_facts: int = 0
    claimed_verified: int = 0
    provenance_violations: int = 0
    repeated_without_progress: int = 0
    effective_invocations: int = 0
    findings: int = 0
    supported_findings: int = 0
    objective_complete: bool = False
    correct_stop: bool = False
    checks: list[str] = field(default_factory=list)
    failures: list[str] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return not self.failures


def _context(scenario: dict[str, Any], index: int) -> RunContext:
    return RunContext(
        tenant_id=TENANT,
        identity=Identity("bench", TENANT, roles=("operator",)),
        run_id=f"bench-{scenario['id']}",
        invocation_id=f"inv-{index}",
    )


def _result(payload: dict[str, Any]) -> ToolResult:
    allowed = {
        key: value
        for key, value in payload.items()
        if key
        in {
            "output",
            "verified",
            "verification_method",
            "evidence",
            "exit_code",
            "accepted_exit_codes",
            "stdout",
            "stderr",
            "timed_out",
            "outcome",
        }
    }
    return ToolResult(**allowed)


def _facts(scenario: dict[str, Any], derived: list[dict[str, Any]]) -> list[dict[str, Any]]:
    facts = [dict(item) for item in scenario.get("facts", [])]
    seen = {(item.get("fact_type"), item.get("key")) for item in facts}
    for item in derived:
        key = (item.get("fact_type"), item.get("key"))
        if key not in seen:
            facts.append(dict(item))
            seen.add(key)
    return facts


def _is_agent_claim(fact: dict[str, Any]) -> bool:
    source = str(fact.get("source") or fact.get("asserted_by") or "").strip().lower()
    return source in {"agent", "model", "model_claim", "llm"}


def _evaluate(scenario: dict[str, Any]) -> ScenarioResult:
    result = ScenarioResult(
        scenario_id=str(scenario["id"]),
        split=str(scenario.get("split") or CALIBRATION),
        category=str(scenario.get("category") or SUCCESS),
        objective_complete=bool(scenario.get("objective_complete")),
    )
    expect = scenario.get("expect") or {}
    recorder = TurnTelemetryRecorder(emit=False)
    derived: list[dict[str, Any]] = []
    seen_signatures: set[str] = set()
    event_signatures: list[str] = []
    journal_keys: list[str] = []

    events = list(scenario.get("events") or [])
    for index, event in enumerate(events):
        context = _context(scenario, index)
        result.tokens += int(event.get("tokens") or 0)
        result.ms += int(event.get("ms") or 0)
        recorder.begin_turn(
            iteration=index + 1,
            phase=str(event.get("phase") or "enumeration"),
            subagent_id=None,
        )
        tool_id = str(event.get("tool_id") or "")
        arguments = dict(event.get("arguments") or {})
        signature = semantic_signature(tool_id, arguments)
        event_signatures.append(signature)
        journal_keys.append(
            InvocationJournal.step_key(tool_id, arguments, phase="enumeration")
        )
        if signature in seen_signatures and not event.get("progress"):
            result.repeated_without_progress += 1
        seen_signatures.add(signature)

        if event.get("raises"):
            recorder.note_tool(
                duration_ms=int(event.get("ms") or 0),
                success=False,
                error_type=str(event["raises"]),
            )
            recorder.finish(outcome="error")
            continue

        tool_result = _result(dict(event.get("result") or {}))
        recorder.note_tool(
            duration_ms=int(event.get("ms") or 0),
            success=tool_result.success,
            outcome=tool_result.outcome_class,
        )
        recorder.finish(outcome=tool_result.outcome_class)
        if tool_result.completed and not tool_result.timed_out:
            try:
                derived.extend(
                    derive_assertions(tool_id, arguments, tool_result, context)
                )
            except Exception as error:  # noqa: BLE001 - a scenario is not an engine
                result.failures.append(
                    f"derive_assertions crashed for {tool_id}: {type(error).__name__}"
                )
        label = tool_result.outcome_class
        if label == "in_flight":
            # Coordination, not an answer: the same step was already running, so
            # the call cannot be a negative observation of the target.
            friction = set(recorder.turns[-1].friction)
            if FrictionFlag.TOOL_FAILURE.value in friction:
                result.failures.append(f"{tool_id}: in_flight classified as tool_failure")
            if FrictionFlag.TOOL_IN_FLIGHT.value not in friction:
                result.failures.append(f"{tool_id}: in_flight did not carry tool_in_flight")
            result.checks.append("in_flight_not_failure")
        if label in DETERMINATE_NEGATIVE_OUTCOMES:
            friction = set(recorder.turns[-1].friction)
            if FrictionFlag.TOOL_FAILURE.value in friction:
                result.failures.append(f"{tool_id}: negative classified as tool_failure")
            if FrictionFlag.TOOL_NEGATIVE.value not in friction:
                result.failures.append(f"{tool_id}: negative did not carry tool_negative")
            result.checks.append("negative_not_failure")
            if any(
                assertion.get("verified") is True for assertion in derived
            ):
                result.failures.append(
                    f"{tool_id}: a negative derived a positive assertion"
                )
        if label == "unavailable":
            evidence = tool_result.evidence or {}
            cause = str(
                evidence.get("cause_code")
                or evidence.get("cause")
                or (tool_result.output or {}).get("cause")
                or ""
            ).strip()
            if not cause:
                result.failures.append(f"{tool_id}: unavailable without a cause code")
            wanted = str(expect.get("unavailable_cause") or "")
            if wanted and wanted not in cause:
                result.failures.append(
                    f"{tool_id}: cause {cause!r} does not name {wanted!r}"
                )

    facts = _facts(scenario, derived)
    for fact in facts:
        claimed = fact.get("verified") is True
        if claimed:
            result.claimed_verified += 1
        if claimed and _is_agent_claim(fact):
            result.provenance_violations += 1
            result.failures.append(
                f"fact {fact.get('fact_type')}:{fact.get('key')} claims verifier provenance "
                "but was asserted by the model"
            )
        elif claimed:
            result.verified_facts += 1
        else:
            result.unverified_facts += 1
    result.findings = len(scenario.get("findings") or [])
    source_ids = {
        str(fact.get("invocation_id") or "")
        for fact in facts
        if fact.get("verified") is True and str(fact.get("invocation_id") or "")
    }
    for finding in scenario.get("findings") or []:
        citation = str(finding.get("evidence") or "").strip()
        cited = str(finding.get("invocation_id") or "").strip()
        if citation and (not cited or not source_ids or cited in source_ids):
            result.supported_findings += 1
    if expect.get("unverified_findings") is not None:
        unsupported = result.findings - result.supported_findings
        if unsupported > int(expect["unverified_findings"]):
            result.failures.append(
                f"{unsupported} finding(s) lack verifiable evidence"
            )

    coverage = build_coverage(facts)
    result.open_branches = len(coverage.open_work)
    result.closed_branches = len(coverage.closed)
    result.families = len(coverage.families)
    result.effective_invocations = len(set(event_signatures)) if event_signatures else 0

    if "open_branches" in expect and result.open_branches != int(expect["open_branches"]):
        result.failures.append(
            f"open branches {result.open_branches} != {expect['open_branches']}"
        )
    if (
        "closed_branches" in expect
        and result.closed_branches != int(expect["closed_branches"])
    ):
        result.failures.append(
            f"closed branches {result.closed_branches} != {expect['closed_branches']}"
        )
    if "findings" in expect and result.findings != int(expect["findings"]):
        result.failures.append(f"findings {result.findings} != {expect['findings']}")
    if (
        "repeated_without_progress" in expect
        and result.repeated_without_progress
        != int(expect["repeated_without_progress"])
    ):
        result.failures.append(
            "repeated without progress "
            f"{result.repeated_without_progress} != "
            f"{expect['repeated_without_progress']}"
        )
    if (
        "effective_invocations" in expect
        and result.effective_invocations != int(expect["effective_invocations"])
    ):
        result.failures.append(
            f"effective invocations {result.effective_invocations} != "
            f"{expect['effective_invocations']}"
        )
    if "families" in expect and result.families != int(expect["families"]):
        result.failures.append(f"families {result.families} != {expect['families']}")
    if expect.get("representative"):
        representative = coverage.family_representative(str(scenario["target"]), "rpc")
        actual = representative.ref if representative is not None else ""
        if actual != str(expect["representative"]):
            result.failures.append(
                f"family representative {actual!r} != {expect['representative']!r}"
            )
    if "deferred_family_members" in expect:
        representative = coverage.family_representative(str(scenario["target"]), "rpc")
        deferred = (
            len(coverage.deferred_family_members(representative))
            if representative is not None
            else 0
        )
        if deferred != int(expect["deferred_family_members"]):
            result.failures.append(
                f"deferred family members {deferred} != "
                f"{expect['deferred_family_members']}"
            )
    if expect.get("no_positive_facts") and result.verified_facts:
        result.failures.append("a non-observation trace produced verified facts")
    if expect.get("no_tool_failure"):
        flags = {flag for turn in recorder.turns for flag in turn.friction}
        if FrictionFlag.TOOL_FAILURE.value in flags:
            result.failures.append("a provider refusal was recorded as a tool failure")
    if scenario.get("stopped") and expect.get("correct_stop"):
        reason = str(scenario.get("stop_reason") or "")
        if not reason:
            result.failures.append("declared stop has no reason")
        result.correct_stop = bool(reason)

    if scenario.get("summary_inputs"):
        inputs = scenario["summary_inputs"]
        summary = termination_summary(
            reason=str(inputs["reason"]),
            max_iterations=int(inputs["max_iterations"]),
            counts={
                "service": sum(
                    1
                    for fact in facts
                    if fact.get("fact_type") == "service"
                    and fact.get("verified") is True
                )
            },
            findings=result.findings,
            closed_branches=int(inputs.get("closed_branches") or 0),
            open_labels=list(inputs.get("open_labels") or ()),
            report_line=str(inputs.get("report_line") or "informe PENDIENTE"),
        )
        for needle in expect.get("summary_fields") or ():
            if str(needle) not in summary:
                result.failures.append(f"terminal summary is missing {needle!r}")
        result.checks.append("honest_summary")

    result.checks.append("provenance")

    # The three dedup layers must agree on what "one scan" means.
    if event_signatures:
        shared = {invocation_signature(event["tool_id"], event.get("arguments")) for event in events}
        if len(shared) != len(set(event_signatures)):
            result.failures.append("semantic and task-manager signatures disagree")
        if len(set(journal_keys)) != len(set(event_signatures)):
            result.failures.append("journal step keys disagree with semantic signatures")
    return result


def _rate(part: int, total: int) -> float:
    return round(part / total, 3) if total else 0.0


def run_benchmark(path: Path | None = None) -> dict[str, Any]:
    """Evaluate every scenario and return the metrics report (pure, offline)."""
    source = path or Path(__file__).with_name("scenarios.json")
    payload = json.loads(source.read_text(encoding="utf-8"))
    scenarios = list(payload.get("scenarios") or [])
    results = [_evaluate(scenario) for scenario in scenarios]

    def bucket(items: list[ScenarioResult]) -> dict[str, Any]:
        completed = [item for item in items if item.objective_complete]
        stops = [item for item in items if item.correct_stop]
        return {
            "scenarios": len(items),
            "passed": sum(1 for item in items if item.passed),
            "objective_complete": len(completed),
            "objective_complete_with_verified_evidence": sum(
                1
                for item in completed
                if item.passed and (item.verified_facts or item.supported_findings)
            ),
            "correct_stops": len(stops),
            "findings": sum(item.findings for item in items),
            "supported_findings": sum(item.supported_findings for item in items),
            "open_branches": sum(item.open_branches for item in items),
            "closed_branches": sum(item.closed_branches for item in items),
            "repeated_without_progress": sum(
                item.repeated_without_progress for item in items
            ),
            "effective_invocations": sum(item.effective_invocations for item in items),
            "tokens": sum(item.tokens for item in items),
            "ms": sum(item.ms for item in items),
            "failures": [
                f"{item.scenario_id}: {failure}"
                for item in items
                for failure in item.failures
            ],
            "success_rate": _rate(
                sum(
                    1
                    for item in completed
                    if item.passed and (item.verified_facts or item.supported_findings)
                ),
                len(completed),
            ),
            "pass_rate": _rate(sum(1 for item in items if item.passed), len(items)),
        }

    by_split = {
        split: bucket([item for item in results if item.split == split])
        for split in (CALIBRATION, RESERVED)
    }
    by_category: dict[str, dict[str, Any]] = {}
    for category in sorted({item.category for item in results}):
        by_category[category] = bucket(
            [item for item in results if item.category == category]
        )
    total = bucket(results)
    total["provenance_precision"] = _rate(
        sum(item.verified_facts for item in results),
        sum(item.claimed_verified for item in results),
    )
    target_met = (
        total["objective_complete"] == 0
        or total["success_rate"] >= TARGET_RATE
    )
    return {
        "benchmark": "autonomy-synthetic",
        "version": payload.get("version", 1),
        "target_rate": TARGET_RATE,
        "target_met": target_met,
        "total": total,
        "by_split": by_split,
        "by_category": by_category,
        "scenarios": [
            {
                "id": item.scenario_id,
                "split": item.split,
                "category": item.category,
                "passed": item.passed,
                "failures": item.failures,
                "verified_facts": item.verified_facts,
                "open_branches": item.open_branches,
                "closed_branches": item.closed_branches,
                "repeated_without_progress": item.repeated_without_progress,
                "tokens": item.tokens,
                "ms": item.ms,
            }
            for item in results
        ],
    }


def _compare(report: dict[str, Any], baseline: dict[str, Any]) -> dict[str, Any]:
    keys = ("success_rate", "repeated_without_progress", "open_branches", "closed_branches", "tokens", "ms")
    return {
        key: {
            "before": (baseline.get("total") or {}).get(key),
            "after": (report.get("total") or {}).get(key),
        }
        for key in keys
    }


def _render(report: dict[str, Any]) -> str:
    total = report["total"]
    lines = [
        "AUTONOMÍA SINTÉTICA (offline; sin red, sin modelo, sin salas)",
        f"objetivos completados con evidencia verificable: "
        f"{total['objective_complete_with_verified_evidence']}/"
        f"{total['objective_complete']} ({total['success_rate']:.1%})"
        f"  objetivo>={report['target_rate']:.0%}: "
        f"{'sí' if report['target_met'] else 'no'}",
        f"escenarios: {total['passed']}/{total['scenarios']} sin violaciones",
        f"invocaciones repetidas sin progreso: {total['repeated_without_progress']}",
        f"ramas resueltas/pendientes: {total['closed_branches']}/{total['open_branches']}",
        f"findings soportados/total: {total['supported_findings']}/{total['findings']}",
        f"provenance precision: {total['provenance_precision']:.1%}",
        f"coste: {total['tokens']} tokens, {total['ms']} ms",
    ]
    for split, data in report["by_split"].items():
        lines.append(
            f"  {split}: {data['passed']}/{data['scenarios']} ok, "
            f"éxito={data['success_rate']:.1%}"
        )
    for category, data in report["by_category"].items():
        lines.append(
            f"  {category}: {data['passed']}/{data['scenarios']} ok"
            f" (pasadas={data['pass_rate']:.1%})"
        )
    if total["failures"]:
        lines.append("violaciones:")
        lines.extend(f"  - {item}" for item in total["failures"])
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Offline synthetic autonomy benchmark")
    parser.add_argument("--scenarios", type=Path, default=None)
    parser.add_argument("--json", type=Path, default=None, help="write the report as JSON")
    parser.add_argument("--baseline", type=Path, default=None, help="compare with a previous JSON report")
    parser.add_argument("--fail-under", type=float, default=None)
    args = parser.parse_args(argv)
    report = run_benchmark(args.scenarios)
    if args.baseline and args.baseline.exists():
        report["baseline_delta"] = _compare(
            report, json.loads(args.baseline.read_text(encoding="utf-8"))
        )
    if args.json:
        args.json.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(_render(report))
    if args.baseline and report.get("baseline_delta"):
        print("delta vs baseline:")
        for key, values in report["baseline_delta"].items():
            print(f"  {key}: {values['before']} -> {values['after']}")
    if args.fail_under is not None and report["total"]["success_rate"] < args.fail_under:
        return 1
    return 0 if report["total"]["passed"] == report["total"]["scenarios"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
