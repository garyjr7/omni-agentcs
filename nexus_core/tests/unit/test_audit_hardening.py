"""Regression evidence for capability delegation, queue isolation and progress."""
from __future__ import annotations

import asyncio
import threading
import time
from dataclasses import replace
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock

import pytest
import yaml

from nexus_core.agent import turn_telemetry
from nexus_core.agent.playbook_proofs import ExecutionProof, execution_proofs
from nexus_core.agent.playbooks import Playbook, PlaybookStep, match_playbook
from nexus_core.agent.subagents import SUBAGENTS_BY_ID
from nexus_core.kernel.control_store import ControlStore
from nexus_core.kernel.errors import BudgetExceeded
from nexus_core.kernel.invocation_journal import InvocationJournal
from nexus_core.kernel.job_authority import JobAuthority, parse_authority, reserve_job, verify_job_reservation
from nexus_core.kernel.models import Identity, RunContext, ToolResult
from nexus_core.kernel import runtime
from nexus_core.playbooks.loader import PACKAGE_DIR, PlaybookSchemaError, load_package_text, load_packages
from nexus_core.tools.handlers import jobs
from nexus_core.tools.registry import durable_tool_definitions


def context_for(store: ControlStore, *, limit: int = 2) -> RunContext:
    run = store.create_run('system', {})
    profile = SUBAGENTS_BY_ID['privesc']
    authority = JobAuthority(run_id=run['id'], profile_id=profile.id,
        tools=tuple(sorted(profile.tools)), token_budget=profile.token_budget,
        run_token_budget=100_000, job_limit=limit)
    return RunContext('system', Identity('operator', 'system', roles=('operator',)),
                      run_id=run['id'], store=store, job_authority=authority)


def local_context(tmp_path: Path) -> RunContext:
    store = ControlStore(tmp_path / 'control.db')
    store.initialize()
    return context_for(store)


async def start_job(context: RunContext) -> dict[str, Any]:
    await jobs.jobs_handler({'action': 'start', 'tool_id': 'nexus.session.list'}, context)
    task = context.store.claim_task('worker')
    assert task is not None
    return dict(task)


def mock_scope(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(jobs, 'validate_session_scope', lambda context: None)


async def test_subagent_cannot_enqueue_upload_or_inject_authority(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    mock_scope(monkeypatch)
    context = local_context(tmp_path)
    with pytest.raises(PermissionError, match='capability'):
        await jobs.jobs_handler({'action': 'start', 'tool_id': 'nexus.web.upload',
            'arguments': {'url': 'https://example.invalid', 'upload': {'field': 'f', 'path': 'f'}}}, context)
    with pytest.raises(ValueError):
        await jobs.jobs_handler({'action': 'start', 'tool_id': 'nexus.session.list',
                                'job_authority': {'profile_id': 'exploit'}}, context)
    assert context.store.claim_task('worker') is None


async def test_enqueue_rejects_exhausted_tokens_and_iteration_allowance(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    mock_scope(monkeypatch)
    context = local_context(tmp_path)
    assert context.job_authority is not None
    exhausted = replace(context, job_authority=context.job_authority.model_copy(update={'job_limit': 0}))
    with pytest.raises(BudgetExceeded):
        await start_job(exhausted)
    context.store.record_usage('system', context.run_id, 'model_route', 'react:privesc', 'tokens', 60_000)
    with pytest.raises(PermissionError, match='token budget'):
        await start_job(context)


async def test_enqueue_checks_policy_before_reservation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    mock_scope(monkeypatch)
    context = replace(local_context(tmp_path), identity=Identity('viewer', 'system', roles=('viewer',)))
    with pytest.raises(PermissionError, match='permission'):
        await start_job(context)
    assert context.store.claim_task('worker') is None


async def test_worker_rechecks_profile_and_budget_before_gateway(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    mock_scope(monkeypatch)
    context = local_context(tmp_path)
    task = await start_job(context)
    envelope = parse_authority(task['payload']['job_authority'])
    child_context = replace(context, job_authority=envelope)
    monkeypatch.setattr(runtime, '_build_run_context', lambda *args: child_context)
    gateway_call = AsyncMock(return_value={})
    monkeypatch.setattr('nexus_core.kernel.tool_gateway.ToolGateway.invoke', gateway_call)
    profile = SUBAGENTS_BY_ID['privesc']
    monkeypatch.setitem(SUBAGENTS_BY_ID, 'privesc', replace(profile, tools=frozenset()))
    execution = runtime.ExecutionContext(context.store, task, 'worker')
    with pytest.raises(PermissionError, match='no longer permits'):
        await runtime.execute_tool(task['payload'], execution)
    monkeypatch.setitem(SUBAGENTS_BY_ID, 'privesc', profile)
    context.store.record_usage('system', context.run_id, 'model_route', 'react', 'tokens', 100_000)
    with pytest.raises(PermissionError, match='run token budget'):
        await runtime.execute_tool(task['payload'], execution)
    gateway_call.assert_not_awaited()


async def test_worker_keeps_gateway_and_single_use_allowance(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    mock_scope(monkeypatch)
    context = local_context(tmp_path)
    task = await start_job(context)
    envelope = parse_authority(task['payload']['job_authority'])
    child_context = replace(context, job_authority=envelope)
    monkeypatch.setattr(runtime, '_build_run_context', lambda *args: child_context)
    gateway_call = AsyncMock(return_value={'verified': True})
    monkeypatch.setattr('nexus_core.kernel.tool_gateway.ToolGateway.invoke', gateway_call)
    execution = runtime.ExecutionContext(context.store, task, 'worker')
    await runtime.execute_tool(task['payload'], execution)
    assert gateway_call.await_count == 1
    with pytest.raises(PermissionError, match='allowance'):
        await runtime.execute_tool(task['payload'], execution)
    assert gateway_call.await_count == 1
    assert gateway_call.call_args.args[2].job_authority == envelope


def test_allowance_cannot_be_reused_by_another_run(tmp_path: Path) -> None:
    context = local_context(tmp_path)
    assert context.job_authority is not None
    reserved = reserve_job(context.job_authority, context)
    other = context_for(context.store)
    with pytest.raises(PermissionError, match='allowance'):
        verify_job_reservation(reserved, other)


async def test_blocked_sink_never_blocks_loop_and_queue_drops_explicitly(monkeypatch: pytest.MonkeyPatch) -> None:
    dispatcher = turn_telemetry.TelemetryDispatcher(capacity=1)
    monkeypatch.setattr(turn_telemetry, '_DISPATCHER', dispatcher)
    entered, release = threading.Event(), threading.Event()

    class BlockedStore:
        def append_run_event(self, *args: Any) -> None:
            entered.set()
            release.wait(timeout=5)

    recorder = turn_telemetry.TurnTelemetryRecorder(store=BlockedStore(), tenant_id='t', run_id='r')
    try:
        recorder.begin_turn(iteration=1, phase='recon', subagent_id='recon')
        recorder.finish(outcome='ok')
        for _ in range(200):
            if entered.is_set():
                break
            await asyncio.sleep(0.005)
        assert entered.is_set()
        started = time.monotonic()
        for iteration in (2, 3):
            recorder.begin_turn(iteration=iteration, phase='recon', subagent_id='recon')
            recorder.finish(outcome='ok')
        assert time.monotonic() - started < 0.1
        assert recorder.dropped_events == 1
        assert not await recorder.flush(timeout=0.02)
        assert len(recorder.turns) == 3
    finally:
        release.set()
        assert await recorder.flush(timeout=2)


def test_telemetry_uses_turn_baseline_and_separates_estimates() -> None:
    recorder = turn_telemetry.TurnTelemetryRecorder(emit=False)
    recorder.begin_turn(iteration=1, phase='recon', subagent_id='recon', counts={'service': 9})
    recorder.note_reasoning(object(), estimated=100, duration_ms=1)
    recorder.note_blackboard(facts_total=10, counts={'service': 10})
    result = recorder.finish(outcome='next_turn')
    assert result is not None
    assert result.blackboard_delta == 1 and result.total_tokens == 0
    assert result.request_tokens_estimated == 100
    assert turn_telemetry.flag_for_error('CancelledError') is turn_telemetry.FrictionFlag.CANCELLED


def test_bad_numeric_telemetry_does_not_raise() -> None:
    recorder = turn_telemetry.TurnTelemetryRecorder(emit=False)
    malformed: Any = float('inf')
    recorder.begin_turn(iteration=1, phase='recon', subagent_id='recon', facts_total=malformed)
    recorder.note_reasoning(object(), estimated=malformed, duration_ms=malformed)
    recorder.note_blackboard(facts_total=malformed, counts={'service': malformed})
    record = recorder.finish(outcome='failure', turn_ms=malformed)
    assert record is not None and record.total_tokens == record.turn_ms == 0


def package_text() -> str:
    return (PACKAGE_DIR / 'red_team_base.yaml').read_text()


def test_catalog_validation_runs_without_explicit_validation_call() -> None:
    text = package_text().replace('nexus.recon.subfinder', 'nexus.recon.nonexistent')
    with pytest.raises(PlaybookSchemaError, match='unknown tool'):
        load_package_text(text)
    with pytest.raises(PlaybookSchemaError, match='cannot call'):
        load_package_text(package_text().replace('nexus.recon.subfinder', 'nexus.web.upload'))


def test_cache_cannot_hide_catalog_revocation(monkeypatch: pytest.MonkeyPatch) -> None:
    assert load_packages(strict=True)
    catalog = durable_tool_definitions()
    catalog.pop('nexus.recon.subfinder')
    monkeypatch.setattr('nexus_core.tools.registry.durable_tool_definitions', lambda: catalog)
    with pytest.raises(PlaybookSchemaError, match='unknown tool'):
        load_packages(strict=True)
    assert load_packages() == ()


def test_malformed_yaml_is_bounded_and_unambiguous() -> None:
    for text in (package_text() + '\ntitle: duplicate\n', 'x: [' * 40 + ']' * 40,
                 'x' * 262_145, 'x: &a [1]\ny: *a'):
        with pytest.raises(PlaybookSchemaError):
            load_package_text(text)
    raw = yaml.safe_load(package_text())
    raw['phases'][0]['gate'] = {'always': True, 'any_fact_types': ['access']}
    with pytest.raises(PlaybookSchemaError):
        load_package_text(yaml.safe_dump(raw))


def test_bad_package_does_not_remove_valid_siblings(tmp_path: Path) -> None:
    (tmp_path / 'valid.yaml').write_text(package_text())
    (tmp_path / 'invalid.yaml').write_text('not: a playbook')
    assert len(load_packages(tmp_path)) == 1


def test_steps_require_ordered_distinct_target_bound_execution() -> None:
    playbook = Playbook('test', 'test', 'recon', '', (
        PlaybookStep('one', 'one', 'tool', None), PlaybookStep('two', 'two', 'tool', 'service')))
    first = ExecutionProof('inv-1', 'tool', 'host-a', frozenset({'service'}))
    other = ExecutionProof('inv-2', 'tool', 'host-b', frozenset({'service'}))
    assert match_playbook(playbook, [{'fact_type': 'service'}]).completed == ()
    assert match_playbook(playbook, [], proofs=(first, first)).completed == ('one',)
    assert match_playbook(playbook, [], proofs=(first, other)).completed == ('one',)
    same = replace(other, target='host-a')
    assert match_playbook(playbook, [], proofs=(first, same)).completed == ('one', 'two')
    assert match_playbook(playbook, [], proofs=(first, same), target='host-c').completed == ()


def journal_result(context: RunContext, *, tool: str = 'nexus.session.list',
                   engagement: str = 'eng', success: bool = True) -> str:
    journal = InvocationJournal(context.store)
    entry = journal.prepare(context, tool, {'nonce': engagement}, 'host-a')
    journal.start(entry['invocation_id'], context.tenant_id)
    result = ToolResult(verified=success, verification_method='fixture').stamp_versions(tool, '1', '1').to_dict()
    result.update(run_id=context.run_id, invocation_id=entry['invocation_id'], engagement_id=engagement)
    journal.finish(entry['invocation_id'], context.tenant_id, result)
    return str(entry['invocation_id'])


def test_proofs_require_journal_success_integrity_run_and_engagement(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    context = local_context(tmp_path)
    monkeypatch.setattr('nexus_core.kernel.tool_gateway._journal_artifact_store', lambda store: None)
    invocation = journal_result(context)
    assert execution_proofs(context.store, 'system', context.run_id, 'eng')[0].invocation_id == invocation
    assert execution_proofs(context.store, 'system', context.run_id, 'another') == ()
    assert execution_proofs(context.store, 'system', 'other-run', 'eng') == ()
    assert execution_proofs(context.store, 'other-tenant', context.run_id, 'eng') == ()
    with context.store.connect() as conn:
        conn.execute('UPDATE kernel_invocations SET result_ref=? WHERE invocation_id=?', ('corrupt', invocation))
    assert execution_proofs(context.store, 'system', context.run_id, 'eng') == ()


def test_negative_journal_result_is_not_progress(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    context = local_context(tmp_path)
    monkeypatch.setattr('nexus_core.kernel.tool_gateway._journal_artifact_store', lambda store: None)
    journal_result(context, success=False)
    assert execution_proofs(context.store, 'system', context.run_id, 'eng') == ()
