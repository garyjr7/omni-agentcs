"""Durable invocation state is not a claim of remote exactly-once."""
import asyncio
from dataclasses import replace
import os
import subprocess
import sys

import pytest
from nexus_core.tests.unit.test_hooks_lifecycle import context
from nexus_core.kernel.audit import AuditWriter
from nexus_core.kernel.models import ToolDefinition,ToolResult
from nexus_core.kernel.policy import PolicyEngine
from nexus_core.kernel.tool_gateway import ToolGateway


def gateway(ctx,handler,*,idempotent=False):
    gw=ToolGateway(PolicyEngine(ctx.store),AuditWriter(ctx.store))
    gw.register(ToolDefinition('probe','system',{},tool_id='probe',idempotent=idempotent),handler)
    return gw


def test_invocation_prepared_before_execution(tmp_path,monkeypatch):
    from nexus_core.kernel.invocation_journal import InvocationJournal
    ctx=context(tmp_path,monkeypatch)
    def handler(a,c):
        row=InvocationJournal(ctx.store).get(c.invocation_id,'system')
        assert row['state']=='running' and row['started_at']
        return ToolResult({},True,'probe')
    assert asyncio.run(gateway(ctx,handler).invoke('probe',{},ctx))['verified']


def test_invocation_state_transitions(tmp_path,monkeypatch):
    from nexus_core.kernel.invocation_journal import InvocationJournal
    ctx=context(tmp_path,monkeypatch);journal=InvocationJournal(ctx.store)
    item=journal.prepare(ctx,'probe',{},'')
    assert item['state']=='prepared'
    journal.start(item['invocation_id'],'system')
    assert journal.get(item['invocation_id'],'system')['state']=='running'
    journal.finish(item['invocation_id'],'system',{'verified':True})
    assert journal.get(item['invocation_id'],'system')['state']=='succeeded'


def test_resume_marks_running_as_unknown(tmp_path,monkeypatch):
    from nexus_core.kernel.invocation_journal import InvocationJournal
    ctx=context(tmp_path,monkeypatch);journal=InvocationJournal(ctx.store)
    item=journal.prepare(ctx,'probe',{},'');journal.start(item['invocation_id'],'system')
    # P2-D2: recovery is fenced by the worker lease; a new owner reconciles
    # only unowned (lease NULL) or its own running invocations.
    assert journal.recover(ctx,lease_id='test-worker')==1
    assert journal.get(item['invocation_id'],'system')['state']=='unknown'


def uncertain(ctx):
    from nexus_core.kernel.invocation_journal import InvocationJournal
    journal=InvocationJournal(ctx.store)
    item=journal.prepare(ctx,'probe',{},'');journal.start(item['invocation_id'],'system');journal.recover(ctx,lease_id='test-worker')
    return item


def test_unknown_invocation_requires_approval(tmp_path,monkeypatch):
    ctx=context(tmp_path,monkeypatch);uncertain(ctx);calls=[]
    with pytest.raises(PermissionError,match='unknown'):
        asyncio.run(gateway(ctx,lambda a,c:calls.append(1)).invoke('probe',{},ctx))
    assert not calls


def test_idempotent_tool_replays_automatically(tmp_path,monkeypatch):
    ctx=context(tmp_path,monkeypatch);uncertain(ctx)
    gw=gateway(ctx,lambda a,c:ToolResult({},True,'probe'),idempotent=True)
    assert asyncio.run(gw.invoke('probe',{},ctx))['verified']


def test_non_idempotent_tool_blocks_replay(tmp_path,monkeypatch):
    ctx=context(tmp_path,monkeypatch);uncertain(ctx)
    with pytest.raises(PermissionError):
        asyncio.run(gateway(ctx,lambda a,c:ToolResult({},True,'probe')).invoke('probe',{},ctx))


def test_crash_during_exploit_does_not_replay(tmp_path,monkeypatch):
    from nexus_core.kernel.invocation_journal import InvocationJournal
    ctx=context(tmp_path,monkeypatch);marker=tmp_path/'effect'
    code='''import os
from pathlib import Path
from nexus_core.kernel.control_store import ControlStore
from nexus_core.kernel.invocation_journal import InvocationJournal
from nexus_core.kernel.models import RunContext,Identity
store=ControlStore(os.environ['TEST_DB'])
ctx=RunContext('system',Identity('agent','system'),run_id='r')
j=InvocationJournal(store)
i=j.prepare(ctx,'probe',{},'');j.start(i['invocation_id'],'system')
Path(os.environ['TEST_EFFECT']).write_text('one effect')
os._exit(42)
'''
    env={**os.environ,'TEST_DB':str(ctx.store.path),'TEST_EFFECT':str(marker)}
    child=subprocess.run([sys.executable,'-c',code],env=env,capture_output=True,timeout=10)
    assert child.returncode==42,child.stderr.decode()
    assert marker.read_text()=='one effect'
    assert InvocationJournal(ctx.store).recover(ctx,lease_id='test-worker')==1
    with pytest.raises(PermissionError):
        asyncio.run(gateway(ctx,lambda a,c:marker.write_text('replayed')).invoke('probe',{},ctx))
    assert marker.read_text()=='one effect'


def test_handler_error_is_unknown_not_safe_to_replay(tmp_path,monkeypatch):
    from nexus_core.kernel.invocation_journal import InvocationJournal
    ctx=context(tmp_path,monkeypatch)
    def handler(a,c): raise RuntimeError('after possible effect')
    with pytest.raises(RuntimeError): asyncio.run(gateway(ctx,handler).invoke('probe',{},ctx))
    assert InvocationJournal(ctx.store).matching(ctx,'probe',{})['state']=='unknown'


def test_journal_tenant_and_run_isolation(tmp_path,monkeypatch):
    from nexus_core.kernel.invocation_journal import InvocationJournal
    ctx=context(tmp_path,monkeypatch);item=uncertain(ctx)
    journal=InvocationJournal(ctx.store)
    assert journal.get(item['invocation_id'],'other') is None
    assert journal.matching(replace(ctx,run_id='other'),'probe',{}) is None


def test_unknown_retry_human_approval_is_consumed(tmp_path,monkeypatch):
    from nexus_core.kernel.approvals import ApprovalService
    ctx=context(tmp_path,monkeypatch);old=uncertain(ctx)
    approvals=ApprovalService(ctx.store)
    request=approvals.request(ctx,'retry:invocation:'+old['invocation_id'])
    approvals.decide(request['id'],'system','alice',True)
    gw=gateway(ctx,lambda a,c:ToolResult({},True,'probe'))
    gw.approvals=approvals
    assert asyncio.run(gw.invoke('probe',{},ctx,approval_id=request['id']))['verified']
    assert not approvals.consume(request['id'],ctx,'retry:invocation:'+old['invocation_id'])


def test_readonly_definitions_declare_idempotency():
    from nexus_core.tools.handlers.nmap import nmap_definition
    from nexus_core.tools.handlers.httpx import httpx_definition
    from nexus_core.tools.handlers.ssh_post import ssh_exec_definition
    assert nmap_definition().idempotent and httpx_definition().idempotent
    assert not ssh_exec_definition().idempotent


def test_successful_effect_is_not_repeated_for_same_run_and_arguments(tmp_path,monkeypatch):
    ctx=context(tmp_path,monkeypatch);calls=[]
    def handler(a,c):
        calls.append(1)
        return ToolResult({'effect_count':len(calls)},True,'probe')
    gw=gateway(ctx,handler)
    first=asyncio.run(gw.invoke('probe',{},ctx))
    second=asyncio.run(gw.invoke('probe',{},ctx))
    assert first['invocation_id']==second['invocation_id']
    assert len(calls)==1


def test_worker_resume_recovers_only_under_owned_lease(tmp_path,monkeypatch):
    from nexus_core.kernel.runtime import ExecutionContext,ExecutorRegistry
    from nexus_core.kernel.invocation_journal import InvocationJournal
    ctx=context(tmp_path,monkeypatch)
    run=ctx.store.create_run('system',{})
    ctx.store.enqueue_task(tenant_id='system',run_id=run['id'],task_type='probe',payload={})
    task=ctx.store.claim_task('worker')
    recovered=replace(ctx,run_id=run['id'])
    journal=InvocationJournal(ctx.store)
    item=journal.prepare(recovered,'probe',{},'')
    journal.start(item['invocation_id'],'system')
    task={**task,'attempts':2}
    registry=ExecutorRegistry()
    async def handler(payload,execution):
        assert InvocationJournal(ctx.store).get(item['invocation_id'],'system')['state']=='unknown'
        return {}
    registry.register('probe',handler)
    asyncio.run(registry.execute(task,ExecutionContext(ctx.store,task,'worker')))
    with pytest.raises(PermissionError,match='lease'):
        asyncio.run(registry.execute(task,ExecutionContext(ctx.store,task,'impostor')))


def test_running_invocation_is_not_concurrently_replayed(tmp_path,monkeypatch):
    from nexus_core.kernel.invocation_journal import InvocationJournal
    ctx=context(tmp_path,monkeypatch);j=InvocationJournal(ctx.store)
    i=j.prepare(ctx,'probe',{},'');j.start(i['invocation_id'],'system')
    with pytest.raises(PermissionError,match='running'):
        asyncio.run(gateway(ctx,lambda a,c:ToolResult({},True),idempotent=True).invoke('probe',{},ctx))
