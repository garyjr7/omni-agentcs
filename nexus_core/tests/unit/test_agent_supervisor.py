"""Supervisor isolation uses the real ReAct engine and durable store."""
import asyncio
import json
from types import SimpleNamespace

import pytest
from nexus_core.kernel.runtime import ExecutionContext
from nexus_core.tests.unit.test_hooks_lifecycle import context


class Client:
    def __init__(self): self.requests=[]
    async def complete(self,messages,**kwargs):
        self.requests.append(messages)
        await asyncio.sleep(0)  # Allow other child runs to enter while a request is in flight.
        return SimpleNamespace(content=json.dumps({'thought':'done','action':'task_complete','summary':'CHILD_PRIVATE_TRANSCRIPT','findings':[]}),tokens_input=3,tokens_output=2,provider='fake',model='fake')


def setup(tmp_path,monkeypatch,global_budget=100,**kwargs):
    from nexus_core.agent.supervisor import AgentSupervisor
    ctx=context(tmp_path,monkeypatch)
    parent=ctx.store.create_run('system',{})
    conversation=ctx.store.create_conversation('system','parent','parent')
    ctx.store.append_message('system',conversation['id'],'user','PARENT_SECRET_TRANSCRIPT',run_id=parent['id'])
    task={'tenant_id':'system','run_id':parent['id'],'payload':{'session_id':conversation['id']}}
    execution=ExecutionContext(ctx.store,task,'test')
    client=Client()
    return AgentSupervisor(execution,client,engagement_id=None,global_budget=global_budget,**kwargs),execution,client


def test_child_gets_isolated_conversation(tmp_path,monkeypatch):
    supervisor,parent,_=setup(tmp_path,monkeypatch)
    child=asyncio.run(supervisor.spawn('recon','offline',{'tokens':20,'iterations':1}))
    assert child.conversation_id!=parent.task['payload']['session_id']
    assert child.run_id!=parent.run_id


def test_parent_receives_summary_not_transcript(tmp_path,monkeypatch):
    supervisor,parent,_=setup(tmp_path,monkeypatch)
    child=asyncio.run(supervisor.spawn('recon','offline',{'tokens':20,'iterations':1}))
    assert set(child.summary)=={'findings','facts_added','phase_reached','blockers','next_steps_suggested'}
    assert 'CHILD_PRIVATE_TRANSCRIPT' not in json.dumps(child.summary)
    assert all('CHILD_PRIVATE_TRANSCRIPT' not in m['content'] for m in parent.store.list_messages('system',parent.task['payload']['session_id']))


def test_child_does_not_inherit_parent_history(tmp_path,monkeypatch):
    supervisor,_,client=setup(tmp_path,monkeypatch)
    asyncio.run(supervisor.spawn('recon','offline',{'tokens':20,'iterations':1}))
    assert 'PARENT_SECRET_TRANSCRIPT' not in str(client.requests)


def test_child_budget_is_enforced_separately(tmp_path,monkeypatch):
    # The tree budget must cover the pre-flight reservation (P2-C1), so the
    # thousands-of-token estimate of a real prompt fits; the child's own
    # ``tokens`` still caps its actual use.
    supervisor,parent,_=setup(tmp_path,monkeypatch,global_budget=1_000_000)
    child=asyncio.run(supervisor.spawn('recon','offline',{'tokens':20,'iterations':1}))
    assert child.tokens_used==5
    assert parent.store.usage_total('system',parent.run_id,'model_route','react','tokens')==0
    assert supervisor.tokens_used==5


def test_supervisor_audit_records_parent_child_lineage(tmp_path,monkeypatch):
    from nexus_core.kernel.audit import AuditWriter
    supervisor,parent,_=setup(tmp_path,monkeypatch,global_budget=1_000_000)
    child=asyncio.run(supervisor.spawn('recon','offline',{'tokens':20,'iterations':1}))
    events=AuditWriter(parent.store).export('system')
    started=next(e for e in events if e['action']=='subagent.started')
    ended=next(e for e in events if e['action']=='subagent.ended')
    assert started['payload']['parent_run_id']==parent.run_id
    assert ended['payload']['run_id']==child.run_id
    assert ended['payload']['tokens_used']==5
    assert ended['payload']['terminated_at']


def test_concurrency_and_depth_limits(tmp_path,monkeypatch):
    # A large tree budget keeps the pre-flight reservation from short-circuiting
    # the children, so the test exercises the real concurrency/depth limits.
    supervisor,_,_=setup(tmp_path,monkeypatch,global_budget=1_000_000,depth=2)
    with pytest.raises(ValueError,match='depth'):
        asyncio.run(supervisor.spawn('recon','offline',{'tokens':20,'iterations':1}))
    supervisor.depth=0
    async def run():
        children=await asyncio.gather(*(supervisor.spawn('recon',str(i),{'tokens':20,'iterations':1}) for i in range(5)),return_exceptions=True)
        assert sum(isinstance(c,Exception) for c in children)>=1
        assert supervisor.peak_concurrency<=4
    asyncio.run(run())


def test_global_budget_cannot_be_oversubscribed(tmp_path,monkeypatch):
    supervisor,_,_=setup(tmp_path,monkeypatch)
    with pytest.raises(ValueError,match='global'):
        asyncio.run(supervisor.spawn('recon','offline',{'tokens':101,'iterations':1}))


def test_child_preserves_operator_session_and_pinned_profile(tmp_path,monkeypatch):
    supervisor,parent,_=setup(tmp_path,monkeypatch)
    child=asyncio.run(supervisor.spawn('web','offline',{'tokens':20,'iterations':1}))
    assert child.operator_session_id==parent.task['payload']['session_id']
    assert child.subagent_id=='web'


def test_child_runs_real_process_tool_without_parent_transcript(tmp_path,monkeypatch):
    from nexus_core.kernel.models import ToolDefinition,ToolResult
    from nexus_core.kernel.sandbox_modes import SandboxPolicy
    supervisor,_,_=setup(tmp_path,monkeypatch,global_budget=1_000_000)
    class ProcessClient(Client):
        async def complete(self,messages,**kwargs):
            if not self.requests:
                self.requests.append(messages)
                return SimpleNamespace(content=json.dumps({'thought':'read','action':'tool_call',
                    'tool_id':'nexus.system.status','arguments':{}}),tokens_input=3,tokens_output=2,provider='fake',model='fake')
            return await super().complete(messages,**kwargs)
    async def handler(a,c):
        sandbox=SandboxPolicy.resolve(workspace_root=tmp_path,allowed_programs=('python3',))[1]
        result=await sandbox.run(['python3','-c','print("local child process")'])
        return ToolResult({'stdout':result.stdout},True,'local_process')
    catalog={'nexus.system.status':(ToolDefinition('status','system',{},tool_id='nexus.system.status'),handler)}
    monkeypatch.setattr('nexus_core.tools.registry.durable_tool_definitions',lambda tenant:catalog)
    supervisor.client=ProcessClient();supervisor.tool_catalog=catalog
    child=asyncio.run(supervisor.spawn('recon','offline',{'tokens':40,'iterations':2}))
    history=supervisor.context.store.list_messages('system',child.conversation_id)
    assert any('local child process' in m['content'] for m in history)
    assert 'PARENT_SECRET_TRANSCRIPT' not in str(supervisor.client.requests)


def test_unknown_profile_rejected_before_creation(tmp_path,monkeypatch):
    supervisor,parent,_=setup(tmp_path,monkeypatch)
    with pytest.raises(ValueError):
        asyncio.run(supervisor.spawn('made-up','offline',{'tokens':20,'iterations':1}))
    assert len(parent.store.list_conversations('system','parent'))==1
