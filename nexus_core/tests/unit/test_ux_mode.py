"""U-04: shared durable permission boundary, never a UI-only flag."""
import asyncio
from dataclasses import replace
import pytest
from nexus_core.kernel.control_store import ControlStore
from nexus_core.kernel.models import Identity, RunContext, ToolDefinition, ToolResult
from nexus_core.kernel.audit import AuditWriter
from nexus_core.kernel.policy import PolicyEngine
from nexus_core.kernel.tool_gateway import ToolGateway


def setup(tmp_path):
    from nexus_core.kernel.operator_mode import OperatorMode
    store = ControlStore(tmp_path/'db'); store.initialize()
    ctx = RunContext('system', Identity('agent','system',kind='agent',roles=('operator',)), run_id='r', session_id='s')
    return store, ctx, OperatorMode(store)


def test_plan_mode_blocks_active_and_audits(tmp_path):
    store, ctx, modes = setup(tmp_path)
    modes.plan(ctx, 'Review target; then execute')
    gateway = ToolGateway(PolicyEngine(store), AuditWriter(store))
    calls=[]
    gateway.register(ToolDefinition('probe','system',{},tool_id='probe',effect='active'), lambda args,ctx:calls.append(1))
    with pytest.raises(PermissionError,match='plan'):
        asyncio.run(gateway.invoke('probe',{},ctx))
    assert not calls
    assert any(e['action']=='mode.denied' for e in AuditWriter(store).export('system'))


def test_plan_mode_persists_and_isolates_sessions(tmp_path):
    store, ctx, modes = setup(tmp_path)
    modes.plan(ctx, 'Review')
    from nexus_core.kernel.operator_mode import OperatorMode
    assert OperatorMode(ControlStore(store.path)).get(ctx)['mode'] == 'plan'
    assert modes.get(replace(ctx,session_id='other'))['mode'] == 'interactive'


def test_model_cannot_approve_plan_or_replay_stale_hash(tmp_path):
    store,ctx,modes=setup(tmp_path)
    old = modes.plan(ctx,'first')['plan_hash']
    with pytest.raises(PermissionError):
        modes.approve(ctx,old,ctx.identity)
    modes.plan(ctx,'second')
    human=Identity('alice','system',kind='human',roles=('operator',))
    with pytest.raises(PermissionError):
        modes.approve(ctx,old,human)
    current=modes.get(ctx)
    modes.approve(ctx,current['plan_hash'],human)
    assert modes.get(ctx)['mode']=='exec'
    assert any(e['action']=='mode.plan_approved' for e in AuditWriter(store).export('system'))


def test_exec_still_requires_per_tool_approval(tmp_path):
    store,ctx,modes=setup(tmp_path)
    state=modes.plan(ctx,'Execute probe')
    modes.approve(ctx,state['plan_hash'],Identity('alice','system',kind='human',roles=('operator',)))
    gateway=ToolGateway(PolicyEngine(store),AuditWriter(store))
    gateway.register(ToolDefinition('probe','system',{},tool_id='probe',effect='active'),lambda a,c:ToolResult({},True,'probe',{}))
    from nexus_core.kernel.errors import ApprovalRequired
    with pytest.raises(ApprovalRequired):
        asyncio.run(gateway.invoke('probe',{},ctx))


def test_worker_context_uses_durable_session(tmp_path):
    store,ctx,modes=setup(tmp_path)
    modes.plan(ctx,'Read only')
    from nexus_core.kernel.runtime import _build_run_context
    from nexus_core.kernel.runtime import ExecutionContext
    task={'id':'task','tenant_id':'system','run_id':'worker-run','payload':{'session_id':'s'}}
    built=_build_run_context({},ExecutionContext(store,task,'worker'))
    assert modes.get(built)['mode']=='plan'


@pytest.mark.parametrize('route',['repl','headless','worker','mcp'])
def test_plan_mode_all_routes_reject_before_handler(tmp_path,monkeypatch,route):
    from nexus_core.cli.session import OmniSession
    from nexus_core.cli.commands import cmd_mode
    from nexus_core.cli import headless
    from nexus_core.kernel.runtime import ExecutionContext, execute_tool
    from nexus_core.kernel.operator_mode import OperatorMode
    import io
    store=ControlStore(tmp_path/'routes.db'); store.initialize()
    session=OmniSession(store=store,tenant_id='system',engagement=None,use_tui=False,
                        operator_id='alice',llm_client=object())
    cmd_mode(session,['plan','on'])
    ctx=session.build_run_context()
    calls=[]
    tool_id='mcp.test.exec' if route=='mcp' else 'probe'
    definition=ToolDefinition('probe','system',{},tool_id=tool_id,effect='active')
    monkeypatch.setattr('nexus_core.tools.registry.durable_tool_definitions',lambda tenant:{tool_id:(definition,lambda a,c:calls.append(1))})
    payload={'tool_id':tool_id,'arguments':{},'session_id':ctx.session_id,'identity':session.agent_identity_payload}
    if route=='repl':
        assert session.invoke_tool(tool_id,{}) is None
    elif route=='headless':
        async def loop(**kwargs):
            return await execute_tool(payload,kwargs['context'])
        monkeypatch.setattr(headless,'run_react_loop',loop)
        assert headless.run_headless(session,'offline',stream=io.StringIO()) == 4
    else:
        task={'id':'task','tenant_id':'system','run_id':'worker','payload':payload}
        with pytest.raises(PermissionError,match='plan'):
            asyncio.run(execute_tool(payload,ExecutionContext(store,task,'worker')))
    assert not calls
    assert OperatorMode(store).get(ctx)['mode']=='plan'
    assert any(e['action']=='mode.denied' for e in AuditWriter(store).export('system'))


def test_approved_exec_invocation_consumes_approval(tmp_path):
    from nexus_core.kernel.approvals import ApprovalService
    store,ctx,modes=setup(tmp_path)
    state=modes.plan(ctx,'Execute probe')
    modes.approve(ctx,state['plan_hash'],Identity('alice','system',kind='human',roles=('operator',)))
    service=ApprovalService(store)
    approval=service.request(ctx,'execute:tool:probe')
    service.decide(approval['id'],'system','alice',True)
    gateway=ToolGateway(PolicyEngine(store),AuditWriter(store),service)
    gateway.register(ToolDefinition('probe','system',{},tool_id='probe',effect='active'),
                     lambda a,c:ToolResult({},True,'probe'))
    assert asyncio.run(gateway.invoke('probe',{},ctx,approval_id=approval['id']))['verified']
    with pytest.raises(PermissionError):
        asyncio.run(gateway.invoke('probe',{},ctx,approval_id=approval['id']))


def test_worker_react_inherits_existing_work_mode_without_explicit_session(tmp_path,monkeypatch):
    from nexus_core.cli.session import OmniSession
    from nexus_core.cli.commands import cmd_mode
    from nexus_core.kernel import runtime
    from nexus_core.kernel.operator_mode import OperatorMode
    store=ControlStore(tmp_path/'worker.db');store.initialize()
    session=OmniSession(store=store,tenant_id='system',engagement=None,use_tui=False)
    cmd_mode(session,['plan','on'])
    async def loop(**kwargs):
        context=kwargs['context']
        # The runtime must bind both the loop conversation and the tool boundary.
        built=runtime._build_run_context({},context)
        assert kwargs.get('conversation_id') == session._ensure_work_session()
        assert OperatorMode(store).get(built)['mode']=='plan'
        raise PermissionError('plan read_only')
    monkeypatch.setattr('nexus_core.agent.react.run_react_loop',loop)
    monkeypatch.setattr(runtime,'select_llm_client',lambda:object())
    payload={'objective':'offline'}
    task={'id':'worker','tenant_id':'system','run_id':'r','payload':payload}
    with pytest.raises(PermissionError,match='plan'):
        asyncio.run(runtime.execute_react(payload,runtime.ExecutionContext(store,task,'worker')))


def test_mode_command_requires_reviewed_hash_and_never_trust_autoapproves(tmp_path):
    from nexus_core.cli.session import OmniSession
    from nexus_core.cli.commands import cmd_mode
    from nexus_core.kernel.operator_mode import OperatorMode
    store=ControlStore(tmp_path/'command.db');store.initialize()
    session=OmniSession(store=store,tenant_id='system',engagement=None,use_tui=False,
                        trust_mode=True,operator_id='alice',input_reader=lambda prompt:'yes')
    cmd_mode(session,['plan','on'])
    ctx=session.build_run_context();modes=OperatorMode(store)
    cmd_mode(session,['plan','off'])
    assert modes.get(ctx)['mode']=='plan'
    session.input_reader=lambda prompt:'aprobar '+modes.get(ctx)['plan_hash']
    cmd_mode(session,['plan','off'])
    assert modes.get(ctx)['mode']=='exec'
