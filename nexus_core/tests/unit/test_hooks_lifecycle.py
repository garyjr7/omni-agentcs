"""Lifecycle hooks exercise real sandbox subprocesses, never shell commands."""
import asyncio
import json
import sys

import pytest

from nexus_core.kernel.audit import AuditWriter
from nexus_core.kernel.control_store import ControlStore
from nexus_core.kernel.models import Identity, RunContext, ToolDefinition, ToolResult
from nexus_core.kernel.policy import PolicyEngine
from nexus_core.kernel.tool_gateway import ToolGateway


def context(tmp_path, monkeypatch):
    monkeypatch.setenv('XDG_CONFIG_HOME', str(tmp_path/'config'))
    monkeypatch.setenv('NEXUS_SANDBOX_MODE', 'local_strict')
    store = ControlStore(tmp_path/'db'); store.initialize()
    return RunContext('system', Identity('agent','system',kind='agent',roles=('operator',)),
                      run_id='r', session_id='s', store=store)


def configure(tmp_path, *, event='pre_tool_use', code='print("{}")', timeout=1):
    script = tmp_path/'hook.py'; script.write_text(code)
    path = tmp_path/'config'/'omni'/'hooks.json'
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({'hooks':{event:[{'name':'probe','command':[sys.executable,str(script)],'timeout':timeout}]}}))
    return path


def invoke(ctx):
    gateway=ToolGateway(PolicyEngine(ctx.store),AuditWriter(ctx.store))
    gateway.register(ToolDefinition('probe','system',{},tool_id='probe'),
                     lambda a,c:ToolResult({'ran':True},True,'local_probe'))
    return asyncio.run(gateway.invoke('probe',{},ctx))


def test_hook_pre_tool_use_blocks_tool(tmp_path,monkeypatch):
    ctx=context(tmp_path,monkeypatch)
    configure(tmp_path,code='print(\'{"decision":"block","reason":"checklist"}\')')
    with pytest.raises(PermissionError,match='checklist'):
        invoke(ctx)
    assert any(e['action']=='hook.blocked' for e in AuditWriter(ctx.store).export('system'))


def test_hook_failure_does_not_break_run(tmp_path,monkeypatch):
    ctx=context(tmp_path,monkeypatch); configure(tmp_path,code='raise SystemExit(7)')
    assert invoke(ctx)['verified']
    assert any(e['action']=='hook.failed' for e in AuditWriter(ctx.store).export('system'))


def test_hook_timeout_is_fail_safe(tmp_path,monkeypatch):
    ctx=context(tmp_path,monkeypatch);configure(tmp_path,code='import time; time.sleep(10)',timeout=.05)
    assert invoke(ctx)['verified']
    assert any(e['action']=='hook.failed' and e['payload']['error']=='timeout'
               for e in AuditWriter(ctx.store).export('system'))


def test_hooks_are_scoped_per_engagement(tmp_path,monkeypatch):
    from nexus_core.hooks import HookRunner, approve_project_hooks
    ctx=context(tmp_path,monkeypatch)
    first=tmp_path/'first';second=tmp_path/'second'
    for root in (first,second): root.mkdir()
    p=first/'.agents'/'hooks.json';p.parent.mkdir()
    p.write_text(json.dumps({'hooks':{'pre_tool_use':[{'name':'a','command':[sys.executable,'-c','print(\'{"decision":"block","reason":"only first"}\')']}]}}))
    approve_project_hooks(first,Identity('alice','system',kind='human',roles=('operator',)))
    assert asyncio.run(HookRunner(ctx,project_root=first).emit('pre_tool_use'))==['only first']
    assert asyncio.run(HookRunner(ctx,project_root=second).emit('pre_tool_use'))==[]


def test_no_hooks_config_is_noop(tmp_path,monkeypatch):
    from nexus_core.hooks import HookRunner
    ctx=context(tmp_path,monkeypatch)
    monkeypatch.setattr(asyncio,'create_subprocess_exec',lambda *a,**k:pytest.fail('must not spawn'))
    assert asyncio.run(HookRunner(ctx).emit('pre_tool_use'))==[]


def test_hook_receives_json_and_no_secret_environment(tmp_path,monkeypatch):
    from nexus_core.hooks import HookRunner
    ctx=context(tmp_path,monkeypatch)
    output=tmp_path/'received.json'
    configure(tmp_path,code=f'import json,sys,os; from pathlib import Path; data=json.load(sys.stdin); data["env_secret"]=os.getenv("NEXUS_SCOPE_HMAC_KEY"); Path({str(output)!r}).write_text(json.dumps(data))')
    monkeypatch.setenv('NEXUS_SCOPE_HMAC_KEY','do-not-leak')
    asyncio.run(HookRunner(ctx).emit('pre_tool_use',tool_id='probe',arguments={'password':'secret'}))
    data=json.loads(output.read_text())
    assert data['event']=='pre_tool_use' and data['session_id']=='s' and data['run_id']=='r'
    assert data['arguments']['password']!='secret' and data['env_secret'] is None


def test_hook_output_limit_is_fail_safe(tmp_path,monkeypatch):
    ctx=context(tmp_path,monkeypatch);configure(tmp_path,code='print("x"*100000)')
    assert invoke(ctx)['verified']
    assert any(e['action']=='hook.failed' for e in AuditWriter(ctx.store).export('system'))


def test_plan_denial_precedes_hook_execution(tmp_path,monkeypatch):
    from nexus_core.kernel.operator_mode import OperatorMode
    ctx=context(tmp_path,monkeypatch)
    marker=tmp_path/'ran'
    configure(tmp_path,code=f'from pathlib import Path; Path({str(marker)!r}).touch()')
    OperatorMode(ctx.store).plan(ctx,'read only')
    gateway=ToolGateway(PolicyEngine(ctx.store),AuditWriter(ctx.store))
    gateway.register(ToolDefinition('probe','system',{},tool_id='probe',effect='exploit'),lambda a,c:ToolResult({},True))
    with pytest.raises(PermissionError,match='plan'):
        asyncio.run(gateway.invoke('probe',{},ctx))
    assert not marker.exists()


def test_changed_project_config_loses_trust(tmp_path,monkeypatch):
    from nexus_core.hooks import HookRunner,approve_project_hooks
    ctx=context(tmp_path,monkeypatch)
    p=tmp_path/'.agents'/'hooks.json';p.parent.mkdir();p.write_text('{}')
    approve_project_hooks(tmp_path,Identity('alice','system',kind='human',roles=('operator',)))
    p.write_text('{"hooks":{}}')
    runner=HookRunner(ctx,project_root=tmp_path)
    assert not runner.project_trusted


def test_agent_cannot_approve_repository_hooks(tmp_path,monkeypatch):
    from nexus_core.hooks import approve_project_hooks
    ctx=context(tmp_path,monkeypatch)
    with pytest.raises(PermissionError):
        approve_project_hooks(tmp_path,ctx.identity)
