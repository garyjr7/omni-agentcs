"""Stop verifiers are trusted processes that can narrow, never widen, closure."""
import asyncio
import json
import sys

from nexus_core.tests.unit.test_hooks_lifecycle import context


def configure(tmp_path,code,**options):
    script=tmp_path/'verify.py';script.write_text(code)
    path=tmp_path/'config'/'omni'/'hooks.json';path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps({'verifiers':[{'name':'checklist','command':[sys.executable,str(script)],**options}]}))


def verify(ctx,**payload):
    from nexus_core.hooks import HookRunner
    return asyncio.run(HookRunner(ctx).verify_stop(**payload))


def test_verifier_blocks_task_complete(tmp_path,monkeypatch):
    ctx=context(tmp_path,monkeypatch)
    configure(tmp_path,'print(\'{"decision":"block","reason":"missing proof"}\')')
    assert verify(ctx,objective='offline')==['missing proof']


def test_verifier_timeout_is_fail_closed(tmp_path,monkeypatch):
    ctx=context(tmp_path,monkeypatch)
    configure(tmp_path,'import time;time.sleep(10)',timeout=.05)
    assert 'timeout' in verify(ctx)[0]
    from nexus_core.kernel.audit import AuditWriter
    assert any(e['action']=='verifier.timeout' for e in AuditWriter(ctx.store).export('system'))


def test_verifier_error_does_not_break_run(tmp_path,monkeypatch):
    ctx=context(tmp_path,monkeypatch)
    configure(tmp_path,'raise SystemExit(4)',fail_closed=False)
    assert verify(ctx)==[]


def test_verifier_error_fail_closed_blocks(tmp_path,monkeypatch):
    ctx=context(tmp_path,monkeypatch)
    configure(tmp_path,'raise SystemExit(4)',fail_closed=True)
    assert 'exit 4' in verify(ctx)[0]


def test_verifier_receives_findings_and_facts(tmp_path,monkeypatch):
    ctx=context(tmp_path,monkeypatch);out=tmp_path/'input.json'
    configure(tmp_path,f'import sys;from pathlib import Path;Path({str(out)!r}).write_text(sys.stdin.read())')
    payload={'findings':[{'type':'host'}],'facts_verified':[{'key':'host','verified':True}],
             'phase':'recon','objective':'offline'}
    assert verify(ctx,**payload)==[]
    assert json.loads(out.read_text())==payload


def test_verifier_only_loaded_from_trusted_path(tmp_path,monkeypatch):
    from nexus_core.hooks import HookRunner
    ctx=context(tmp_path,monkeypatch);p=tmp_path/'.agents'/'hooks.json';p.parent.mkdir()
    p.write_text(json.dumps({'verifiers':[{'command':[sys.executable,'-c','raise SystemExit(1)']}]}))
    assert asyncio.run(HookRunner(ctx,project_root=tmp_path).verify_stop())==[]


def test_verifier_invalid_output_fails_closed(tmp_path,monkeypatch):
    ctx=context(tmp_path,monkeypatch);configure(tmp_path,'print("not JSON")')
    assert verify(ctx)


def test_verifier_passed_is_audited(tmp_path,monkeypatch):
    from nexus_core.kernel.audit import AuditWriter
    ctx=context(tmp_path,monkeypatch);configure(tmp_path,'print("{}")')
    assert verify(ctx)==[]
    actions={e['action'] for e in AuditWriter(ctx.store).export('system')}
    assert {'verifier.executed','verifier.passed'}<=actions


def test_verifier_integrates_react_objection_history(tmp_path,monkeypatch):
    from nexus_core.agent.react import run_react_loop,ReActConfig
    from nexus_core.kernel.runtime import ExecutionContext
    from types import SimpleNamespace
    ctx=context(tmp_path,monkeypatch)
    configure(tmp_path,'print(\'{"decision":"block","reason":"missing proof"}\')')
    class Client:
        async def complete(self,*args,**kwargs):
            return SimpleNamespace(content=json.dumps({'thought':'done','action':'task_complete','summary':'done','findings':[]}),tokens_input=1,tokens_output=1,provider='fake',model='fake')
    run=ctx.store.create_run('system',{})
    task={'tenant_id':'system','run_id':run['id'],'payload':{}}
    result=asyncio.run(run_react_loop(context=ExecutionContext(ctx.store,task,'test'),
        objective='offline',engagement_id=None,llm_client=Client(),tool_catalog={},
        config=ReActConfig(max_iterations=2,enforce_completion_gates=False,enable_summarization=False)))
    assert result.status!='completed'
    assert 'missing proof' in ';'.join(result.completion_objections)
    assert any('missing proof' in str(m['content']) for m in ctx.store.list_messages('system',result.conversation_id))
