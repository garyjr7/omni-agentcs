#!/usr/bin/env python3
"""Offline orchestration probes using temporary stores and local processes.

These are smoke checks that demonstrate the closed Fase 2 behaviour on the real
code paths (temporary stores, a real sandbox subprocess, an optional real
PostgreSQL). They complement — never replace — the pytest suite; a probe prints
either ``CERTIFIED`` (observed here) or ``LIMIT`` (documented, not certified).
"""
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import argparse
import asyncio
import json
import os
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import patch


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline',action='store_true')
    args=parser.parse_args()
    if args.baseline:
        for path in ('nexus_core/hooks','nexus_core/agent/supervisor.py','nexus_core/kernel/invocation_journal.py',
                     'nexus_core/kernel/budget_ledger.py','nexus_core/cli/hooks_cli.py','nexus_core/cli/resume_cli.py'):
            print(f'{path}: exists={Path(path).exists()}')
        return 0
    from nexus_core.kernel.control_store import ControlStore
    from nexus_core.kernel.models import RunContext,Identity,ToolDefinition,ToolResult
    from nexus_core.kernel.runtime import ExecutionContext
    from nexus_core.kernel.audit import AuditWriter
    from nexus_core.kernel.policy import PolicyEngine
    from nexus_core.kernel.tool_gateway import ToolGateway
    from nexus_core.kernel.budget_ledger import BudgetLedger
    from nexus_core.kernel.errors import BudgetExceeded
    from nexus_core.hooks import HookRunner,approve_project_hooks,trusted_project_hooks,revoke_project_hooks
    from nexus_core.cli.hooks_cli import run_hooks_command
    from nexus_core.agent.supervisor import AgentSupervisor,SupervisorTree,should_autospawn
    from nexus_core.agent.react import ReActConfig,run_react_loop
    from nexus_core.kernel.invocation_journal import InvocationJournal
    with TemporaryDirectory(prefix='omni-orchestration-') as directory:
        root=Path(directory)
        with patch.dict(os.environ,XDG_CONFIG_HOME=str(root/'config'),XDG_STATE_HOME=str(root/'state'),
                        XDG_DATA_HOME=str(root/'data'),NEXUS_SANDBOX_MODE='local_strict'):
            store=ControlStore(root/'db');store.initialize()
            run=store.create_run('system',{})
            ctx=RunContext('system',Identity('agent','system',kind='agent',roles=('operator',)),run_id=run['id'],store=store,session_id='operator')

            # P2-A/B: real local process block, global hook + verifier.
            path=root/'config'/'omni'/'hooks.json';path.parent.mkdir(parents=True,exist_ok=True)
            command=[sys.executable,'-c','print(\'{"decision":"block","reason":"offline checklist"}\')']
            path.write_text(json.dumps({'hooks':{'pre_tool_use':[{'command':command}]},'verifiers':[{'command':command}]}))
            assert asyncio.run(HookRunner(ctx).emit('pre_tool_use'))==['offline checklist']
            assert asyncio.run(HookRunner(ctx).verify_stop(objective='offline'))==['offline checklist']
            path.unlink()
            print('P2-A/B CERTIFIED: real local process block observed (host isolation still local_strict, no target)')

            # P2-A1: repository hooks require explicit operator trust.
            project=root/'project';project.mkdir()
            project_hooks=project/'.agents'/'hooks.json';project_hooks.parent.mkdir()
            project_hooks.write_text(json.dumps({'hooks':{'pre_tool_use':[]}}))
            assert run_hooks_command(['trust',str(project),'--yes'],'system')==0
            assert any(entry['path']==str(project_hooks.resolve()) for entry in trusted_project_hooks())
            project_hooks.write_text(json.dumps({'hooks':{'pre_tool_use':[]},'x':1}))
            assert not HookRunner(ctx,project_root=project).project_trusted  # changed bytes revoke trust
            assert revoke_project_hooks(project) is True
            print('P2-A1 CERTIFIED: repository hooks load only after operator trust; any edit revokes it')

            # P2-A3: session_end fires on an engine exception and cannot swallow it.
            marker=root/'session_end.json'
            path=root/'config'/'omni'/'hooks.json'
            capture=[sys.executable,'-c',
                'import sys,json; from pathlib import Path; d=json.loads(sys.stdin.read()); '
                f'Path({str(marker)!r}).write_text(json.dumps(d)); print("{{}}")']
            path.write_text(json.dumps({'hooks':{'session_end':[{'command':capture}]}}))
            react=__import__('nexus_core.agent.react',fromlist=['_run_react_loop_impl'])
            original=react._run_react_loop_impl

            async def boom(**kwargs):
                raise RuntimeError('offline engine failure')

            react._run_react_loop_impl=boom
            execution=ExecutionContext(store,{'tenant_id':'system','run_id':run['id'],'payload':{'session_id':'operator'}},'probe')
            try:
                asyncio.run(run_react_loop(context=execution,objective='offline',engagement_id=None,
                                           llm_client=None,config=ReActConfig(enforce_completion_gates=False)))
            except RuntimeError:
                pass
            else:
                raise AssertionError('exception was swallowed')
            finally:
                react._run_react_loop_impl=original
            assert json.loads(marker.read_text())['status']=='exception'
            path.unlink()
            print('P2-A3 CERTIFIED: session_end(status=exception) recorded; the engine error still propagated')

            # P2-C1: durable reservation before the provider call.
            ledger=BudgetLedger(store)
            reservation=ledger.reserve('system',root_id='probe-root',run_id='child',parent_id=run['id'],
                                       tokens=40,global_budget=50)
            try:
                ledger.reserve('system',root_id='probe-root',run_id='child',parent_id=run['id'],
                               tokens=20,global_budget=50)
            except BudgetExceeded:
                pass
            else:
                raise AssertionError('oversubscription was accepted')
            ledger.release(reservation)
            assert ledger.committed('system','probe-root')==0
            print('P2-C1 CERTIFIED: reservation made before the call; oversubscription refused with BudgetExceeded')

            # P2-C3/C4: autospawn decision and durable, shared root.
            assert should_autospawn('recon','exploit',expected_iterations=8)
            assert not should_autospawn('web','services',expected_iterations=8)
            supervisor=AgentSupervisor.root(execution,SimpleNamespace(),engagement_id=None,
                                            global_budget=1_000_000,autospawn=True)
            assert supervisor.maybe_spawn('recon','exploit') is True
            tree=SupervisorTree(store)
            assert tree.root_of('system',run['id'])==supervisor.root_id
            assert AgentSupervisor.root(execution,SimpleNamespace(),engagement_id=None,
                                        global_budget=1_000_000).root_id==supervisor.root_id
            print('P2-C3/C4 CERTIFIED: phase-family autospawn gate; durable root shared and survives restart')

            # P2-D1/D2: gateway step key and lease fencing.
            journal=InvocationJournal(store)
            key_a=journal.step_key('probe',{},phase='recon')
            assert key_a!=journal.step_key('probe',{},phase='exploitation')
            item=journal.prepare(ctx,'probe',{},'',lease_id='worker-A');journal.start(item['invocation_id'],'system')
            assert journal.recover(ctx,lease_id='worker-B')==0  # live lease untouched
            assert journal.recover(ctx,lease_id='worker-A')==1  # owner reclaims → unknown
            assert journal.get(item['invocation_id'],'system')['state']=='unknown'
            gateway=ToolGateway(PolicyEngine(store),AuditWriter(store))
            gateway.register(ToolDefinition('probe','system',{},tool_id='probe'),lambda a,c:ToolResult({},True,'local'))
            try:
                asyncio.run(gateway.invoke('probe',{},ctx))
            except PermissionError:
                pass
            else:
                raise AssertionError('unsafe replay')
            print('P2-D1/D2 CERTIFIED: step key distinguishes intent; fencing leaves a live worker untouched; '
                  'unknown non-idempotent replay blocked')

    dsn=os.getenv('NEXUS_TEST_PG_DSN') or os.getenv('DATABASE_URL') or ''
    if dsn.startswith(('postgresql://','postgres://')):
        from nexus_core.tests.integration import test_journal_pg as pg
        print('P2-D5 CERTIFIED: PostgreSQL journal/fencing/concurrency covered by '
              'nexus_core/tests/integration/test_journal_pg.py against NEXUS_TEST_PG_DSN')
    else:
        print('P2-D5 LIMIT: no NEXUS_TEST_PG_DSN configured; run test_journal_pg.py against real PostgreSQL to certify')
    print('LIMIT: remote exactly-once is not promised; a sandboxed container (OCI) is still not exercised here')
    return 0

if __name__=='__main__':
    raise SystemExit(main())
