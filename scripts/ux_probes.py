#!/usr/bin/env python3
"""Offline UX probes and workload measurement; no credentials or real targets."""
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import argparse
import asyncio
import json
import os
from tempfile import TemporaryDirectory
import time
import tracemalloc
from types import SimpleNamespace
from unittest.mock import patch


def baseline(root):
    from nexus_core.cli.tui.history import file_history
    from nexus_core.cli.tui.session import TuiSession
    from nexus_core.cli.tui.status import StatusState, render_status_plain
    from nexus_core.cli.commands import COMMANDS
    p=root/'history'; original='uno\n\t世界\nfin'
    file_history(p).store_string(original)
    recalled=list(file_history(p).load_history_strings())[0]
    print(f'U-02 multiline roundtrip: {original == recalled}; recalled={recalled!r}')
    print(f'U-01 segmented paste API: {hasattr(TuiSession,"paste_text")}')
    print(f'U-04 /mode registered: {"/mode" in COMMANDS}')
    print(f'U-03 HUD: {render_status_plain(StatusState())}')
    print(f'O-03 task event consumer: {hasattr(TuiSession,"task_event")}')


def paste(root):
    from nexus_core.cli.tui.paste import InputDocument
    doc=InputDocument(path=root/'draft.json')
    original='x'*100_000
    start=time.perf_counter()
    doc.insert_paste(0,original)
    doc.synchronize(doc.text+' between ')
    doc.insert_paste(len(doc.text),'\n\t世界'*100)
    assert doc.reconstruct()==original+' between '+'\n\t世界'*100
    assert InputDocument(path=doc.path).reconstruct()==doc.reconstruct()
    adjacent=InputDocument()
    adjacent.insert_paste(0,'a'*1500)
    adjacent.insert_paste(1,'b'*1500)
    adjacent.replace_text(0,1,'')
    assert adjacent.reconstruct()=='b'*1500
    print(json.dumps({'paste_bytes':100_000,'visible_chars':len(doc.render()),'seconds':round(time.perf_counter()-start,6)}))


def history(root):
    from nexus_core.cli.tui.history import file_history
    p=root/'history';p.write_bytes(b'old\nsecond\n')
    hist=file_history(p)
    assert list(hist.load_history_strings())==['second','old']
    text='linea\n\t世界\n'
    hist.store_string(text)
    assert list(file_history(p).load_history_strings())[0]==text
    assert p.with_suffix('.legacy.bak').read_bytes()==b'old\nsecond\n'


def mode(root):
    from nexus_core.cli.session import OmniSession
    from nexus_core.cli.commands import cmd_mode
    from nexus_core.cli import headless
    from nexus_core.kernel.runtime import ExecutionContext, execute_tool
    from nexus_core.kernel.control_store import ControlStore
    from nexus_core.kernel.models import ToolDefinition
    from nexus_core.kernel.audit import AuditWriter
    import io
    from contextlib import redirect_stdout
    store=ControlStore(root/'mode.db');store.initialize()
    session=OmniSession(store=store,tenant_id='system',engagement=None,use_tui=False,llm_client=object())
    with redirect_stdout(io.StringIO()):
        cmd_mode(session,['plan','on'])
    called=[]
    definition=ToolDefinition('probe','system',{},tool_id='probe',effect='exploit')
    payload={'tool_id':'probe','arguments':{},'identity':session.agent_identity_payload}
    with patch('nexus_core.tools.registry.durable_tool_definitions',lambda tenant:{'probe':(definition,lambda a,c:called.append(1))}):
        with redirect_stdout(io.StringIO()):
            assert session.invoke_tool('probe',{}) is None
        async def invoke(**kwargs):
            return await execute_tool(payload,kwargs['context'])
        with patch.object(headless,'run_react_loop',invoke):
            assert headless.run_headless(session,'offline',stream=io.StringIO())==4
        task={'id':'w','tenant_id':'system','run_id':'w','payload':{}}
        try:
            asyncio.run(execute_tool(payload,ExecutionContext(store,task,'worker')))
        except PermissionError:
            pass
        else:
            raise AssertionError('worker active tool permitted')
    assert not called
    assert sum(e['action']=='mode.denied' for e in AuditWriter(store).export('system'))==3


def context(root):
    from nexus_core.cli.tui.usage import MeteredClient
    from nexus_core.cli.tui.status import StatusState,render_status_plain
    states=[];responses=[]
    class Client:
        async def complete(self,messages):
            return SimpleNamespace(tokens_input=len(messages[0].content),tokens_output=1)
    async def run():
        client=MeteredClient(Client(),responses.append,context_callback=states.append)
        await client.complete([SimpleNamespace(content='x'*900)])
        await client.complete([SimpleNamespace(content='summary '*5)])
    with patch.dict(os.environ,NEXUS_CONTEXT_WINDOW='1000'):
        asyncio.run(run())
    assert states[-1]['context_tokens'] < states[1]['context_tokens']
    assert sum(r.tokens_input for r in responses)>900
    assert 'ctx ~?%' in render_status_plain(StatusState())
    print('HUD: '+render_status_plain(StatusState(**states[-1])))


def tasks(root):
    from nexus_core.cli.tui.tasks import TaskPanel
    panel=TaskPanel()
    for task in ('a','b'):
        panel.consume({'event_type':'subagent.started','run_id':'r','payload':{'task_id':task}})
    panel.consume({'event_type':'subagent.ended','run_id':'r','payload':{'task_id':'a','status':'cancelled'}})
    assert panel.tasks['r:a']['status']=='cancelled' and panel.tasks['r:b']['status']=='running'
    assert 'cancelled' in ''.join(t for _,t in panel.render(no_color=True))


def benchmark(root):
    from prompt_toolkit.input import create_pipe_input
    from prompt_toolkit.output import DummyOutput
    from nexus_core.cli.tui.session import TuiSession
    with create_pipe_input() as pipe:
        ui=TuiSession(use_tui=True,input=pipe,output=DummyOutput(),enable_completion=False)
        ui._start()
        tracemalloc.start()
        start=time.perf_counter()
        for i in range(10000):
            ui.append_scrollback(f'event {i}: offline progress\n')
        ui.flush()
        elapsed=time.perf_counter()-start
        _,peak=tracemalloc.get_traced_memory();tracemalloc.stop()
        assert len(ui._segments)==10000
        print(json.dumps({'transcript_events':10000,'seconds':round(elapsed,3),'peak_traced_bytes':peak,
                          'retained_segments':len(ui._segments),'backpressure_implemented':False}))
        ui.close()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline',action='store_true')
    parser.add_argument('--benchmark',action='store_true')
    args=parser.parse_args()
    failures=0
    with TemporaryDirectory(prefix='omni-ux-') as directory:
        root=Path(directory)
        with patch.dict(os.environ,XDG_CONFIG_HOME=str(root/'config'),XDG_STATE_HOME=str(root/'state'),NEXUS_SANDBOX_MODE='local_strict',NEXUS_PREFLIGHT_BINARIES='0'):
            if args.baseline:
                baseline(root);return 0
            for name,probe in [('U-01',paste),('U-02',history),('U-04',mode),('U-03',context),('O-03 UI',tasks)]:
                try:
                    probe(root);print(name+': CLOSED')
                except Exception as exc:
                    failures+=1;print(f'{name}: FAILED ({type(exc).__name__}: {exc})')
            if args.benchmark:
                benchmark(root)
    print(f'{failures} fallos reproducidos')
    return int(bool(failures))

if __name__=='__main__':
    raise SystemExit(main())
