"""O-03 UI: concurrent task lifecycle and independent cancellation."""
import asyncio
from nexus_core.cli.tui.session import TuiSession


def test_parallel_task_states_and_late_events():
    ui=TuiSession(use_tui=False)
    ui.task_event({'event_type':'subagent.started','run_id':'r','payload':{'task_id':'a','subagent_id':'recon'}})
    ui.task_event({'event_type':'subagent.started','run_id':'r','payload':{'task_id':'b','subagent_id':'web'}})
    ui.task_event({'event_type':'subagent.ended','run_id':'r','payload':{'task_id':'a','status':'cancelled'}})
    ui.task_event({'event_type':'subagent.started','run_id':'r','payload':{'task_id':'a'}})
    assert ui.task_panel.tasks['r:a']['status']=='cancelled'
    assert ui.task_panel.tasks['r:b']['status']=='running'
    text=''.join(t for _,t in ui.task_panel.render())
    assert 'cancelled' in text and 'running' in text


def test_task_panel_is_bounded():
    from nexus_core.cli.tui.tasks import TaskPanel
    panel=TaskPanel(max_tasks=5)
    for i in range(30):
        panel.consume({'event_type':'subagent.ended','run_id':'r','payload':{'task_id':str(i),'status':'ok'}})
    assert len(panel.tasks)<=5


def test_task_panel_keeps_input_usable(tui_factory):
    ui=tui_factory()
    ui.session.task_event({'event_type':'subagent.started','run_id':'r','payload':{'task_id':'a'}})
    ui.pipe.send_text('operator input\r')
    assert ui.session.prompt()=='operator input'
    assert ui.session.task_panel.tasks['r:a']['status']=='running'


def test_real_fanout_cancel_one_does_not_cancel_sibling(tmp_path,monkeypatch):
    from nexus_core.cli.session import OmniSession
    from nexus_core.kernel.control_store import ControlStore
    store=ControlStore(tmp_path/'db');store.initialize()
    session=OmniSession(store=store,tenant_id='system',engagement=None,use_tui=False)
    async def execute(payload,context):
        if payload['arguments']['target']=='a':
            task=asyncio.current_task()
            asyncio.get_running_loop().call_soon(task.cancel)
            await asyncio.sleep(0)
        return {'output':{'verified':True}}
    monkeypatch.setattr('nexus_core.kernel.runtime.execute_tool',execute)
    results=session.fan_out_tool('nexus.recon.nmap',['a','b'])
    assert isinstance(results[0],asyncio.CancelledError)
    assert isinstance(results[1],dict)
    states={task['target']:task['status'] for task in session._tui.task_panel.tasks.values()}
    assert states=={'a':'cancelled','b':'ok'}
