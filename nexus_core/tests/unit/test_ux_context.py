"""U-03: occupancy is not cumulative spend, and unknown is not zero."""
import asyncio
from types import SimpleNamespace
from nexus_core.cli.tui.status import StatusState, render_status_plain, render_status_bar


def test_unknown_context_is_not_zero():
    assert 'ctx ~?%' in render_status_plain(StatusState())
    assert 'ctx 0% usado' in render_status_plain(StatusState(context_tokens=0,context_window=1000))


def test_context_thresholds_and_accessible_labels():
    for used, color in [(49,'ansigreen'),(50,'ansiyellow'),(80,'ansiyellow'),(81,'ansired')]:
        state=StatusState(context_tokens=used,context_window=100)
        fragments=render_status_bar(state,width=500)
        assert any(color in style and f'ctx {used}%' in text for style,text in fragments)
    assert 'compact' in render_status_plain(StatusState(context_tokens=81,context_window=100))


def test_context_never_displaces_protected_segments():
    state=StatusState(context_tokens=90,context_window=100,trust_mode=True,plan_phase='recon')
    text=''.join(t for _,t in render_status_bar(state,width=25))
    assert 'TRUST' in text and 'recon' in text


def test_request_meter_reflects_compaction_not_run_spend(monkeypatch):
    from nexus_core.cli.tui.usage import MeteredClient
    monkeypatch.setenv('NEXUS_CONTEXT_WINDOW','1000')
    states=[]; spend=[]
    class Client:
        async def complete(self,messages,**kwargs):
            return SimpleNamespace(tokens_input=len(messages[0].content),tokens_output=1)
    client=MeteredClient(Client(),spend.append,context_callback=states.append)
    async def calls():
        await client.complete([SimpleNamespace(content='x'*900)])
        await client.complete([SimpleNamespace(content='summary '*5)])
    asyncio.run(calls())
    assert states[-1]['context_tokens'] < states[1]['context_tokens']
    assert sum(r.tokens_input for r in spend)>900
    assert states[-1]['context_window']==1000


def test_context_fields_preference_preserves_status_toggle(tmp_path,monkeypatch):
    from nexus_core.cli.tui.status import save_status_fields, load_status_fields, save_status_preference
    monkeypatch.setenv('XDG_CONFIG_HOME',str(tmp_path))
    save_status_fields(['ctx','tokens'])
    save_status_preference(False)
    assert load_status_fields()==('ctx','tokens')
    text=render_status_plain(StatusState(fields=('ctx','tokens')))
    assert 'ctx' in text and 'run' in text and '(sin modelo)' not in text
