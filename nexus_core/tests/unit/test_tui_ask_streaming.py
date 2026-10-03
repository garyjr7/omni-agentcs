"""``/ask`` streams token by token into the live overlay, then commits it."""

from types import SimpleNamespace

from nexus_core.cli import commands as commands_module
from nexus_core.cli.session import OmniSession
from nexus_core.cli.tui.output import TuiOutput, route_output


class _StreamingLLM:
    supports_streaming = True

    def __init__(self) -> None:
        self.complete_called = False
        self.last_stream_response = SimpleNamespace(
            tokens_input=5, tokens_output=9, provider="fake"
        )

    async def stream(self, messages, **kwargs):
        for piece in ["Hola ", "**mundo**"]:
            yield piece

    async def complete(self, messages, **kwargs):  # pragma: no cover - must not run
        self.complete_called = True
        raise AssertionError("complete() must not be used when streaming is supported")


class _NonStreamingLLM:
    supports_streaming = False

    def __init__(self) -> None:
        self.calls = 0

    async def complete(self, messages, **kwargs):
        self.calls += 1
        return SimpleNamespace(content="respuesta completa", tokens_input=1, tokens_output=1)


def _tui_session(tui_factory, llm):
    ui = tui_factory()
    session = OmniSession(store=None, use_tui=False)
    session._tui = ui.session
    session._output = TuiOutput(ui.session)
    session.llm_client = llm
    return session, ui


def test_ask_streams_into_the_overlay_and_commits(tui_factory):
    llm = _StreamingLLM()
    session, ui = _tui_session(tui_factory, llm)
    with route_output(session._output):
        commands_module.cmd_ask(session, ["hola"])
    transcript = ui.session.transcript
    assert not llm.complete_called
    assert "Hola" in transcript and "mundo" in transcript
    # The overlay is closed once the answer is committed to the scrollback.
    assert ui.session.answer_active is False
    # Streaming usage is recorded on the status bar.
    assert ui.session._status.tokens_output == 9


def test_ask_falls_back_to_complete_without_streaming(tui_factory):
    llm = _NonStreamingLLM()
    session, ui = _tui_session(tui_factory, llm)
    with route_output(session._output):
        commands_module.cmd_ask(session, ["hola"])
    assert llm.calls == 1
    assert "respuesta completa" in ui.session.transcript
    assert ui.session.answer_active is False
