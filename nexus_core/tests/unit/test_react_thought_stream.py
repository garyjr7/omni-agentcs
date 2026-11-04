"""Streamed ReAct reasoning: partial-JSON thought extraction + turn helper."""

import asyncio
from types import SimpleNamespace

from nexus_core.agent import react
from nexus_core.agent.react_support import extract_partial_answer


class _StreamingClient:
    supports_streaming = True

    def __init__(self, chunks):
        self._chunks = list(chunks)
        self.complete_calls = 0

    async def stream(self, messages, **kwargs):
        for chunk in self._chunks:
            yield chunk

    async def complete(self, messages, **kwargs):
        self.complete_calls += 1
        return "complete"

    @property
    def last_stream_response(self):
        return None


class _BrokenStreamClient(_StreamingClient):
    async def stream(self, messages, **kwargs):
        yield '{"thought": "empiezo'
        raise RuntimeError("boom")


def test_extract_partial_thought_from_incomplete_json():
    assert react.extract_partial_thought('{"thought": "escaneo') == "escaneo"
    assert react.extract_partial_thought('{"action": "tool_call"}') == ""
    assert react.extract_partial_thought("not json at all") == ""


def test_extract_partial_thought_unescapes() -> None:
    assert react.extract_partial_thought('{"thought": "di \\"hola\\"') == 'di "hola"'


def test_extract_partial_answer_requires_task_complete() -> None:
    assert extract_partial_answer('{"action": "tool_call", "summary": "no"}') == ""
    assert extract_partial_answer(
        '{"action": "task_complete", "summary": "listo'
    ) == "listo"
    assert extract_partial_answer('{"thought": "sin resumen"}') == ""


def test_complete_turn_streams_thought_until_done():
    thoughts: list[str] = []
    done: list[bool] = []
    client = _StreamingClient(
        [
            '{"thought"',
            ': "escaneo ',
            'el puerto 80"',
            ', "action": "task_complete", "summary": "ok", "findings": []}',
        ]
    )
    config = react.ReActConfig(
        on_thought=thoughts.append, on_thought_done=lambda: done.append(True)
    )
    response = asyncio.run(react._complete_turn(client, [], config))
    assert "task_complete" in response.content
    assert thoughts[0].rstrip() == "escaneo"
    assert thoughts[-1] == "escaneo el puerto 80"
    assert done == [True]
    assert client.complete_calls == 0


def test_complete_turn_streams_the_final_answer():
    answers: list[str] = []
    done: list[bool] = []
    client = _StreamingClient(
        [
            '{"thought": "termino", "action": "task_complete", "summary": "El ',
            'servicio 80 responde.',
            '", "findings": []}',
        ]
    )
    config = react.ReActConfig(
        on_answer=answers.append, on_answer_done=lambda: done.append(True)
    )
    asyncio.run(react._complete_turn(client, [], config))
    assert answers[0] == "El "
    assert answers[-1] == "El servicio 80 responde."
    assert done == [True]
    assert client.complete_calls == 0


def test_complete_turn_without_hook_uses_complete():
    client = _StreamingClient(['{"thought": "x"}'])
    response = asyncio.run(react._complete_turn(client, [], react.ReActConfig()))
    assert response == "complete"
    assert client.complete_calls == 1


def test_complete_turn_falls_back_when_streaming_fails():
    client = _BrokenStreamClient([])
    done: list[bool] = []

    async def fallback(messages, **kwargs):
        client.complete_calls += 1
        return SimpleNamespace(content="fallback", tokens_input=1, tokens_output=1)

    client.complete = fallback  # type: ignore[method-assign]
    config = react.ReActConfig(
        on_thought=lambda _text: None, on_thought_done=lambda: done.append(True)
    )
    response = asyncio.run(react._complete_turn(client, [], config))
    assert response.content == "fallback"
    assert client.complete_calls == 1
    assert done
