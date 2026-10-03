"""Token streaming on the LLM layer and its metered wrapper."""

import asyncio
from types import SimpleNamespace

from nexus_core.cli.tui.usage import MeteredClient
from nexus_core.llm.abstraction import (
    FakeLLMClient,
    LLMConfig,
    LLMMessage,
    LLMProvider,
    NexusLLM,
    OpenAIClient,
)


class _Usage:
    prompt_tokens = 11
    completion_tokens = 7


class _Chunk:
    def __init__(self, content=None, usage=None):
        self.choices = (
            [SimpleNamespace(delta=SimpleNamespace(content=content))] if content else []
        )
        self.usage = usage


class _FakeCompletions:
    last_kwargs = None

    async def create(self, **kwargs):
        _FakeCompletions.last_kwargs = kwargs

        async def gen():
            for piece in ["Hel", "lo ", "**world**"]:
                yield _Chunk(piece)
            yield _Chunk(None, _Usage())

        return gen()


def _groq_client() -> OpenAIClient:
    client = OpenAIClient(
        LLMConfig(
            provider=LLMProvider.GROQ,
            model="m",
            api_key="x",
            base_url="https://api.groq.com/openai/v1",
        )
    )
    client.client = SimpleNamespace(chat=SimpleNamespace(completions=_FakeCompletions()))
    return client


def test_openai_stream_yields_deltas_and_usage():
    client = _groq_client()

    async def run():
        return [piece async for piece in client.stream([LLMMessage("user", "hi")])]

    chunks = asyncio.run(run())
    assert chunks == ["Hel", "lo ", "**world**"]
    assert client.supports_streaming is True
    response = client.last_stream_response
    assert (response.tokens_input, response.tokens_output) == (11, 7)
    assert _FakeCompletions.last_kwargs["stream_options"] == {"include_usage": True}


def test_default_stream_yields_the_whole_answer_once():
    client = FakeLLMClient(LLMConfig(provider=LLMProvider.FAKE, model="f"))

    async def run():
        return [piece async for piece in client.stream([LLMMessage("user", "hi")])]

    assert client.supports_streaming is False
    assert len(asyncio.run(run())) == 1
    assert client.last_stream_response is not None


def test_metered_stream_reports_usage_to_the_callback():
    client = _groq_client()
    seen: list = []
    metered = MeteredClient(client, seen.append)

    async def run():
        return [piece async for piece in metered.stream([LLMMessage("user", "hi")])]

    assert "".join(asyncio.run(run())) == "Hello **world**"
    assert len(seen) == 1
    assert seen[0].tokens_output == 7


def test_nexus_streaming_delegates_to_the_primary():
    primary = _groq_client()
    nexus = NexusLLM(primary=primary)
    assert nexus.supports_streaming is True

    async def run():
        return [piece async for piece in nexus.stream([LLMMessage("user", "hi")])]

    assert "".join(asyncio.run(run())) == "Hello **world**"
    assert nexus.last_stream_response is primary.last_stream_response
