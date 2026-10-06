"""LLM contract fixes (audit H12): sync availability and truthful provider."""

from __future__ import annotations

import asyncio
import inspect

from nexus_core.agent.react import ReActConfig, _complete_turn
from nexus_core.llm.abstraction import LLMConfig, LLMProvider, LLMResponse, OllamaClient


def test_ollama_is_available_is_synchronous():
    """``BaseLLMClient.is_available`` is sync; the override must match."""
    assert not inspect.iscoroutinefunction(OllamaClient.is_available)
    assert inspect.iscoroutinefunction(OllamaClient.ping)


def test_ollama_is_available_returns_bool_without_await():
    client = OllamaClient(
        LLMConfig(
            provider=LLMProvider.OLLAMA,
            model="llama3",
            base_url="http://localhost:11434",
        )
    )
    try:
        assert client.is_available() is True
    finally:
        asyncio.run(client.client.aclose())


class _StreamWithoutUsage:
    """A streaming provider that never publishes ``last_stream_response``."""

    supports_streaming = True

    def __init__(self, config: LLMConfig) -> None:
        self.config = config

    async def stream(self, messages, **kwargs):
        yield '{"action": "task_complete", "thought": "done", "summary": "s", "findings": []}'

    async def complete(self, messages, **kwargs):  # pragma: no cover - not used
        raise AssertionError("complete() must not be called when streaming works")


def _streaming_config() -> ReActConfig:
    return ReActConfig(on_thought=lambda _text: None, on_thought_done=lambda: None)


async def test_complete_turn_reports_the_real_provider():
    client = _StreamWithoutUsage(
        LLMConfig(provider=LLMProvider.ANTHROPIC, model="claude", api_key="x")
    )
    response = await _complete_turn(client, [], _streaming_config())
    assert isinstance(response, LLMResponse)
    assert response.provider is LLMProvider.ANTHROPIC


async def test_complete_turn_falls_back_to_fake_for_unknown_provider():
    class _Bare:
        supports_streaming = True
        config = object()  # no ``provider`` attribute

        async def stream(self, messages, **kwargs):
            yield "text"

    response = await _complete_turn(_Bare(), [], _streaming_config())
    assert response.provider is LLMProvider.FAKE
