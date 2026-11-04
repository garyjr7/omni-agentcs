"""``AnthropicClient.complete`` reads native ``thinking`` blocks without a network."""

from __future__ import annotations

from typing import ClassVar
from unittest.mock import patch

from nexus_core.llm import anthropic_client as module
from nexus_core.llm.abstraction import LLMConfig, LLMMessage, LLMProvider
from nexus_core.llm.anthropic_client import AnthropicClient


class _Response:
    def __init__(self, data):
        self._data = data

    def raise_for_status(self):
        return None

    def json(self):
        return self._data


class _AsyncClient:
    """Stands in for ``httpx.AsyncClient``: records the request payload."""

    payloads: ClassVar[list] = []
    response_data: ClassVar[dict] = {}

    def __init__(self, *args, **kwargs):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def post(self, *args, **kwargs):
        self.payloads.append(kwargs.get("json") or {})
        return _Response(self.response_data)


def _client() -> AnthropicClient:
    return AnthropicClient(
        LLMConfig(provider=LLMProvider.ANTHROPIC, model="claude-test", api_key="test-key")
    )


async def test_thinking_blocks_populate_reasoning_and_the_cap_applies():
    thinking = "paso de razonamiento " * 200  # 4 200 characters, over the cap
    _AsyncClient.payloads = []
    _AsyncClient.response_data = {
        "content": [
            {"type": "thinking", "thinking": thinking},
            {"type": "text", "text": "respuesta final"},
        ],
        "usage": {"input_tokens": 11, "output_tokens": 7},
    }

    with patch.object(module.httpx, "AsyncClient", _AsyncClient):
        response = await _client().complete(
            [LLMMessage(role="system", content="eres un agente"),
             LLMMessage(role="user", content="hola")]
        )

    assert response.content == "respuesta final"
    assert response.reasoning == thinking[:2000]
    assert len(response.reasoning or "") == 2000
    assert response.tokens_input == 11 and response.tokens_output == 7
    # The system prompt travels in its own field, never as a message.
    payload = _AsyncClient.payloads[0]
    assert payload["system"] == "eres un agente"
    assert [message["role"] for message in payload["messages"]] == ["user"]


async def test_missing_thinking_blocks_leave_reasoning_empty():
    _AsyncClient.payloads = []
    _AsyncClient.response_data = {
        "content": [{"type": "text", "text": "solo texto"}],
        "usage": {},
    }

    with patch.object(module.httpx, "AsyncClient", _AsyncClient):
        response = await _client().complete([LLMMessage(role="user", content="hola")])

    assert response.reasoning is None
