"""Fase 4.0: an OTPM 429 shrinks the output reservation instead of looping.

Groq rejects a ``max_tokens`` larger than the model's per-minute *output* budget
with 429 (not 413). The client used to retry the same oversized request forever;
``qwen/qwen3.8-27b`` (OTPM 1000 > ReAct default 1536) died on iteration 1.
"""

from __future__ import annotations

from types import SimpleNamespace

import httpx
import openai
import pytest

from nexus_core.llm.abstraction import LLMConfig, LLMMessage, LLMProvider, OpenAIClient
from nexus_core.llm.limits import mentions_output_token_limit


def _status_error(status: int, message: str) -> openai.APIStatusError:
    request = httpx.Request("POST", "https://api.groq.com/openai/v1/chat/completions")
    response = httpx.Response(status, request=request, json={"error": {"message": message}})
    return openai.APIStatusError(message, response=response, body=None)


def test_helper_detects_otpm_messages():
    assert mentions_output_token_limit(
        _status_error(429, "Request too large ... on output tokens per minute (OTPM): Limit 1000")
    )
    assert mentions_output_token_limit(Exception("please reduce max_tokens and try again"))
    assert not mentions_output_token_limit(Exception("plain rate limit, slow down"))


@pytest.mark.asyncio
async def test_client_shrinks_max_tokens_on_otpm_429(monkeypatch):
    monkeypatch.setenv("NEXUS_LLM_TPM_PACING", "0")
    monkeypatch.setenv("NEXUS_LLM_BACKOFF_SECONDS", "0")

    seen: list[int] = []

    class _FakeCompletions:
        async def create(self, **params):
            seen.append(params["max_tokens"])
            if params["max_tokens"] > 1000:
                raise _status_error(
                    429,
                    "Request too large for model `qwen/qwen3.8-27b` on output tokens "
                    "per minute (OTPM): Limit 1000, Requested 1536.",
                )
            return SimpleNamespace(
                choices=[SimpleNamespace(message=SimpleNamespace(content='{"ok": true}'))],
                usage=None,
                model_dump=lambda: {},
            )

    client = OpenAIClient(
        LLMConfig(provider=LLMProvider.GROQ, model="qwen/qwen3.8-27b", api_key="gsk_fixture")
    )
    client.client = SimpleNamespace(
        chat=SimpleNamespace(completions=_FakeCompletions())
    )

    response = await client.complete([LLMMessage("system", "x")], max_tokens=1536)

    assert response.content == '{"ok": true}'
    # First attempt kept the reservation, the retry halved it below the OTPM cap.
    assert seen == [1536, 768]
