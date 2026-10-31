"""The output-token key follows the model, not the client.

OpenAI renamed the completion ceiling to ``max_completion_tokens`` and answers
the old ``max_tokens`` with a 400 *Unsupported parameter* for every model
released since (gpt-4o, the o-series, gpt-5, gpt-6). A run on ``gpt-6-luna``
therefore died before the first token, while ``gpt-4-turbo`` still expects the
old key. These tests pin both halves: the capability table, and the wire payload
of ``complete``, ``stream`` and the fallback provider (which every sub-agent
shares, since sub-agents never build their own payload).
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

import httpx
import openai
import pytest

from nexus_core.llm import limits
from nexus_core.llm.abstraction import (
    LLMConfig,
    LLMMessage,
    LLMProvider,
    NexusLLM,
    NexusLLMError,
    OpenAIClient,
    completion_token_parameter,
)

REPORTED_ERROR = (
    "Unsupported parameter: 'max_tokens' is not supported with this model. "
    "Use 'max_completion_tokens' instead."
)

#: What the real API does: the new families reject ``max_tokens``.
_NEW_FAMILIES = ("gpt-4o", "gpt-4.1", "gpt-5", "gpt-6", "chatgpt-4o", "o1", "o3", "o4")


@pytest.fixture(autouse=True)
def _no_waiting(monkeypatch):
    monkeypatch.setenv(limits.BACKOFF_BASE_ENV, "0")
    monkeypatch.setenv(limits.TPM_PACING_ENV, "0")
    limits.reset_pacer()
    yield
    limits.reset_pacer()


def _bad_request(message: str) -> openai.BadRequestError:
    request = httpx.Request("POST", "https://api.openai.com/v1/chat/completions")
    return openai.BadRequestError(
        message, response=httpx.Response(400, request=request), body=None
    )


class _OpenAICompletions:
    """A double that validates the payload the way OpenAI documents it."""

    def __init__(self) -> None:
        self.calls: list[dict] = []

    async def create(self, **kwargs):
        self.calls.append(dict(kwargs))
        if str(kwargs.get("model", "")).startswith(_NEW_FAMILIES):
            if "max_tokens" in kwargs:
                raise _bad_request(REPORTED_ERROR)
            if "max_completion_tokens" not in kwargs:
                raise _bad_request("Missing required parameter: 'max_completion_tokens'.")
        if kwargs.get("stream"):
            return _chunks()
        return SimpleNamespace(
            choices=[SimpleNamespace(message=SimpleNamespace(content="ok"))],
            usage=SimpleNamespace(prompt_tokens=10, completion_tokens=5),
            model_dump=lambda: {},
        )



async def _chunks():
    yield SimpleNamespace(
        choices=[SimpleNamespace(delta=SimpleNamespace(content="ok"))], usage=None
    )


def _client(model: str, *, provider=LLMProvider.OPENAI, completions=None) -> OpenAIClient:
    client = OpenAIClient(
        LLMConfig(provider=provider, model=model, api_key="x", base_url="https://x/v1")
    )
    client.client = SimpleNamespace(
        chat=SimpleNamespace(completions=completions or _OpenAICompletions())
    )
    return client


# ------------------------------------------------------------- capability table
@pytest.mark.parametrize(
    "model",
    ["gpt-6-luna", "gpt-6", "gpt-5.1", "gpt-4o", "gpt-4o-mini", "gpt-4.1", "chatgpt-4o-latest",
     "o1", "o1-mini", "o3-mini", "o4-mini", "GPT-6-LUNA"],
)
def test_new_families_use_max_completion_tokens(model):
    assert completion_token_parameter(model, LLMProvider.OPENAI) == "max_completion_tokens"


@pytest.mark.parametrize(
    "model", ["gpt-4-turbo", "gpt-4", "gpt-3.5-turbo", "gpt-4-0613", "text-davinci-003"]
)
def test_legacy_families_keep_max_tokens(model):
    assert completion_token_parameter(model, LLMProvider.OPENAI) == "max_tokens"


def test_an_unknown_openai_model_is_assumed_new():
    assert completion_token_parameter("gpt-7-preview", LLMProvider.OPENAI) == (
        "max_completion_tokens"
    )


def test_a_compatible_gateway_keeps_the_key_it_already_accepts():
    assert completion_token_parameter("llama-3.3-70b", LLMProvider.GROQ) == "max_tokens"
    assert completion_token_parameter("deepseek-chat", LLMProvider.DEEPSEEK) == "max_tokens"
    assert completion_token_parameter("mystery", "not-a-provider") == "max_tokens"


# ------------------------------------------------------------------ wire payload
def test_complete_sends_max_completion_tokens_for_gpt_6_luna():
    completions = _OpenAICompletions()
    client = _client("gpt-6-luna", completions=completions)

    asyncio.run(client.complete([LLMMessage("user", "hi")], max_tokens=512))

    assert len(completions.calls) == 1  # no 400, so no retry
    payload = completions.calls[0]
    assert payload["max_completion_tokens"] == 512
    assert "max_tokens" not in payload


def test_complete_keeps_max_tokens_for_a_legacy_model():
    completions = _OpenAICompletions()
    client = _client("gpt-4-turbo", completions=completions)

    asyncio.run(client.complete([LLMMessage("user", "hi")], max_tokens=512))

    payload = completions.calls[0]
    assert payload["max_tokens"] == 512
    assert "max_completion_tokens" not in payload


def test_the_configured_ceiling_is_the_default_value():
    completions = _OpenAICompletions()
    client = _client("gpt-6-luna", completions=completions)

    asyncio.run(client.complete([LLMMessage("user", "hi")]))

    assert completions.calls[0]["max_completion_tokens"] == client.config.max_tokens


def test_the_new_key_accepts_an_explicit_completion_tokens_kwarg():
    completions = _OpenAICompletions()
    client = _client("gpt-6-luna", completions=completions)

    asyncio.run(client.complete([LLMMessage("user", "hi")], max_completion_tokens=256))

    assert completions.calls[0]["max_completion_tokens"] == 256


def test_stream_sends_max_completion_tokens_for_gpt_6_luna():
    completions = _OpenAICompletions()
    client = _client("gpt-6-luna", completions=completions)

    async def run():
        return [piece async for piece in client.stream([LLMMessage("user", "hi")], max_tokens=128)]

    assert asyncio.run(run()) == ["ok"]
    payload = completions.calls[0]
    assert payload["max_completion_tokens"] == 128
    assert "max_tokens" not in payload
    assert payload["stream"] is True


# ---------------------------------------------------- fallback and the sub-agents
class _BrokenClient(OpenAIClient):
    """A primary provider that fails the way an unreachable one does."""

    def __init__(self) -> None:
        super().__init__(
            LLMConfig(provider=LLMProvider.GROQ, model="broken", api_key="x")
        )

    async def complete(self, messages, **kwargs):  # noqa: D102 - test double
        raise NexusLLMError("primary is down")


def test_the_fallback_provider_picks_its_own_key():
    """The chain calls ``client.complete``, so the fallback serialises correctly."""
    completions = _OpenAICompletions()
    fallback = _client("gpt-6-luna", completions=completions)
    chain = NexusLLM(primary=_BrokenClient(), fallback=fallback)

    response = asyncio.run(chain.complete([LLMMessage("user", "hi")], max_tokens=384))

    assert response.content == "ok"
    payload = completions.calls[0]
    assert payload["max_completion_tokens"] == 384
    assert "max_tokens" not in payload


def test_a_sub_agent_kwarg_maps_to_the_new_key():
    """Sub-agents pass ``max_tokens`` through the shared client, not their own payload."""
    completions = _OpenAICompletions()
    client = _client("gpt-6-luna", completions=completions)

    asyncio.run(client.complete([LLMMessage("system", "s"), LLMMessage("user", "u")], max_tokens=64))

    assert completions.calls[0]["max_completion_tokens"] == 64


# ------------------------------------------------------------ fidelity of the double
def test_the_double_reproduces_the_reported_production_failure():
    """Guards the tests above: the fake is faithful or they prove nothing."""

    async def send_old_key():
        return await _OpenAICompletions().create(
            model="gpt-6-luna", messages=[{"role": "user", "content": "hi"}], max_tokens=512
        )

    with pytest.raises(openai.BadRequestError) as caught:
        asyncio.run(send_old_key())
    assert "Use 'max_completion_tokens' instead" in str(caught.value)


def test_an_old_key_rejection_surfaces_as_a_typed_llm_error():
    """A 400 is terminal: it must not be retried or silently swallowed."""
    client = _client("gpt-6-luna", completions=_RejectingCompletions())

    with pytest.raises(NexusLLMError) as caught:
        asyncio.run(client.complete([LLMMessage("user", "hi")], max_tokens=512))

    assert "Unsupported parameter: 'max_tokens'" in str(caught.value)


class _RejectingCompletions:
    """Always answers with the documented 400, whatever the payload."""

    async def create(self, **kwargs):
        raise _bad_request(REPORTED_ERROR)
