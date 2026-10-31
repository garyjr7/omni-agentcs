"""B5: a 413 is a rate limit, and a TPM budget is a budget.

The E2E run #2 died with ``413 Request too large ... Requested 8438`` because the
client only retried ``openai.RateLimitError``. These tests pin the two halves of
the fix: the status is retried (with a smaller completion reservation), and the
provider's per-minute budget is respected *before* the request is spent.
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
    LLMFactory,
    LLMMessage,
    LLMProvider,
    NexusLLMError,
    OpenAIClient,
)
from nexus_core.llm.limits import (
    MIN_COMPLETION_TOKENS,
    TokenPacer,
    estimate_request_tokens,
    is_rate_limit_status,
    provider_tpm,
    reset_pacer,
)


@pytest.fixture(autouse=True)
def _no_waiting(monkeypatch):
    """Retries and pacing must not turn a unit test into a sleeper."""
    monkeypatch.setenv(limits.BACKOFF_BASE_ENV, "0")
    monkeypatch.setenv(limits.TPM_PACING_ENV, "0")
    reset_pacer()
    yield
    reset_pacer()


def _status_error(status: int) -> openai.APIStatusError:
    request = httpx.Request("POST", "https://api.groq.com/openai/v1/chat/completions")
    return openai.APIStatusError(
        f"error code: {status}", response=httpx.Response(status, request=request), body=None
    )


class _Completions:
    """Fails the first ``failures`` calls with ``status``, then succeeds."""

    def __init__(self, failures: int = 1, status: int = 413):
        self.failures = failures
        self.status = status
        self.calls: list[dict] = []

    async def create(self, **kwargs):
        self.calls.append(dict(kwargs))
        if len(self.calls) <= self.failures:
            raise _status_error(self.status)
        return SimpleNamespace(
            choices=[SimpleNamespace(message=SimpleNamespace(content="ok"))],
            usage=SimpleNamespace(prompt_tokens=10, completion_tokens=5),
            model_dump=lambda: {},
        )


def _client(completions, *, provider=LLMProvider.GROQ) -> OpenAIClient:
    client = OpenAIClient(
        LLMConfig(provider=provider, model="m", api_key="x", base_url="https://x/v1")
    )
    client.client = SimpleNamespace(chat=SimpleNamespace(completions=completions))
    return client


# ------------------------------------------------------------------- primitives
def test_rate_limit_statuses_cover_413_as_well_as_429():
    assert is_rate_limit_status(413) is True
    assert is_rate_limit_status(429) is True
    assert is_rate_limit_status(503) is True
    assert is_rate_limit_status(400) is False
    assert is_rate_limit_status(None) is False
    assert is_rate_limit_status("nope") is False


def test_provider_tpm_is_documented_and_unknown_providers_are_not_paced():
    assert provider_tpm("groq") == 8_000
    assert provider_tpm(LLMProvider.DEEPSEEK) == 1_000_000
    assert provider_tpm("ollama") == 0  # local: nothing to pace
    assert provider_tpm("mystery-provider") is None


def test_estimate_request_tokens_counts_the_reserved_completion():
    messages = [LLMMessage("user", "x" * 400)]
    assert estimate_request_tokens(messages, 1536) == 100 + 1536


# ------------------------------------------------------------------ the pacer
def test_pacer_never_delays_the_first_request():
    now = {"t": 0.0}
    slept: list[float] = []

    async def fake_sleep(delay: float) -> None:
        slept.append(delay)
        now["t"] += delay

    pacer = TokenPacer(clock=lambda: now["t"], sleep=fake_sleep)
    assert asyncio.run(pacer.wait("groq", estimated_tokens=7000)) == 0.0
    assert slept == []


def test_pacer_waits_out_the_window_once_the_budget_is_spent(monkeypatch):
    monkeypatch.setenv(limits.TPM_PACING_ENV, "1")
    now = {"t": 0.0}
    slept: list[float] = []

    async def fake_sleep(delay: float) -> None:
        slept.append(delay)
        now["t"] += delay

    pacer = TokenPacer(clock=lambda: now["t"], sleep=fake_sleep)
    pacer.record("groq", 7000)
    # 7000 + 7000 > 8000: the window has to free up first.
    delay = asyncio.run(pacer.wait("groq", estimated_tokens=7000))
    assert delay == limits.WINDOW_SECONDS
    assert slept == [limits.WINDOW_SECONDS]
    # A request that fits is not delayed.
    pacer.record("groq", 1000)
    assert asyncio.run(pacer.wait("groq", estimated_tokens=1000)) == 0.0


def test_pacer_ignores_an_unknown_provider_and_the_disable_flag(monkeypatch):
    now = {"t": 0.0}
    slept: list[float] = []

    async def fake_sleep(delay: float) -> None:
        slept.append(delay)
        now["t"] += delay

    pacer = TokenPacer(clock=lambda: now["t"], sleep=fake_sleep)
    pacer.record("unknown", 10_000_000)
    assert asyncio.run(pacer.wait("unknown", estimated_tokens=10_000_000)) == 0.0
    assert slept == []

    # An operator (or CI) can turn pacing off without touching the table.
    pacer.record("groq", 7000)
    assert asyncio.run(pacer.wait("groq", estimated_tokens=7000)) == 0.0
    monkeypatch.setenv(limits.TPM_PACING_ENV, "1")
    assert asyncio.run(pacer.wait("groq", estimated_tokens=7000)) > 0


def test_pacer_records_usage_from_a_real_response():
    completions = _Completions(failures=0)
    client = _client(completions)
    asyncio.run(client.complete([LLMMessage("user", "hi")], max_tokens=64))
    assert limits.PACER.usage("groq") == 15


# ------------------------------------------------------- 413 becomes a retry
def test_a_413_is_retried_with_a_smaller_completion_reservation():
    completions = _Completions(failures=1, status=413)
    client = _client(completions)

    response = asyncio.run(
        client.complete([LLMMessage("user", "hi")], max_tokens=4096)
    )

    assert response.content == "ok"
    assert [call["max_tokens"] for call in completions.calls] == [4096, 2048]
    assert client.last_stream_response is None  # sanity: non-streaming path


def test_the_shrink_never_goes_below_the_floor():
    completions = _Completions(failures=2, status=413)
    client = _client(completions)
    asyncio.run(client.complete([LLMMessage("user", "hi")], max_tokens=300))
    assert [call["max_tokens"] for call in completions.calls] == [300, 256, 256]
    assert MIN_COMPLETION_TOKENS == 256


def test_a_429_is_retried_without_touching_the_reservation():
    completions = _Completions(failures=1, status=429)
    client = _client(completions)
    asyncio.run(client.complete([LLMMessage("user", "hi")], max_tokens=1024))
    assert [call["max_tokens"] for call in completions.calls] == [1024, 1024]


def test_a_non_rate_limit_error_is_not_retried():
    completions = _Completions(failures=5, status=400)
    client = _client(completions)
    with pytest.raises(NexusLLMError):
        asyncio.run(client.complete([LLMMessage("user", "hi")]))
    assert len(completions.calls) == 1


# ------------------------------------------------ DeepSeek: ready, not default
def test_deepseek_is_a_supported_openai_compatible_provider():
    client = LLMFactory.create(
        LLMConfig(
            provider=LLMProvider.DEEPSEEK,
            model="deepseek-v4.1-flash",
            api_key="x",
            base_url="https://api.deepseek.com/v1",
        )
    )
    assert isinstance(client, OpenAIClient)
    assert client.config.provider == LLMProvider.DEEPSEEK


def test_deepseek_client_is_built_only_when_the_key_is_exported(
    monkeypatch, tmp_path, no_stored_keys
):
    """Only the exported key counts: a stored key must not build the client."""
    for name in ("OPENAI_API_KEY", "GEMINI_API_KEY", "GROQ_API_KEY", "ANTHROPIC_API_KEY",
                 "OLLAMA_BASE_URL", "DEEPSEEK_API_KEY"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("NEXUS_LLM_FIXTURES", str(tmp_path / "missing.json"))

    assert "deepseek" not in LLMFactory.create_from_env()
    monkeypatch.setenv("DEEPSEEK_API_KEY", "k")
    clients = LLMFactory.create_from_env()
    assert clients["deepseek"].config.provider == LLMProvider.DEEPSEEK
    assert clients["deepseek"].config.base_url == "https://api.deepseek.com"


def test_deepseek_pricing_and_tpm_are_documented():
    from nexus_core.cli.tui import pricing

    assert pricing.default_rates("deepseek-v4.1-flash", "deepseek") == (0.15, 0.60)
    # The identifier the client actually sends and reports (V4.1-Flash is
    # normalized to it), so the meter knows what DeepSeek costs.
    assert pricing.default_rates("deepseek-flash", "deepseek") == (0.15, 0.60)
    assert pricing.PROVIDER_TPM["deepseek"] == 1_000_000
