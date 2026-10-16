"""DeepSeek wire contracts and pacing without external API calls."""

from __future__ import annotations

import asyncio
import json
from typing import Any

import httpx
import pytest
from openai import AsyncOpenAI

from nexus_core.agent.parser import parse_react_response
from nexus_core.kernel.domain_dto import TaskComplete
from nexus_core.llm.abstraction import (
    DeepSeekClient,
    LLMConfig,
    LLMMessage,
    LLMProvider,
    NexusLLMError,
)
from nexus_core.llm.limits import (
    DEFAULT_DEEPSEEK_MAX_ATTEMPTS,
    DEFAULT_DEEPSEEK_TIMEOUT_SECONDS,
    MAX_DEEPSEEK_ATTEMPTS,
    MIN_DEEPSEEK_TIMEOUT_SECONDS,
    TokenPacer,
    deepseek_max_attempts,
    deepseek_timeout_seconds,
    is_transient_status,
)

ACTION = '{"action":"task_complete","thought":"done","summary":"verified","findings":[]}'


def response(text: str = ACTION, finish: str = "stop") -> dict[str, Any]:
    return {
        "id": "test",
        "object": "chat.completion",
        "created": 1,
        "model": "deepseek-flash",
        "choices": [
            {"index": 0, "message": {"role": "assistant", "content": text}, "finish_reason": finish}
        ],
        "usage": {"prompt_tokens": 19, "completion_tokens": 7, "total_tokens": 26},
    }


def client(transport: httpx.MockTransport) -> DeepSeekClient:
    result = DeepSeekClient(
        LLMConfig(
            LLMProvider.DEEPSEEK,
            "deepseek-v4.1-flash",
            api_key="fixture-key",
            system_prompt="Follow the domain action schema.",
        )
    )
    result.client = AsyncOpenAI(
        api_key="fixture-key",
        base_url=result.config.base_url,
        max_retries=0,
        http_client=httpx.AsyncClient(transport=transport),
    )
    result.pacer = TokenPacer(tpm={"deepseek": 100000}, rpm={"deepseek": 100})
    return result


@pytest.mark.asyncio
async def test_wire_auth_endpoint_json_and_domain_dto() -> None:
    def handle(request: httpx.Request) -> httpx.Response:
        assert str(request.url) == "https://api.deepseek.com/chat/completions"
        assert request.headers["authorization"] == "Bearer fixture-key"
        body = json.loads(request.content)
        assert body["model"] == "deepseek-flash"
        assert body["response_format"] == {"type": "json_object"}
        assert body["thinking"] == {"type": "disabled"}
        assert any(m["content"] == "Follow the domain action schema." for m in body["messages"])
        return httpx.Response(200, json=response())

    llm = client(httpx.MockTransport(handle))
    result = await llm.complete(
        [LLMMessage("system", "session rules"), LLMMessage("user", "finish")],
        response_format={"type": "json_object"},
    )
    assert isinstance(parse_react_response(result.content), TaskComplete)
    assert (result.tokens_input, result.tokens_output) == (19, 7)
    assert llm.pacer.usage("deepseek") == 26
    await llm.client.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [429, 503])
async def test_retry_is_bounded_and_preserves_json(
    status: int, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("NEXUS_LLM_BACKOFF_SECONDS", "0")
    requests: list[dict[str, Any]] = []

    def handle(request: httpx.Request) -> httpx.Response:
        requests.append(json.loads(request.content))
        if len(requests) < 3:
            return httpx.Response(status, json={"error": {"message": "fixture"}})
        return httpx.Response(200, json=response())

    llm = client(httpx.MockTransport(handle))
    await llm.complete([LLMMessage("user", "JSON")], response_format={"type": "json_object"})
    assert len(requests) == 3 and requests[0] == requests[2]
    await llm.client.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "text,finish", [("", "stop"), (ACTION, "length"), ('{"x":1,"x":2}', "stop"), ("[]", "stop")]
)
async def test_invalid_json_and_truncation_fail_closed(text: str, finish: str) -> None:
    llm = client(httpx.MockTransport(lambda _: httpx.Response(200, json=response(text, finish))))
    with pytest.raises(NexusLLMError):
        await llm.complete([LLMMessage("user", "JSON")], response_format={"type": "json_object"})
    await llm.client.close()


@pytest.mark.asyncio
async def test_stream_usage_on_final_content_chunk_and_empty_choices() -> None:
    chunks: list[dict[str, Any]] = [
        {"choices": [], "usage": None},
        {"choices": [{"index": 0, "delta": {"content": ACTION}, "finish_reason": None}]},
        {
            "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 11, "completion_tokens": 0, "total_tokens": 11},
        },
    ]
    body = (
        ": keep-alive\n\n"
        + "".join(
            "data: "
            + json.dumps(
                {
                    "id": "s",
                    "model": "deepseek-flash",
                    "created": 1,
                    "object": "chat.completion.chunk",
                    **chunk,
                }
            )
            + "\n\n"
            for chunk in chunks
        )
        + "data: [DONE]\n\n"
    )
    llm = client(
        httpx.MockTransport(
            lambda _: httpx.Response(200, text=body, headers={"content-type": "text/event-stream"})
        )
    )
    output = "".join(
        [
            text
            async for text in llm.stream(
                [LLMMessage("user", "JSON")], response_format={"type": "json_object"}
            )
        ]
    )
    result = llm.last_stream_response
    assert output == ACTION and result is not None
    assert (result.tokens_input, result.tokens_output) == (11, 0)
    assert isinstance(parse_react_response(result.content), TaskComplete)
    await llm.client.close()


@pytest.mark.asyncio
async def test_reservations_are_atomic_and_settle_without_double_counting() -> None:
    now = [0.0]
    sleeps: list[float] = []

    async def sleep(delay: float) -> None:
        sleeps.append(delay)
        now[0] += delay
        await asyncio.sleep(0)

    pacer = TokenPacer(
        tpm={"deepseek": 100}, rpm={"deepseek": 1}, clock=lambda: now[0], sleep=sleep
    )
    first, second = await asyncio.gather(
        *(pacer.reserve("deepseek", estimated_tokens=60) for _ in range(2))
    )
    assert second.created - first.created >= 60
    pacer.settle(first, 10)
    pacer.settle(second, 20)
    pacer.settle(second, 20)
    assert pacer.usage("deepseek") == 20 and sleeps == [60.0]
    with pytest.raises(ValueError):
        await pacer.reserve("deepseek", estimated_tokens=101)


def test_primary_selection_supports_deepseek() -> None:
    from nexus_core.cli.llm_env import resolve_provider
    from nexus_core.config.schema import OmniConfig

    assert (
        resolve_provider({"NEXUS_LLM_DEFAULT_PROVIDER": "deepseek", "DEEPSEEK_API_KEY": "fixture"})
        == "deepseek"
    )
    config = OmniConfig.from_toml(
        '[llm]\ndefault_provider="deepseek"\ndefault_model="deepseek-flash"\n'
    )
    assert config.llm.default_provider == "deepseek"


@pytest.mark.asyncio
async def test_stream_retries_before_deltas_but_not_after_partial_content(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("NEXUS_LLM_BACKOFF_SECONDS", "0")
    calls = [0]

    class BrokenStream(httpx.AsyncByteStream):
        async def __aiter__(self):
            chunk = {
                "id": "s",
                "object": "chat.completion.chunk",
                "created": 1,
                "model": "deepseek-flash",
                "choices": [{"index": 0, "delta": {"content": "partial"}, "finish_reason": None}],
            }
            yield ("data: " + json.dumps(chunk) + "\n\n").encode()
            raise httpx.ReadError("fixture connection lost")

    def handle(_: httpx.Request) -> httpx.Response:
        calls[0] += 1
        if calls[0] == 1:
            return httpx.Response(503, json={"error": {"message": "busy"}})
        return httpx.Response(
            200, stream=BrokenStream(), headers={"content-type": "text/event-stream"}
        )

    llm = client(httpx.MockTransport(handle))
    deltas: list[str] = []
    with pytest.raises(NexusLLMError):
        async for text in llm.stream([LLMMessage("user", "fixture")]):
            deltas.append(text)
    assert calls[0] == 2 and deltas == ["partial"]
    assert llm.last_stream_response is None and not llm.pacer._reservations
    await llm.client.close()


@pytest.mark.asyncio
async def test_authentication_error_is_not_retried_or_leaked() -> None:
    calls = [0]

    def handle(_: httpx.Request) -> httpx.Response:
        calls[0] += 1
        return httpx.Response(401, json={"error": {"message": "fixture-key"}})

    llm = client(httpx.MockTransport(handle))
    with pytest.raises(NexusLLMError) as error:
        await llm.complete([LLMMessage("user", "fixture")])
    assert "fixture-key" not in str(error.value) and calls[0] == 1
    assert not llm.pacer._reservations
    await llm.client.close()


@pytest.mark.asyncio
async def test_rpm_works_when_tpm_is_disabled_and_missing_usage_keeps_reservation() -> None:
    now = [0.0]

    async def sleep(delay: float) -> None:
        now[0] += delay

    pacer = TokenPacer(tpm={"deepseek": 0}, rpm={"deepseek": 1}, clock=lambda: now[0], sleep=sleep)
    first = await pacer.reserve("deepseek", estimated_tokens=30)
    pacer.settle(first)
    assert pacer.usage("deepseek") == 30
    second = await pacer.reserve("deepseek", estimated_tokens=40)
    assert second.created == 60.0
    pacer.settle(second, 0)
    assert pacer.usage("deepseek") == 0


@pytest.mark.asyncio
async def test_react_turn_requests_json_only_for_capable_adapter() -> None:
    from unittest.mock import AsyncMock
    from types import SimpleNamespace
    from nexus_core.agent.react_support import _complete_turn
    from nexus_core.agent.react_types import ReActConfig

    complete = AsyncMock(return_value=SimpleNamespace(content=ACTION))
    adapter = SimpleNamespace(supports_action_json=True, complete=complete)
    await _complete_turn(adapter, [LLMMessage("user", "fixture")], ReActConfig())
    assert complete.call_args.kwargs["response_format"] == {"type": "json_object"}


@pytest.mark.asyncio
async def test_system_prompt_role_and_input_history_are_preserved() -> None:
    llm = client(httpx.MockTransport(lambda _: httpx.Response(200, json=response())))
    messages = [LLMMessage("user", llm.config.system_prompt or "")]
    payload = llm._payload(messages, {"response_format": {"type": "json_object"}})
    assert payload["messages"][1]["role"] == "system"
    assert len(messages) == 1 and messages[0].role == "user"
    await llm.client.close()


# ------------------------------------------------------- latency hardening
def test_deepseek_timeout_is_raised_floored_and_overridable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("DEEPSEEK_TIMEOUT", raising=False)
    assert deepseek_timeout_seconds() == DEFAULT_DEEPSEEK_TIMEOUT_SECONDS >= 120
    # A configured value below the floor cannot re-introduce the 60 s cut.
    monkeypatch.setenv("DEEPSEEK_TIMEOUT", "5")
    assert deepseek_timeout_seconds() == MIN_DEEPSEEK_TIMEOUT_SECONDS == 120.0
    monkeypatch.setenv("DEEPSEEK_TIMEOUT", "400")
    assert deepseek_timeout_seconds() == 400.0
    monkeypatch.setenv("DEEPSEEK_TIMEOUT", "nonsense")
    assert deepseek_timeout_seconds() == DEFAULT_DEEPSEEK_TIMEOUT_SECONDS


def test_deepseek_client_overrides_the_provider_agnostic_60s_default() -> None:
    llm = DeepSeekClient(
        LLMConfig(LLMProvider.DEEPSEEK, "deepseek-flash", api_key="fixture-key")
    )
    assert llm.config.timeout >= 120
    asyncio.run(llm.client.close())


def test_deepseek_attempt_budget_is_clamped_and_overridable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("DEEPSEEK_MAX_ATTEMPTS", raising=False)
    assert deepseek_max_attempts() == DEFAULT_DEEPSEEK_MAX_ATTEMPTS
    monkeypatch.setenv("DEEPSEEK_MAX_ATTEMPTS", "0")
    assert deepseek_max_attempts() == 1  # retries disabled, never zero attempts
    monkeypatch.setenv("DEEPSEEK_MAX_ATTEMPTS", "999")
    assert deepseek_max_attempts() == MAX_DEEPSEEK_ATTEMPTS


def test_transient_status_covers_stalls_but_not_client_errors() -> None:
    for status in (408, 409, 425, 429, 500, 502, 503, 504):
        assert is_transient_status(status) is True
    for terminal in (400, 401, 403, 404, 422, None, "nope"):
        assert is_transient_status(terminal) is False


@pytest.mark.asyncio
async def test_transport_stall_is_retried_instead_of_aborting(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("NEXUS_LLM_BACKOFF_SECONDS", "0")
    calls: list[int] = []

    def handle(request: httpx.Request) -> httpx.Response:
        calls.append(1)
        if len(calls) < 2:
            # A slow provider / dropped socket reaches the client as a transport
            # stall, which previously aborted the run with a NexusLLMError.
            raise httpx.ReadTimeout("fixture stall", request=request)
        return httpx.Response(200, json=response())

    llm = client(httpx.MockTransport(handle))
    result = await llm.complete([LLMMessage("user", "hello")])
    assert result.content == ACTION and len(calls) == 2
    await llm.client.close()


@pytest.mark.asyncio
async def test_transport_stall_is_bounded_by_the_attempt_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("NEXUS_LLM_BACKOFF_SECONDS", "0")
    monkeypatch.setenv("DEEPSEEK_MAX_ATTEMPTS", "3")
    calls: list[int] = []

    def handle(request: httpx.Request) -> httpx.Response:
        calls.append(1)
        raise httpx.ConnectError("fixture unreachable", request=request)

    llm = client(httpx.MockTransport(handle))
    with pytest.raises(NexusLLMError):
        await llm.complete([LLMMessage("user", "hello")])
    assert len(calls) == 3 and not llm.pacer._reservations
    await llm.client.close()


@pytest.mark.asyncio
async def test_a_retry_is_reserved_and_settled_once_per_attempt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("NEXUS_LLM_BACKOFF_SECONDS", "0")
    calls: list[int] = []

    def handle(request: httpx.Request) -> httpx.Response:
        calls.append(1)
        if len(calls) < 2:
            return httpx.Response(503, json={"error": {"message": "busy"}})
        return httpx.Response(200, json=response())

    llm = client(httpx.MockTransport(handle))
    messages = [LLMMessage("user", "hello")]
    params = llm._payload(messages, {"max_tokens": 64})
    estimate = sum(len(m["content"].encode("utf-8")) + 16 for m in params["messages"]) + 64
    await llm.complete(messages, max_tokens=64)
    # The failed attempt keeps its estimated charge; only the successful one is
    # settled with the provider's real usage, and nothing stays reserved.
    assert llm.pacer.usage("deepseek") == estimate + 26
    assert not llm.pacer._reservations
    await llm.client.close()
