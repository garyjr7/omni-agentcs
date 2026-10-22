"""Tanda C, Fix 4: the provider chain, its retry policy and its aggregate error.

Before this module ``NexusLLM`` had two slots and fell back on **any** exception:
a 401 on the primary spent the secondary's quota, a 503 that the client had
already retried never reached the next provider, and the run died with
``Both primary and fallback LLM providers failed.`` and no cause. Each test here
pins one line of the policy: quota/transient moves on, malformed JSON earns one
correction on the same provider, authentication stops the run, and a dead chain
reports every provider with its own status.
"""

from __future__ import annotations

import pytest

from nexus_core.llm.abstraction import (
    JSON_ONLY_INSTRUCTION,
    BaseLLMClient,
    LLMChainExhausted,
    LLMConfig,
    LLMInvalidJSONError,
    LLMMessage,
    LLMProvider,
    LLMResponse,
    NexusLLM,
    NexusLLMError,
)

SYSTEM = [LLMMessage(role="system", content="eres un agente")]


class _StatusError(NexusLLMError):
    """A provider failure that carries the HTTP status, like the real clients."""

    def __init__(self, status: int, message: str = "") -> None:
        super().__init__(message or f"provider answered {status}")
        self.status_code = status


class _ScriptedClient(BaseLLMClient):
    """Answers ``deck`` in order; ``"ok"`` is a valid completion."""

    def __init__(self, provider: LLMProvider, deck: list[object]) -> None:
        super().__init__(LLMConfig(provider=provider, model=f"{provider.value}-test"))
        self.deck = list(deck)
        self.calls = 0
        self.messages: list[list[str]] = []

    def is_available(self) -> bool:
        return True

    async def complete(self, messages, **kwargs):  # noqa: ANN001 - test double
        self.calls += 1
        self.messages.append([message.content for message in messages])
        item = self.deck.pop(0) if self.deck else "ok"
        if item == "ok":
            return LLMResponse(
                content='{"action": "finish"}',
                model=self.config.model,
                provider=self.config.provider,
                tokens_input=3,
                tokens_output=2,
                duration_ms=1.0,
            )
        if isinstance(item, BaseException):
            raise item
        raise RuntimeError(str(item))


def _chain(*clients: BaseLLMClient) -> NexusLLM:
    return NexusLLM(primary=clients[0], fallback=clients[1] if len(clients) > 1 else None,
                    chain=list(clients))


@pytest.fixture(autouse=True)
def _no_backoff(monkeypatch):
    """Backoff is a wall-clock cost, not a behaviour; keep the suite fast."""
    monkeypatch.setenv("NEXUS_LLM_BACKOFF_SECONDS", "0")


def _events(llm: NexusLLM) -> list[tuple[str, dict]]:
    captured: list[tuple[str, dict]] = []
    llm.attach_event_sink(lambda event_type, payload: captured.append((event_type, payload)))
    return captured


# ------------------------------------------------------------------- transient
async def test_a_503_moves_to_the_next_provider_and_reports_it_once():
    groq = _ScriptedClient(LLMProvider.GROQ, [_StatusError(503)])
    deepseek = _ScriptedClient(LLMProvider.DEEPSEEK, ["ok"])
    llm = _chain(groq, deepseek)
    events = _events(llm)

    response = await llm.complete(SYSTEM)

    assert response.provider is LLMProvider.DEEPSEEK
    assert groq.calls == 1, "un 503 no debe consumir reintentos del primario"
    assert deepseek.calls == 1
    assert events == [
        (
            "provider_fallback",
            {"from": "groq", "to": "deepseek", "reason": "transient", "attempt": 1},
        )
    ], "una transición, un evento: no uno por reintento"


@pytest.mark.parametrize("status", [413, 429, 500, 502, 504])
async def test_every_quota_and_gateway_status_moves_on(status):
    primary = _ScriptedClient(LLMProvider.GROQ, [_StatusError(status)])
    secondary = _ScriptedClient(LLMProvider.DEEPSEEK, ["ok"])

    response = await _chain(primary, secondary).complete(SYSTEM)

    assert response.provider is LLMProvider.DEEPSEEK
    assert primary.calls == 1


async def test_a_network_stall_moves_on_too():
    primary = _ScriptedClient(LLMProvider.GROQ, [TimeoutError("read timed out")])
    secondary = _ScriptedClient(LLMProvider.DEEPSEEK, ["ok"])

    response = await _chain(primary, secondary).complete(SYSTEM)

    assert response.provider is LLMProvider.DEEPSEEK


async def test_the_last_provider_retries_itself_before_giving_up():
    """No provider left: the failing one gets ``CHAIN_MAX_ATTEMPTS`` tries."""
    only = _ScriptedClient(
        LLMProvider.GROQ, [_StatusError(503), _StatusError(503), "ok"]
    )
    llm = _chain(only)

    response = await llm.complete(SYSTEM)

    assert response.provider is LLMProvider.GROQ
    assert only.calls == 3
    assert llm.get_stats()["calls_primary_success"] == 1


async def test_a_single_provider_stops_at_three_attempts():
    only = _ScriptedClient(LLMProvider.GROQ, [_StatusError(503)] * 5)

    with pytest.raises(LLMChainExhausted) as raised:
        await _chain(only).complete(SYSTEM)

    assert only.calls == 3
    assert len(raised.value.causes) == 3
    assert {cause["provider"] for cause in raised.value.causes} == {"groq"}


# ------------------------------------------------------------------ bad JSON
async def test_invalid_json_gets_one_correction_on_the_same_provider():
    primary = _ScriptedClient(
        LLMProvider.GROQ,
        [LLMInvalidJSONError("Groq returned invalid JSON"), "ok"],
    )
    secondary = _ScriptedClient(LLMProvider.DEEPSEEK, ["ok"])
    llm = _chain(primary, secondary)

    response = await llm.complete(SYSTEM)

    assert response.provider is LLMProvider.GROQ
    assert primary.calls == 2
    assert secondary.calls == 0
    assert primary.messages[0] == ["eres un agente"]
    assert primary.messages[1][-1] == JSON_ONLY_INSTRUCTION
    assert primary.messages[1][:-1] == primary.messages[0]


async def test_a_second_invalid_json_moves_to_the_next_provider():
    primary = _ScriptedClient(
        LLMProvider.GROQ,
        [LLMInvalidJSONError("invalid JSON"), LLMInvalidJSONError("invalid JSON")],
    )
    secondary = _ScriptedClient(LLMProvider.DEEPSEEK, ["ok"])
    llm = _chain(primary, secondary)
    events = _events(llm)

    response = await llm.complete(SYSTEM)

    assert response.provider is LLMProvider.DEEPSEEK
    assert primary.calls == 2
    assert secondary.calls == 1
    assert [event[1]["reason"] for event in events] == ["invalid_json"]
    assert events[0][1]["from"] == "groq" and events[0][1]["to"] == "deepseek"


# ------------------------------------------------------------ authentication
@pytest.mark.parametrize("status", [401, 403])
async def test_authentication_is_terminal_and_never_touches_the_chain(status):
    primary = _ScriptedClient(LLMProvider.GROQ, [_StatusError(status)])
    secondary = _ScriptedClient(LLMProvider.DEEPSEEK, ["ok"])
    llm = _chain(primary, secondary)
    events = _events(llm)

    with pytest.raises(LLMChainExhausted) as raised:
        await llm.complete(SYSTEM)

    assert primary.calls == 1
    assert secondary.calls == 0, "una clave rechazada no debe gastar el resto de la cadena"
    assert events == []
    assert raised.value.causes[0]["reason"] == "authentication"
    assert raised.value.causes[0]["status_code"] == status
    assert str(status) in str(raised.value)


async def test_a_401_in_the_middle_of_the_chain_stops_it():
    """One bad key is configuration: the rest of the chain is not spent on it."""
    first = _ScriptedClient(LLMProvider.GROQ, [_StatusError(503)])
    rejected = _ScriptedClient(LLMProvider.DEEPSEEK, [_StatusError(401)])
    third = _ScriptedClient(LLMProvider.OLLAMA, ["ok"])

    with pytest.raises(LLMChainExhausted) as raised:
        await _chain(first, rejected, third).complete(SYSTEM)

    assert rejected.calls == 1
    assert third.calls == 0
    assert [cause["reason"] for cause in raised.value.causes] == [
        "transient",
        "authentication",
    ]


# ------------------------------------------------------------- dead chain
async def test_a_dead_chain_reports_every_provider_and_its_status():
    groq = _ScriptedClient(LLMProvider.GROQ, [_StatusError(503)])
    deepseek = _ScriptedClient(LLMProvider.DEEPSEEK, [_StatusError(429)])
    ollama = _ScriptedClient(LLMProvider.OLLAMA, [_StatusError(500)] * 4)

    with pytest.raises(LLMChainExhausted) as raised:
        await _chain(groq, deepseek, ollama).complete(SYSTEM)

    causes = raised.value.causes
    assert [cause["provider"] for cause in causes] == [
        "groq",
        "deepseek",
        "ollama",
        "ollama",
        "ollama",
    ]
    assert [cause["status_code"] for cause in causes[:3]] == [503, 429, 500]
    message = str(raised.value)
    for fragment in ("groq", "deepseek", "ollama", "503", "429", "500", "transient"):
        assert fragment in message, f"el error agregado no nombra {fragment}: {message!r}"


async def test_an_unknown_failure_is_not_retried_on_the_same_provider():
    """``other`` moves to the next provider once: nobody re-sends a bug."""
    primary = _ScriptedClient(LLMProvider.GROQ, [NexusLLMError("unexpected payload")])
    secondary = _ScriptedClient(LLMProvider.DEEPSEEK, ["ok"])

    response = await _chain(primary, secondary).complete(SYSTEM)

    assert response.provider is LLMProvider.DEEPSEEK
    assert primary.calls == 1


async def test_an_unknown_failure_on_the_last_provider_fails_at_once():
    only = _ScriptedClient(LLMProvider.GROQ, [NexusLLMError("unexpected payload")])

    with pytest.raises(LLMChainExhausted) as raised:
        await _chain(only).complete(SYSTEM)

    assert only.calls == 1, "un fallo desconocido no se reintenta con backoff"
    assert raised.value.causes[0]["reason"] == "other"


# --------------------------------------------------------------- contract
def test_two_slots_still_mean_the_same_chain():
    """The ``primary``/``fallback`` callers keep working unchanged."""
    primary = _ScriptedClient(LLMProvider.GROQ, [])
    fallback = _ScriptedClient(LLMProvider.DEEPSEEK, [])

    llm = NexusLLM(primary=primary, fallback=fallback)

    assert llm.chain == (primary, fallback)
    assert llm.provider_names == ("groq", "deepseek")


async def test_the_fallback_event_lands_in_the_run_journal(tmp_path):
    """Fix 4.3: the event is written by the run, in ``kernel_run_events``.

    The chain sits below the coordinator, so the sink installed by
    ``run_react_loop`` is the only thing that can record the transition. One row,
    free-form JSON, nothing the coordinator has to understand.
    """
    from types import SimpleNamespace

    from nexus_core.agent.react import _attach_llm_event_sink
    from nexus_core.kernel.control_store import ControlStore

    store = ControlStore(tmp_path / "events.db")
    store.initialize()
    run = store.create_run("system", {})
    groq = _ScriptedClient(LLMProvider.GROQ, [_StatusError(503)])
    deepseek = _ScriptedClient(LLMProvider.DEEPSEEK, ["ok"])
    llm = _chain(groq, deepseek)
    _attach_llm_event_sink(
        llm, SimpleNamespace(store=store, tenant_id="system", run_id=run["id"])
    )

    await llm.complete(SYSTEM)

    rows = [
        row
        for row in store.list_run_events("system", run["id"])
        if row["event_type"] == "provider_fallback"
    ]
    assert len(rows) == 1
    assert rows[0]["payload"] == {
        "from": "groq",
        "to": "deepseek",
        "reason": "transient",
        "attempt": 1,
    }


async def test_a_raising_sink_never_breaks_a_completion():
    """Telemetry is best-effort: a closed journal must not fail the turn."""
    primary = _ScriptedClient(LLMProvider.GROQ, [_StatusError(503)])
    secondary = _ScriptedClient(LLMProvider.DEEPSEEK, ["ok"])
    llm = _chain(primary, secondary)

    def sink(event_type, payload):
        raise RuntimeError("the journal is closed")

    llm.attach_event_sink(sink)

    response = await llm.complete(SYSTEM)

    assert response.provider is LLMProvider.DEEPSEEK
