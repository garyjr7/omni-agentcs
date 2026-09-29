"""Unit tests for the durable ReAct memory (kernel conversations/messages)."""

from __future__ import annotations

import pytest

from nexus_core.agent import memory
from nexus_core.agent.memory import (
    HISTORY_SUMMARY_KIND,
    SYSTEM_MESSAGE_KIND,
    append_step,
    ensure_conversation,
    estimate_tokens,
    load_history,
    summarize_history_if_large,
)
from nexus_core.kernel.control_store import ControlStore
from nexus_core.llm.abstraction import LLMProvider, LLMResponse


class SummaryClient:
    """Deterministic stand-in for a provider used during compaction."""

    def __init__(self, content: str = "RESUMEN COMPACTO") -> None:
        self.content = content
        self.calls: list[list[object]] = []

    async def complete(self, messages, **kwargs):
        self.calls.append(list(messages))
        return LLMResponse(
            content=self.content,
            model="summary-fake",
            provider=LLMProvider.FAKE,
        )


@pytest.fixture()
def store(tmp_path):
    control = ControlStore(tmp_path / "react.db")
    control.initialize()
    return control


def test_ensure_conversation_creates_once(store):
    first = ensure_conversation(store, "system", "run-1", "omni")
    second = ensure_conversation(store, "system", "run-1", "omni")
    other = ensure_conversation(store, "system", "run-2", "omni")

    assert first == second
    assert first != other
    assert len(store.list_conversations("system", "omni")) == 2


def test_ensure_conversation_is_tenant_scoped(store):
    conversation_id = ensure_conversation(store, "system", "run-1", "omni")

    assert store.get_conversation("other", conversation_id) is None
    assert store.get_conversation("system", conversation_id) is not None


def test_append_step_persists_message(store):
    conversation_id = ensure_conversation(store, "system", "run-1", "omni")

    message_id = append_step(
        store, "system", conversation_id, "assistant", "hola", {"kind": "react.action"}
    )

    messages = store.list_messages("system", conversation_id)
    assert [message["id"] for message in messages] == [message_id]
    assert messages[0]["role"] == "assistant"
    assert messages[0]["content"] == "hola"
    assert messages[0]["metadata"]["kind"] == "react.action"


def test_append_step_rejects_unknown_role(store):
    conversation_id = ensure_conversation(store, "system", "run-1", "omni")

    with pytest.raises(ValueError):
        append_step(store, "system", conversation_id, "hacker", "x", {})


def test_load_history_returns_chronological(store):
    conversation_id = ensure_conversation(store, "system", "run-1", "omni")
    for index in range(3):
        append_step(store, "system", conversation_id, "user", f"paso-{index}", {})

    history = load_history(store, "system", conversation_id)

    assert [message["content"] for message in history] == ["paso-0", "paso-1", "paso-2"]


def test_load_history_respects_limit(store):
    conversation_id = ensure_conversation(store, "system", "run-1", "omni")
    for index in range(10):
        append_step(store, "system", conversation_id, "user", f"paso-{index}", {})

    history = load_history(store, "system", conversation_id, limit=3)

    assert [message["content"] for message in history] == ["paso-7", "paso-8", "paso-9"]


async def test_summarize_history_noop_when_small(store):
    conversation_id = ensure_conversation(store, "system", "run-1", "omni")
    append_step(store, "system", conversation_id, "user", "objetivo corto", {})
    client = SummaryClient()

    summary = await summarize_history_if_large(store, "system", conversation_id, client)

    assert summary == ""
    assert client.calls == []
    history = load_history(store, "system", conversation_id)
    assert len(history) == 1


def _large_conversation(store, count: int = 30) -> str:
    conversation_id = ensure_conversation(store, "system", "run-1", "omni")
    append_step(
        store, "system", conversation_id, "system", "OBJETIVO", {"kind": SYSTEM_MESSAGE_KIND}
    )
    for index in range(count):
        append_step(store, "system", conversation_id, "user", f"mensaje-{index}", {})
    return conversation_id


async def test_summarize_history_replaces_old_messages(store):
    conversation_id = _large_conversation(store)
    client = SummaryClient("RESUMEN: se escanearon 10.0.0.5 y 10.0.0.6")

    assert estimate_tokens(load_history(store, "system", conversation_id, limit=500)) > 50

    summary = await summarize_history_if_large(
        store, "system", conversation_id, client, max_tokens=50
    )

    assert summary.startswith("RESUMEN")
    history = load_history(store, "system", conversation_id, limit=500)
    contents = [message["content"] for message in history]
    assert "mensaje-0" not in contents
    assert "mensaje-5" not in contents
    assert summary in contents
    assert any(
        message["metadata"].get("kind") == HISTORY_SUMMARY_KIND for message in history
    )


async def test_summarize_preserves_system_prompt(store):
    conversation_id = _large_conversation(store)
    client = SummaryClient()

    await summarize_history_if_large(store, "system", conversation_id, client, max_tokens=50)

    history = load_history(store, "system", conversation_id, limit=500)
    assert history[0]["content"] == "OBJETIVO"
    assert history[0]["metadata"]["kind"] == SYSTEM_MESSAGE_KIND
    # The system prompt itself must never reach the summarizer.
    summarized_text = "\n".join(
        message.content for call in client.calls for message in call
    )
    assert "OBJETIVO" not in summarized_text
    assert "mensaje-0" in summarized_text


async def test_summarize_preserves_last_10_messages(store):
    conversation_id = _large_conversation(store)
    client = SummaryClient()

    await summarize_history_if_large(store, "system", conversation_id, client, max_tokens=50)

    history = load_history(store, "system", conversation_id, limit=500)
    contents = [message["content"] for message in history]
    for index in range(20, 30):
        assert f"mensaje-{index}" in contents
    assert memory.latest_summary(history) == "RESUMEN COMPACTO"


async def test_summarize_force_triggers_on_message_count(store):
    conversation_id = ensure_conversation(store, "system", "run-1", "omni")
    append_step(
        store, "system", conversation_id, "system", "OBJETIVO", {"kind": SYSTEM_MESSAGE_KIND}
    )
    for index in range(15):
        append_step(store, "system", conversation_id, "user", f"mensaje-{index}", {})
    client = SummaryClient()

    summary = await summarize_history_if_large(
        store, "system", conversation_id, client, max_tokens=8000, force=True
    )

    assert summary == "RESUMEN COMPACTO"
    history = load_history(store, "system", conversation_id, limit=500)
    assert len(history) < 16
    assert "mensaje-0" not in [message["content"] for message in history]
