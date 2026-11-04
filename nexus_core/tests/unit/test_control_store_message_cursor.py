"""The message cursor against the real store: no mocks of ``ControlStore``.

The stream used to ask for the last 500 messages on every poll, so once a run
passed 500 rows the log froze. These tests exercise the durable contract that
replaced it: a cursor returns only ``sequence > N``, in order and bounded by
``limit``, and an empty conversation has sequence 0.
"""

from __future__ import annotations

import pytest

from nexus_core.kernel.control_store import ControlStore

TENANT = "system"


@pytest.fixture()
def store(tmp_path) -> ControlStore:
    value = ControlStore(tmp_path / "messages.db")
    value.initialize()
    return value


def _conversation(store: ControlStore) -> str:
    return store.create_conversation(TENANT, "owner-1", "cursor tests")["id"]


def _seed(store: ControlStore, conversation_id: str, count: int) -> None:
    for index in range(1, count + 1):
        store.append_message(TENANT, conversation_id, "assistant", f"message {index}")


def test_after_sequence_returns_only_later_messages_in_order_and_respects_limit(store):
    conversation_id = _conversation(store)
    _seed(store, conversation_id, 10)

    messages = store.list_messages(
        TENANT, conversation_id, limit=3, after_sequence=4
    )

    assert [message["sequence"] for message in messages] == [5, 6, 7]
    assert [message["content"] for message in messages] == [
        "message 5", "message 6", "message 7",
    ]


def test_the_window_after_the_cursor_reaches_messages_beyond_500(store):
    conversation_id = _conversation(store)
    _seed(store, conversation_id, 550)

    messages = store.list_messages(
        TENANT, conversation_id, limit=500, after_sequence=500
    )

    assert [message["sequence"] for message in messages] == list(range(501, 551))
    # The cursor is exhaustive: a second poll at the head returns nothing.
    assert store.list_messages(
        TENANT, conversation_id, limit=500, after_sequence=550
    ) == []


def test_last_message_sequence_is_the_maximum(store):
    conversation_id = _conversation(store)
    _seed(store, conversation_id, 12)

    assert store.last_message_sequence(TENANT, conversation_id) == 12


def test_last_message_sequence_is_zero_for_an_empty_conversation(store):
    conversation_id = _conversation(store)

    assert store.last_message_sequence(TENANT, conversation_id) == 0
