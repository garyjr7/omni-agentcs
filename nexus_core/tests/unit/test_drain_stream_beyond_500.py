"""The stream cursor is durable: messages 501+ are not frozen out of the log."""

from types import SimpleNamespace

from nexus_core.cli import session as module


def test_drain_stream_beyond_500(monkeypatch):
    messages = [
        {
            "id": f"m{index}", "sequence": index, "role": "assistant",
            "content": f"message {index}", "metadata": {},
        }
        for index in range(1, 551)
    ]

    def list_messages(tenant_id, conversation_id, limit=100, after_sequence=None):
        window = [m for m in messages if after_sequence is None or m["sequence"] > after_sequence]
        return window[:limit]

    store = SimpleNamespace(
        list_run_events=lambda *args, **kwargs: [],
        list_messages=list_messages,
        last_message_sequence=lambda *args, **kwargs: 0,
    )
    session = SimpleNamespace(
        store=store,
        tenant_id="system",
        conversation_id="conversation",
        run_id="run",
        _tui=SimpleNamespace(use_tui=False),
    )
    seen: list[dict] = []
    monkeypatch.setattr(module, "_render_message", lambda message: seen.append(message))

    state = {"run_id": "run", "sequence": 0, "message_sequence": 0, "turn": 0}
    for _ in range(10):
        module._drain_stream(session, state)

    sequences = [message["sequence"] for message in seen]
    assert sequences == list(range(1, 551))
    assert 549 in sequences and 550 in sequences
