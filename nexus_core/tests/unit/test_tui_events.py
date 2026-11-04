"""Push notifications and the UI batcher that coalesces them."""

import threading
import time

from nexus_core.cli.tui.events import UpdateBatcher
from nexus_core.kernel.control_store import ControlStore


def test_a_burst_of_posts_becomes_one_flush() -> None:
    seen: list[list[object]] = []
    flushed = threading.Event()

    def flush(items: list[object]) -> None:
        seen.append(items)
        flushed.set()

    batcher = UpdateBatcher(flush, interval=0.05).start()
    try:
        for index in range(5):
            batcher.post(index)
        assert flushed.wait(1)
    finally:
        batcher.stop()
    assert len(seen) == 1
    assert sorted(seen[0]) == list(range(5))


def test_stop_flushes_queued_updates() -> None:
    seen: list[list[object]] = []
    batcher = UpdateBatcher(lambda items: seen.append(items), interval=0.05).start()
    batcher.post("last")
    batcher.stop()
    assert seen and seen[0] == ["last"]


def test_control_store_notifies_message_and_run_event(tmp_path) -> None:
    store = ControlStore(tmp_path / "notify.db")
    store.initialize()
    conversation = store.create_conversation("system", "owner", "notify")["id"]
    run_id = store.create_run("system", {})["id"]
    calls: list[tuple[str, dict]] = []
    unsubscribe = store.subscribe(lambda kind, meta: calls.append((kind, meta)))

    store.append_message("system", conversation, "assistant", "hola")
    store.append_run_event("system", run_id, "react.action", {"n": 1})
    assert [kind for kind, _ in calls] == ["message", "run_event"]
    assert calls[0][1]["conversation_id"] == conversation
    assert calls[1][1]["run_id"] == run_id

    unsubscribe()
    store.append_message("system", conversation, "assistant", "otra")
    assert len(calls) == 2


def test_stream_thread_drains_on_notification_not_on_a_timer(monkeypatch) -> None:
    from nexus_core.cli import session as module

    drains: list[float] = []
    callback = None

    def subscribe(receive):
        nonlocal callback
        callback = receive

        def unsubscribe() -> None:
            return None

        return unsubscribe

    store = type("Store", (), {"subscribe": staticmethod(subscribe)})()
    session = type("Session", (), {"store": store, "stream_interval": 30.0})()
    monkeypatch.setattr(module, "_drain_stream", lambda *_: drains.append(time.monotonic()))
    stop = threading.Event()
    thread = threading.Thread(
        target=module._stream_run_events.__wrapped__, args=(session, stop)
    )
    thread.start()
    try:
        deadline = time.monotonic() + 1
        while not drains and time.monotonic() < deadline:
            time.sleep(0.01)
        assert drains, "the initial cursor drain must run"
        before = len(drains)
        assert callback is not None
        callback("message", {})
        deadline = time.monotonic() + 1
        while len(drains) == before and time.monotonic() < deadline:
            time.sleep(0.01)
        assert len(drains) > before
    finally:
        stop.set()
        thread.join(2)
    assert not thread.is_alive()
