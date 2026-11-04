"""Coalesce durable-store notifications into paced UI updates.

The agent writes a message or a run event on its own thread; waking the
renderer for every row would redraw the transcript dozens of times per second.
``UpdateBatcher`` collects those wakes and flushes them once per interval,
which mirrors React's batched message updater without owning any UI state.
"""

from __future__ import annotations

import threading
from typing import Any, Callable

#: The flush window: short enough to feel live, long enough that a burst of
#: tool rows becomes one redraw.
BATCH_MIN_SECONDS = 0.05
BATCH_MAX_SECONDS = 0.10
BATCH_DEFAULT_SECONDS = 0.075


class UpdateBatcher:
    """A push queue: ``post`` from any thread, ``flush`` on a worker.

    ``flush`` receives every item posted since the previous flush. It runs on
    the batcher thread, never on the writer's thread, so a slow renderer cannot
    block the agent's durable append. A stop flushes whatever is still queued.
    """

    def __init__(
        self,
        flush: Callable[[list[Any]], None],
        *,
        interval: float = BATCH_DEFAULT_SECONDS,
        name: str = "omni-ui-batcher",
    ) -> None:
        self._flush = flush
        self.interval = max(BATCH_MIN_SECONDS, min(BATCH_MAX_SECONDS, float(interval)))
        self._name = name
        self._lock = threading.Lock()
        self._items: list[Any] = []
        self._wake = threading.Event()
        self._stopped = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> "UpdateBatcher":
        if self._thread is not None and self._thread.is_alive():
            return self
        self._stopped.clear()
        self._thread = threading.Thread(target=self._run, name=self._name, daemon=True)
        self._thread.start()
        return self

    def post(self, item: Any = None) -> None:
        """Queue one update and wake the worker; never blocks on rendering."""
        with self._lock:
            self._items.append(item)
        self._wake.set()

    def _take(self) -> list[Any]:
        with self._lock:
            items, self._items = self._items, []
        return items

    def _run(self) -> None:
        try:
            while not self._stopped.is_set():
                if not self._wake.wait(timeout=0.5):
                    continue
                # A burst inside this quiet window becomes one flush. Clear
                # before taking so a post during the wait is in this batch.
                self._wake.clear()
                self._stopped.wait(self.interval)
                items = self._take()
                if items:
                    self._flush(items)
        finally:
            items = self._take()
            if items:
                self._flush(items)

    def stop(self, *, timeout: float = 2.0) -> None:
        self._stopped.set()
        self._wake.set()
        thread = self._thread
        if thread is not None and thread.is_alive():
            thread.join(timeout=timeout)
        self._thread = None

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()
