"""Provider request limits: 413 is a rate limit, and TPM is a budget (B5).

Groq's on-demand tier answers a request whose prompt **plus the reserved**
``max_tokens`` exceeds the per-minute token budget with HTTP ``413 Request too
large``, not ``429``. The E2E run #2 died exactly there: the client only retried
``openai.RateLimitError``, so a 413 aborted the loop instead of being retried
with a smaller completion reservation.

Two things live here:

* :func:`is_rate_limit_status` — the statuses that mean "too much, too fast"
  (413/429/503), so the client can retry them uniformly;
* :class:`TokenPacer` — a per-provider rolling-60s token counter. A provider with
  ``TPM=8000`` cannot serve two ~7k-token ReAct turns back to back; pacing waits
  out the window instead of burning a request that is guaranteed to fail.

Nothing here talks to a provider. The TPM numbers are *reference* values for
local pacing (documented in ``cli/tui/pricing.py``); an unknown provider is never
paced (it returns ``None``), and pacing is disabled with
``NEXUS_LLM_TPM_PACING=0``.
"""

from __future__ import annotations

import asyncio
import os
import time
from collections import deque
from typing import Any, Callable, Mapping

#: The rolling window of a tokens-per-minute budget.
WINDOW_SECONDS = 60.0

#: Statuses that mean the request (or its reservation) went over a rate budget.
#: 413 is included deliberately: providers use it for the per-minute token limit.
RATE_LIMIT_STATUS_CODES: frozenset[int] = frozenset({413, 429, 503})

#: Set to ``0`` to disable pacing entirely (CI, tests, a provider with a huge
#: budget). Read at call time so a test can flip it per-case.
TPM_PACING_ENV = "NEXUS_LLM_TPM_PACING"

#: Retry backoff base, in seconds (a test/CI can set it to 0).
BACKOFF_BASE_ENV = "NEXUS_LLM_BACKOFF_SECONDS"
DEFAULT_BACKOFF_BASE_SECONDS = 2.0

#: Never sleep longer than one window: a request that cannot fit the budget even
#: alone must be *shrunk* by the caller, not delayed forever.
MAX_PACING_SLEEP_SECONDS = 60.0

#: Smallest ``max_tokens`` a retry may shrink a request down to.
MIN_COMPLETION_TOKENS = 256

#: Reference tokens-per-minute budgets of the standard tiers (public vendor
#: docs, Aug 2026). Used only to space local requests; they never gate a call.
PROVIDER_TPM: Mapping[str, int] = {
    "groq": 8_000,
    "deepseek": 1_000_000,
    "openai": 500_000,
    "openai_compatible": 500_000,
    "anthropic": 400_000,
    "gemini": 1_000_000,
    "ollama": 0,  # local: no provider budget to respect
}


def _env_flag(name: str, default: bool = True) -> bool:
    raw = os.getenv(name)
    if raw is None or str(raw).strip() == "":
        return default
    return str(raw).strip().lower() in {"1", "true", "yes", "on"}


def backoff_base_seconds() -> float:
    """Retry backoff base in seconds (env-overridable; never negative)."""
    raw = os.getenv(BACKOFF_BASE_ENV, "")
    try:
        return max(0.0, float(str(raw).strip()))
    except (TypeError, ValueError):
        return DEFAULT_BACKOFF_BASE_SECONDS


def is_rate_limit_status(status: Any) -> bool:
    """True when an HTTP status is a rate/token-limit answer worth retrying."""
    try:
        return int(status) in RATE_LIMIT_STATUS_CODES
    except (TypeError, ValueError):
        return False


def provider_tpm(provider: Any) -> int | None:
    """Reference TPM of a provider (``None`` when unknown; ``0`` means unlimited)."""
    key = str(getattr(provider, "value", provider) or "").strip().lower()
    if not key:
        return None
    value = PROVIDER_TPM.get(key)
    return None if value is None else int(value)


def estimate_request_tokens(messages: Any, max_tokens: int) -> int:
    """Cheap request estimate: ≈4 characters per token + the reservation.

    The reservation is counted because that is exactly what a TPM-limited
    provider bills against the request (the failure in run #2 was
    ``Requested 8438`` for a ~4.3k-token prompt with ``max_tokens=4096``).
    """
    chars = 0
    for message in messages or ():
        chars += len(str(getattr(message, "content", "") or ""))
    return max(1, chars // 4) + max(0, int(max_tokens))


class TokenPacer:
    """Keep a provider's rolling-window token usage under its TPM budget.

    Usage is recorded from *observed* responses, so the very first request of a
    process is never delayed (there is nothing to pace against yet) and a
    provider that reports no usage is never paced. Injected ``clock``/``sleep``
    make the whole thing deterministic in tests.
    """

    def __init__(
        self,
        *,
        tpm: Mapping[str, int] | None = None,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], Any] | None = None,
        window: float = WINDOW_SECONDS,
    ) -> None:
        self.tpm = dict(tpm if tpm is not None else PROVIDER_TPM)
        self.clock = clock
        self.sleep = sleep or asyncio.sleep
        self.window = window
        self._events: dict[str, deque[tuple[float, int]]] = {}

    # ------------------------------------------------------------------ state
    def _prune(self, key: str) -> None:
        events = self._events.get(key)
        if not events:
            return
        cutoff = self.clock() - self.window
        while events and events[0][0] < cutoff:
            events.popleft()

    def usage(self, provider: Any) -> int:
        """Tokens recorded for a provider inside the current window."""
        key = str(getattr(provider, "value", provider) or "").strip().lower()
        self._prune(key)
        return sum(tokens for _, tokens in self._events.get(key, ()))

    def record(self, provider: Any, tokens: Any) -> None:
        """Record the tokens a completed request actually consumed."""
        try:
            amount = int(tokens)
        except (TypeError, ValueError):
            return
        if amount <= 0:
            return
        key = str(getattr(provider, "value", provider) or "").strip().lower()
        if not key:
            return
        self._events.setdefault(key, deque()).append((self.clock(), amount))

    def limit(self, provider: Any) -> int | None:
        """TPM of a provider inside this pacer (``None`` = do not pace)."""
        key = str(getattr(provider, "value", provider) or "").strip().lower()
        value = self.tpm.get(key)
        if value is None:
            return None
        return int(value) or None

    def reset(self) -> None:
        """Forget every recorded event (tests, or an operator after a plan change)."""
        self._events.clear()

    # ---------------------------------------------------------------- pacing
    async def wait(self, provider: Any, *, estimated_tokens: int) -> float:
        """Sleep just enough that ``estimated_tokens`` fits the provider budget.

        Returns the seconds slept (0.0 when no wait was needed). Bounded: at most
        ``MAX_PACING_SLEEP_SECONDS`` per call, and the loop runs twice so a
        request that is small next to the budget still gets analysed instead of
        waiting for the whole window.
        """
        limit = self.limit(provider)
        if limit is None or not _env_flag(TPM_PACING_ENV, default=True):
            return 0.0
        estimate = max(0, int(estimated_tokens))
        slept = 0.0
        for _ in range(2):
            key = str(getattr(provider, "value", provider) or "").strip().lower()
            self._prune(key)
            events = self._events.get(key)
            used = sum(tokens for _, tokens in events or ())
            if used <= 0:
                return slept
            overflow = used + estimate - limit
            if overflow <= 0:
                return slept
            if not events:  # pragma: no cover - defensive, events were non-empty
                return slept
            delay = min(
                MAX_PACING_SLEEP_SECONDS,
                max(0.0, events[0][0] + self.window - self.clock()),
            )
            if delay <= 0:
                return slept
            await self.sleep(delay)
            slept += delay
        return slept


#: Process-wide pacer used by the OpenAI-compatible client (Groq, OpenAI,
#: DeepSeek, ...). Kept module-level so every client instance shares the budget.
PACER = TokenPacer()


def reset_pacer() -> None:
    """Drop every recorded event of the shared pacer (tests/operators)."""
    PACER.reset()


async def pace_request(provider: Any, *, estimated_tokens: int) -> float:
    """Wait (if needed) before sending a request from the shared pacer."""
    return await PACER.wait(provider, estimated_tokens=estimated_tokens)


def record_provider_usage(provider: Any, tokens: Any) -> None:
    """Record observed usage in the shared pacer."""
    PACER.record(provider, tokens)


__all__ = [
    "BACKOFF_BASE_ENV",
    "DEFAULT_BACKOFF_BASE_SECONDS",
    "MAX_PACING_SLEEP_SECONDS",
    "MIN_COMPLETION_TOKENS",
    "PACER",
    "PROVIDER_TPM",
    "RATE_LIMIT_STATUS_CODES",
    "TPM_PACING_ENV",
    "WINDOW_SECONDS",
    "TokenPacer",
    "backoff_base_seconds",
    "estimate_request_tokens",
    "is_rate_limit_status",
    "pace_request",
    "provider_tpm",
    "record_provider_usage",
    "reset_pacer",
]
