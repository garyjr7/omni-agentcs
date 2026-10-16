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
import math
import os
import time
import threading
from dataclasses import dataclass
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

#: DeepSeek request (read) timeout, in seconds. The provider can take minutes to
#: close one completion under load, and the historical 60 s cut aborted the ReAct
#: turn instead of waiting it out. Env-overridable, never below the floor that a
#: slow provider needs to answer.
DEEPSEEK_TIMEOUT_ENV = "DEEPSEEK_TIMEOUT"
DEFAULT_DEEPSEEK_TIMEOUT_SECONDS = 180.0
MIN_DEEPSEEK_TIMEOUT_SECONDS = 120.0

#: Connect/write/pool budget. Kept short so a dead endpoint fails fast and hands
#: over to the retry loop, while the read budget above stays generous for the
#: long silence between streamed tokens.
DEEPSEEK_CONNECT_TIMEOUT_SECONDS = 15.0
DEEPSEEK_WRITE_TIMEOUT_SECONDS = 30.0

#: Total attempts (first try plus retries) of one DeepSeek completion.
DEEPSEEK_ATTEMPTS_ENV = "DEEPSEEK_MAX_ATTEMPTS"
DEFAULT_DEEPSEEK_MAX_ATTEMPTS = 4
MAX_DEEPSEEK_ATTEMPTS = 8

#: Upper bound of a single retry sleep: a transient stall is waited out inside a
#: pacer window instead of stalling the run for minutes.
MAX_RETRY_SLEEP_SECONDS = 30.0

#: Statuses a retry can rescue: request timeout, conflict, too-early, rate/token
#: limit and the gateway/upstream 5xx family. Auth, malformed request and every
#: other status stay terminal so a broken key or schema never loops.
TRANSIENT_STATUS_CODES: frozenset[int] = frozenset({408, 409, 425, 429, 500, 502, 503, 504})

#: Outer request guard used by the policy router, in seconds. It must exceed the
#: provider client's own read budget, otherwise the router cancels a request the
#: client would still have completed.
LLM_REQUEST_TIMEOUT_ENV = "NEXUS_LLM_REQUEST_TIMEOUT"
DEFAULT_LLM_REQUEST_TIMEOUT_SECONDS = 300.0

#: Never sleep longer than one window: a request that cannot fit the budget even
#: alone must be *shrunk* by the caller, not delayed forever.
MAX_PACING_SLEEP_SECONDS = 60.0

#: Smallest ``max_tokens`` a retry may shrink a request down to.
MIN_COMPLETION_TOKENS = 256

#: Reference tokens-per-minute budgets of the standard tiers (public vendor
#: docs, Aug 2026). Used only to space local requests; they never gate a call.
PROVIDER_TPM: Mapping[str, int] = {
    "groq": 8_000,
    "deepseek": 1_000_000,  # Local policy; DeepSeek publishes concurrency limits.
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


def is_transient_status(status: Any) -> bool:
    """True when an HTTP status is a transient gateway/stall answer.

    Broader than :func:`is_rate_limit_status`: it also covers the upstream 5xx
    family the provider raises while its own backend is overloaded (502/504),
    the request-timeout code (408) and the conflict/too-early codes (409/425).
    Everything else (401/403/422…) is terminal, so a retry cannot turn a bad key
    or a malformed payload into a loop.
    """
    try:
        return int(status) in TRANSIENT_STATUS_CODES
    except (TypeError, ValueError):
        return False


def deepseek_timeout_seconds() -> float:
    """DeepSeek request timeout in seconds (env-overridable, floored, finite).

    ``DEEPSEEK_TIMEOUT`` below :data:`MIN_DEEPSEEK_TIMEOUT_SECONDS` is raised to
    the floor: an operator cannot re-introduce the premature-drop bug through
    configuration. A non-numeric or non-finite value falls back to the default.
    """
    raw = os.getenv(DEEPSEEK_TIMEOUT_ENV, "")
    try:
        value = float(str(raw).strip())
    except (TypeError, ValueError):
        value = DEFAULT_DEEPSEEK_TIMEOUT_SECONDS
    if not math.isfinite(value):
        return DEFAULT_DEEPSEEK_TIMEOUT_SECONDS
    return max(MIN_DEEPSEEK_TIMEOUT_SECONDS, value)


def deepseek_max_attempts() -> int:
    """Total attempts (first try plus retries) of one DeepSeek completion.

    ``DEEPSEEK_MAX_ATTEMPTS`` is clamped to ``[1, MAX_DEEPSEEK_ATTEMPTS]`` so a
    typo cannot spin forever. ``1`` disables retries entirely.
    """
    raw = os.getenv(DEEPSEEK_ATTEMPTS_ENV, "")
    try:
        value = int(str(raw).strip())
    except (TypeError, ValueError):
        value = DEFAULT_DEEPSEEK_MAX_ATTEMPTS
    return max(1, min(MAX_DEEPSEEK_ATTEMPTS, value))


def llm_request_timeout_seconds() -> float:
    """Outer request guard of the policy router, in seconds (env-overridable)."""
    raw = os.getenv(LLM_REQUEST_TIMEOUT_ENV, "")
    try:
        value = float(str(raw).strip())
    except (TypeError, ValueError):
        value = DEFAULT_LLM_REQUEST_TIMEOUT_SECONDS
    if not math.isfinite(value) or value <= 0:
        return DEFAULT_LLM_REQUEST_TIMEOUT_SECONDS
    return value


def mentions_output_token_limit(error: Any) -> bool:
    """True when a 429 is about the *output* reservation, not the request rate.

    Groq answers a ``max_tokens`` larger than the model's per-minute output
    budget (OTPM) with **429**, not 413 (Fase 4.0: ``qwen/qwen3.8-27b`` has
    OTPM 1000 while the ReAct default reserved 1536). The body names the output
    limit, so the client can shrink the reservation exactly like the 413 path
    instead of retrying the same oversized request forever.
    """
    text = str(error).lower()
    return "output tokens per minute" in text or "otpm" in text or "reduce max_tokens" in text


def mentions_input_token_limit(error: Any) -> bool:
    """True when a 413 is about the *input* size, not the output reservation.

    Free-tier Groq enforces a per-minute **input** budget (ITPM). Fase 4.0: with
    ``qwen/qwen3.8-27b`` (ITPM 7000) the accumulated ReAct context reached 7136
    and every retry failed, because shrinking ``max_tokens`` cannot shrink the
    prompt. Detecting this lets the client trim the conversation instead.
    """
    text = str(error).lower()
    return "input tokens per minute" in text or "itpm" in text


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


@dataclass(frozen=True)
class Reservation:
    ticket: int
    provider: str
    created: float
    tokens: int


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
        rpm: Mapping[str, int] | None = None,
    ) -> None:
        self.rpm = dict(rpm or {})
        self._lock = threading.RLock()
        self._reservations: dict[int, Reservation] = {}
        self._requests: dict[str, deque[float]] = {}
        self._next_ticket = 0
        self.tpm = dict(tpm if tpm is not None else PROVIDER_TPM)
        self.clock = clock
        self.sleep = sleep or asyncio.sleep
        self.window = window
        self._events: dict[str, deque[tuple[float, int]]] = {}

    async def reserve(self, provider: str, *, estimated_tokens: int) -> Reservation:
        """Atomically reserve estimated TPM and one RPM slot before dispatch.

        This is process-local, across threads/event loops. Waiting never holds
        the lock. Oversized requests fail immediately instead of waiting forever.
        """
        key = provider.lower()
        if estimated_tokens < 0:
            raise ValueError("estimated_tokens must be nonnegative")
        limit = self.limit(key)
        rpm = self.rpm.get(key, 0)
        enabled = _env_flag(TPM_PACING_ENV)
        if enabled and limit and estimated_tokens > limit:
            raise ValueError("request exceeds configured TPM; reduce context or max_tokens")
        while True:
            with self._lock:
                now = self.clock()
                cutoff = now - self.window
                self._prune(key)
                requests = self._requests.setdefault(key, deque())
                while requests and requests[0] <= cutoff:
                    requests.popleft()
                pending = [
                    r
                    for r in self._reservations.values()
                    if r.provider == key and r.created > cutoff
                ]
                events = list(self._events.get(key, ())) + [(r.created, r.tokens) for r in pending]
                token_full = bool(
                    limit and sum(amount for _, amount in events) + estimated_tokens > limit
                )
                request_full = bool(rpm and len(requests) >= rpm)
                if not enabled or not (token_full or request_full):
                    self._next_ticket += 1
                    reservation = Reservation(self._next_ticket, key, now, estimated_tokens)
                    self._reservations[reservation.ticket] = reservation
                    requests.append(now)
                    return reservation
                expiries = [stamp + self.window for stamp, _ in events] if token_full else []
                if request_full:
                    expiries.append(requests[0] + self.window)
                delay = max(0.001, min(expiries) - now)
            await self.sleep(delay)

    def settle(self, reservation: Reservation, actual_tokens: int | None = None) -> None:
        """Replace reservation with usage; retain estimate when usage is unknown.

        Failed/cancelled requests retain their RPM slot and estimated token cost.
        Calling twice is harmless; no successful request is charged twice.
        """
        with self._lock:
            item = self._reservations.pop(reservation.ticket, None)
            if item is None:
                return
            amount = item.tokens if actual_tokens is None else max(0, actual_tokens)
            events = self._events.setdefault(item.provider, deque())
            events.append((item.created, amount))
            self._events[item.provider] = deque(sorted(events))
            self._prune(item.provider)

    # ------------------------------------------------------------------ state
    def _prune(self, key: str) -> None:
        events = self._events.get(key)
        if not events:
            return
        cutoff = self.clock() - self.window
        while events and events[0][0] <= cutoff:
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
        with self._lock:
            self._events.clear()
            self._reservations.clear()
            self._requests.clear()

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
    DEEPSEEK_PACER.reset()


async def pace_request(provider: Any, *, estimated_tokens: int) -> float:
    """Wait (if needed) before sending a request from the shared pacer."""
    return await PACER.wait(provider, estimated_tokens=estimated_tokens)


def record_provider_usage(provider: Any, tokens: Any) -> None:
    """Record observed usage in the shared pacer."""
    PACER.record(provider, tokens)


__all__ = [
    "BACKOFF_BASE_ENV",
    "DEFAULT_BACKOFF_BASE_SECONDS",
    "DEFAULT_DEEPSEEK_MAX_ATTEMPTS",
    "DEFAULT_DEEPSEEK_TIMEOUT_SECONDS",
    "DEFAULT_LLM_REQUEST_TIMEOUT_SECONDS",
    "DEEPSEEK_ATTEMPTS_ENV",
    "DEEPSEEK_CONNECT_TIMEOUT_SECONDS",
    "DEEPSEEK_TIMEOUT_ENV",
    "DEEPSEEK_WRITE_TIMEOUT_SECONDS",
    "LLM_REQUEST_TIMEOUT_ENV",
    "MAX_DEEPSEEK_ATTEMPTS",
    "MAX_PACING_SLEEP_SECONDS",
    "MAX_RETRY_SLEEP_SECONDS",
    "MIN_COMPLETION_TOKENS",
    "MIN_DEEPSEEK_TIMEOUT_SECONDS",
    "PACER",
    "PROVIDER_TPM",
    "RATE_LIMIT_STATUS_CODES",
    "TPM_PACING_ENV",
    "TRANSIENT_STATUS_CODES",
    "WINDOW_SECONDS",
    "TokenPacer",
    "backoff_base_seconds",
    "deepseek_max_attempts",
    "deepseek_timeout_seconds",
    "estimate_request_tokens",
    "is_rate_limit_status",
    "is_transient_status",
    "llm_request_timeout_seconds",
    "mentions_input_token_limit",
    "mentions_output_token_limit",
    "pace_request",
    "provider_tpm",
    "record_provider_usage",
    "reset_pacer",
]


def deepseek_limits() -> tuple[int, int]:
    """Local operator budgets, not published DeepSeek service quotas."""
    values = []
    for name, default in (("DEEPSEEK_TPM", 1_000_000), ("DEEPSEEK_RPM", 60)):
        raw = os.getenv(name, str(default))
        try:
            value = int(raw)
        except ValueError:
            raise ValueError(f"{name} must be a nonnegative integer") from None
        if value < 0:
            raise ValueError(f"{name} must be a nonnegative integer")
        values.append(value)
    return values[0], values[1]


DEEPSEEK_PACER = TokenPacer(tpm={"deepseek": 1_000_000}, rpm={"deepseek": 60})
