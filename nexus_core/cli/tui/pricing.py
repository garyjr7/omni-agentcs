"""Reference LLM list prices for cost accounting (P1 of the E2E report).

``cli/tui/usage.py`` only computed a USD cost when the operator exported
``NEXUS_TUI_INPUT_USD_PER_MTOK``/``NEXUS_TUI_OUTPUT_USD_PER_MTOK``; without them
the E2E recorded ``_cost_known=False``. These are *reference list prices per
million tokens* (public vendor pricing) used only for local reporting. They are
best-effort: an explicit env override always wins, and an unknown model returns
``None`` so the cost is reported as unknown rather than invented.

Prices are for internal accounting, not billing. Update the table when a vendor
changes its list price.
"""

from __future__ import annotations

from typing import Mapping

from nexus_core.llm.limits import PROVIDER_TPM as _PROVIDER_TPM

#: Reference tokens-per-minute budgets of each provider's standard tier, used by
#: the LLM client to space requests instead of earning a 413/429 (B5). Documented
#: here next to the prices because both are "what the provider charges/allows";
#: the single source of truth lives in ``nexus_core.llm.limits``.
PROVIDER_TPM: Mapping[str, int] = _PROVIDER_TPM

#: Key -> (input USD / 1M tokens, output USD / 1M tokens). Keys match a model
#: name by longest-substring; a provider key applies when no model matches.
REFERENCE_RATES_USD_PER_MTOK: Mapping[str, tuple[float, float]] = {
    # Groq (the E2E provider). Source: Groq public pricing, Aug 2026.
    # ``qwen3.8-27b`` is the Fase 3.8 default and is used on the free tier only
    # (no billing), so its reference cost is reported as zero rather than a
    # paid list price. See docs/missions/FASE38_MODEL_CHANGE.md.
    "qwen3.8-27b": (0.0, 0.0),
    "gpt-oss-120b": (0.15, 0.60),
    "gpt-oss-20b": (0.10, 0.50),
    "llama-3.3-70b": (0.59, 0.79),
    "llama-3.1-8b": (0.05, 0.08),
    # OpenAI.
    "gpt-4o-mini": (0.15, 0.60),
    "gpt-4o": (2.50, 10.00),
    "gpt-4.1-mini": (0.40, 1.60),
    "o3-mini": (1.10, 4.40),
    # Anthropic.
    "claude-3-5-sonnet": (3.00, 15.00),
    "claude-3-5-haiku": (0.80, 4.00),
    # Google.
    "gemini-2.0-flash": (0.10, 0.40),
    "gemini-1.5-flash": (0.075, 0.30),
    # DeepSeek. V4.1 Flash: $0.15/M input (cache miss) and $0.60/M output
    # off-peak; the peak rate doubles. Source: DeepSeek API docs / vendor
    # coverage of the Sep 2026 V4.1-Flash release (see FASE36_CLOSE_E2E.md).
    # ``deepseek-chat`` is the older, pricier model and keeps its own row.
    "deepseek-v4.1-flash": (0.15, 0.60),
    # The client normalizes the V4.1-Flash product name to its API identifier
    # (``DeepSeekClient._client`` -> ``deepseek-flash``), and that identifier is
    # what reaches the meter, so it needs its own row: without it every
    # DeepSeek run reported an unknown cost (``$—``).
    "deepseek-flash": (0.15, 0.60),
    "deepseek-chat": (0.27, 1.10),
}

#: Fallback by provider when the model name is unrecognised. Deliberately sparse:
#: an unknown provider stays "cost unknown" rather than reporting a wrong number.
PROVIDER_FALLBACK: Mapping[str, tuple[float, float]] = {
    "groq": (0.15, 0.60),
}


def default_rates(model: str, provider: str | None = None) -> tuple[float, float] | None:
    """Return ``(input, output)`` USD/1M tokens for a model, or ``None``."""
    model_lower = str(model or "").lower()
    matches = [
        (key, rates)
        for key, rates in REFERENCE_RATES_USD_PER_MTOK.items()
        if key in model_lower
    ]
    if matches:
        # Longest key wins so "gpt-4o-mini" beats "gpt-4o".
        return max(matches, key=lambda item: len(item[0]))[1]
    if provider:
        return PROVIDER_FALLBACK.get(str(provider).lower())
    return None


__all__ = [
    "PROVIDER_FALLBACK",
    "PROVIDER_TPM",
    "REFERENCE_RATES_USD_PER_MTOK",
    "default_rates",
]
