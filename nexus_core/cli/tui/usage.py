"""Observe actual LLM response usage without changing the agent or kernel."""

import math
import os


class MeteredClient:
    def __init__(self, client, callback):
        self._client = client
        self._callback = callback

    def __getattr__(self, name):
        return getattr(self._client, name)

    async def complete(self, *args, **kwargs):
        response = await self._client.complete(*args, **kwargs)
        self._callback(response)
        return response

    async def stream(self, *args, **kwargs):
        """Yield chunks while recording the usage the provider reports at the end."""
        async for chunk in self._client.stream(*args, **kwargs):
            yield chunk
        response = getattr(self._client, "last_stream_response", None)
        if response is not None:
            self._callback(response)


def _resolve_rates(provider: str, model: str | None):
    """Env override first, then the reference price table (P1)."""
    try:
        input_rate = float(os.environ["NEXUS_TUI_INPUT_USD_PER_MTOK"])
        output_rate = float(os.environ["NEXUS_TUI_OUTPUT_USD_PER_MTOK"])
        if min(input_rate, output_rate) < 0 or not all(
            map(math.isfinite, (input_rate, output_rate))
        ):
            raise ValueError("invalid rates")
        return input_rate, output_rate
    except (KeyError, ValueError):
        pass
    from .pricing import default_rates

    return default_rates(model or "", provider)


def response_usage(response):
    incoming = max(0, int(getattr(response, "tokens_input", 0) or 0))
    outgoing = max(0, int(getattr(response, "tokens_output", 0) or 0))
    provider = getattr(response, "provider", "")
    provider = getattr(provider, "value", provider)
    if provider in {"fake", "ollama"}:
        return incoming, outgoing, 0.0
    model = getattr(response, "model", "")
    rates = _resolve_rates(str(provider), str(model) if model else None)
    if rates is None:
        return incoming, outgoing, None
    input_rate, output_rate = rates
    cost = (incoming * input_rate + outgoing * output_rate) / 1_000_000
    return incoming, outgoing, cost
