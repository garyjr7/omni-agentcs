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


def response_usage(response):
    incoming = max(0, int(getattr(response, "tokens_input", 0) or 0))
    outgoing = max(0, int(getattr(response, "tokens_output", 0) or 0))
    provider = getattr(response, "provider", "")
    provider = getattr(provider, "value", provider)
    if provider in {"fake", "ollama"}:
        return incoming, outgoing, 0.0
    try:
        input_rate = float(os.environ["NEXUS_TUI_INPUT_USD_PER_MTOK"])
        output_rate = float(os.environ["NEXUS_TUI_OUTPUT_USD_PER_MTOK"])
        if min(input_rate, output_rate) < 0 or not all(map(math.isfinite, (input_rate, output_rate))):
            raise ValueError("invalid rates")
        cost = (incoming * input_rate + outgoing * output_rate) / 1_000_000
    except (KeyError, ValueError):
        cost = None
    return incoming, outgoing, cost
