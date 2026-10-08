"""Observe actual LLM response usage without changing the agent or kernel."""

import math
import os
import json


class MeteredClient:
    def __init__(self, client, callback, context_callback=None):
        self._client = client
        self._callback = callback
        self._context_callback = context_callback

    def __getattr__(self, name):
        return getattr(self._client, name)

    async def complete(self, *args, **kwargs):
        messages = args[0] if args else kwargs.get('messages', [])
        track = self._context(messages)
        response = await self._client.complete(*args, **kwargs)
        self._callback(response)
        if track:
            self._context(messages, response)
        return response

    async def stream(self, *args, **kwargs):
        """Yield chunks while recording the usage the provider reports at the end."""
        messages = args[0] if args else kwargs.get('messages', [])
        track = self._context(messages)
        async for chunk in self._client.stream(*args, **kwargs):
            yield chunk
        response = getattr(self._client, "last_stream_response", None)
        if response is not None:
            self._callback(response)
            if track:
                self._context(messages, response)

    def _context(self, messages, response=None):
        if self._context_callback is None:
            return False
        contents = [str(m.get('content','') if isinstance(m,dict) else getattr(m,'content','')) for m in messages]
        # Summarizer requests spend tokens but do not replace the active conversation.
        if contents and contents[0] == 'Eres un compresor de contexto preciso.':
            return False
        incoming = getattr(response,'tokens_input',None)
        measured = incoming is not None and incoming > 0
        tokens = incoming + (getattr(response,'tokens_output',0) or 0) if measured else sum((len(s)+3)//4 for s in contents)
        self._context_callback(dict(context_tokens=tokens,
            context_window=context_window(self._client,response),
            context_source='provider' if measured else 'estimate'))
        return True


def context_window(client, response=None):
    """Explicit deployment metadata; unknown models never inherit a guessed limit."""
    try:
        explicit = os.getenv('NEXUS_CONTEXT_WINDOW')
        if explicit:
            value = int(explicit)
        else:
            model = getattr(response,'model',None) or getattr(client,'model','')
            provider = getattr(response,'provider',None) or getattr(client,'provider','')
            provider = getattr(provider,'value',provider)
            configured = json.loads(os.getenv('NEXUS_CONTEXT_WINDOWS','{}'))
            value = configured.get(f'{provider}/{model}',getattr(client,'context_window',None))
        return int(value) if value is not None and int(value)>0 else None
    except (ValueError,TypeError,AttributeError):
        return None


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
