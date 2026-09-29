"""Anthropic Messages API adapter using the existing httpx dependency."""

import time
import httpx

from .abstraction import BaseLLMClient, LLMResponse, NexusLLMError


class AnthropicClient(BaseLLMClient):
    def is_available(self):
        return bool(self.config.api_key)

    async def complete(self, messages, **kwargs):
        if not self.is_available():
            raise NexusLLMError("Anthropic API key is required")
        start = time.perf_counter()
        system = (
            "\n".join(m.content for m in messages if m.role == "system")
            or self.config.system_prompt
        )
        payload = {
            "model": self.config.model,
            "messages": [
                {"role": m.role, "content": m.content} for m in messages if m.role != "system"
            ],
            "max_tokens": kwargs.get("max_tokens", self.config.max_tokens),
        }
        if system:
            payload["system"] = system
        try:
            async with httpx.AsyncClient(timeout=self.config.timeout) as client:
                response = await client.post(
                    "https://api.anthropic.com/v1/messages",
                    json=payload,
                    headers={"x-api-key": self.config.api_key, "anthropic-version": "2023-06-01"},
                )
                response.raise_for_status()
                data = response.json()
            content = "".join(part["text"] for part in data["content"] if part["type"] == "text")
            usage = data.get("usage", {})
        except (httpx.HTTPError, ValueError, KeyError, TypeError):
            raise NexusLLMError("Anthropic request failed") from None
        return LLMResponse(
            content=content,
            model=self.config.model,
            provider=self.config.provider,
            tokens_input=usage.get("input_tokens", 0),
            tokens_output=usage.get("output_tokens", 0),
            duration_ms=(time.perf_counter() - start) * 1000,
            raw_response=data,
        )
