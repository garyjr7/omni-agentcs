# nexus_core/llm/abstraction.py

"""
Provides a provider-agnostic abstraction layer for interacting with LLMs.

This module defines a unified interface for various LLM providers like OpenAI,
Google Gemini, and local Ollama instances. It includes:
- Data classes for configuration, messages, and standardized responses.
- An abstract base class `BaseLLMClient` to enforce a common contract.
- Concrete client implementations for different providers.
- A `LLMFactory` for easy instantiation of clients.
- A `NexusLLM` wrapper that provides high-level features like automatic
  provider fallback and performance tracking.
"""

import abc
import asyncio
import json
import logging
import os
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    import httpx
    HTTPX_AVAILABLE = True
except ImportError:
    httpx = None
    HTTPX_AVAILABLE = False

# Conditional imports for provider-specific libraries
try:
    import openai
    from openai import AsyncOpenAI
    from openai.types.chat import ChatCompletion
    OPENAI_AVAILABLE = True
except ImportError:
    OPENAI_AVAILABLE = False

try:
    from google import genai
    from google.genai import types as genai_types
    GEMINI_AVAILABLE = True
except ImportError:
    GEMINI_AVAILABLE = False

# Assuming a logger utility exists. If not, a standard logger is used.
try:
    from nexus_core.utils.logger import get_logger
except ImportError:
    def get_logger(name: str) -> logging.Logger:
        """Provides a basic logger instance."""
        logger = logging.getLogger(name)
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)
        logger.setLevel(logging.INFO)
        return logger

# --- Custom Exception ---

class NexusLLMError(Exception):
    """Custom exception for errors within the NexusLLM layer."""
    pass

# --- Data Classes and Enums ---

class LLMProvider(str, Enum):
    """Enumerates the supported LLM providers."""
    OPENAI = "openai"
    GEMINI = "gemini"
    OLLAMA = "ollama"
    FAKE = "fake"
    GROQ = "groq"
    OPENAI_COMPATIBLE = "openai_compatible"
    ANTHROPIC = "anthropic"

@dataclass
class LLMConfig:
    """
    Configuration for an LLM client.

    Attributes:
        provider: The LLM provider to use.
        model: The specific model name for the provider.
        api_key: The API key for authentication (if required).
        base_url: The base URL for the API, primarily for Ollama.
        temperature: The sampling temperature for generation.
        max_tokens: The maximum number of tokens to generate.
        timeout: The request timeout in seconds.
        system_prompt: A default system prompt to prepend to conversations.
    """
    provider: LLMProvider
    model: str
    api_key: Optional[str] = None
    base_url: Optional[str] = None
    temperature: float = 0.1
    max_tokens: int = 4096
    timeout: int = 60
    system_prompt: Optional[str] = None

@dataclass
class LLMMessage:
    """Represents a single message in a conversation history."""
    role: str  # "system", "user", or "assistant"
    content: str

@dataclass
class LLMResponse:
    """
    A standardized response object from an LLM completion call.
    """
    content: str
    model: str
    provider: LLMProvider
    tokens_input: int = 0
    tokens_output: int = 0
    duration_ms: float = 0.0
    raw_response: Optional[Dict[str, Any]] = field(default=None, repr=False)

    @property
    def total_tokens(self) -> int:
        """The sum of input and output tokens."""
        return self.tokens_input + self.tokens_output

# --- Abstract Base Client ---

class BaseLLMClient(abc.ABC):
    """
    Abstract base class for all LLM clients.
    """
    #: Providers that emit real token deltas override ``stream`` and set this
    #: to True; the CLI only enables the streaming UI when it is True.
    supports_streaming = False

    def __init__(self, config: LLMConfig):
        self.config = config
        self._logger = get_logger(f"LLMClient.{self.config.provider.value}")

    @abc.abstractmethod
    async def complete(
        self, messages: List[LLMMessage], **kwargs: Any
    ) -> LLMResponse:
        """
        Generates a completion for a given conversation history.

        Args:
            messages: A list of LLMMessage objects representing the conversation.
            **kwargs: Provider-specific arguments to override config.

        Returns:
            An LLMResponse object with the completion details.
        """
        raise NotImplementedError

    async def stream(self, messages: List[LLMMessage], **kwargs: Any):
        """Yield the response content in chunks.

        The default implementation delegates to :meth:`complete` and yields the
        whole answer once, so every provider keeps working. Providers with real
        token streaming override it and set ``supports_streaming = True``.
        """
        response = await self.complete(messages, **kwargs)
        self._last_stream_response = response
        yield response.content

    @property
    def last_stream_response(self) -> Optional[LLMResponse]:
        """Usage of the most recent :meth:`stream` call, when the provider reports it."""
        return getattr(self, "_last_stream_response", None)

    @abc.abstractmethod
    def is_available(self) -> bool:
        """
        Checks if the client is configured and ready to use.

        Returns:
            True if the client is available, False otherwise.
        """
        raise NotImplementedError

    async def ask(
        self, system_prompt: str, user_message: str, **kwargs: Any
    ) -> str:
        """
        A shortcut method for a simple two-turn conversation.

        Args:
            system_prompt: The system message to guide the model.
            user_message: The user's query.
            **kwargs: Provider-specific arguments.

        Returns:
            The string content of the model's response.
        """
        messages = [
            LLMMessage(role="system", content=system_prompt),
            LLMMessage(role="user", content=user_message),
        ]
        response = await self.complete(messages, **kwargs)
        return response.content

# --- Concrete Client Implementations ---

class OpenAIClient(BaseLLMClient):
    """LLM client for OpenAI models."""

    #: OpenAI, Groq and compatible endpoints all support SSE token streaming.
    supports_streaming = True

    def __init__(self, config: LLMConfig):
        super().__init__(config)
        if not OPENAI_AVAILABLE:
            raise ImportError("The 'openai' library is not installed. Please install it with 'pip install openai'.")
        if not self.config.api_key:
            raise ValueError("OpenAI API key is required for OpenAIClient.")
        
        client_options = {
            "api_key": self.config.api_key,
            "timeout": self.config.timeout,
        }
        if self.config.base_url:
            client_options["base_url"] = self.config.base_url
        self.client = AsyncOpenAI(**client_options)

    def is_available(self) -> bool:
        return bool(self.config.api_key)

    async def complete(
        self, messages: List[LLMMessage], **kwargs: Any
    ) -> LLMResponse:
        start_time = time.perf_counter()
        
        # Prepare messages for OpenAI API
        api_messages = [{"role": m.role, "content": m.content} for m in messages]
        if self.config.system_prompt and api_messages[0]["role"] != "system":
            api_messages.insert(0, {"role": "system", "content": self.config.system_prompt})

        request_params = {
            "model": self.config.model,
            "messages": api_messages,
            "temperature": kwargs.get("temperature", self.config.temperature),
            "max_tokens": kwargs.get("max_tokens", self.config.max_tokens),
        }

        max_retries = 3
        backoff_factor = 2.0
        for attempt in range(max_retries):
            try:
                response: ChatCompletion = await self.client.chat.completions.create(**request_params)
                duration_ms = (time.perf_counter() - start_time) * 1000

                usage = response.usage
                return LLMResponse(
                    content=response.choices[0].message.content or "",
                    model=self.config.model,
                    provider=self.config.provider,
                    tokens_input=usage.prompt_tokens if usage else 0,
                    tokens_output=usage.completion_tokens if usage else 0,
                    duration_ms=duration_ms,
                    raw_response=response.model_dump(),
                )
            except openai.RateLimitError as e:
                if attempt + 1 == max_retries:
                    self._logger.error("OpenAI rate limit exceeded after max retries.")
                    raise NexusLLMError("OpenAI rate limit exceeded") from e
                
                wait_time = backoff_factor * (2 ** attempt)
                self._logger.warning(f"OpenAI rate limit hit. Retrying in {wait_time:.2f}s...")
                await asyncio.sleep(wait_time)
            except openai.APIError as e:
                self._logger.error(f"OpenAI API error: {e}")
                raise NexusLLMError(f"OpenAI API error: {e}") from e
        
        # This line should not be reachable
        raise NexusLLMError("OpenAI request failed after all retries.")

    async def stream(self, messages: List[LLMMessage], **kwargs: Any):
        """Yield token deltas as they arrive (SSE streaming).

        Usage is captured from the final chunk when the endpoint supports
        ``stream_options`` (OpenAI and Groq do); otherwise output tokens are
        approximated from the received text so the status bar stays meaningful.
        """
        start_time = time.perf_counter()
        api_messages = [{"role": m.role, "content": m.content} for m in messages]
        if self.config.system_prompt and api_messages[0]["role"] != "system":
            api_messages.insert(0, {"role": "system", "content": self.config.system_prompt})

        request_params: Dict[str, Any] = {
            "model": self.config.model,
            "messages": api_messages,
            "temperature": kwargs.get("temperature", self.config.temperature),
            "max_tokens": kwargs.get("max_tokens", self.config.max_tokens),
            "stream": True,
        }
        if self.config.provider in (LLMProvider.OPENAI, LLMProvider.GROQ):
            request_params["stream_options"] = {"include_usage": True}

        collected: List[str] = []
        usage_input = usage_output = 0
        try:
            response = await self.client.chat.completions.create(**request_params)
            async for chunk in response:
                usage = getattr(chunk, "usage", None)
                if usage is not None:
                    usage_input = getattr(usage, "prompt_tokens", 0) or usage_input
                    usage_output = getattr(usage, "completion_tokens", 0) or usage_output
                choices = getattr(chunk, "choices", None) or []
                if not choices:
                    continue
                delta = getattr(choices[0], "delta", None)
                content = getattr(delta, "content", None) if delta is not None else None
                if content:
                    collected.append(content)
                    yield content
        except openai.APIError as e:
            self._logger.error(f"OpenAI streaming error: {e}")
            raise NexusLLMError(f"OpenAI API error: {e}") from e

        text = "".join(collected)
        self._last_stream_response = LLMResponse(
            content=text,
            model=self.config.model,
            provider=self.config.provider,
            tokens_input=usage_input,
            tokens_output=usage_output or max(1, len(text.split())),
            duration_ms=(time.perf_counter() - start_time) * 1000,
        )


class GeminiClient(BaseLLMClient):
    """LLM client for Google Gemini models."""

    def __init__(self, config: LLMConfig):
        super().__init__(config)
        if not GEMINI_AVAILABLE:
            raise ImportError("The 'google-genai' library is required for GeminiClient")
        if not self.config.api_key:
            raise ValueError("Gemini API key is required for GeminiClient.")
        
        self.client = genai.Client(api_key=self.config.api_key)

    def is_available(self) -> bool:
        return bool(self.config.api_key)

    async def complete(
        self, messages: List[LLMMessage], **kwargs: Any
    ) -> LLMResponse:
        start_time = time.perf_counter()
        
        system_messages = [msg.content for msg in messages if msg.role == "system"]
        contents = [
            genai_types.Content(
                role="model" if msg.role == "assistant" else "user",
                parts=[genai_types.Part.from_text(text=msg.content)],
            )
            for msg in messages if msg.role != "system"
        ]
        config = genai_types.GenerateContentConfig(
            temperature=kwargs.get("temperature", self.config.temperature),
            max_output_tokens=kwargs.get("max_tokens", self.config.max_tokens),
            system_instruction="\n".join(filter(None, [self.config.system_prompt, *system_messages])) or None,
        )

        try:
            response = await self.client.aio.models.generate_content(
                model=self.config.model, contents=contents, config=config,
            )
            duration_ms = (time.perf_counter() - start_time) * 1000
            
            usage = response.usage_metadata

            return LLMResponse(
                content=response.text or "",
                model=self.config.model,
                provider=self.config.provider,
                tokens_input=getattr(usage, "prompt_token_count", 0) or 0,
                tokens_output=getattr(usage, "candidates_token_count", 0) or 0,
                duration_ms=duration_ms,
                raw_response=response.model_dump(mode="json", exclude_none=True),
            )
        except Exception as e:
            self._logger.error(f"Gemini API error: {e}")
            raise NexusLLMError(f"Gemini API error: {e}") from e


class OllamaClient(BaseLLMClient):
    """LLM client for local Ollama instances."""

    def __init__(self, config: LLMConfig):
        super().__init__(config)
        if not HTTPX_AVAILABLE:
            raise ImportError("The 'httpx' library is required for OllamaClient")
        self.base_url = self.config.base_url or "http://localhost:11434"
        self.client = httpx.AsyncClient(base_url=self.base_url, timeout=self.config.timeout)

    def is_available(self) -> bool:
        """True when an Ollama endpoint is configured.

        This is synchronous on purpose: it matches
        :meth:`BaseLLMClient.is_available`, which callers use as a plain boolean.
        Reachability is not probed here because a blocking HTTP call must never
        run on the event loop; ``complete``/``stream`` surface an unreachable
        server as :class:`NexusLLMError` instead. Use :meth:`ping` when an async
        caller explicitly wants a reachability check.
        """
        return bool(self.base_url)

    async def ping(self) -> bool:
        """Async reachability probe against ``/api/tags`` (never raises)."""
        try:
            response = await self.client.get("/api/tags", timeout=5)
            return response.status_code == 200
        except httpx.RequestError:
            return False

    async def complete(
        self, messages: List[LLMMessage], **kwargs: Any
    ) -> LLMResponse:
        start_time = time.perf_counter()
        
        api_messages = [{"role": m.role, "content": m.content} for m in messages]
        if self.config.system_prompt and api_messages[0]["role"] != "system":
            api_messages.insert(0, {"role": "system", "content": self.config.system_prompt})

        payload = {
            "model": self.config.model,
            "messages": api_messages,
            "stream": False, # Keep it simple, no streaming for now
            "options": {
                "temperature": kwargs.get("temperature", self.config.temperature),
                "num_predict": kwargs.get("max_tokens", self.config.max_tokens),
            }
        }

        try:
            response = await self.client.post("/api/chat", json=payload)
            response.raise_for_status()
            data = response.json()
            duration_ms = (time.perf_counter() - start_time) * 1000

            return LLMResponse(
                content=data["message"]["content"],
                model=self.config.model,
                provider=self.config.provider,
                tokens_input=data.get("prompt_eval_count", 0),
                tokens_output=data.get("eval_count", 0),
                duration_ms=duration_ms,
                raw_response=data,
            )
        except httpx.RequestError as e:
            self._logger.error(f"Ollama connection error: {e}")
            raise NexusLLMError(f"Could not connect to Ollama at {self.base_url}") from e
        except httpx.HTTPStatusError as e:
            self._logger.error(f"Ollama API error: {e.response.status_code} - {e.response.text}")
            raise NexusLLMError(f"Ollama API error: {e.response.status_code}") from e


class FakeLLMClient(BaseLLMClient):
    """Deterministic provider for development, CI and offline evaluation."""

    def __init__(self, config: LLMConfig):
        super().__init__(config)
        fixture_path = config.base_url or os.getenv(
            "NEXUS_LLM_FIXTURES",
            str(Path(__file__).with_name("fixtures") / "responses.json"),
        )
        self.fixture_path = Path(fixture_path)
        self._fixtures = self._load_fixtures()

    def _load_fixtures(self) -> Dict[str, Any]:
        if not self.fixture_path.exists():
            return {"default": {"content": "Fake LLM response"}}
        with self.fixture_path.open("r", encoding="utf-8") as fixture_file:
            data = json.load(fixture_file)
        if not isinstance(data, dict):
            raise ValueError("Fake LLM fixture file must contain a JSON object")
        return data

    def is_available(self) -> bool:
        return True

    async def complete(
        self, messages: List[LLMMessage], **kwargs: Any
    ) -> LLMResponse:
        started = time.perf_counter()
        scenario = str(kwargs.get("scenario", "default"))
        fixture = self._fixtures.get(scenario, self._fixtures.get("default", {}))
        if not isinstance(fixture, dict):
            raise NexusLLMError(f"Invalid fake fixture for scenario '{scenario}'")

        delay_ms = int(fixture.get("delay_ms", 0))
        if delay_ms:
            await asyncio.sleep(delay_ms / 1000)

        error = fixture.get("error")
        if error:
            raise NexusLLMError(str(error))

        content = fixture.get("content", "Fake LLM response")
        if fixture.get("echo_last_message") and messages:
            content = messages[-1].content

        input_tokens = sum(max(1, len(message.content.split())) for message in messages)
        output_tokens = max(1, len(str(content).split()))
        return LLMResponse(
            content=str(content),
            model=self.config.model,
            provider=LLMProvider.FAKE,
            tokens_input=input_tokens,
            tokens_output=output_tokens,
            duration_ms=(time.perf_counter() - started) * 1000,
            raw_response={"scenario": scenario, "fixture": True},
        )

# --- Factory and High-Level Wrapper ---

class LLMFactory:
    """Factory for creating LLM clients."""

    @staticmethod
    def create(config: LLMConfig) -> BaseLLMClient:
        """
        Creates an LLM client based on the provided configuration.

        Args:
            config: The LLMConfig object.

        Returns:
            An instance of a BaseLLMClient subclass.
        
        Raises:
            ValueError: If an unsupported provider is specified.
        """
        from .anthropic_client import AnthropicClient
        provider_map = {
            LLMProvider.ANTHROPIC: AnthropicClient,
            LLMProvider.OPENAI: OpenAIClient,
            LLMProvider.GEMINI: GeminiClient,
            LLMProvider.OLLAMA: OllamaClient,
            LLMProvider.FAKE: FakeLLMClient,
            LLMProvider.GROQ: OpenAIClient,
            LLMProvider.OPENAI_COMPATIBLE: OpenAIClient,
        }
        client_class = provider_map.get(config.provider)
        if not client_class:
            raise ValueError(f"Unsupported LLM provider: {config.provider}")
        return client_class(config)

    @staticmethod
    def create_from_env() -> Dict[str, BaseLLMClient]:
        """
        Creates all available LLM clients based on environment variables.

        Returns:
            A dictionary of available client names to their instances.
        """
        clients: Dict[str, BaseLLMClient] = {}
        logger = get_logger("LLMFactory")

        fake_config = LLMConfig(
            provider=LLMProvider.FAKE,
            model=os.getenv("FAKE_LLM_MODEL", "nexus-fake-v1"),
            base_url=os.getenv("NEXUS_LLM_FIXTURES"),
        )
        clients["fake"] = FakeLLMClient(fake_config)

        # OpenAI
        if os.getenv("OPENAI_API_KEY"):
            try:
                config = LLMConfig(
                    provider=LLMProvider.OPENAI,
                    model=os.getenv("OPENAI_MODEL", "gpt-4o-mini"),
                    api_key=os.getenv("OPENAI_API_KEY")
                )
                clients["openai"] = OpenAIClient(config)
                # Visibility is decided by NEXUS_LOG_LEVEL (default warning), so
                # these stay INFO: one switch controls all internal chatter.
                logger.info("OpenAI client created from environment variables.")
            except Exception as e:
                logger.warning(f"Failed to create OpenAI client from env: {e}")

        # Gemini
        if os.getenv("GEMINI_API_KEY"):
            try:
                config = LLMConfig(
                    provider=LLMProvider.GEMINI,
                    model=os.getenv("GEMINI_MODEL", "gemini-1.5-flash"),
                    api_key=os.getenv("GEMINI_API_KEY")
                )
                clients["gemini"] = GeminiClient(config)
                logger.info("Gemini client created from environment variables.")
            except Exception as e:
                logger.warning(f"Failed to create Gemini client from env: {e}")

        # Groq / OpenAI-compatible endpoint
        if os.getenv("GROQ_API_KEY"):
            try:
                config = LLMConfig(
                    provider=LLMProvider.GROQ,
                    model=os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile"),
                    api_key=os.getenv("GROQ_API_KEY"),
                    base_url=os.getenv("GROQ_BASE_URL", "https://api.groq.com/openai/v1"),
                )
                clients["groq"] = OpenAIClient(config)
                logger.info("Groq client created from environment variables.")
            except Exception as e:
                logger.warning(f"Failed to create Groq client from env: {e}")

        if os.getenv("ANTHROPIC_API_KEY"):
            clients["anthropic"] = LLMFactory.create(LLMConfig(
                provider=LLMProvider.ANTHROPIC,
                model=os.getenv("ANTHROPIC_MODEL", "claude-sonnet-4-20250514"),
                api_key=os.getenv("ANTHROPIC_API_KEY"),
            ))

        # Ollama
        if os.getenv("OLLAMA_BASE_URL"):
            try:
                config = LLMConfig(
                    provider=LLMProvider.OLLAMA,
                    model=os.getenv("OLLAMA_MODEL", "llama3"),
                    base_url=os.getenv("OLLAMA_BASE_URL")
                )
                clients["ollama"] = OllamaClient(config)
                logger.info("Ollama client created from environment variables.")
            except Exception as e:
                logger.warning(f"Failed to create Ollama client from env: {e}")
        
        return clients


class NexusLLM:
    """
    A high-level wrapper for LLM clients that provides resilience and stats.
    """
    def __init__(
        self,
        primary: BaseLLMClient,
        fallback: Optional[BaseLLMClient] = None,
        logger: Optional[logging.Logger] = None
    ):
        """
        Initializes the NexusLLM wrapper.

        Args:
            primary: The main LLM client to use.
            fallback: An optional secondary client to use if the primary fails.
            logger: An optional logger instance.
        """
        self.primary = primary
        self.fallback = fallback
        self._logger = logger or get_logger("NexusLLM")
        
        # Stats tracking
        self._calls_total = 0
        self._calls_primary = 0
        self._calls_fallback = 0
        self._total_tokens = 0
        self._total_latency_ms = 0.0

    async def complete(
        self, messages: List[LLMMessage], **kwargs: Any
    ) -> LLMResponse:
        """
        Executes a completion request with optional fallback.

        Tries the primary client first. If it fails, and a fallback client
        is configured, it retries the request with the fallback.

        Args:
            messages: The conversation history.
            **kwargs: Provider-specific arguments.

        Returns:
            The LLMResponse from the successful client.

        Raises:
            NexusLLMError: If both primary and fallback clients fail.
        """
        self._calls_total += 1
        try:
            self._logger.info(f"Attempting completion with primary provider: {self.primary.config.provider.value}")
            self._calls_primary += 1
            response = await self.primary.complete(messages, **kwargs)
            self._update_stats(response)
            return response
        except Exception as primary_error:
            self._logger.warning(
                f"Primary provider '{self.primary.config.provider.value}' failed: {primary_error}"
            )
            if self.fallback:
                self._logger.info(f"Attempting completion with fallback provider: {self.fallback.config.provider.value}")
                self._calls_fallback += 1
                try:
                    response = await self.fallback.complete(messages, **kwargs)
                    self._update_stats(response)
                    return response
                except Exception as fallback_error:
                    self._logger.error(
                        f"Fallback provider '{self.fallback.config.provider.value}' also failed: {fallback_error}"
                    )
                    raise NexusLLMError("Both primary and fallback LLM providers failed.") from fallback_error
            else:
                raise NexusLLMError("Primary LLM provider failed and no fallback is configured.") from primary_error

    @property
    def supports_streaming(self) -> bool:
        """True when the primary provider can emit real token deltas."""
        return bool(getattr(self.primary, "supports_streaming", False))

    async def stream(self, messages: List[LLMMessage], **kwargs: Any):
        """Stream from the primary provider.

        No mid-stream fallback: once bytes reach the operator, restarting on
        another provider would duplicate the visible answer.
        """
        async for chunk in self.primary.stream(messages, **kwargs):
            yield chunk

    @property
    def last_stream_response(self) -> Optional[LLMResponse]:
        return getattr(self.primary, "last_stream_response", None)

    async def ask(self, system_prompt: str, user_message: str) -> str:
        """
        A shortcut for simple queries.

        Args:
            system_prompt: The system message.
            user_message: The user's message.

        Returns:
            The string content of the response.
        """
        messages = [
            LLMMessage(role="system", content=system_prompt),
            LLMMessage(role="user", content=user_message),
        ]
        response = await self.complete(messages)
        return response.content

    def _update_stats(self, response: LLMResponse) -> None:
        """Updates internal performance statistics."""
        self._total_tokens += response.total_tokens
        self._total_latency_ms += response.duration_ms
        self._logger.info(
            f"LLM call successful via {response.provider.value}. "
            f"Duration: {response.duration_ms:.2f}ms, "
            f"Tokens: {response.total_tokens}."
        )

    def get_stats(self) -> Dict[str, Any]:
        """
        Retrieves the current performance statistics.

        Returns:
            A dictionary of performance metrics.
        """
        avg_latency = (self._total_latency_ms / self._calls_total) if self._calls_total > 0 else 0
        return {
            "calls_total": self._calls_total,
            "calls_primary_success": self._calls_primary - self._calls_fallback,
            "calls_fallback_success": self._calls_fallback,
            "total_tokens_processed": self._total_tokens,
            "avg_latency_ms": avg_latency,
        }
