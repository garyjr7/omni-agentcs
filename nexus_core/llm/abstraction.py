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
import math
import os
import random
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, AsyncIterator, Callable, Dict, List, Optional, cast

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

from .limits import (
    MAX_RETRY_SLEEP_SECONDS,
    MIN_COMPLETION_TOKENS,
    backoff_base_seconds,
    deepseek_max_attempts,
    estimate_request_tokens,
    is_rate_limit_status,
    is_transient_status,
    mentions_input_token_limit,
    mentions_output_token_limit,
    pace_request,
    record_provider_usage,
)

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


class LLMChainExhausted(NexusLLMError):
    """Every provider of the chain failed; ``causes`` says how each one did.

    The coordinator never learns there was a chain: it sees either the final
    answer or this error, whose text names every provider, its status and its
    failure class, so the operator does not have to guess which key is dead.
    """

    def __init__(self, causes: List[Dict[str, Any]]) -> None:
        self.causes = tuple(causes)
        detail = "; ".join(
            f"{cause.get('provider') or '?'}: {cause.get('reason') or 'failed'}"
            + (f" (status {cause['status_code']})" if cause.get("status_code") else "")
            for cause in self.causes
        )
        super().__init__(
            "all LLM providers failed: " + (detail or "no provider configured")
        )


class LLMInvalidJSONError(NexusLLMError):
    """The provider answered with content that is not the requested JSON object.

    A malformed *answer* says nothing about the health of the provider or of the
    engagement: the ReAct loop retries that turn with an explicit correction
    instead of closing the run as ``provider_error`` (measured in Simple CTF
    Run 3, 2026-10-17: DeepSeek answered a non-JSON object on iteration 3 and
    the engine aborted with exit 3 while the target was still live).
    """


def is_invalid_json_error(error: BaseException | None) -> bool:
    """Whether ``error`` -or the cause it wraps- is a malformed JSON answer.

    The ReAct turn reaches the provider through ``NexusLLM`` (and, with a
    configured fallback, through a second client), so the typed error is
    usually reachable only through the exception chain. The text check keeps the
    contract for a client that already translated it into a plain
    ``NexusLLMError``.
    """
    seen: set[int] = set()
    current = error
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        if isinstance(current, LLMInvalidJSONError):
            return True
        if "invalid json" in str(current).lower():
            return True
        current = current.__cause__ or current.__context__
    return False


# --- Provider chain (Tanda C, Fix 4) -----------------------------------------
#
# Measured problem: ``NexusLLM`` had two slots and fell back on *any* exception,
# so a 401 spent the other provider's quota, a 503 never reached the next
# provider (the client raised after its own quota retry), and the final error was
# one sentence with no cause. The chain classifies the failure first.

#: Total attempts a **single** provider gets when it is the last one in the
#: chain and the failure is transient (Fix 4.2).
CHAIN_MAX_ATTEMPTS = 3

#: The correction a malformed-JSON turn gets on the same provider, once.
JSON_ONLY_INSTRUCTION = (
    "Responde SOLO con un objeto JSON válido, sin markdown ni texto fuera del objeto."
)

FAILURE_AUTH = "authentication"
FAILURE_TRANSIENT = "transient"
FAILURE_INVALID_JSON = "invalid_json"
FAILURE_OTHER = "other"

#: Statuses that mean "the configuration is wrong", not "the provider is busy".
AUTH_STATUS_CODES = frozenset({401, 403})


def _status_code_of(error: BaseException | None) -> int | None:
    """HTTP status of an exception, walking the cause chain.

    The clients wrap provider errors in ``NexusLLMError`` (sometimes with
    ``from e``, sometimes after dropping it), so the code can live on the error
    itself or on any of its causes.
    """
    seen: set[int] = set()
    current = error
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        raw = getattr(current, "status_code", None)
        if isinstance(raw, int):
            return raw
        raw = getattr(getattr(current, "response", None), "status_code", None)
        if isinstance(raw, int):
            return raw
        current = current.__cause__ or current.__context__
    return None


def classify_failure(error: Exception) -> str:
    """Which retry policy a provider failure asks for (Fix 4.2).

    * ``authentication`` -401/403: configuration, terminal, no retry anywhere;
    * ``invalid_json`` -the provider answered, the answer is not the contract;
    * ``transient`` -quota (413/429/503), the 5xx family (500/502/504) and
      network stalls: another provider may serve it right now, and as the last
      provider it earns the bounded retries;
    * ``other`` -anything else: never retried on the same provider, but the next
      one still gets the turn; as the last provider it fails the run.
    """
    if is_invalid_json_error(error):
        return FAILURE_INVALID_JSON
    status = _status_code_of(error)
    if status in AUTH_STATUS_CODES:
        return FAILURE_AUTH
    if status is not None and (
        is_transient_status(status) or is_rate_limit_status(status)
    ):
        return FAILURE_TRANSIENT
    if _is_transport_stall(error) or isinstance(error, (asyncio.TimeoutError, TimeoutError)):
        return FAILURE_TRANSIENT
    return FAILURE_OTHER


def _nexus_error(message: str, cause: BaseException | None = None) -> "NexusLLMError":
    """A ``NexusLLMError`` that keeps the provider's status for the chain."""
    error = NexusLLMError(message)
    status = _status_code_of(cause) if cause is not None else None
    if status is not None:
        error.status_code = status  # type: ignore[attr-defined]
    return error


def _with_json_correction(messages: List["LLMMessage"]) -> List["LLMMessage"]:
    """``messages`` plus the one-shot instruction a malformed answer earns."""
    return [*messages, LLMMessage(role="user", content=JSON_ONLY_INSTRUCTION)]


def _is_transport_stall(error: Exception) -> bool:
    """True when an exception is a network stall, not a rejected request.

    Connect/read timeouts and dropped sockets reach us as ``httpx`` transport
    errors, which the OpenAI SDK re-wraps as ``APITimeoutError`` /
    ``APIConnectionError``; both mean "the provider never answered", so a retry
    is safe. A status error is classified by its code instead.
    """
    if HTTPX_AVAILABLE and isinstance(error, (httpx.TimeoutException, httpx.TransportError)):
        return True
    if OPENAI_AVAILABLE and isinstance(error, (openai.APITimeoutError, openai.APIConnectionError)):
        return True
    return False


def _retry_after_seconds(error: Exception) -> float:
    """Numeric ``Retry-After`` of a provider response (``0.0`` when absent)."""
    headers = getattr(getattr(error, "response", None), "headers", None)
    if not headers:
        return 0.0
    try:
        value = float(headers.get("retry-after", 0))
    except (TypeError, ValueError):
        return 0.0
    return value if math.isfinite(value) and value > 0 else 0.0


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
    #: OpenAI-compatible endpoint (https://api.deepseek.com/v1). Supported from
    #: Fase 3.6 but deliberately NOT the default: switching the development model
    #: is a Fase 4 decision, made by pointing ``llm.default_provider`` at it once
    #: the operator has the API key (B8.2.4).
    DEEPSEEK = "deepseek"

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
        self._last_stream_response: Optional[LLMResponse] = None
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

    async def stream(self, messages: List[LLMMessage], **kwargs: Any) -> AsyncIterator[str]:
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


def trim_oldest_messages(
    api_messages: List[Dict[str, Any]], *, keep: int = 6
) -> List[Dict[str, Any]]:
    """Drop the oldest non-system messages, keeping the system prompt.

    Fase 4.0: when a provider rejects a request for exceeding its per-minute
    *input* budget (Groq ITPM), only shrinking the prompt can help. The system
    prompt already carries a summarised history block, so dropping the oldest
    turns loses the least context.
    """
    system = [m for m in api_messages if m.get("role") == "system"]
    rest = [m for m in api_messages if m.get("role") != "system"]
    if len(rest) <= keep:
        return api_messages
    return system + rest[-keep:]


#: Model families that only accept ``max_completion_tokens``. OpenAI retired
#: ``max_tokens`` for these: sending it is a 400 *Unsupported parameter*.
NEW_COMPLETION_TOKEN_MODELS: tuple[str, ...] = (
    "gpt-4o",
    "gpt-4.1",
    "gpt-5",
    "gpt-6",
    "chatgpt-4o",
    "o1",
    "o3",
    "o4",
    "gpt-oss",
)

#: Model families that predate the rename and still expect ``max_tokens``.
#: Checked *after* the new ones, so ``gpt-4o`` is never read as ``gpt-4``.
LEGACY_COMPLETION_TOKEN_MODELS: tuple[str, ...] = (
    "gpt-3.5",
    "gpt-4",
    "text-davinci",
    "davinci",
    "babbage",
    "ada",
    "curie",
)


def completion_token_parameter(
    model: str, provider: LLMProvider | str = LLMProvider.OPENAI
) -> str:
    """The Chat Completions key that caps output tokens for ``model``.

    OpenAI renamed the output ceiling to ``max_completion_tokens`` and rejects
    ``max_tokens`` for the models released since (gpt-4o, the o-series, gpt-5,
    gpt-6). Sending the old key there is a 400 that fails the whole turn, so the
    payload key has to follow the model, not the client.

    Resolution order:

    1. a known *new* family -> ``max_completion_tokens``;
    2. a known *legacy* family -> ``max_tokens`` (gpt-3.5, gpt-4, gpt-4-turbo);
    3. an unknown name from the OpenAI provider -> ``max_completion_tokens``,
       because a model we do not know is far more likely to be newer than the
       rename than older; any other provider keeps the OpenAI-compatible
       ``max_tokens`` that every compatible gateway already accepts.
    """
    name = (model or "").strip().lower()
    for prefix in NEW_COMPLETION_TOKEN_MODELS:
        if name.startswith(prefix):
            return "max_completion_tokens"
    for prefix in LEGACY_COMPLETION_TOKEN_MODELS:
        if name.startswith(prefix):
            return "max_tokens"
    try:
        resolved = provider if isinstance(provider, LLMProvider) else LLMProvider(provider)
    except ValueError:
        return "max_tokens"
    return "max_completion_tokens" if resolved is LLMProvider.OPENAI else "max_tokens"


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

        # ``kwargs`` always names the ceiling ``max_tokens`` (the internal
        # contract every caller and sub-agent already uses); only the wire key
        # changes, because the new model families reject the old one.
        token_key = completion_token_parameter(self.config.model, self.config.provider)
        request_params: Dict[str, Any] = {
            "model": self.config.model,
            "messages": api_messages,
            "temperature": kwargs.get("temperature", self.config.temperature),
            token_key: kwargs.get(
                "max_tokens", kwargs.get("max_completion_tokens", self.config.max_tokens)
            ),
        }

        max_retries = 3
        backoff_factor = backoff_base_seconds()
        for attempt in range(max_retries):
            # Respect the provider's tokens-per-minute budget before spending a
            # request that is guaranteed to be rejected (B5).
            await pace_request(
                self.config.provider,
                estimated_tokens=estimate_request_tokens(
                    messages, request_params[token_key]
                ),
            )
            try:
                response: ChatCompletion = await self.client.chat.completions.create(**request_params)
                duration_ms = (time.perf_counter() - start_time) * 1000

                usage = response.usage
                tokens_input = usage.prompt_tokens if usage else 0
                tokens_output = usage.completion_tokens if usage else 0
                record_provider_usage(
                    self.config.provider, tokens_input + tokens_output
                )
                return LLMResponse(
                    content=response.choices[0].message.content or "",
                    model=self.config.model,
                    provider=self.config.provider,
                    tokens_input=tokens_input,
                    tokens_output=tokens_output,
                    duration_ms=duration_ms,
                    raw_response=response.model_dump(),
                )
            except openai.APIStatusError as e:
                # 429 (rate limit) and 413 (the reserved max_tokens itself blew
                # the per-minute token budget) are the same problem: retry with
                # backoff, and for 413 also shrink the reservation.
                raw_status = getattr(e, "status_code", None)
                status = int(raw_status) if isinstance(raw_status, int) else 0
                if not is_rate_limit_status(status) or attempt + 1 == max_retries:
                    self._logger.error(f"OpenAI API error: {e}")
                    raise NexusLLMError(f"OpenAI API error: {e}") from e
                # 413 is "too large"; some providers (Groq) answer an oversized
                # *output* reservation with 429/OTPM instead. Both mean "shrink
                # the reservation", so treat them the same.
                if status == 413 or (
                    status == 429 and mentions_output_token_limit(e)
                ):
                    shrunk = max(
                        MIN_COMPLETION_TOKENS, int(request_params[token_key]) // 2
                    )
                    self._logger.warning(
                        f"Provider rejected the request as too large (status {status}); "
                        f"shrinking {token_key} {request_params[token_key]} -> {shrunk}."
                    )
                    request_params[token_key] = shrunk
                # An *input*-token rejection cannot be fixed by shrinking the
                # reservation: trim the oldest conversation turns instead.
                if status == 413 and mentions_input_token_limit(e):
                    trimmed = trim_oldest_messages(request_params["messages"])
                    if len(trimmed) < len(request_params["messages"]):
                        self._logger.warning(
                            "Request exceeds the provider's input budget (ITPM); "
                            f"trimming context {len(request_params['messages'])} -> "
                            f"{len(trimmed)} messages."
                        )
                        request_params["messages"] = trimmed
                wait_time = backoff_factor * (2 ** attempt)
                self._logger.warning(
                    f"Provider rate/token limit (status {status}). "
                    f"Retrying in {wait_time:.2f}s..."
                )
                await asyncio.sleep(wait_time)
            except openai.APIError as e:
                self._logger.error(f"OpenAI API error: {e}")
                raise NexusLLMError(f"OpenAI API error: {e}") from e
        
        # This line should not be reachable
        raise NexusLLMError("OpenAI request failed after all retries.")

    async def stream(self, messages: List[LLMMessage], **kwargs: Any) -> AsyncIterator[str]:
        """Yield token deltas as they arrive (SSE streaming).

        Usage is captured from the final chunk when the endpoint supports
        ``stream_options`` (OpenAI and Groq do); otherwise output tokens are
        approximated from the received text so the status bar stays meaningful.
        """
        start_time = time.perf_counter()
        api_messages = [{"role": m.role, "content": m.content} for m in messages]
        if self.config.system_prompt and api_messages[0]["role"] != "system":
            api_messages.insert(0, {"role": "system", "content": self.config.system_prompt})

        token_key = completion_token_parameter(self.config.model, self.config.provider)
        request_params: Dict[str, Any] = {
            "model": self.config.model,
            "messages": api_messages,
            "temperature": kwargs.get("temperature", self.config.temperature),
            token_key: kwargs.get(
                "max_tokens", kwargs.get("max_completion_tokens", self.config.max_tokens)
            ),
            "stream": True,
        }
        if self.config.provider in (LLMProvider.OPENAI, LLMProvider.GROQ):
            request_params["stream_options"] = {"include_usage": True}

        collected: List[str] = []
        usage_input = usage_output = 0
        # A streamed turn also counts against the provider's per-minute budget.
        await pace_request(
            self.config.provider,
            estimated_tokens=estimate_request_tokens(
                messages, request_params[token_key]
            ),
        )
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
        tokens_output = usage_output or max(1, len(text.split()))
        record_provider_usage(self.config.provider, usage_input + tokens_output)
        self._last_stream_response = LLMResponse(
            content=text,
            model=self.config.model,
            provider=self.config.provider,
            tokens_input=usage_input,
            tokens_output=tokens_output,
            duration_ms=(time.perf_counter() - start_time) * 1000,
        )


class DeepSeekClient(OpenAIClient):
    """DeepSeek Chat Completions with explicit JSON and reservation boundaries."""

    supports_action_json = True

    def __init__(self, config: LLMConfig) -> None:
        from dataclasses import replace
        from .limits import (
            DEEPSEEK_CONNECT_TIMEOUT_SECONDS,
            DEEPSEEK_PACER,
            DEEPSEEK_WRITE_TIMEOUT_SECONDS,
            deepseek_limits,
            deepseek_timeout_seconds,
        )

        model = config.model or "deepseek-flash"
        if model == "deepseek-v4.1-flash":
            model = "deepseek-flash"  # Product name -> documented API identifier.
        # Override the provider-agnostic 60 s default: DeepSeek can take minutes to
        # close one completion under load, and cutting it short aborted the ReAct
        # turn instead of waiting it out. The value is env-overridable and floored.
        timeout = deepseek_timeout_seconds()
        from nexus_core.config.secrets import resolve_api_key

        super().__init__(replace(config, model=model,
            api_key=config.api_key or resolve_api_key("deepseek"),
            base_url=config.base_url or "https://api.deepseek.com",
            timeout=int(timeout)))
        # One retry owner: SDK retries would bypass our per-attempt reservation.
        # ``httpx.Timeout`` splits the budget: a short connect/pool so a dead
        # endpoint fails fast, and a generous *read* budget that re-arms on every
        # streamed chunk, so a slow-but-alive provider is never dropped mid-turn.
        if HTTPX_AVAILABLE:
            self.client = self.client.with_options(
                max_retries=0,
                timeout=httpx.Timeout(
                    connect=DEEPSEEK_CONNECT_TIMEOUT_SECONDS,
                    read=timeout,
                    write=DEEPSEEK_WRITE_TIMEOUT_SECONDS,
                    pool=DEEPSEEK_CONNECT_TIMEOUT_SECONDS,
                ),
            )
        else:
            self.client = self.client.with_options(max_retries=0)
        self.pacer = DEEPSEEK_PACER
        tpm, rpm = deepseek_limits()
        self.pacer.tpm["deepseek"] = tpm
        self.pacer.rpm["deepseek"] = rpm

    def _payload(self, messages: List[LLMMessage], options: Dict[str, Any]) -> Dict[str, Any]:
        api_messages = [{"role": m.role, "content": m.content} for m in messages]
        if self.config.system_prompt:
            if not api_messages or api_messages[0]["role"] != "system" or api_messages[0]["content"] != self.config.system_prompt:
                api_messages.insert(0, {"role": "system", "content": self.config.system_prompt})
        if not api_messages:
            raise NexusLLMError("DeepSeek requires at least one message")
        maximum = options.get("max_tokens", self.config.max_tokens)
        if type(maximum) is not int or maximum <= 0:
            raise ValueError("max_tokens must be a positive integer")
        params: Dict[str, Any] = {
            "model": self.config.model, "messages": api_messages, "max_tokens": maximum,
            "temperature": options.get("temperature", self.config.temperature),
        }
        response_format = options.get("response_format", {"type": "text"})
        if response_format not in ({"type": "text"}, {"type": "json_object"}):
            raise ValueError("DeepSeek supports text or json_object response_format")
        params["response_format"] = response_format
        if response_format["type"] == "json_object":
            api_messages.insert(0, {"role": "system", "content":
                "Return exactly one JSON object matching the requested schema. "
                "Do not add Markdown fences or fields outside that schema."})
        for key in ("stop", "top_p"):
            if key in options:
                params[key] = options[key]
        # Non-thinking defaults keep the existing text-only session history
        # compatible; reasoning_content is never fed to the action parser.
        if self.config.model != "deepseek-chat":
            thinking = options.get("thinking", "disabled")
            if thinking not in ("enabled", "disabled"):
                raise ValueError("thinking must be enabled or disabled")
            params["extra_body"] = {"thinking": {"type": thinking}}
        return params

    @staticmethod
    def _check_content(text: str, params: Dict[str, Any], finish: str | None) -> None:
        if finish not in (None, "stop") or not text.strip():
            raise NexusLLMError("DeepSeek returned empty, interrupted or unsupported completion")
        if params["response_format"]["type"] == "json_object":
            from nexus_core.kernel.serialization import decode_json
            try:
                value = decode_json(text)
            except (ValueError, RecursionError):
                raise LLMInvalidJSONError("DeepSeek returned invalid JSON") from None
            if not isinstance(value, dict):
                raise LLMInvalidJSONError("DeepSeek JSON response must be an object")

    async def _retry(self, error: Exception, attempt: int) -> bool:
        """Replay a transient DeepSeek failure with exponential backoff.

        ``attempt`` is zero-based; at most :func:`deepseek_max_attempts` total
        tries are made, so the number of replays is that count minus one. A
        transport stall (connect/read timeout, dropped socket) or a transient
        gateway/rate-limit status is retried; authentication, a malformed request
        or an unsupported payload is terminal, so a broken key never loops.

        Each replay is a brand-new HTTP request and therefore takes a fresh pacer
        reservation, so the retry is accounted (and billed) once per attempt.
        """
        status = getattr(error, "status_code", None)
        if not (is_transient_status(status) or _is_transport_stall(error)):
            return False
        attempts = deepseek_max_attempts()
        if attempt + 1 >= attempts:
            return False
        delay = backoff_base_seconds() * (2 ** attempt)
        delay = max(delay, _retry_after_seconds(error))
        if delay > 0:
            # Jitter de-synchronises concurrent retries; the deterministic base-0
            # test path (NEXUS_LLM_BACKOFF_SECONDS=0) is left untouched.
            delay += random.uniform(0.0, delay / 10.0)
        delay = min(MAX_RETRY_SLEEP_SECONDS, delay)
        self._logger.warning(
            f"DeepSeek transient failure ({type(error).__name__}, attempt "
            f"{attempt + 1}/{attempts}); retrying in {delay:.2f}s"
        )
        await asyncio.sleep(delay)
        return True

    async def complete(self, messages: List[LLMMessage], **kwargs: Any) -> LLMResponse:
        start = time.perf_counter()
        params = self._payload(messages, kwargs)
        estimate = sum(len(m["content"].encode("utf-8")) + 16 for m in params["messages"]) + params["max_tokens"]
        for attempt in range(deepseek_max_attempts()):
            # A fresh reservation per attempt: a replayed request is a new HTTP
            # request, so it must be paced and accounted independently.
            reservation = await self.pacer.reserve("deepseek", estimated_tokens=estimate)
            actual: int | None = None
            try:
                response = await self.client.chat.completions.create(**params)
                usage = response.usage
                if usage is not None:
                    actual = usage.prompt_tokens + usage.completion_tokens
                if not response.choices:
                    raise NexusLLMError("DeepSeek returned no choices")
                choice = response.choices[0]
                content = choice.message.content or ""
                self._check_content(content, params, choice.finish_reason)
                return LLMResponse(content, response.model or self.config.model, self.config.provider,
                    usage.prompt_tokens if usage else 0, usage.completion_tokens if usage else 0,
                    (time.perf_counter() - start) * 1000, response.model_dump())
            except (openai.APIError, httpx.HTTPError) as exc:
                if not await self._retry(exc, attempt):
                    # Keep the status on the error: the chain decides "next
                    # provider" or "fail the run" from it (Tanda C, Fix 4.2).
                    raise _nexus_error(f"DeepSeek request failed ({type(exc).__name__})", exc) from None
            finally:
                self.pacer.settle(reservation, actual)
        raise NexusLLMError("DeepSeek retry budget exhausted")

    async def stream(self, messages: List[LLMMessage], **kwargs: Any) -> AsyncIterator[str]:
        self._last_stream_response = None
        start = time.perf_counter()
        params = self._payload(messages, kwargs)
        params.update(stream=True, stream_options={"include_usage": True})
        estimate = sum(len(m["content"].encode("utf-8")) + 16 for m in params["messages"]) + params["max_tokens"]
        for attempt in range(deepseek_max_attempts()):
            reservation = await self.pacer.reserve("deepseek", estimated_tokens=estimate)
            response = None
            actual: int | None = None
            collected: List[str] = []
            usage_input = usage_output = 0
            finish: str | None = None
            model = self.config.model
            try:
                response = await self.client.chat.completions.create(**params)
                async for chunk in response:
                    model = chunk.model or model
                    if chunk.usage is not None:
                        usage_input = chunk.usage.prompt_tokens
                        usage_output = chunk.usage.completion_tokens
                        actual = usage_input + usage_output
                    if not chunk.choices:
                        continue
                    choice = chunk.choices[0]
                    finish = choice.finish_reason or finish
                    content = choice.delta.content
                    if content:
                        collected.append(content)
                        yield content
                text = "".join(collected)
                if finish is None:
                    raise NexusLLMError("DeepSeek stream ended without a finish marker")
                self._check_content(text, params, finish)
                self._last_stream_response = LLMResponse(text, model, self.config.provider,
                    usage_input, usage_output, (time.perf_counter() - start) * 1000,
                    {"finish_reason": finish, "usage_available": actual is not None})
                return
            except (openai.APIError, httpx.HTTPError) as exc:
                # Never replay deltas after any content reached the consumer.
                if collected or not await self._retry(exc, attempt):
                    raise _nexus_error(f"DeepSeek stream failed ({type(exc).__name__})", exc) from None
            finally:
                try:
                    if response is not None:
                        await response.close()
                finally:
                    self.pacer.settle(reservation, actual)


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
            return bool(response.status_code == 200)
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
        self.fixture_path = Path(str(fixture_path))
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
            LLMProvider.DEEPSEEK: DeepSeekClient,
        }
        client_class = provider_map.get(config.provider)
        if not client_class:
            raise ValueError(f"Unsupported LLM provider: {config.provider}")
        return cast(BaseLLMClient, client_class(config))

    @staticmethod
    def create_from_env() -> Dict[str, BaseLLMClient]:
        """
        Creates all available LLM clients from the operator's stored keys.

        The key comes from :func:`nexus_core.config.secrets.resolve_api_key`,
        which reads the local store (OS keyring, else the ``0600`` file) **first**
        and only then the environment. So a key entered once with
        ``omni auth login`` wins over a stale export or ``.env`` line, and no
        secret has to live in the process environment to build a client.

        Returns:
            A dictionary of available client names to their instances.
        """
        from nexus_core.config.secrets import resolve_api_key

        keys = {
            name: resolve_api_key(name)
            for name in ("openai", "gemini", "groq", "deepseek", "anthropic")
        }
        clients: Dict[str, BaseLLMClient] = {}
        logger = get_logger("LLMFactory")

        fake_config = LLMConfig(
            provider=LLMProvider.FAKE,
            model=os.getenv("FAKE_LLM_MODEL", "nexus-fake-v1"),
            base_url=os.getenv("NEXUS_LLM_FIXTURES"),
        )
        clients["fake"] = FakeLLMClient(fake_config)

        # OpenAI
        if keys["openai"]:
            try:
                config = LLMConfig(
                    provider=LLMProvider.OPENAI,
                    model=os.getenv("OPENAI_MODEL", "gpt-4o-mini"),
                    api_key=keys["openai"]
                )
                clients["openai"] = OpenAIClient(config)
                # Visibility is decided by NEXUS_LOG_LEVEL (default warning), so
                # these stay INFO: one switch controls all internal chatter.
                logger.info("OpenAI client created from environment variables.")
            except Exception as e:
                logger.warning(f"Failed to create OpenAI client from env: {e}")

        # Gemini
        if keys["gemini"]:
            try:
                config = LLMConfig(
                    provider=LLMProvider.GEMINI,
                    model=os.getenv("GEMINI_MODEL", "gemini-1.5-flash"),
                    api_key=keys["gemini"]
                )
                clients["gemini"] = GeminiClient(config)
                logger.info("Gemini client created from environment variables.")
            except Exception as e:
                logger.warning(f"Failed to create Gemini client from env: {e}")

        # Groq / OpenAI-compatible endpoint
        if keys["groq"]:
            try:
                config = LLMConfig(
                    provider=LLMProvider.GROQ,
                    model=os.getenv("GROQ_MODEL", "qwen/qwen3.8-27b"),
                    api_key=keys["groq"],
                    base_url=os.getenv("GROQ_BASE_URL", "https://api.groq.com/openai/v1"),
                )
                clients["groq"] = OpenAIClient(config)
                logger.info("Groq client created from environment variables.")
            except Exception as e:
                logger.warning(f"Failed to create Groq client from env: {e}")

        # DeepSeek (OpenAI-compatible). Available from Fase 3.6, not the default;
        # a client is only built when the operator exported the key.
        if keys["deepseek"]:
            try:
                config = LLMConfig(
                    provider=LLMProvider.DEEPSEEK,
                    model=os.getenv("DEEPSEEK_MODEL", "deepseek-flash"),
                    api_key=keys["deepseek"],
                    base_url=os.getenv("DEEPSEEK_BASE_URL", "https://api.deepseek.com"),
                )
                clients["deepseek"] = DeepSeekClient(config)
                logger.info("DeepSeek client created from environment variables.")
            except Exception as e:
                logger.warning(f"Failed to create DeepSeek client from env: {e}")

        if keys["anthropic"]:
            clients["anthropic"] = LLMFactory.create(LLMConfig(
                provider=LLMProvider.ANTHROPIC,
                model=os.getenv("ANTHROPIC_MODEL", "claude-sonnet-4-20250514"),
                api_key=keys["anthropic"],
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
    """A chain of LLM clients with per-cause retry and aggregated errors.

    ``primary``/``fallback`` stay for the callers that still name two slots;
    ``chain`` is the real order. The coordinator is deliberately unaware of the
    chain: it receives the final response or :class:`LLMChainExhausted`, whose
    text names every provider, its status code and its failure class (Fix 4.4).
    """

    def __init__(
        self,
        primary: BaseLLMClient,
        fallback: Optional[BaseLLMClient] = None,
        logger: Optional[logging.Logger] = None,
        *,
        chain: Optional[List[BaseLLMClient]] = None,
    ):
        """
        Initializes the NexusLLM wrapper.

        Args:
            primary: The main LLM client to use.
            fallback: An optional secondary client to use if the primary fails.
            logger: An optional logger instance.
            chain: The full provider order, when longer than two. ``None``
                keeps the historical ``(primary, fallback)`` pair.
        """
        self.primary = primary
        self.fallback = fallback
        self._logger = logger or get_logger("NexusLLM")
        ordered = [primary, fallback] if chain is None else list(chain)
        self.chain: tuple[BaseLLMClient, ...] = tuple(
            client for client in ordered if client is not None
        )
        self._event_sink: Optional[Callable[[str, Dict[str, Any]], None]] = None

        # Stats tracking
        self._calls_total = 0
        self._calls_primary = 0
        self._calls_fallback = 0
        self._successes_primary = 0
        self._successes_fallback = 0
        self._total_tokens = 0
        self._total_latency_ms = 0.0

    @property
    def provider_names(self) -> tuple[str, ...]:
        """The chain in order, as the operator named it."""
        return tuple(client.config.provider.value for client in self.chain)

    def attach_event_sink(self, sink: Optional[Callable[[str, Dict[str, Any]], None]]) -> None:
        """Route chain telemetry (``provider_fallback``) to the run journal.

        The sink is a plain ``(event_type, payload)`` callable so the LLM layer
        never imports the kernel (Fix 4.3). Telemetry must never break a turn:
        a raising sink is logged and ignored.
        """
        self._event_sink = sink

    def _emit(self, event_type: str, payload: Dict[str, Any]) -> None:
        if self._event_sink is None:
            return
        try:
            self._event_sink(event_type, payload)
        except Exception as error:  # noqa: BLE001 - telemetry is best-effort
            self._logger.warning(f"LLM telemetry sink failed for {event_type}: {error}")

    async def complete(
        self, messages: List[LLMMessage], **kwargs: Any
    ) -> LLMResponse:
        """Executes a completion request across the provider chain (Fix 4.2).

        * transient (413/429/500/502/503/504, network stall): next provider, and
          when the failing one is the last, up to ``CHAIN_MAX_ATTEMPTS`` attempts
          with exponential backoff;
        * invalid JSON: the same provider once more with an explicit
          \"answer only JSON\" turn, then the next provider;
        * authentication (401/403): terminal, the run fails with the cause.

        Args:
            messages: The conversation history.
            **kwargs: Provider-specific arguments.

        Returns:
            The LLMResponse from the first provider that answered.

        Raises:
            LLMChainExhausted: If every provider failed; carries each cause.
        """
        self._calls_total += 1
        chain = self.chain or (self.primary,)
        causes: List[Dict[str, Any]] = []
        for index, client in enumerate(chain):
            name = client.config.provider.value
            is_last = index == len(chain) - 1
            self._logger.info(f"Attempting completion with provider: {name}")
            if index == 0:
                self._calls_primary += 1
            else:
                self._calls_fallback += 1
            json_correction_used = False
            attempt = 1
            while True:
                try:
                    response = await client.complete(messages, **kwargs)
                    if index == 0:
                        self._successes_primary += 1
                    else:
                        self._successes_fallback += 1
                    self._update_stats(response)
                    return response
                except Exception as error:  # noqa: BLE001 - classified below
                    kind = classify_failure(error)
                    status = _status_code_of(error)
                    causes.append(
                        {
                            "provider": name,
                            "status_code": status,
                            "reason": kind,
                            "message": str(error)[:300],
                            "attempt": attempt,
                        }
                    )
                    self._logger.warning(
                        f"Provider '{name}' failed ({kind}"
                        f"{f', status {status}' if status else ''}): {error}"
                    )
                    if kind == FAILURE_AUTH:
                        # A rejected key or a forbidden account is configuration:
                        # spending the rest of the chain on it hides the cause.
                        raise LLMChainExhausted(causes) from error
                    if kind == FAILURE_INVALID_JSON and not json_correction_used:
                        json_correction_used = True
                        attempt += 1
                        messages = _with_json_correction(messages)
                        self._logger.info(
                            f"Provider '{name}' returned invalid JSON; retrying once "
                            f"with an explicit JSON-only instruction"
                        )
                        continue
                    if not is_last:
                        self._emit(
                            "provider_fallback",
                            {
                                "from": name,
                                "to": chain[index + 1].config.provider.value,
                                "reason": kind,
                                "attempt": attempt,
                            },
                        )
                        break
                    if kind == FAILURE_TRANSIENT and attempt < CHAIN_MAX_ATTEMPTS:
                        delay = backoff_base_seconds() * (2 ** (attempt - 1))
                        if delay > 0:
                            await asyncio.sleep(delay)
                        attempt += 1
                        continue
                    raise LLMChainExhausted(causes) from error
        raise LLMChainExhausted(causes)

    @property
    def supports_streaming(self) -> bool:
        """True when the primary provider can emit real token deltas."""
        return bool(getattr(self.primary, "supports_streaming", False))

    async def stream(self, messages: List[LLMMessage], **kwargs: Any) -> AsyncIterator[str]:
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
            "calls_primary_success": self._successes_primary,
            "calls_fallback_success": self._successes_fallback,
            "total_tokens_processed": self._total_tokens,
            "avg_latency_ms": avg_latency,
        }
