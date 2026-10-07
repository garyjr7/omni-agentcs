"""Canonical LLM provider resolution, shared by every entry point.

``omni.py`` (CLI) and ``nexus_worker.py`` both have to publish the operator's
provider choice in the environment *before* the kernel resolves a client, and
they used to derive it with two slightly different expressions. They now call
:func:`publish_default_provider`, so the CLI, the worker, ``execute_react`` and
``build_llm_client`` all agree on the same provider by construction.

This module also owns the log-level policy: ``NEXUS_LOG_LEVEL`` (default
``warning``) decides whether the internal LLM loggers may speak at all.
"""

from __future__ import annotations

import logging
import os
from typing import Any

#: Env var that the kernel's ``select_llm_client`` reads as the operator choice.
DEFAULT_PROVIDER_ENV = "NEXUS_LLM_DEFAULT_PROVIDER"
#: Legacy/short env var accepted as an alias for the same choice.
LEGACY_PROVIDER_ENV = "LLM_PROVIDER"
#: Env var controlling the CLI log level.
LOG_LEVEL_ENV = "NEXUS_LOG_LEVEL"
#: Default level: warning, so the internal LLM chatter never reaches the REPL.
DEFAULT_LOG_LEVEL = "warning"

#: Loggers that emit one line per provider/call and would corrupt the spinner.
NOISY_LOGGERS = (
    "LLMFactory",
    "NexusLLM",
    "LLMClient.fake",
    "LLMClient.groq",
    "LLMClient.openai",
    "LLMClient.gemini",
    "LLMClient.anthropic",
    "LLMClient.ollama",
)

#: Providers accepted from the environment, in the factory's resolution order.
PROVIDER_ORDER = ("openai", "gemini", "groq", "anthropic", "ollama")
#: Provider name -> env var holding its API key/base URL.
PROVIDER_KEY_ENVS = {
    "openai": "OPENAI_API_KEY",
    "gemini": "GEMINI_API_KEY",
    "groq": "GROQ_API_KEY",
    "anthropic": "ANTHROPIC_API_KEY",
    "ollama": "OLLAMA_BASE_URL",
}
#: Provider name -> (model env var, factory default model).
PROVIDER_MODEL_ENVS = {
    "fake": ("FAKE_LLM_MODEL", "nexus-fake-v1"),
    "openai": ("OPENAI_MODEL", "gpt-4o-mini"),
    "gemini": ("GEMINI_MODEL", "gemini-1.5-flash"),
    "groq": ("GROQ_MODEL", "qwen/qwen3.8-27b"),
    "anthropic": ("ANTHROPIC_MODEL", "claude-sonnet-4-20250514"),
    "ollama": ("OLLAMA_MODEL", "llama3"),
}
#: Always available, deterministic, offline.
FAKE_PROVIDER = "fake"

_LOG_LEVELS = {
    "debug": logging.DEBUG,
    "info": logging.INFO,
    "warning": logging.WARNING,
    "warn": logging.WARNING,
    "error": logging.ERROR,
    "critical": logging.CRITICAL,
}


def resolve_log_level() -> int:
    """Level for the CLI's own loggers, from ``NEXUS_LOG_LEVEL`` (default warning)."""
    raw = str(os.getenv(LOG_LEVEL_ENV) or DEFAULT_LOG_LEVEL).strip().lower()
    return _LOG_LEVELS.get(raw, logging.WARNING)


def verbose_logging() -> bool:
    """True when the operator explicitly asked for ``info``/``debug`` detail."""
    return resolve_log_level() <= logging.INFO


def configure_logging() -> int:
    """Apply ``NEXUS_LOG_LEVEL`` to the noisy loggers; return the effective level.

    ``get_logger`` reconfigures its logger (new handler + ``setLevel(DEBUG)``) on
    every call, so this has to be re-applied per entry point instead of once at
    import time. Idempotent and cheap.
    """
    level = resolve_log_level()
    for name in NOISY_LOGGERS:
        logging.getLogger(name).setLevel(level)
    return level


def available_providers(env: dict[str, str] | None = None) -> list[str]:
    """Providers that can actually be built, ``fake`` always included and first.

    Mirrors ``LLMFactory.create_from_env`` without constructing any client (which
    would log one INFO line per provider).
    """
    source = os.environ if env is None else env
    found = [
        name
        for name in PROVIDER_ORDER
        if str(source.get(PROVIDER_KEY_ENVS[name]) or "").strip()
    ]
    return [FAKE_PROVIDER, *found]


def resolve_provider(env: dict[str, str] | None = None) -> str:
    """The provider the kernel will use, resolved exactly like ``select_llm_client``.

    Precedence: an explicit ``NEXUS_LLM_DEFAULT_PROVIDER`` wins, but only when
    that provider is actually available — otherwise the offline ``fake`` client
    is used, never a different cloud. Without an explicit choice, the first real
    provider wins. This is the single source of truth for "which provider".
    """
    source = os.environ if env is None else env
    available = available_providers(source)
    selected = str(source.get(DEFAULT_PROVIDER_ENV) or "").strip().lower()
    if selected:
        return selected if selected in available else FAKE_PROVIDER
    real = [name for name in available if name != FAKE_PROVIDER]
    return real[0] if real else FAKE_PROVIDER


def provider_summary(env: dict[str, str] | None = None) -> tuple[str, int]:
    """``("<provider>/<model>", real_provider_count)`` for the banner."""
    source = os.environ if env is None else env
    chosen = resolve_provider(source)
    model_env, default_model = PROVIDER_MODEL_ENVS.get(chosen, ("", "unknown"))
    model = str(source.get(model_env) or default_model) if model_env else default_model
    real = [name for name in available_providers(source) if name != FAKE_PROVIDER]
    return f"{chosen}/{model}", len(real)


def publish_default_provider(config: Any = None) -> str:
    """Publish the operator's provider choice into ``NEXUS_LLM_DEFAULT_PROVIDER``.

    Called by every process that runs agentic work (CLI, worker) before the
    kernel resolves a client. An explicit ``NEXUS_LLM_DEFAULT_PROVIDER`` already
    in the environment always wins; then ``LLM_PROVIDER``; then the global
    config. A ``fake`` alias is only adopted when no real provider is
    configured, so a stale ``LLM_PROVIDER=fake`` cannot silently downgrade a
    working cloud provider, and a configured provider without credentials
    resolves to ``fake`` instead of being published as if it were usable.
    """
    explicit = str(os.getenv(DEFAULT_PROVIDER_ENV) or "").strip().lower()
    if explicit:
        return explicit
    available = available_providers()
    candidates = [
        str(os.getenv(LEGACY_PROVIDER_ENV) or "").strip().lower(),
        str(getattr(getattr(config, "llm", None), "default_provider", "") or "").strip().lower(),
    ]
    for candidate in candidates:
        # Only a provider that can actually be built may be published, so the
        # environment never advertises a provider without credentials.
        if candidate and candidate != FAKE_PROVIDER and candidate in available:
            os.environ[DEFAULT_PROVIDER_ENV] = candidate
            return candidate
    os.environ[DEFAULT_PROVIDER_ENV] = FAKE_PROVIDER
    return FAKE_PROVIDER


__all__ = [
    "DEFAULT_LOG_LEVEL",
    "DEFAULT_PROVIDER_ENV",
    "FAKE_PROVIDER",
    "LEGACY_PROVIDER_ENV",
    "LOG_LEVEL_ENV",
    "NOISY_LOGGERS",
    "PROVIDER_KEY_ENVS",
    "PROVIDER_MODEL_ENVS",
    "PROVIDER_ORDER",
    "available_providers",
    "configure_logging",
    "provider_summary",
    "publish_default_provider",
    "resolve_log_level",
    "resolve_provider",
    "verbose_logging",
]