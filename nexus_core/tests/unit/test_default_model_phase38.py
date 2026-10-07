"""Fase 3.8: the default Groq model is coherent across every layer.

The default model lives in three places that must not drift: the versioned
schema (``DEFAULT_MODELS``/``LlmConfig``), the CLI provider table
(``llm_env.PROVIDER_MODEL_ENVS``) and the factory fallback in
``LLMFactory.create_from_env``. This locks all of them to the model chosen in
``docs/missions/FASE38_MODEL_CHANGE.md``: ``qwen/qwen3.8-27b``.
"""

from __future__ import annotations

from nexus_core.cli import llm_env
from nexus_core.cli.tui.pricing import PROVIDER_FALLBACK, default_rates
from nexus_core.config.schema import DEFAULT_MODELS, LlmConfig

DEFAULT_GROQ_MODEL = "qwen/qwen3.8-27b"


def test_schema_default_is_the_phase_38_model():
    assert DEFAULT_MODELS["groq"] == DEFAULT_GROQ_MODEL
    assert LlmConfig().default_model == DEFAULT_GROQ_MODEL
    assert LlmConfig().default_provider == "groq"


def test_cli_provider_table_matches_the_schema():
    env_name, model = llm_env.PROVIDER_MODEL_ENVS["groq"]
    assert env_name == "GROQ_MODEL"
    assert model == DEFAULT_MODELS["groq"]


def test_factory_fallback_matches_the_schema(monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", "gsk_fixture")
    monkeypatch.delenv("GROQ_MODEL", raising=False)

    from nexus_core.llm.abstraction import LLMFactory

    clients = LLMFactory.create_from_env()
    assert clients["groq"].config.model == DEFAULT_MODELS["groq"]


def test_free_tier_model_reports_zero_reference_cost():
    # The operator runs on Groq's free tier, so the reference cost is zero
    # rather than a paid list price.
    assert default_rates(DEFAULT_GROQ_MODEL, "groq") == (0.0, 0.0)
    # A groq model without its own row still falls back to the provider rate.
    assert default_rates("some-unknown-groq-model", "groq") == PROVIDER_FALLBACK["groq"]
