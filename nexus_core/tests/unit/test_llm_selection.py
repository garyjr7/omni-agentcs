"""LLM provider selection: one canonical decision for CLI, worker and agent.

Regression target: with a working ``GROQ_API_KEY`` in ``.env`` and a stale
``LLM_PROVIDER=fake``, ``execute_react`` used to run on the offline fake client.
"""

from __future__ import annotations

import os
from types import SimpleNamespace
from unittest import mock

import pytest

from nexus_core.cli import llm_env
from nexus_core.cli.session import OmniSession, build_llm_client

TENANT = "system"


@pytest.fixture()
def clean_env(monkeypatch, no_stored_keys):
    """A provider environment with no keys and no explicit choice.

    ``no_stored_keys`` keeps the operator's ``omni auth login`` store out of the
    picture: ``resolve_api_key`` prefers it over the environment.
    """
    for key in llm_env.PROVIDER_KEY_ENVS.values():
        monkeypatch.delenv(key, raising=False)
    monkeypatch.delenv(llm_env.DEFAULT_PROVIDER_ENV, raising=False)
    monkeypatch.delenv(llm_env.LEGACY_PROVIDER_ENV, raising=False)
    return monkeypatch


def _config(default_provider: str = "groq"):
    return SimpleNamespace(llm=SimpleNamespace(default_provider=default_provider))


# ------------------------------------------------------------- resolve_provider
def test_resolve_provider_prefers_real_provider_over_fake(clean_env):
    clean_env.setenv("GROQ_API_KEY", "gsk_fixture")
    assert llm_env.resolve_provider() == "groq"


def test_resolve_provider_uses_env_default_when_set(clean_env):
    clean_env.setenv("GROQ_API_KEY", "gsk_fixture")
    clean_env.setenv("OPENAI_API_KEY", "sk_fixture")
    clean_env.setenv(llm_env.DEFAULT_PROVIDER_ENV, "openai")
    assert llm_env.resolve_provider() == "openai"


def test_resolve_provider_falls_back_to_fake_when_no_real(clean_env):
    assert llm_env.resolve_provider() == "fake"
    assert llm_env.available_providers() == ["fake"]


def test_resolve_provider_selected_without_key_falls_back_to_fake(clean_env):
    clean_env.setenv("GROQ_API_KEY", "gsk_fixture")
    clean_env.setenv(llm_env.DEFAULT_PROVIDER_ENV, "openai")
    # Never silently pick a different cloud than the one asked for.
    assert llm_env.resolve_provider() == "fake"


def test_resolve_provider_ignores_legacy_llm_provider_env(clean_env):
    """``LLM_PROVIDER`` is only an alias; the canonical var is what counts."""
    clean_env.setenv("GROQ_API_KEY", "gsk_fixture")
    clean_env.setenv(llm_env.LEGACY_PROVIDER_ENV, "fake")
    assert llm_env.resolve_provider() == "groq"


# ------------------------------------------------------- publish_default_provider
def test_publish_ignores_stale_fake_when_real_provider_configured(clean_env):
    """The exact production bug: ``LLM_PROVIDER=fake`` must not shadow Groq."""
    clean_env.setenv("GROQ_API_KEY", "gsk_fixture")
    clean_env.setenv(llm_env.LEGACY_PROVIDER_ENV, "fake")
    assert llm_env.publish_default_provider(_config("groq")) == "groq"
    assert os.environ[llm_env.DEFAULT_PROVIDER_ENV] == "groq"


def test_publish_respects_explicit_default_provider(clean_env):
    clean_env.setenv("GROQ_API_KEY", "gsk_fixture")
    clean_env.setenv(llm_env.DEFAULT_PROVIDER_ENV, "fake")
    assert llm_env.publish_default_provider(_config("groq")) == "fake"


def test_publish_uses_legacy_value_when_it_names_a_real_provider(clean_env):
    clean_env.setenv("GROQ_API_KEY", "gsk_fixture")
    clean_env.setenv(llm_env.LEGACY_PROVIDER_ENV, "groq")
    assert llm_env.publish_default_provider(_config("openai")) == "groq"


def test_publish_adopts_fake_only_when_no_real_provider_exists(clean_env):
    assert llm_env.publish_default_provider(_config("groq")) == "fake"
    assert os.environ[llm_env.DEFAULT_PROVIDER_ENV] == "fake"


def test_publish_tolerates_config_without_llm_section(clean_env):
    clean_env.setenv("GROQ_API_KEY", "gsk_fixture")
    assert llm_env.publish_default_provider(object()) == "fake"


# -------------------------------------------------------------- select_llm_client
def test_select_llm_client_prefers_real_provider_over_fake(clean_env):
    clean_env.setenv("GROQ_API_KEY", "gsk_fixture")
    from nexus_core.kernel.runtime import select_llm_client

    llm = select_llm_client()
    assert llm.primary.config.provider.value == "groq"


def test_select_llm_client_uses_env_default_when_set(clean_env):
    clean_env.setenv("GROQ_API_KEY", "gsk_fixture")
    clean_env.setenv("OPENAI_API_KEY", "sk_fixture")
    clean_env.setenv(llm_env.DEFAULT_PROVIDER_ENV, "openai")
    from nexus_core.kernel.runtime import select_llm_client

    assert select_llm_client().primary.config.provider.value == "openai"


def test_select_llm_client_falls_back_to_fake_when_no_real(clean_env):
    from nexus_core.kernel.runtime import select_llm_client

    assert select_llm_client().primary.config.provider.value == "fake"


# ------------------------------------------- the chain (Tanda C, Fix 4.1)
def _clients(*names):
    from nexus_core.llm.abstraction import LLMProvider, LLMConfig

    class _Stub:
        def __init__(self, name):
            self.config = LLMConfig(provider=LLMProvider(name), model=f"{name}-stub")

    return {name: _Stub(name) for name in names}


def test_select_llm_client_builds_the_whole_configured_chain(clean_env):
    """The configured chain is the order, not "primary + one fallback"."""
    from nexus_core.kernel import runtime

    clean_env.setenv("NEXUS_LLM_FALLBACK_CHAIN", "groq,deepseek,ollama")
    clients = _clients("groq", "deepseek", "ollama", "fake")
    with mock.patch.object(
        runtime.LLMFactory, "create_from_env", return_value=clients
    ):
        llm = runtime.select_llm_client()

    assert llm.provider_names == ("groq", "deepseek", "ollama")
    assert llm.primary.config.provider.value == "groq"
    assert llm.fallback.config.provider.value == "deepseek"


def test_an_absent_chain_keeps_the_historical_pair(clean_env):
    from nexus_core.kernel import runtime

    clean_env.delenv("NEXUS_LLM_FALLBACK_CHAIN", raising=False)
    clients = _clients("groq", "deepseek", "ollama", "fake")
    with mock.patch.object(
        runtime.LLMFactory, "create_from_env", return_value=clients
    ):
        llm = runtime.select_llm_client()

    assert llm.provider_names == ("groq", "deepseek")


def test_a_chain_naming_a_missing_provider_drops_it(clean_env):
    """A provider without a key is not silently replaced by another cloud."""
    from nexus_core.kernel import runtime

    clean_env.setenv("NEXUS_LLM_FALLBACK_CHAIN", "groq,nope,ollama")
    clients = _clients("groq", "ollama", "fake")
    with mock.patch.object(
        runtime.LLMFactory, "create_from_env", return_value=clients
    ):
        llm = runtime.select_llm_client()

    assert llm.provider_names == ("groq", "ollama")


def test_a_chain_with_no_usable_provider_falls_back_to_the_offline_fake(clean_env):
    from nexus_core.kernel import runtime

    clean_env.setenv("NEXUS_LLM_FALLBACK_CHAIN", "nope")
    clients = _clients("fake")
    with mock.patch.object(
        runtime.LLMFactory, "create_from_env", return_value=clients
    ):
        llm = runtime.select_llm_client()

    assert llm.provider_names == ("fake",)


# ------------------------------------------------------------------- consumers
async def test_execute_react_uses_select_llm_client(clean_env, monkeypatch):
    """``execute_react`` must delegate the decision, never re-implement it."""
    clean_env.setenv("GROQ_API_KEY", "gsk_fixture")
    sentinel = object()
    captured: dict = {}

    async def _fake_loop(**kwargs):
        captured.update(kwargs)
        return SimpleNamespace(
            status="completed", completion_verified=False, iterations=1, final_summary="ok",
            findings=[], question=None, conversation_id="c-1", actions=[],
        )

    monkeypatch.setattr("nexus_core.agent.react.run_react_loop", _fake_loop)
    with mock.patch(
        "nexus_core.kernel.runtime.select_llm_client", return_value=sentinel
    ) as selector:
        from nexus_core.kernel.runtime import ExecutionContext, execute_react

        context = ExecutionContext(
            store=mock.MagicMock(),
            task={"id": "t", "tenant_id": TENANT, "run_id": "r", "task_type": "react.run"},
            worker_id="w",
        )
        await execute_react({"objective": "escanea scanme"}, context)

    selector.assert_called_once_with()
    assert captured["llm_client"] is sentinel


def test_cli_and_execute_react_agree_on_provider(clean_env):
    """Both paths resolve the same provider from the same environment."""
    clean_env.setenv("GROQ_API_KEY", "gsk_fixture")
    clean_env.setenv(llm_env.LEGACY_PROVIDER_ENV, "fake")
    llm_env.publish_default_provider(_config("groq"))

    from nexus_core.kernel.runtime import select_llm_client

    assert build_llm_client().primary.config.provider.value == "groq"
    assert select_llm_client().primary.config.provider.value == "groq"
    assert llm_env.provider_summary() == ("groq/qwen/qwen3.8-27b", 1)


def test_cli_process_publishes_real_provider_despite_stale_fake(clean_env, tmp_path):
    """``omni.main`` publishes the real provider: the end-to-end regression.

    The four XDG roots are redirected to ``tmp_path``: ``omni.main`` reads the
    config *from disk*, and an operator's own ``config.toml`` (a different
    provider, or a provider without a key) would decide the outcome instead of
    the fixture. The test was green in CI and red on any machine with a config.
    """
    for name in ("CONFIG", "DATA", "STATE", "CACHE"):
        clean_env.setenv(f"XDG_{name}_HOME", str(tmp_path / name.lower()))
    clean_env.setenv("GROQ_API_KEY", "gsk_fixture")
    clean_env.setenv(llm_env.LEGACY_PROVIDER_ENV, "fake")
    with (
        mock.patch("dotenv.load_dotenv"),
        mock.patch("nexus_core.cli.wizard.should_run_wizard", return_value=False),
        mock.patch("nexus_core.cli.main.main", return_value=0) as cli_main,
    ):
        import omni

        assert omni.main(["--no-wizard"]) == 0
    assert cli_main.called
    # The config on disk selects groq; the stale LLM_PROVIDER=fake is ignored.
    assert os.environ[llm_env.DEFAULT_PROVIDER_ENV] == "groq"


def test_worker_process_publishes_provider_from_config(clean_env, monkeypatch):
    """The worker resolves the provider itself instead of requiring LLM_PROVIDER."""
    monkeypatch.setenv("GROQ_API_KEY", "gsk_fixture")
    store = mock.MagicMock()
    store.claim_task.return_value = None
    monkeypatch.setattr("sys.argv", ["nexus_worker.py", "--once"])
    with (
        mock.patch("dotenv.load_dotenv"),
        mock.patch("nexus_core.config.loader.load_config", return_value=_config("groq")),
        mock.patch("nexus_core.config.loader.apply_environment"),
        mock.patch("nexus_worker.get_control_store", return_value=store),
        mock.patch("nexus_worker.build_default_registry"),
    ):
        import nexus_worker

        nexus_worker.main()
    assert os.environ[llm_env.DEFAULT_PROVIDER_ENV] == "groq"
    store.initialize.assert_called_once_with()


def test_provider_summary_counts_only_real_providers(clean_env):
    clean_env.setenv("GROQ_API_KEY", "gsk_fixture")
    clean_env.setenv("GEMINI_API_KEY", "gem_fixture")
    clean_env.setenv("GROQ_MODEL", "openai/gpt-oss-20b")
    clean_env.setenv(llm_env.DEFAULT_PROVIDER_ENV, "gemini")
    assert llm_env.provider_summary() == ("gemini/gemini-1.5-flash", 2)


def test_session_llm_stats_delegates_to_canonical_resolution(clean_env, monkeypatch):
    """The banner and the kernel cannot drift apart."""
    clean_env.setenv("GROQ_API_KEY", "gsk_fixture")
    session = OmniSession(store=None, engagement=None, operator_id="operator:t")
    # ``_llm_stats`` imports the helper at call time, so patch it at the source.
    with mock.patch.object(llm_env, "provider_summary", return_value=("groq/x", 1)) as patched:
        assert session._llm_stats() == ("groq/x", 1)
    patched.assert_called_once_with()
    assert session._llm_stats() == llm_env.provider_summary()