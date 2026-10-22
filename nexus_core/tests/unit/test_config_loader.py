from dataclasses import asdict
from unittest.mock import patch
import pytest

from nexus_core.config.schema import OmniConfig
from nexus_core.config.loader import (
    ConfigError,
    apply_environment,
    config_exists,
    load_config,
    save_config,
)

pytestmark = pytest.mark.usefixtures("onboarding_env")


def test_default_config_schema_version_1():
    assert OmniConfig().schema_version == 1


def test_roundtrip_toml_serialization():
    config = OmniConfig()
    config.llm.api_keys = {"groq": 'secret"\\\nñ'}
    config.tools_detected = {"nmap": {"present": True, "version": "1"}}
    assert asdict(OmniConfig.from_toml(config.to_toml())) == asdict(config)


def test_load_missing_file_returns_defaults(onboarding_env):
    assert load_config(onboarding_env.paths) == OmniConfig()


def test_load_valid_file_returns_config(onboarding_env):
    config = OmniConfig()
    config.db.path = "/tmp/custom.db"
    save_config(config, onboarding_env.paths)
    assert load_config(onboarding_env.paths) == config


def test_load_corrupt_file_backs_up_and_returns_defaults(onboarding_env):
    paths = onboarding_env.paths
    paths.ensure_dirs()
    paths.config_file.write_text("[broken")
    assert load_config(paths) == OmniConfig()
    assert OmniConfig.from_toml(paths.config_file.read_text()) == OmniConfig()


def test_load_creates_backup_with_bak_suffix(onboarding_env):
    paths = onboarding_env.paths
    paths.ensure_dirs()
    paths.config_file.write_text("schema_version = 'wrong'")
    load_config(paths)
    assert paths.config_file.with_suffix(".toml.bak").read_text() == "schema_version = 'wrong'"


def test_save_creates_dirs(onboarding_env):
    save_config(OmniConfig(), onboarding_env.paths)
    assert onboarding_env.paths.data_dir.is_dir()


def test_save_sets_mode_600(onboarding_env):
    result = save_config(OmniConfig(), onboarding_env.paths)
    assert result.stat().st_mode & 0o777 == 0o600


def test_save_overwrites_atomically(onboarding_env):
    paths = onboarding_env.paths
    save_config(OmniConfig(), paths)
    original = paths.config_file.read_bytes()
    config = OmniConfig()
    config.db.path = "/tmp/new.db"
    with patch("nexus_core.config.loader.os.replace", side_effect=OSError):
        with pytest.raises(ConfigError):
            save_config(config, paths)
    assert paths.config_file.read_bytes() == original
    assert not list(paths.config_dir.glob("*.tmp"))


def test_config_exists_true_false(onboarding_env):
    assert not config_exists(onboarding_env.paths)
    save_config(OmniConfig(), onboarding_env.paths)
    assert config_exists(onboarding_env.paths)


def test_env_precedence_and_config_provider(onboarding_env, monkeypatch):
    import os

    config = OmniConfig()
    config.llm.api_keys = {"groq": "from-config"}
    monkeypatch.setenv("GROQ_API_KEY", "from-env")
    monkeypatch.setenv("NEXUS_DB_PATH", "/tmp/explicit.db")
    apply_environment(config, onboarding_env.paths)
    assert os.environ["GROQ_API_KEY"] == "from-env"
    assert os.environ["NEXUS_DB_PATH"] == "/tmp/explicit.db"


def test_unwritable_recovery_does_not_crash(onboarding_env):
    paths = onboarding_env.paths
    paths.ensure_dirs()
    paths.config_file.write_text("x=[")
    with patch("pathlib.Path.replace", side_effect=OSError):
        assert load_config(paths) == OmniConfig()


# ------------------------------------------- the provider chain (Tanda C, 4.1)
def test_the_fallback_chain_round_trips_and_reaches_the_environment(
    onboarding_env, monkeypatch
):
    import os

    monkeypatch.delenv("NEXUS_LLM_FALLBACK_CHAIN", raising=False)
    config = OmniConfig()
    config.llm.fallback_chain = ["groq", "deepseek", "ollama"]

    restored = OmniConfig.from_toml(config.to_toml())
    apply_environment(restored, onboarding_env.paths)

    assert restored.llm.fallback_chain == ["groq", "deepseek", "ollama"]
    assert os.environ["NEXUS_LLM_FALLBACK_CHAIN"] == "groq,deepseek,ollama"


def test_an_absent_chain_keeps_the_environment_unset(onboarding_env, monkeypatch):
    import os

    monkeypatch.delenv("NEXUS_LLM_FALLBACK_CHAIN", raising=False)
    apply_environment(OmniConfig(), onboarding_env.paths)
    assert "NEXUS_LLM_FALLBACK_CHAIN" not in os.environ


@pytest.mark.parametrize(
    "chain",
    [
        ["groq", "nope"],          # unknown provider
        ["groq", "deepseek", "groq"],  # a provider twice is a typo, not a plan
        ["groq", "fake"],          # the fake would answer every failure
    ],
)
def test_an_invalid_chain_is_rejected(chain):
    config = OmniConfig()
    config.llm.fallback_chain = chain
    with pytest.raises(ValueError):
        OmniConfig.from_toml(config.to_toml())
