"""Atomic global config storage. Corrupt files are preserved before recovery."""

import os
from pathlib import Path
import sys
import tempfile
import time

from .schema import OmniConfig, model_env_name
from .xdg import resolve_xdg_paths


class ConfigError(Exception):
    """Configuration could not be persisted."""


def config_exists(paths=None) -> bool:
    return (paths or resolve_xdg_paths()).config_file.is_file()


def save_config(config: OmniConfig, paths=None) -> Path:
    paths = paths or resolve_xdg_paths()
    temporary = None
    try:
        text = config.to_toml()
        paths.ensure_dirs()
        fd, temporary = tempfile.mkstemp(prefix=".config-", suffix=".tmp", dir=paths.config_dir)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, paths.config_file)
        return paths.config_file
    except (OSError, ValueError, TypeError) as exc:
        raise ConfigError(f"cannot save config ({type(exc).__name__})") from None
    finally:
        if temporary and Path(temporary).exists():
            Path(temporary).unlink()


def load_config(paths=None) -> OmniConfig:
    paths = paths or resolve_xdg_paths()
    try:
        return OmniConfig.from_toml(paths.config_file.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return OmniConfig()
    except OSError:
        print("No se puede leer config; usando defaults.", file=sys.stderr)
        return OmniConfig()
    except (ValueError, TypeError, UnicodeError):
        print("Config corrupto; respaldando y usando defaults.", file=sys.stderr)
        try:
            backup = paths.config_file.with_suffix(".toml.bak")
            if backup.exists():
                backup = paths.config_file.with_name("config.toml.bak." + str(time.time_ns()))
            paths.config_file.replace(backup)
            backup.chmod(0o600)
            save_config(OmniConfig(), paths)
        except (OSError, ConfigError):
            print(
                "No se pudo guardar la recuperación; usando defaults en memoria.", file=sys.stderr
            )
        return OmniConfig()


def effective_db_path(config, paths):
    from nexus_core.config import NEXUS_ROOT

    value = os.getenv("NEXUS_DB_PATH") or config.db.path
    if os.getenv("DATABASE_URL", "").startswith("sqlite:///"):
        value = os.environ["DATABASE_URL"].removeprefix("sqlite:///")
    path = Path(value).expanduser() if value else paths.db_file
    return path if path.is_absolute() else NEXUS_ROOT / path


def apply_environment(config, paths):
    """Explicit environment/.env wins; global config fills unset values."""
    os.environ.setdefault("NEXUS_DB_PATH", str(effective_db_path(config, paths)))
    os.environ.setdefault("NEXUS_DATA_PATH", str(paths.data_dir))
    os.environ.setdefault("NEXUS_STATE_PATH", str(paths.state_dir))
    os.environ.setdefault("NEXUS_CACHE_PATH", str(paths.cache_dir))
    os.environ.setdefault("LLM_PROVIDER", config.llm.default_provider)
    os.environ.setdefault(model_env_name(config.llm.default_provider), config.llm.default_model)
    for provider, key in config.llm.api_keys.items():
        if key and not os.getenv(provider.upper() + "_API_KEY"):
            os.environ[provider.upper() + "_API_KEY"] = key
    if config.scope.signing_secret:
        os.environ.setdefault("NEXUS_SCOPE_SIGNING_SECRET", config.scope.signing_secret)
    if config.llm.default_provider == "ollama":
        os.environ.setdefault("OLLAMA_BASE_URL", "http://127.0.0.1:11434")
    # Tanda C (Fix 4.1): the chain travels through the environment like every
    # other operator setting, so the durable runner and the CLI build the same
    # one without either re-reading the TOML.
    if config.llm.fallback_chain:
        os.environ.setdefault(
            "NEXUS_LLM_FALLBACK_CHAIN", ",".join(config.llm.fallback_chain)
        )
    if config.db.backend == "postgres" and not os.getenv("DATABASE_URL", "").startswith(
        ("postgres://", "postgresql://")
    ):
        raise ConfigError("postgres requires DATABASE_URL")
