"""Versioned global configuration with a small, fixed-section TOML writer."""

from dataclasses import asdict, dataclass, field, fields
import json
import math
import tomllib
from typing import Any

CURRENT_SCHEMA_VERSION = 1
PROVIDERS = ("groq", "openai", "anthropic", "gemini", "ollama", "fake")
DEFAULT_MODELS = {
    # Fase 3.8: the free Groq model with the best instruction-following of the
    # options the operator's key actually exposes (see docs/missions/
    # FASE38_MODEL_CHANGE.md). gpt-oss-120b was the default and failed the E2E
    # #4 on schema/instruction following; gpt-oss-safeguard-20b cannot fit the
    # ~3k-token agent prompt inside its 2k free-tier TPM budget.
    "groq": "qwen/qwen3.8-27b",
    "openai": "gpt-4o-mini",
    "anthropic": "claude-sonnet-4-20250514",
    "gemini": "gemini-2.5-flash",
    "ollama": "llama3",
    "fake": "nexus-fake-v1",
}


def model_env_name(provider: str) -> str:
    return "FAKE_LLM_MODEL" if provider == "fake" else provider.upper() + "_MODEL"


@dataclass
class LlmConfig:
    default_provider: str = "groq"
    default_model: str = "qwen/qwen3.8-27b"
    api_keys: dict[str, str] = field(default_factory=dict, repr=False)


@dataclass
class DbConfig:
    path: str = ""
    backend: str = "sqlite"


@dataclass
class ProvisioningConfig:
    auto_install: bool = False
    prefer_user_install: bool = True
    install_dir: str = ""
    available_managers: list[str] = field(default_factory=list)


@dataclass
class ScopeConfig:
    signing_secret: str = field(default="", repr=False)


def _value(value):
    if isinstance(value, dict):
        return "{ " + ", ".join(f"{json.dumps(k)} = {_value(v)}" for k, v in value.items()) + " }"
    if isinstance(value, list):
        return "[" + ", ".join(_value(item) for item in value) + "]"
    if type(value) in (str, bool, int) or (type(value) is float and math.isfinite(value)):
        return json.dumps(value, ensure_ascii=False)
    raise ValueError("unsupported TOML value")


@dataclass
class OmniConfig:
    schema_version: int = CURRENT_SCHEMA_VERSION
    llm: LlmConfig = field(default_factory=LlmConfig)
    db: DbConfig = field(default_factory=DbConfig)
    provisioning: ProvisioningConfig = field(default_factory=ProvisioningConfig)
    scope: ScopeConfig = field(default_factory=ScopeConfig)
    tools_detected: dict[str, Any] = field(default_factory=dict)

    def to_toml(self) -> str:
        data = asdict(self)
        lines = [f"schema_version = {data.pop('schema_version')}"]
        for section, values in data.items():
            lines.extend(["", f"[{section}]"])
            lines.extend(f"{json.dumps(key)} = {_value(value)}" for key, value in values.items())
        text = "\n".join(lines) + "\n"
        self.from_toml(text)
        return text

    @classmethod
    def from_toml(cls, text: str):
        data = tomllib.loads(text)
        if set(data) - {f.name for f in fields(cls)}:
            raise ValueError("unknown config fields")
        version = data.get("schema_version", CURRENT_SCHEMA_VERSION)
        if type(version) is not int or version != CURRENT_SCHEMA_VERSION:
            raise ValueError("unsupported schema version")
        result = cls()
        for section, kind in (
            ("llm", LlmConfig),
            ("db", DbConfig),
            ("provisioning", ProvisioningConfig),
            ("scope", ScopeConfig),
        ):
            values = data.get(section, {})
            if not isinstance(values, dict):
                raise ValueError("config sections must be tables")
            obj = kind(**values)
            for f in fields(kind):
                if type(getattr(obj, f.name)) is not type(getattr(kind(), f.name)):
                    raise ValueError("invalid config field type")
            setattr(result, section, obj)
        if result.llm.default_provider not in PROVIDERS or result.db.backend not in {
            "sqlite",
            "postgres",
        }:
            raise ValueError("invalid provider or database backend")
        if not all(k in PROVIDERS and isinstance(v, str) for k, v in result.llm.api_keys.items()):
            raise ValueError("invalid API key mapping")
        if not all(isinstance(v, str) for v in result.provisioning.available_managers):
            raise ValueError("invalid managers")
        cache = data.get("tools_detected", {})
        if not isinstance(cache, dict):
            raise ValueError("tools_detected must be a table")
        result.tools_detected = cache
        return result
