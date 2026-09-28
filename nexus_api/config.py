"""Configuración central de nexus_api — carga desde .env."""
import os
from pathlib import Path
from typing import List

from pydantic_settings import BaseSettings

DEFAULT_NEXUS_ROOT = Path(__file__).resolve().parent.parent


def _resolve_path(value: str | Path, base: Path) -> Path:
    path = Path(value).expanduser()
    if not path.is_absolute():
        path = base / path
    return path.resolve()


class Settings(BaseSettings):
    # NEXUS
    NEXUS_ROOT: Path = DEFAULT_NEXUS_ROOT
    NEXUS_DATA_PATH: Path | None = None
    NEXUS_DB_PATH: Path | None = None
    NEXUS_CORE_PATH: Path | None = None
    # LLM
    OPENAI_API_KEY: str = ""
    GEMINI_API_KEY: str = ""
    LLM_PROVIDER: str = "openai"
    # API Server
    API_HOST: str = "0.0.0.0"
    API_PORT: int = 8000
    NEXUS_PUBLIC_URL: str = "http://localhost:8000"
    # CORS como string simple — se parsea en la propiedad
    CORS_ORIGINS: str = "http://localhost:3000,http://127.0.0.1:3000"
    DEBUG: bool = False
    NEXUS_ENV: str = "development"
    RATE_LIMIT_PER_MINUTE: int = 60
    RATE_LIMIT_BURST: int = 10
    # Workspace
    PROJECTS_DIR: Path | None = None
    DOCKER_TEMPLATES: Path | None = None

    def model_post_init(self, __context) -> None:
        self.NEXUS_ROOT = _resolve_path(self.NEXUS_ROOT, DEFAULT_NEXUS_ROOT)
        data_value = self.NEXUS_DATA_PATH or os.getenv("NEXUS_DATA_DIR") or "data"
        self.NEXUS_DATA_PATH = _resolve_path(data_value, self.NEXUS_ROOT)
        self.NEXUS_DB_PATH = _resolve_path(
            self.NEXUS_DB_PATH or self.NEXUS_DATA_PATH / "nexus_pro.db",
            self.NEXUS_ROOT,
        )
        self.NEXUS_CORE_PATH = _resolve_path(
            self.NEXUS_CORE_PATH or "nexus_core", self.NEXUS_ROOT
        )
        self.PROJECTS_DIR = _resolve_path(
            self.PROJECTS_DIR or self.NEXUS_DATA_PATH / "factory" / "projects",
            self.NEXUS_ROOT,
        )
        self.DOCKER_TEMPLATES = _resolve_path(
            self.DOCKER_TEMPLATES or "docker/templates", self.NEXUS_ROOT
        )

    @property
    def cors_origins_list(self) -> List[str]:
        """Retorna CORS_ORIGINS como lista, soporta comma-separated."""
        return [o.strip() for o in self.CORS_ORIGINS.split(",") if o.strip()]

    @property
    def is_production(self) -> bool:
        return self.NEXUS_ENV.lower() == "production"

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        extra = "ignore"


settings = Settings()

NEXUS_ROOT = settings.NEXUS_ROOT
NEXUS_DATA_PATH = settings.NEXUS_DATA_PATH
NEXUS_DB_PATH = settings.NEXUS_DB_PATH
