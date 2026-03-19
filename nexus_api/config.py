"""Configuración central de nexus_api — carga desde .env."""
from pydantic_settings import BaseSettings
from typing import List

class Settings(BaseSettings):
    # NEXUS
    NEXUS_CORE_PATH: str = "../nexus_core"
    # LLM
    OPENAI_API_KEY: str = ""
    GEMINI_API_KEY: str = ""
    LLM_PROVIDER: str = "openai"
    # API Server
    API_HOST: str = "0.0.0.0"
    API_PORT: int = 8000
    # CORS como string simple — se parsea en la propiedad
    CORS_ORIGINS: str = "http://localhost:3000,http://127.0.0.1:3000"
    DEBUG: bool = False
    # Workspace
    PROJECTS_DIR: str = "../projects"
    DOCKER_TEMPLATES: str = "../docker/templates"

    @property
    def cors_origins_list(self) -> List[str]:
        """Retorna CORS_ORIGINS como lista, soporta comma-separated."""
        return [o.strip() for o in self.CORS_ORIGINS.split(",") if o.strip()]

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        extra = "ignore"

settings = Settings()
