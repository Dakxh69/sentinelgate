"""Application configuration for SentinelGate.

Loads settings from environment variables (optionally via a .env file).
JWT_SECRET is strictly required for security; the application fails fast at startup if missing.
"""

from __future__ import annotations

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8", extra="ignore"
    )

    # PostgreSQL connection URL (psycopg3 driver)
    DATABASE_URL: str = "postgresql+psycopg://postgres@127.0.0.1:5432/sentinelgate"
    REDIS_URL: str = "redis://127.0.0.1:6379/0"

    JWT_SECRET: str  # Required 32+ byte key
    JWT_EXPIRATION_MINUTES: int = 30

    RATE_LIMIT_REQUESTS: int = 100
    RATE_LIMIT_WINDOW_SECONDS: int = 60

    # Internal protected microservice URL
    BACKEND_URL: str = "http://backend:8001"

    # CORS allowlist: comma-separated origins. Empty string disables CORS.
    CORS_ALLOWED_ORIGINS: str = ""

    # C++ DLP Engine binary path (fail-closed when configured)
    DLP_ENGINE_PATH: str | None = None

    ADMIN_PASSWORD: str | None = None
    SEED_USER_PASSWORD: str | None = None

    def cors_origins(self) -> list[str]:
        """Parse CORS_ALLOWED_ORIGINS into a list. Empty list disables CORS."""
        raw = (self.CORS_ALLOWED_ORIGINS or "").strip()
        if not raw:
            return []
        return [origin.strip() for origin in raw.split(",") if origin.strip()]

    def sync_database_url(self) -> str:
        """Return the URL in SQLAlchemy psycopg3 form.

        Accepts both `postgresql://` (spec examples) and
        `postgresql+psycopg://`; the asyncpg form is rejected explicitly.
        """
        if self.DATABASE_URL.startswith("postgresql+psycopg://"):
            return self.DATABASE_URL
        if self.DATABASE_URL.startswith("postgresql://"):
            return self.DATABASE_URL.replace("postgresql://", "postgresql+psycopg://", 1)
        if self.DATABASE_URL.startswith("postgresql+asyncpg://"):
            raise ValueError("asyncpg is not supported; use a sync psycopg URL")
        return self.DATABASE_URL


@lru_cache
def get_settings() -> Settings:
    return Settings()  # type: ignore[call-arg]  # reads env/.env


def reset_settings_cache() -> None:
    """Clear the cached settings (used by tests to swap configuration)."""
    get_settings.cache_clear()
