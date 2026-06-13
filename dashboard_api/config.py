"""
dashboard_api/config.py
API-layer settings, read from environment / .env.

Kept separate from core.config.Settings so the API can be deployed without the
pipeline's NVD/R2 credentials. pydantic-settings ignores undeclared env vars,
so a shared .env containing both is fine.
"""
from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class DashboardAPISettings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # --- auth ---
    # Required to call any data endpoint. Empty => auth is treated as
    # mis-configured and every request is rejected (fail closed).
    DASHBOARD_API_KEY: str = ""
    # Optional: gate any future /admin/* routes behind a stronger key.
    ADMIN_API_KEY: str = ""

    # --- CORS ---
    # Comma-separated origin list, or "*" for any (dev only).
    CORS_ALLOW_ORIGINS: str = "*"

    # --- rate limiting (per client IP, sliding 60s window) ---
    RATE_LIMIT_PER_MINUTE: int = 120

    # --- pagination guards ---
    DEFAULT_PAGE_SIZE: int = 25
    MAX_PAGE_SIZE: int = 100

    # --- misc ---
    ENV: str = "dev"

    @property
    def cors_origins(self) -> list[str]:
        raw = (self.CORS_ALLOW_ORIGINS or "").strip()
        if raw == "*" or raw == "":
            return ["*"]
        return [origin.strip() for origin in raw.split(",") if origin.strip()]


api_settings = DashboardAPISettings()
