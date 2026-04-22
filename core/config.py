"""
core/config.py
Everything that changes between environments (dev, staging, prod).
"""
from pydantic_settings import BaseSettings
from typing import ClassVar


class Settings(BaseSettings):
    NVD_API_KEY: str
    DATABASE_URL: str
    R2_EXTRACTOR_KEY: str
    R2_EXTRACTOR_SECRECT_KEY: str
    R2_PL_URL: str
    R2_BUCKET_NAME: str

    ALLOWED_HOSTS: ClassVar[set] = {
        "services.nvd.nist.gov",
        "api.first.org",
        "epss.empiricalsecurity.com",
        "raw.githubusercontent.com",
        "www.cisa.gov",
    }

    SENSITIVE_KEYS: ClassVar[set] = {
        "authorization",
        "x-api-key",
        "x-secret-key",
        "x-access-token",
        "apikey",
    }

    class Config:
        env_file = ".env"


settings = Settings()
