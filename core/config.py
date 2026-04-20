"""
core/config.py
Everything that changes between environments (dev, staging, prod).
"""
import os
from dotenv import load_dotenv
from pydantic_settings import BaseSettings
from typing import ClassVar
class Settings(BaseSettings):
    NVD_API_KEY: str
    EPSS_KEY: str
    CISA_KEV_KEY: str
    CWE_KEY: str
    DATABASE_URL: str
    R2_EXTRACTOR_KEY: str
    R2_EXTRACTOR_SECRECT_KEY: str
    R2_PL_URL: str
    R2_BUCKET_NAME: str
    ALLOWED_HOSTS : ClassVar[set] = {
    "services.nvd.nist.gov",
    "api.first.org",
    "epss.empiricalsecurity.com",
    "raw.githubusercontent.com",
    "www.cisa.gov",
}
    SENSITIVE_KEYS : ClassVar[set] = {
        "Authorization",
        "X-API-Key",
        "X-Secret-Key",
        "X-Access-Token",
        "X-Token",
        "X-Key",
        "X-Secret",
        "X-Token",
        "X-Key",
        "X-Secret",
    }

    class Config:
        env_file = ".env"

