"""
pipeline/extractors/base.py
Shared behavior: retry, log, store.
"""
import logging
import httpx
from abc import ABC, abstractmethod
from tenacity import (
    retry,
    stop_after_attempt,
    wait_exponential,
    retry_if_not_exception_type,
)
from core.security import is_allowed_url
from core.exceptions.exceptions import (
    URLNotAllowedError,
    RateLimitError,
    ExtractionError,
    StoreError,
)
from storage.parquet import to_parquet_bytes
from storage.s3 import upload_parquet


class BaseExtractor(ABC):
    def __init__(self, elt_run_id: str, source: str):
        self.elt_run_id = elt_run_id
        self.source = source

    @abstractmethod
    def fetch(self) -> list[dict]:
        pass
    @abstractmethod
    def build_url(self) -> str:
        pass
    @abstractmethod
    def _parser(self,resp: httpx.Response) -> list[dict]:
        pass
    @abstractmethod
    def fetch(self) -> list[dict]:
        pass
    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=2, min=2, max=10),
        retry=retry_if_not_exception_type((URLNotAllowedError, RateLimitError)),
        reraise=True,
    )
    def _request(
        self, url: str, params: dict = None, headers: dict = None
    ) -> httpx.Response:
        """
        Guarded HTTP GET: allowlist check → request → retry on transient failures.
        403 and blocked URLs raise immediately (not retried).
        """
        if not is_allowed_url(url):
            raise URLNotAllowedError(f"URL not allowed: {url}")
        try:
            response = httpx.get(url, params=params, headers=headers)
            if response.status_code == 403:
                raise RateLimitError(f"403 on {url} — not retrying")
            response.raise_for_status()
            return response
        except (URLNotAllowedError, RateLimitError):
            raise
        except Exception as e:
            print(f"Fetch failed for {url}: {e}")
            raise ExtractionError(f"Fetch failed for {url}") from e

    def _store(self, records: list[dict], s3_key: str) -> None:
        """Serialize records to Parquet and upload to R2."""
        try:
            parquet_bytes = to_parquet_bytes(records)
            upload_parquet(parquet_bytes, s3_key)
        except Exception as e:
            raise StoreError(
                f"Failed to store {len(records)} records to {s3_key}"
            ) from e

    def _log(self, message: str):
        """Placeholder — will write to pipeline_logs table."""
        pass
