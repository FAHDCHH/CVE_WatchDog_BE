"""
pipeline/extractors/base.py
Shared behavior: retry, log, store.
"""

from abc import ABC, abstractmethod

import httpx
from tenacity import (
    retry,
    retry_if_not_exception_type,
    stop_after_attempt,
    wait_exponential,
)

from core.exceptions.exceptions import (
    ExtractionError,
    LoggingError,
    RateLimitError,
    StoreError,
    URLNotAllowedError,
)
from core.security import is_allowed_url
from pipeline.logs.pipeline_logs import PipelineLogger
from storage.parquet import to_parquet_bytes
from storage.s3 import upload_parquet


class BaseExtractor(ABC):
    def __init__(self, elt_run_id: str, source: str, db=None):
        self.elt_run_id = elt_run_id
        self.source = source
        self.logger = PipelineLogger(db=db, elt_run_id=elt_run_id) if db else None

    @abstractmethod
    def fetch(self) -> list[dict]:
        pass

    @abstractmethod
    def build_url(self) -> str:
        pass

    @abstractmethod
    def _parser(self, resp: httpx.Response) -> list[dict]:
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
        Guarded HTTP GET: allowlist check, request, then retry on transient failures.
        403 and blocked URLs raise immediately.
        """
        if not is_allowed_url(url):
            raise URLNotAllowedError(f"URL not allowed: {url}")
        try:
            response = httpx.get(url, params=params, headers=headers)
            if response.status_code == 403:
                raise RateLimitError(f"403 on {url}; not retrying")
            response.raise_for_status()
            return response
        except (URLNotAllowedError, RateLimitError):
            raise
        except Exception as exc:
            raise ExtractionError(f"Fetch failed for {url}") from exc

    def _store(self, records: list[dict], s3_key: str) -> None:
        """Serialize records to Parquet and upload to R2."""
        try:
            parquet_bytes = to_parquet_bytes(records)
            upload_parquet(parquet_bytes, s3_key)
        except Exception as exc:
            raise StoreError(
                f"Failed to store {len(records)} records to {s3_key}"
            ) from exc

    def _log(self, event_type: str, message: str, level: str = "info", **context):
        """Validate and persist a pipeline log event when a DB session is available."""
        if self.logger is None:
            raise LoggingError("Extractor logger requires a database session")
        return self.logger.log(
            level=level,
            source=self.source,
            event_type=event_type,
            message=message,
            **context,
        )

    def _safe_log(self, event_type: str, message: str, level: str = "info", **context):
        """Best-effort log: no-op when no DB session, never raises.

        Extraction must not abort because a log row failed to write, and the
        daily snapshot extractors run without a session at all. This lets the
        same logging calls live in every extractor regardless of wiring.
        """
        if self.logger is None:
            return None
        try:
            return self.logger.log(
                level=level,
                source=self.source,
                event_type=event_type,
                message=message,
                **context,
            )
        except Exception:
            return None
