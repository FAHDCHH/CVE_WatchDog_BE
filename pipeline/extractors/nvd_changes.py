"""
pipeline/extractors/nvd_changes.py
NVD Change History-specific extractor.
"""
import httpx
import time
from urllib.parse import urlencode
from datetime import datetime, timedelta
from core.config import settings
from pipeline.extractors.base import BaseExtractor
from storage.s3 import build_s3_key
from db.models import EltRun

class NVD_Changes_Extractor(BaseExtractor):
    URL = "https://services.nvd.nist.gov/rest/json/cvehistory/2.0"

    def __init__(self, elt_run_id: str, mode: str, db=None):
        super().__init__(elt_run_id=elt_run_id, source="nvd_changes", db=db)
        if mode not in ("bulk_load", "delta_poll"):
            raise ValueError(f"Invalid mode: {mode}")
        if mode == "delta_poll" and db is None:
            raise ValueError("delta_poll mode requires a db session")
        self.mode = mode
        self.db = db
    def build_url(self, params: dict) -> str:
        qs = urlencode(params, safe=":")
        return f"{self.URL}?{qs}"

    def _build_params(self, start_date: str) -> dict:
        return {
            "changeStartDate": start_date,
            "changeEndDate": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000Z"),
            "resultsPerPage": 5000,
        }

    def _parser(self, resp: httpx.Response) -> list[dict]:
        return resp.json().get("cveChanges", [])

    def fetch(self):
        if self.mode == "bulk_load":
            # NVD max window is 120 days — start from beginning of NVD history
            start_date = "2026-04-01T00:00:00.000Z"
        else:
            last_run = self.db.query(EltRun).filter(
                EltRun.status == "success"
            ).order_by(EltRun.started_at.desc()).first()
            # First-run fallback: no prior successful run exists yet, so there
            # is no watermark to poll from. Use a bounded recent lookback window
            # instead of crashing on None.attribute access.
            if last_run is None:
                lookback_hours = int(getattr(settings, "DELTA_LOOKBACK_HOURS", 36))
                watermark = datetime.utcnow() - timedelta(hours=lookback_hours)
            else:
                watermark = last_run.started_at
            start_date = watermark.strftime("%Y-%m-%dT%H:%M:%S.000Z")

        params = self._build_params(start_date)
        start_index = 0
        page = 1
        while True:
            params["startIndex"] = start_index
            url = self.build_url(params)
            self._safe_log(
                "extract_change_history_started",
                f"Fetching change-history page {page}",
                page_number=page, request_url=url,
            )
            try:
                resp = self._request(url, headers={"apiKey": settings.NVD_API_KEY})
            except Exception as exc:
                self._safe_log(
                    "extract_change_history_failed",
                    f"Change-history page {page} fetch failed",
                    level="error", page_number=page,
                    metadata={"error_type": exc.__class__.__name__},
                )
                raise
            records = self._parser(resp)
            s3_key = build_s3_key(
                self.source,
                datetime.utcnow().strftime("%Y-%m-%d"),
                self.elt_run_id,
                f"{self.mode}_page_{page:03d}"
            )
            try:
                self._store(records, s3_key)
                self._safe_log(
                    "extract_r2_write_success",
                    f"Stored change-history page {page}",
                    page_number=page, s3_key=s3_key,
                )
            except Exception as exc:
                self._safe_log(
                    "extract_r2_write_failed",
                    f"R2 write failed for change-history page {page}",
                    level="error", page_number=page, s3_key=s3_key,
                    metadata={"error_type": exc.__class__.__name__},
                )
                raise
            self._safe_log(
                "extract_change_history_success",
                f"Change-history page {page} extracted",
                page_number=page, response_size_bytes=len(resp.content),
            )
            total = resp.json()["totalResults"]
            start_index += 5000
            page += 1
            if start_index >= total:
                break
            time.sleep(2)
