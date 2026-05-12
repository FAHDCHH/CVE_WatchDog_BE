"""
pipeline/extractors/nvd_cves.py
NVD CVEs-specific extractor.
"""
import httpx
import time
from urllib.parse import urlencode
from datetime import datetime, timedelta
from core.config import settings
from pipeline.extractors.base import BaseExtractor
from storage.s3 import build_s3_key
from db.models import EltRun

class NVDCVEsExtractor(BaseExtractor):
    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    def __init__(self, elt_run_id: str, mode: str, db=None):
        super().__init__(elt_run_id=elt_run_id, source="nvd_cves")
        if mode not in ("bulk_load", "delta_poll"):
            raise ValueError(f"Invalid mode: {mode}")
        if mode == "delta_poll" and db is None:
            raise ValueError("delta_poll mode requires a db session")
        self.mode = mode
        self.db = db

   
    def build_url(self, extra_params: dict) -> str:
        """Construct the full NVD request URL.

        noRejected is a *valueless* boolean flag in NVD API v2.0
        (the server expects '?noRejected', not '?noRejected=').
        httpx replaces the URL query string entirely when params= is given,
        so we build the fi nal URL string here and pass params=None.
        """
        qs = "noRejected"
        if extra_params:
            qs += "&" + urlencode(extra_params)
        return f"{self.BASE_URL}?{qs}"
    def _parser(self, resp: httpx.Response) -> list[dict]:
        return resp.json()["vulnerabilities"]
    def _build_params(self, pass_name: str = None, start_date: str = None) -> dict:
        if self.mode == "bulk_load":
            if pass_name not in ("CRITICAL", "HIGH", "KEV"):
                raise ValueError(f"Invalid pass: {pass_name}")
            if pass_name == "KEV":
                return {"hasKev": ""}
            return {"cvssV3Severity": pass_name}
        
        if self.mode == "delta_poll":
            if not start_date:
                raise ValueError("delta_poll requires start_date")
            return {
                "lastModStartDate": start_date,
                "lastModEndDate": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000Z")}
    def _fetch_paginated(self, base_params: dict, s3_key_prefix: str) -> None:
        """Shared pagination loop used by both bulk and delta modes."""
        start_index = 0
        page = 1
        while True:
            url = self.build_url({**base_params, "startIndex": start_index, "resultsPerPage": 2000})
            resp = self._request(url, headers={"apiKey": settings.NVD_API_KEY})
            records = self._parser(resp)
            date_str = datetime.utcnow().strftime("%Y-%m-%d")
            s3_key = build_s3_key(
                self.source,
                date_str,
                self.elt_run_id,
                f"{s3_key_prefix}_page_{page:03d}",
            )
            self._store(records, s3_key)
            total = resp.json()["totalResults"]
            start_index += 2000
            page += 1
            if start_index >= total:
                break
            time.sleep(2)

    def fetch(self):
        if self.mode == "bulk_load":
            # Three passes as designed — CRITICAL, HIGH, KEV — each fully paginated.
            # Overlaps between passes are deduplicated in the transformation layer.
            for pass_name in ("CRITICAL", "HIGH", "KEV"):
                base_params = self._build_params(pass_name=pass_name)
                self._fetch_paginated(base_params, s3_key_prefix=f"bulk_{pass_name.lower()}")

        elif self.mode == "delta_poll":
            last_run = (
                self.db.query(EltRun)
                .filter(EltRun.status == "success")
                .order_by(EltRun.started_at.desc())
                .first()
            )
            start_date = last_run.started_at.strftime("%Y-%m-%dT%H:%M:%S.000Z")
            base_params = self._build_params(start_date=start_date)
            self._fetch_paginated(base_params, s3_key_prefix="delta")