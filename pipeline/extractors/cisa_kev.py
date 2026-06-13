"""
pipeline/extractors/cisa_kev.py
CISA KEV-specific extractor.
"""

import httpx
from datetime import datetime
from pipeline.extractors.base import BaseExtractor
from storage.s3 import build_s3_key


class CISA_KEVExtractor(BaseExtractor):
    def __init__(self, elt_run_id: str, db=None):
        super().__init__(elt_run_id=elt_run_id, source="cisa_kev", db=db)

    def build_url(self,type:str):
        """Constructs the API URL for CISA KEV"""
        if type == "primary":
            return "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json"
        elif type == "secondary":
    
            return "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    def _parser(self, resp: httpx.Response) -> list[dict]:
        """Parses the CISA KEV JSON response using pyarrow"""
        data = resp.json()
        return data["vulnerabilities"]

       

    def fetch(self):
        """Fetches CISA KEV data and stores it in the raw store"""
        self._safe_log("extract_kev_started", "CISA KEV fetch started", request_url=self.build_url("primary"))
        try:
            resp = self._request(self.build_url("primary"))
        except Exception as exc:
            self._safe_log(
                "extract_kev_retry", "Primary KEV source failed; trying secondary",
                level="warn", request_url=self.build_url("secondary"),
                metadata={"error_type": exc.__class__.__name__},
            )
            try:
                resp = self._request(self.build_url("secondary"))
            except Exception as exc2:
                self._safe_log(
                    "extract_kev_failed", "Both KEV sources failed",
                    level="error", metadata={"error_type": exc2.__class__.__name__},
                )
                raise
        records = self._parser(resp)

        s3_key = build_s3_key(
            self.source,
            datetime.now().strftime("%Y-%m-%d"),
            self.elt_run_id,
            "snapshot"
        )
        try:
            self._store(records, s3_key)
            self._safe_log("extract_r2_write_success", "CISA KEV snapshot stored", s3_key=s3_key)
        except Exception as exc:
            self._safe_log(
                "extract_kev_failed", "CISA KEV R2 write failed",
                level="error", s3_key=s3_key, metadata={"error_type": exc.__class__.__name__},
            )
            raise
        self._safe_log(
            "extract_kev_success", "CISA KEV extracted",
            s3_key=s3_key, response_size_bytes=len(resp.content),
            metadata={"records": len(records)},
        )
