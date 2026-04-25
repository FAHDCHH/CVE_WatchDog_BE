"""
pipeline/extractors/cisa_kev.py
CISA KEV-specific extractor.
"""

import httpx
from datetime import datetime
from pipeline.extractors.base import BaseExtractor
from storage.s3 import build_s3_key


class CISA_KEVExtractor(BaseExtractor):
    def __init__(self, elt_run_id: str):
        super().__init__(elt_run_id=elt_run_id, source="cisa_kev")

    def url_construction(self,type:str):
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
        try:
            resp = self._request(self.url_construction("primary"))
        except Exception:
            resp = self._request(self.url_construction("primary"))
        records = self._parser(resp)

        s3_key = build_s3_key(  
            self.source, 
            datetime.now().strftime("%Y-%m-%d"), 
            self.elt_run_id, 
            "snapshot"
        )
        print(records)
        self._store(records, s3_key)
