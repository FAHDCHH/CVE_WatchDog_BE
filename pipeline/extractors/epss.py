"""
pipeline/extractors/epss.py
EPSS-specific: fetch, parse, schema, key pattern.
"""
 
from datetime import datetime, timedelta
import httpx
from pipeline.extractors.base import BaseExtractor
from storage.s3 import build_s3_key
import io
import gzip
from pyarrow import csv as pa_csv
from pyarrow.csv import ReadOptions

class EPSSextractor(BaseExtractor):
    def __init__(self, elt_run_id: str):
        super().__init__(elt_run_id=elt_run_id, source="epss")
    def build_url(self):
        """constructs the queried url based for the current date to this format : `https://epss.empiricalsecurity.com/epss_scores-YYYY-MM-DD.csv.gz`"""
        yesterday = datetime.now() - timedelta(days=1)
        current_date = yesterday.strftime('%Y-%m-%d')
        return f"https://epss.empiricalsecurity.com/epss_scores-{current_date}.csv.gz"
    def _parser(self,resp: httpx.Response) -> list[dict]:
        """parses the epss csv response and returns a list of dictionaries"""
        csv_bytes = gzip.decompress(resp.content)
        buffer = io.BytesIO(csv_bytes)
        table = pa_csv.read_csv(
            buffer,
            read_options=ReadOptions(skip_rows=1)
        )
        return table.to_pylist()
    def fetch(self):
        """fetches the epss csv and stores it in the raw store"""
        url = self.build_url()
        resp = self._request(url, headers={"User-Agent": "Mozilla/5.0"})
        records = self._parser(resp)
       
        s3_key = build_s3_key(self.source, datetime.now().strftime("%Y-%m-%d"),self.elt_run_id, "snapshot")
        self._store(records, s3_key)
    
        