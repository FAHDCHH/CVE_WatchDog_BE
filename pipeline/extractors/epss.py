"""
pipeline/extractors/epss.py
EPSS-specific: fetch, parse, schema, key pattern.
"""
 
from pipeline.extractors.base import BaseExtractor
from storage.s3 import build_s3_key
class epssExtractor(BaseExtractor):
    def __init__(self, elt_run_id: str):
        super().__init__(elt_run_id=elt_run_id, source="epss")
    def url_construction():
        """constructs the queried url based for the current date to this format : `https://epss.empiricalsecurity.com/epss_scores-YYYY-MM-DD.csv.gz`"""
        current_date = datetime.now().strftime("%Y-%m-%d")
        return f"https://epss.empiricalsecurity.com/epss_scores-{current_date}.csv.gz"
    def epss_csv_parser(self,resp: httpx.Response) -> list[dict]:
        """parses the epss csv response and returns a list of dictionaries"""
    def fetch(self):
        """fetches the epss csv and stores it in the raw store"""
        self.url_construction()
        resp = self._request()
        records = self.epss_csv_parser(resp)
        s3_key = build_s3_key(self.source, self.elt_run_id, "snapshot")
        self._store(records, s3_key)
            
        