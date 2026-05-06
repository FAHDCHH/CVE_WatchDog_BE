"""
pipeline/extractors/cwe.py
One-time CWE reference data pull.
"""
import httpx
import zipfile
import io
import json
from datetime import datetime

from pipeline.extractors.base import BaseExtractor
from storage.s3 import build_s3_key


class CWEExtractor(BaseExtractor):
    URL = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"

    def __init__(self, elt_run_id: str):
        super().__init__(elt_run_id=elt_run_id, source="cwe")
    def build_url(self):
        return self.URL

    def _parser(self, resp: httpx.Response) -> list[dict]:
        zip_bytes = io.BytesIO(resp.content)
        with zipfile.ZipFile(zip_bytes) as z:
            xml_filename = [f for f in z.namelist() if f.endswith(".xml")][0]
            xml_bytes = z.read(xml_filename)
        return [{"raw_xml": xml_bytes.decode("utf-8")}]

    def fetch(self):
        resp = self._request(self.build_url())
        records = self._parser(resp)
        s3_key = build_s3_key(self.source, self.elt_run_id, "snapshot")
        self._store(records, s3_key)