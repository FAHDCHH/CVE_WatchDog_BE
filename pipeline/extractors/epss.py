"""
pipeline/extractors/epss.py
EPSS-specific: fetch, parse, schema, key pattern.
"""
 
from pipeline.extractors.base import BaseExtractor
class epssExtractor(BaseExtractor):
    def __init__(self, elt_run_id: str):
        super().__init__(elt_run_id=elt_run_id, source="epss")
    def url_construction():
        """constructs the queried url based for the current date to this format : `https://epss.empiricalsecurity.com/epss_scores-YYYY-MM-DD.csv.gz`"""
        