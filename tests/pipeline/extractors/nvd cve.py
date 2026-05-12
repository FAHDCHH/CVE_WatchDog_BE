import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
from pipeline.extractors.nvd_cves import NVDCVEsExtractor

def test_nvd_cves():
    extractor = NVDCVEsExtractor("test-run-001", mode="bulk_load")
    extractor.fetch()

test_nvd_cves()