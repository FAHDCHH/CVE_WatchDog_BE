import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from pipeline.extractors.nvd_changes import NVD_Changes_Extractor

def test_nvd_changes():
    extractor = NVD_Changes_Extractor("test-run-001", mode="bulk_load")
    extractor.fetch()

test_nvd_changes()