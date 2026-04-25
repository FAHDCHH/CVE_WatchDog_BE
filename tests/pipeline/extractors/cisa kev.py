import sys
from pathlib import Path

# Add project root to sys.path so 'pipeline' package is importable
sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from pipeline.extractors.cisa_kev import CISA_KEVExtractor

def test_cisa_kev():
    extractor = CISA_KEVExtractor("test-run-001")
    extractor.fetch()

test_cisa_kev()