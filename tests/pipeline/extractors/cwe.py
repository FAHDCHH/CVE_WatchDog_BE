import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from pipeline.extractors.cwe import CWEExtractor

def extract_cwe():
    cwe_extractor = CWEExtractor("etl_run_000")
    cwe_extractor.fetch()

if __name__ == "__main__":
    extract_cwe()
