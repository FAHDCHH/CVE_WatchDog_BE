import sys
from pathlib import Path

# Add project root to sys.path so 'pipeline' package is importable
sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from pipeline.extractors.epss import EPSSextractor

def extract_epss():
    epss_extractor = EPSSextractor("etl_run_000")
    epss_extractor.fetch()

if __name__ == "__main__":
    extract_epss()