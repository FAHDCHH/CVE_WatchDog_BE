"""
pipeline/run.py
Orchestration only — no source-specific logic.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import uuid
from datetime import datetime


from pipeline.extractors.epss import EPSSextractor
from pipeline.extractors.cisa_kev import CISA_KEVExtractor
from pipeline.extractors.nvd_cves import NVDCVEsExtractor
from pipeline.extractors.nvd_changes import NVD_Changes_Extractor
from db.session import SessionLocal
from db.models import EltRun

class Orchestrator:

    def __init__(self, triggered_by: str = "scheduled", mode: str = "delta_poll"):
        self.triggered_by = triggered_by
        self.mode = mode
        self.db = SessionLocal()
        self.elt_run = self._create_run()
        self.run_id = str(self.elt_run.id)

    def _create_run(self) -> EltRun:
        elt_run = EltRun(
            id=uuid.uuid4(),
            triggered_by=self.triggered_by,
            status="running",
            started_at=datetime.utcnow()
        )
        self.db.add(elt_run)
        self.db.commit()
        return elt_run

    def _finalize_run(self, sources_status: dict):
        if all(v == "failed" for v in sources_status.values()):
            final_status = "failed"
        elif any(v == "failed" for v in sources_status.values()):
            final_status = "partial_failure"
        else:
            final_status = "success"

        self.elt_run.status = final_status
        self.elt_run.completed_at = datetime.utcnow()
        self.elt_run.sources_status = sources_status
        self.db.add(self.elt_run)
        self.db.commit()
        self.db.close()

    def run_nvd(self):
        extractors = [
            NVDCVEsExtractor(self.run_id, mode=self.mode, db=self.db),
            NVD_Changes_Extractor(self.run_id, mode=self.mode, db=self.db),
        ]
        sources_status = {}
        for extractor in extractors:
            try:
                extractor.fetch()
                sources_status[extractor.source] = "success"
            except Exception:
                sources_status[extractor.source] = "failed"
        self._finalize_run(sources_status)

    def run_daily(self):
        extractors = [
            EPSSextractor(self.run_id),
            CISA_KEVExtractor(self.run_id),
        ]
        sources_status = {}
        for extractor in extractors:
            try:
                extractor.fetch()
                sources_status[extractor.source] = "success"
            except Exception:
                sources_status[extractor.source] = "failed"
        self._finalize_run(sources_status)


