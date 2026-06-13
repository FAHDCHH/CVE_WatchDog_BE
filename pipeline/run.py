"""
pipeline/run.py
Orchestration only — no source-specific logic.
"""
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Self-bootstrap: if we're not already running inside the project's .venv,
# re-exec with the venv interpreter so third-party packages are always found.
# This means `python -m pipeline.run ...` works without manually activating.
# ---------------------------------------------------------------------------
_PROJECT_ROOT = Path(__file__).resolve().parents[1]
_VENV_PYTHON = (
    _PROJECT_ROOT / ".venv" / "Scripts" / "python.exe"   # Windows
    if sys.platform == "win32"
    else _PROJECT_ROOT / ".venv" / "bin" / "python"      # Linux / macOS
)

def _running_in_venv() -> bool:
    """True when the current interpreter lives inside our .venv."""
    try:
        return Path(sys.executable).resolve().is_relative_to(_VENV_PYTHON.parent)
    except AttributeError:
        # Python < 3.9 doesn't have is_relative_to
        return str(Path(sys.executable).resolve()).startswith(str(_VENV_PYTHON.parent))

if not _running_in_venv() and _VENV_PYTHON.exists():
    import os, subprocess
    result = subprocess.run([str(_VENV_PYTHON), "-m", "pipeline.run"] + sys.argv[1:])
    sys.exit(result.returncode)
elif not _VENV_PYTHON.exists():
    print(
        f"[pipeline.run] WARNING: .venv not found at {_VENV_PYTHON}. "
        "Run `python -m venv .venv && .venv\\Scripts\\pip install -r requirements.txt` first.",
        file=sys.stderr,
    )
# ---------------------------------------------------------------------------

sys.path.insert(0, str(_PROJECT_ROOT))

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
            mode=self.mode,
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
        # Transform + load + consistency for the pages this run just extracted.
        sources_status["transform"] = self._run_transform()
        self._finalize_run(sources_status)

    def run_transform(self):
        """Standalone transform over the latest artifacts already in R2."""
        sources_status = {"transform": self._run_transform()}
        self._finalize_run(sources_status)

    def _run_transform(self) -> str:
        from pipeline.transform.runner import TransformRunner

        try:
            summary = TransformRunner(self.db, self.run_id).run()
            print(f"[transform] summary: {summary}")
            return "success"
        except Exception as exc:
            print(f"[transform] failed: {exc!r}")
            return "failed"

    def run_daily(self):
        extractors = [
            EPSSextractor(self.run_id, db=self.db),
            CISA_KEVExtractor(self.run_id, db=self.db),
        ]
        sources_status = {}
        for extractor in extractors:
            try:
                extractor.fetch()
                sources_status[extractor.source] = "success"
            except Exception:
                sources_status[extractor.source] = "failed"
        self._finalize_run(sources_status)


if __name__ == "__main__":
    # Called by GitHub Actions as:
    #   python -m pipeline.run <mode> <pipeline>
    #   e.g. python -m pipeline.run delta_poll nvd
    #        python -m pipeline.run delta_poll daily
    #        python -m pipeline.run bulk_load nvd
    if len(sys.argv) != 3:
        print("Usage: python -m pipeline.run <mode> <pipeline>")
        print("  mode:     bulk_load | delta_poll")
        print("  pipeline: nvd | daily | transform")
        sys.exit(1)

    mode = sys.argv[1]
    pipeline = sys.argv[2]

    if mode not in ("bulk_load", "delta_poll"):
        print(f"Invalid mode: {mode}")
        sys.exit(1)

    if pipeline not in ("nvd", "daily", "transform"):
        print(f"Invalid pipeline: {pipeline}")
        sys.exit(1)

    orchestrator = Orchestrator(triggered_by="scheduled", mode=mode)

    if pipeline == "nvd":
        orchestrator.run_nvd()
    elif pipeline == "daily":
        orchestrator.run_daily()
    elif pipeline == "transform":
        orchestrator.run_transform()
