"""
pipeline/recovery.py
Re-runs failed sources from last elt_run.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from db.session import SessionLocal
from db.models import EltRun
from pipeline.run import Orchestrator


def recover():
    db = SessionLocal()
    last_run = db.query(EltRun).order_by(EltRun.started_at.desc()).first()
    db.close()

    if not last_run:
        print("No runs found.")
        return

    if last_run.status in ("success", "running"):
        print(f"Last run status: {last_run.status}. No recovery needed.")
        return

    print(f"Recovering from status: {last_run.status}")
    orchestrator = Orchestrator(triggered_by="recovery", mode="delta_poll")
    orchestrator.run_nvd()


if __name__ == "__main__":
    recover()