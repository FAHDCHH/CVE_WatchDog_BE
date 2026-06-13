"""
dashboard_api/routers/health.py
Liveness + readiness. Unauthenticated by design (used by load balancers / CI).
"""
from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.orm import Session

from dashboard_api.dependencies import get_db

router = APIRouter(tags=["health"])


@router.get("/health")
def health() -> dict:
    """Liveness: the process is up."""
    return {"status": "ok"}


@router.get("/ready")
def ready(db: Session = Depends(get_db)) -> dict:
    """Readiness: the process can reach the database."""
    db.execute(text("SELECT 1"))
    return {"status": "ready"}
