"""
dashboard_api/routers/stats.py
Dashboard aggregates (cards + charts).
"""
from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from dashboard_api.dependencies import get_db
from dashboard_api.schemas.stats import DashboardStats
from dashboard_api.services import stats_service

router = APIRouter(prefix="/stats", tags=["stats"])


@router.get("", response_model=DashboardStats, summary="Dashboard aggregate stats")
def stats(db: Session = Depends(get_db)) -> DashboardStats:
    return stats_service.dashboard_stats(db)
