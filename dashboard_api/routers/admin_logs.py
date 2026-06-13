"""
dashboard_api/routers/admin_logs.py
Admin surface for embedding pipeline status in the dashboard.

Gated by the admin key (wired in main.py). Read-only: recent runs and a
filterable, paginated log feed. Filter values are length-bounded at the edge;
unknown values simply match nothing rather than erroring.
"""
from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from dashboard_api.dependencies import Pagination, get_db, pagination_params
from dashboard_api.schemas.admin import LogEntry, RunSummary
from dashboard_api.schemas.common import Page
from dashboard_api.services import admin_service

router = APIRouter(prefix="/admin", tags=["admin"])


@router.get("/runs", response_model=Page[RunSummary], summary="Recent pipeline runs")
def list_runs(
    status: str | None = Query(default=None, max_length=32),
    pipeline: str | None = Query(default=None, max_length=32),
    page: Pagination = Depends(pagination_params),
    db: Session = Depends(get_db),
) -> Page[RunSummary]:
    rows, total = admin_service.list_runs(
        db, status=status, pipeline=pipeline, limit=page.limit, offset=page.offset
    )
    return Page[RunSummary](
        items=[RunSummary.model_validate(r) for r in rows],
        total=total,
        limit=page.limit,
        offset=page.offset,
    )


@router.get("/logs", response_model=Page[LogEntry], summary="Pipeline logs")
def list_logs(
    run_id: UUID | None = Query(default=None),
    cve_id: str | None = Query(default=None, max_length=32, pattern=r"^[A-Za-z0-9\-]+$"),
    level: str | None = Query(default=None, max_length=16),
    source: str | None = Query(default=None, max_length=32),
    event_type: str | None = Query(default=None, max_length=64),
    page: Pagination = Depends(pagination_params),
    db: Session = Depends(get_db),
) -> Page[LogEntry]:
    rows, total = admin_service.list_logs(
        db,
        run_id=run_id,
        cve_id=cve_id.upper() if cve_id else None,
        level=level,
        source=source,
        event_type=event_type,
        limit=page.limit,
        offset=page.offset,
    )
    return Page[LogEntry](
        items=[LogEntry.model_validate(r) for r in rows],
        total=total,
        limit=page.limit,
        offset=page.offset,
    )
