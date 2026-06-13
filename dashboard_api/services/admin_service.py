"""
dashboard_api/services/admin_service.py
Read-only queries over EltRun and PipelineLog for the admin dashboard.

All filtering uses the SQLAlchemy expression API (bound params, no string SQL).
List endpoints return (rows, total) so the caller can build a paged envelope.
"""
from __future__ import annotations

from uuid import UUID

from sqlalchemy import func
from sqlalchemy.orm import Session

from db.models import EltRun, PipelineLog


def list_runs(
    db: Session,
    *,
    status: str | None,
    pipeline: str | None,
    limit: int,
    offset: int,
) -> tuple[list[EltRun], int]:
    q = db.query(EltRun)
    if status:
        q = q.filter(EltRun.status == status)
    if pipeline:
        q = q.filter(EltRun.pipeline == pipeline)

    total = q.with_entities(func.count(EltRun.id)).scalar() or 0
    rows = (
        q.order_by(EltRun.started_at.desc().nullslast())
        .limit(limit)
        .offset(offset)
        .all()
    )
    return rows, total


def list_logs(
    db: Session,
    *,
    run_id: UUID | None,
    cve_id: str | None,
    level: str | None,
    source: str | None,
    event_type: str | None,
    limit: int,
    offset: int,
) -> tuple[list[PipelineLog], int]:
    q = db.query(PipelineLog)
    if run_id:
        q = q.filter(PipelineLog.elt_run_id == run_id)
    if cve_id:
        q = q.filter(PipelineLog.cve_id == cve_id)
    if level:
        q = q.filter(PipelineLog.level == level)
    if source:
        q = q.filter(PipelineLog.source == source)
    if event_type:
        q = q.filter(PipelineLog.event_type == event_type)

    total = q.with_entities(func.count(PipelineLog.id)).scalar() or 0
    rows = (
        q.order_by(PipelineLog.created_at.desc())
        .limit(limit)
        .offset(offset)
        .all()
    )
    return rows, total
