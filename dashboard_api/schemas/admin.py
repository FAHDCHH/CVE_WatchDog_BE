"""
dashboard_api/schemas/admin.py
DTOs for the admin surface: pipeline runs and pipeline logs.

These mirror db.models.EltRun and db.models.PipelineLog but expose only the
fields a dashboard needs. UUIDs and timestamps serialize to strings/ISO-8601.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict


class RunSummary(BaseModel):
    """One pipeline execution (an EltRun)."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    triggered_by: str
    mode: str
    pipeline: str | None = None
    status: str
    current_phase: str | None = None
    started_at: datetime | None = None
    last_heartbeat_at: datetime | None = None
    completed_at: datetime | None = None
    sources_status: dict[str, Any] | None = None
    skipped_sources: Any | None = None
    error_summary: str | None = None


class LogEntry(BaseModel):
    """One pipeline log line."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    elt_run_id: UUID
    cve_id: str | None = None
    level: str
    source: str
    event_type: str
    phase: str | None = None
    message: str
    http_status: int | None = None
    attempt_number: int | None = None
    duration_ms: int | None = None
    page_number: int | None = None
    s3_key: str | None = None
    created_at: datetime | None = None
