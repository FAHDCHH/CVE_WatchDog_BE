"""
Database-backed pipeline logger.
"""

from __future__ import annotations

from typing import Any
from uuid import UUID

from sqlalchemy.orm import Session

from core.exceptions.exceptions import LoggingError
from db.models import LOG_LEVELS, PIPELINE_EVENT_TYPES, PIPELINE_SOURCES, PipelineLog
from pipeline.logs.base_logs import BaseLogger


class PipelineLogger(BaseLogger):
    allowed_levels = LOG_LEVELS
    allowed_sources = PIPELINE_SOURCES
    allowed_event_types = PIPELINE_EVENT_TYPES

    def __init__(
        self,
        db: Session,
        elt_run_id: UUID | str,
        commit_immediately: bool = True,
    ):
        super().__init__(db=db, commit_immediately=commit_immediately)
        self.elt_run_id = elt_run_id

    def log(
        self,
        *,
        level: str,
        source: str,
        event_type: str,
        message: str,
        cve_id: str | None = None,
        phase: str | None = None,
        http_status: int | None = None,
        attempt_number: int | None = None,
        duration_ms: int | None = None,
        request_url: str | None = None,
        response_size_bytes: int | None = None,
        page_number: int | None = None,
        s3_key: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> PipelineLog:
        self._validate_event(
            level=level,
            source=source,
            event_type=event_type,
            message=message,
        )
        request_url = self._sanitize_url(request_url)
        return self._write_to_database(
            level=level,
            source=source,
            event_type=event_type,
            message=message,
            cve_id=cve_id,
            phase=phase,
            http_status=http_status,
            attempt_number=attempt_number,
            duration_ms=duration_ms,
            request_url=request_url,
            response_size_bytes=response_size_bytes,
            page_number=page_number,
            s3_key=s3_key,
            log_metadata=metadata,
        )

    def _write_to_database(self, **fields: Any) -> PipelineLog:
        log = PipelineLog(
            elt_run_id=self.elt_run_id,
            **fields,
        )
        try:
            self.db.add(log)
            if self.commit_immediately:
                self.db.commit()
                self.db.refresh(log)
            else:
                self.db.flush()
            return log
        except Exception as exc:
            self.db.rollback()
            raise LoggingError("Failed to write pipeline log") from exc

    def debug(
        self,
        *,
        source: str,
        event_type: str,
        message: str,
        **context: Any,
    ) -> PipelineLog:
        return self.log(
            level="debug",
            source=source,
            event_type=event_type,
            message=message,
            **context,
        )

    def info(
        self,
        *,
        source: str,
        event_type: str,
        message: str,
        **context: Any,
    ) -> PipelineLog:
        return self.log(
            level="info",
            source=source,
            event_type=event_type,
            message=message,
            **context,
        )

    def warn(
        self,
        *,
        source: str,
        event_type: str,
        message: str,
        **context: Any,
    ) -> PipelineLog:
        return self.log(
            level="warn",
            source=source,
            event_type=event_type,
            message=message,
            **context,
        )

    def error(
        self,
        *,
        source: str,
        event_type: str,
        message: str,
        **context: Any,
    ) -> PipelineLog:
        return self.log(
            level="error",
            source=source,
            event_type=event_type,
            message=message,
            **context,
        )

    def exception(
        self,
        *,
        source: str,
        event_type: str,
        message: str,
        exc: Exception,
        **context: Any,
    ) -> PipelineLog:
        metadata = dict(context.pop("metadata", {}) or {})
        metadata.update(
            {
                "error_type": exc.__class__.__name__,
                "error_message": str(exc),
            }
        )
        return self.error(
            source=source,
            event_type=event_type,
            message=message,
            metadata=metadata,
            **context,
        )
