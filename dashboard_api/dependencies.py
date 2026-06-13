"""
dashboard_api/dependencies.py
Shared FastAPI dependencies: DB session lifecycle and pagination params.
"""
from __future__ import annotations

from typing import Iterator

from fastapi import Query
from sqlalchemy.orm import Session

from dashboard_api.config import api_settings
from db.session import SessionLocal


def get_db() -> Iterator[Session]:
    """Yield a read-only-by-convention session and always close it."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


class Pagination:
    def __init__(self, limit: int, offset: int) -> None:
        self.limit = limit
        self.offset = offset


def pagination_params(
    limit: int = Query(
        default=api_settings.DEFAULT_PAGE_SIZE,
        ge=1,
        le=api_settings.MAX_PAGE_SIZE,
        description="Max rows to return (capped server-side).",
    ),
    offset: int = Query(default=0, ge=0, description="Rows to skip."),
) -> Pagination:
    return Pagination(limit=limit, offset=offset)
