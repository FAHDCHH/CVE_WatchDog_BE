"""
dashboard_api/schemas/common.py
Cross-cutting enums and the generic paginated envelope.
"""
from __future__ import annotations

from enum import Enum
from typing import Generic, TypeVar

from pydantic import BaseModel

T = TypeVar("T")


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    NONE = "NONE"


class SortField(str, Enum):
    cvss_score = "cvss_score"
    epss_score = "epss_score"
    epss_percentile = "epss_percentile"
    published_at = "published_at"
    last_modified_at = "last_modified_at"
    kev_date_added = "kev_date_added"


class SortOrder(str, Enum):
    asc = "asc"
    desc = "desc"


class Page(BaseModel, Generic[T]):
    """Uniform list envelope. Empty results are a normal 200, not an error."""

    items: list[T]
    total: int
    limit: int
    offset: int


class ErrorBody(BaseModel):
    code: str
    message: str
    detail: object | None = None


class ErrorResponse(BaseModel):
    error: ErrorBody
