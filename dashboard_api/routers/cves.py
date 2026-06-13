"""
dashboard_api/routers/cves.py
Filtered CVE listing and single-CVE detail.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Path
from sqlalchemy.orm import Session

from dashboard_api.dependencies import Pagination, get_db, pagination_params
from dashboard_api.errors import not_found
from dashboard_api.schemas.common import Page
from dashboard_api.schemas.cve import CveDetail, CveSummary
from dashboard_api.schemas.filters import CveFilters, cve_filters
from dashboard_api.services import cve_service

router = APIRouter(prefix="/cves", tags=["cves"])


@router.get("", response_model=Page[CveSummary], summary="List/filter CVEs")
def list_cves(
    filters: CveFilters = Depends(cve_filters),
    page: Pagination = Depends(pagination_params),
    db: Session = Depends(get_db),
) -> Page[CveSummary]:
    rows, total = cve_service.list_cves(db, filters, page.limit, page.offset)
    return Page[CveSummary](
        items=[CveSummary.model_validate(row) for row in rows],
        total=total,
        limit=page.limit,
        offset=page.offset,
    )


@router.get("/{cve_id}", response_model=CveDetail, summary="Get one CVE")
def get_cve(
    cve_id: str = Path(..., max_length=32, pattern=r"^[A-Za-z0-9\-]+$"),
    db: Session = Depends(get_db),
) -> CveDetail:
    row = cve_service.get_cve(db, cve_id.upper())
    if row is None:
        raise not_found("CVE", cve_id)
    return CveDetail.model_validate(row)
