"""
dashboard_api/routers/meta.py
Distinct filter values for building frontend dropdowns.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from dashboard_api.dependencies import get_db
from dashboard_api.schemas.stats import FilterOptions
from dashboard_api.services import meta_service

router = APIRouter(prefix="/meta", tags=["meta"])


@router.get("/filters", response_model=FilterOptions, summary="Available filter values")
def filters(db: Session = Depends(get_db)) -> FilterOptions:
    return meta_service.filter_options(db)
