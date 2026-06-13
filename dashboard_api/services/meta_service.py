"""
dashboard_api/services/meta_service.py
Distinct filter values so the frontend can build dropdowns without hardcoding.
"""
from __future__ import annotations

from sqlalchemy.orm import Session

from dashboard_api.schemas.stats import FilterOptions
from db.models import CveEnriched


def _distinct(db: Session, column) -> list[str]:
    rows = db.query(column).filter(column.isnot(None)).distinct().all()
    return sorted(str(value) for (value,) in rows)


def filter_options(db: Session) -> FilterOptions:
    return FilterOptions(
        severity=_distinct(db, CveEnriched.cvss_severity),
        vuln_status=_distinct(db, CveEnriched.vuln_status),
        cvss_version=_distinct(db, CveEnriched.cvss_version),
        attack_vector=_distinct(db, CveEnriched.attack_vector),
        exploit_maturity=_distinct(db, CveEnriched.exploit_maturity),
        ransomware_known=_distinct(db, CveEnriched.ransomware_known),
    )
