"""
dashboard_api/services/stats_service.py
Aggregates for the dashboard cards and charts. All GROUP BY over indexed columns.
"""
from __future__ import annotations

from sqlalchemy import Numeric, case, cast, func
from sqlalchemy.orm import Session

from dashboard_api.schemas.stats import Bucket, DashboardStats
from db.models import CveEnriched


def _grouped(db: Session, column) -> list[Bucket]:
    rows = (
        db.query(column, func.count())
        .group_by(column)
        .order_by(func.count().desc())
        .all()
    )
    return [Bucket(key=str(value) if value is not None else "unknown", count=count) for value, count in rows]


def _epss_buckets(db: Session) -> list[Bucket]:
    pct = cast(CveEnriched.epss_percentile, Numeric)
    bucket = case(
        (CveEnriched.epss_percentile.is_(None), "unknown"),
        (pct >= 0.9, "0.90-1.00"),
        (pct >= 0.7, "0.70-0.90"),
        (pct >= 0.5, "0.50-0.70"),
        (pct >= 0.25, "0.25-0.50"),
        else_="0.00-0.25",
    )
    rows = db.query(bucket, func.count()).group_by(bucket).all()
    return [Bucket(key=str(k), count=c) for k, c in rows]


def _top_cwes(db: Session, limit: int = 10) -> list[Bucket]:
    cwe = func.unnest(CveEnriched.cwe_ids).label("cwe")
    sub = db.query(cwe).subquery()
    rows = (
        db.query(sub.c.cwe, func.count())
        .group_by(sub.c.cwe)
        .order_by(func.count().desc())
        .limit(limit)
        .all()
    )
    return [Bucket(key=str(k), count=c) for k, c in rows if k is not None]


def dashboard_stats(db: Session) -> DashboardStats:
    total = db.query(func.count(CveEnriched.cve_id)).scalar() or 0
    kev = db.query(func.count()).filter(CveEnriched.is_kev.is_(True)).scalar() or 0
    ransomware = (
        db.query(func.count())
        .filter(CveEnriched.ransomware_known == "Known")
        .scalar()
        or 0
    )
    return DashboardStats(
        total_cves=total,
        kev_count=kev,
        ransomware_count=ransomware,
        by_severity=_grouped(db, CveEnriched.cvss_severity),
        by_status=_grouped(db, CveEnriched.vuln_status),
        by_attack_vector=_grouped(db, CveEnriched.attack_vector),
        epss_buckets=_epss_buckets(db),
        top_cwes=_top_cwes(db),
    )
