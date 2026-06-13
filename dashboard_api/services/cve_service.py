"""
dashboard_api/services/cve_service.py
Filtered listing + single-CVE detail.

All filters compose through the SQLAlchemy expression API (parameterized),
so user input never reaches raw SQL — SQL injection is structurally impossible.
"""
from __future__ import annotations

from sqlalchemy import and_, or_
from sqlalchemy.orm import Query, Session

from dashboard_api.schemas.common import SortField, SortOrder
from dashboard_api.schemas.filters import CveFilters
from db.models import CveEnriched

_SORT_COLUMNS = {
    SortField.cvss_score: CveEnriched.cvss_score,
    SortField.epss_score: CveEnriched.epss_score,
    SortField.epss_percentile: CveEnriched.epss_percentile,
    SortField.published_at: CveEnriched.published_at,
    SortField.last_modified_at: CveEnriched.last_modified_at,
    SortField.kev_date_added: CveEnriched.kev_date_added,
}


def _apply_filters(query: Query, f: CveFilters) -> Query:
    conds = []

    if f.severity:
        conds.append(CveEnriched.cvss_severity.in_([s.value for s in f.severity]))
    if f.cvss_min is not None:
        conds.append(CveEnriched.cvss_score >= f.cvss_min)
    if f.cvss_max is not None:
        conds.append(CveEnriched.cvss_score <= f.cvss_max)
    if f.cvss_version:
        conds.append(CveEnriched.cvss_version == f.cvss_version)

    if f.epss_min is not None:
        conds.append(CveEnriched.epss_score >= f.epss_min)
    if f.epss_max is not None:
        conds.append(CveEnriched.epss_score <= f.epss_max)
    if f.epss_pct_min is not None:
        conds.append(CveEnriched.epss_percentile >= f.epss_pct_min)
    if f.epss_pct_max is not None:
        conds.append(CveEnriched.epss_percentile <= f.epss_pct_max)

    if f.is_kev is not None:
        conds.append(CveEnriched.is_kev.is_(f.is_kev))
    if f.ransomware_known:
        conds.append(CveEnriched.ransomware_known == f.ransomware_known)

    if f.vuln_status:
        conds.append(CveEnriched.vuln_status.in_(f.vuln_status))
    if f.attack_vector:
        conds.append(CveEnriched.attack_vector == f.attack_vector)
    if f.privileges_required:
        conds.append(CveEnriched.privileges_required == f.privileges_required)
    if f.user_interaction:
        conds.append(CveEnriched.user_interaction == f.user_interaction)
    if f.automatable:
        conds.append(CveEnriched.automatable == f.automatable)
    if f.exploit_maturity:
        conds.append(CveEnriched.exploit_maturity == f.exploit_maturity)

    if f.cwe_id:
        # ARRAY contains: cwe_id = ANY(cwe_ids)
        conds.append(CveEnriched.cwe_ids.any(f.cwe_id))

    if f.vendor:
        conds.append(CveEnriched.kev_vendor_project.ilike(f"%{f.vendor}%"))
    if f.product:
        conds.append(CveEnriched.kev_product.ilike(f"%{f.product}%"))

    if f.published_from is not None:
        conds.append(CveEnriched.published_at >= f.published_from)
    if f.published_to is not None:
        conds.append(CveEnriched.published_at <= f.published_to)
    if f.modified_from is not None:
        conds.append(CveEnriched.last_modified_at >= f.modified_from)
    if f.modified_to is not None:
        conds.append(CveEnriched.last_modified_at <= f.modified_to)
    if f.kev_added_from is not None:
        conds.append(CveEnriched.kev_date_added >= f.kev_added_from)
    if f.kev_added_to is not None:
        conds.append(CveEnriched.kev_date_added <= f.kev_added_to)

    if f.q:
        like = f"%{f.q}%"
        conds.append(
            or_(
                CveEnriched.cve_id.ilike(like),
                CveEnriched.description_en.ilike(like),
            )
        )

    if conds:
        query = query.filter(and_(*conds))
    return query


def _apply_sort(query: Query, f: CveFilters) -> Query:
    column = _SORT_COLUMNS[f.sort]
    direction = column.desc() if f.order == SortOrder.desc else column.asc()
    # NULLs last in both directions, then a stable tiebreak on the PK.
    return query.order_by(direction.nullslast(), CveEnriched.cve_id.asc())


def list_cves(db: Session, f: CveFilters, limit: int, offset: int) -> tuple[list[CveEnriched], int]:
    base = _apply_filters(db.query(CveEnriched), f)
    total = base.order_by(None).count()
    rows = _apply_sort(base, f).limit(limit).offset(offset).all()
    return rows, total


def get_cve(db: Session, cve_id: str) -> CveEnriched | None:
    return db.get(CveEnriched, cve_id)
