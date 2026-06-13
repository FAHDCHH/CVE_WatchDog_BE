"""
dashboard_api/schemas/filters.py
The CVE filter surface, expressed as a validated FastAPI dependency.

Every parameter is typed and constrained here, at the edge, so invalid input is
rejected with a 422 (naming the field) before any query is built. Enums bound
the categorical filters; ge/le bound the numeric ranges; max_length bounds text.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date

from fastapi import Query

from dashboard_api.schemas.common import Severity, SortField, SortOrder


@dataclass
class CveFilters:
    severity: list[Severity] = field(default_factory=list)
    cvss_min: float | None = None
    cvss_max: float | None = None
    cvss_version: str | None = None
    epss_min: float | None = None
    epss_max: float | None = None
    epss_pct_min: float | None = None
    epss_pct_max: float | None = None
    is_kev: bool | None = None
    ransomware_known: str | None = None
    vuln_status: list[str] = field(default_factory=list)
    attack_vector: str | None = None
    privileges_required: str | None = None
    user_interaction: str | None = None
    automatable: str | None = None
    exploit_maturity: str | None = None
    cwe_id: str | None = None
    vendor: str | None = None
    product: str | None = None
    published_from: date | None = None
    published_to: date | None = None
    modified_from: date | None = None
    modified_to: date | None = None
    kev_added_from: date | None = None
    kev_added_to: date | None = None
    q: str | None = None
    sort: SortField = SortField.cvss_score
    order: SortOrder = SortOrder.desc


def cve_filters(
    severity: list[Severity] | None = Query(default=None, description="Filter by CVSS severity (repeatable)."),
    cvss_min: float | None = Query(default=None, ge=0, le=10),
    cvss_max: float | None = Query(default=None, ge=0, le=10),
    cvss_version: str | None = Query(default=None, max_length=16),
    epss_min: float | None = Query(default=None, ge=0, le=1),
    epss_max: float | None = Query(default=None, ge=0, le=1),
    epss_pct_min: float | None = Query(default=None, ge=0, le=1),
    epss_pct_max: float | None = Query(default=None, ge=0, le=1),
    is_kev: bool | None = Query(default=None),
    ransomware_known: str | None = Query(default=None, max_length=32),
    vuln_status: list[str] | None = Query(default=None, description="Filter by vuln status (repeatable)."),
    attack_vector: str | None = Query(default=None, max_length=32),
    privileges_required: str | None = Query(default=None, max_length=32),
    user_interaction: str | None = Query(default=None, max_length=32),
    automatable: str | None = Query(default=None, max_length=32),
    exploit_maturity: str | None = Query(default=None, max_length=32),
    cwe_id: str | None = Query(default=None, max_length=32, description="Match CVEs whose CWE list contains this id."),
    vendor: str | None = Query(default=None, max_length=256),
    product: str | None = Query(default=None, max_length=256),
    published_from: date | None = Query(default=None),
    published_to: date | None = Query(default=None),
    modified_from: date | None = Query(default=None),
    modified_to: date | None = Query(default=None),
    kev_added_from: date | None = Query(default=None),
    kev_added_to: date | None = Query(default=None),
    q: str | None = Query(default=None, max_length=128, description="Free-text search on CVE id and description."),
    sort: SortField = Query(default=SortField.cvss_score),
    order: SortOrder = Query(default=SortOrder.desc),
) -> CveFilters:
    return CveFilters(
        severity=severity or [],
        cvss_min=cvss_min,
        cvss_max=cvss_max,
        cvss_version=cvss_version,
        epss_min=epss_min,
        epss_max=epss_max,
        epss_pct_min=epss_pct_min,
        epss_pct_max=epss_pct_max,
        is_kev=is_kev,
        ransomware_known=ransomware_known,
        vuln_status=vuln_status or [],
        attack_vector=attack_vector,
        privileges_required=privileges_required,
        user_interaction=user_interaction,
        automatable=automatable,
        exploit_maturity=exploit_maturity,
        cwe_id=cwe_id,
        vendor=vendor,
        product=product,
        published_from=published_from,
        published_to=published_to,
        modified_from=modified_from,
        modified_to=modified_to,
        kev_added_from=kev_added_from,
        kev_added_to=kev_added_to,
        q=q,
        sort=sort,
        order=order,
    )
