"""
dashboard_api/schemas/cve.py
Response DTOs for CVE list rows and the full detail view.

Numeric DB columns are Decimal; these models type them as float so JSON output
is a plain number. Pydantic coerces Decimal -> float on validation.
"""
from __future__ import annotations

from datetime import date, datetime

from pydantic import BaseModel, ConfigDict


class CveSummary(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    cve_id: str
    description_en: str | None = None
    vuln_status: str | None = None

    cvss_score: float | None = None
    cvss_severity: str | None = None
    cvss_version: str | None = None

    epss_score: float | None = None
    epss_percentile: float | None = None

    is_kev: bool = False
    ransomware_known: str | None = None
    exploit_maturity: str | None = None

    cwe_ids: list[str] | None = None

    published_at: datetime | None = None
    last_modified_at: datetime | None = None
    kev_date_added: date | None = None


class CveDetail(CveSummary):
    model_config = ConfigDict(from_attributes=True)

    source_identifier: str | None = None

    cvss_vector: str | None = None
    cvss_source: str | None = None
    cvss_type: str | None = None
    exploitability_score: float | None = None
    impact_score: float | None = None

    attack_vector: str | None = None
    attack_complexity: str | None = None
    attack_requirements: str | None = None
    privileges_required: str | None = None
    user_interaction: str | None = None
    automatable: str | None = None

    epss_score_date: date | None = None

    cwe_names: list[str] | None = None

    kev_vendor_project: str | None = None
    kev_product: str | None = None
    kev_vulnerability_name: str | None = None
    kev_due_date: date | None = None
    kev_required_action: str | None = None
    kev_short_description: str | None = None

    references: object | None = None

    first_seen_at: datetime | None = None
    last_seen_at: datetime | None = None
