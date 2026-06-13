"""
dashboard_api/schemas/stats.py
Aggregate DTOs that back the dashboard cards and charts.
"""
from __future__ import annotations

from pydantic import BaseModel


class Bucket(BaseModel):
    key: str
    count: int


class DashboardStats(BaseModel):
    total_cves: int
    kev_count: int
    ransomware_count: int
    by_severity: list[Bucket]
    by_status: list[Bucket]
    by_attack_vector: list[Bucket]
    epss_buckets: list[Bucket]
    top_cwes: list[Bucket]


class FilterOptions(BaseModel):
    """Distinct values the frontend can render as dropdowns."""

    severity: list[str]
    vuln_status: list[str]
    cvss_version: list[str]
    attack_vector: list[str]
    exploit_maturity: list[str]
    ransomware_known: list[str]
