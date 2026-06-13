from dataclasses import dataclass, field
from datetime import date
from decimal import Decimal
from uuid import UUID


@dataclass
class CVSSResult:
    version_used: str
    source: str | None
    cvss_type: str | None
    vector: str | None
    score: Decimal | None
    severity: str | None
    attack_vector: str | None = None
    attack_complexity: str | None = None
    attack_requirements: str | None = None
    privileges_required: str | None = None
    user_interaction: str | None = None
    vulnerable_confidentiality: str | None = None
    vulnerable_integrity: str | None = None
    vulnerable_availability: str | None = None
    subsequent_confidentiality: str | None = None
    subsequent_integrity: str | None = None
    subsequent_availability: str | None = None
    cvss_scope: str | None = None
    exploitability_score: Decimal | None = None
    impact_score: Decimal | None = None
    exploit_maturity: str | None = None
    provider_urgency: str | None = None
    automatable: str | None = None
    recovery: str | None = None
    value_density: str | None = None
    safety: str | None = None
    vulnerability_response_effort: str | None = None


@dataclass
class KEVEntry:
    cve_id: str
    vendor_project: str | None = None
    product: str | None = None
    vulnerability_name: str | None = None
    date_added: date | None = None
    due_date: date | None = None
    required_action: str | None = None
    short_description: str | None = None
    ransomware_known: str | None = None
    notes: str | None = None
    cwes: list[str] = field(default_factory=list)
    catalog_version: str | None = None


@dataclass
class KEVDiff:
    cve_id: str
    change_type: str
    changed_fields: dict[str, tuple[str | None, str | None]]
    incoming: KEVEntry | None = None


@dataclass
class CWEResolution:
    cwe_id: str
    found: bool
    name: str | None
    source: str | None = None
    weakness_type: str | None = None


@dataclass
class TransformResult:
    cve_id: str
    run_id: UUID
    raw_nvd: dict | None
    current_values: dict | None = None
    include: bool = True
    skip_reason: str | None = None
    old_status: str | None = None
    new_status: str | None = None
    status_changed: bool = False
    cvss: CVSSResult | None = None
    cvss_changed: bool = False
    epss_score: Decimal | None = None
    epss_percentile: Decimal | None = None
    epss_score_date: date | None = None
    epss_changed: bool = False
    epss_surge: bool = False
    kev_entry: KEVEntry | None = None
    kev_diff: KEVDiff | None = None
    cwe_resolutions: list[CWEResolution] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    is_updated: bool = False
    raw_nvd_s3_key: str | None = None
    raw_epss_s3_key: str | None = None
    raw_kev_s3_key: str | None = None


@dataclass
class ConsistencyResult:
    cve_id: str
    run_id: UUID
    nvd_ok: bool
    cvss_resolved: bool
    epss_ok: bool
    kev_ok: bool
    overall_ok: bool
    failure_detail: dict
