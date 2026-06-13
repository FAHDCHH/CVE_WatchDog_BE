import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    Column,
    Computed,
    Date,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    Numeric,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, UUID
from sqlalchemy.orm import declarative_base, relationship

from core.constants import LOG_LEVELS, PIPELINE_SOURCES, PIPELINE_EVENT_TYPES

Base = declarative_base()


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class EltRun(Base):
    __tablename__ = "elt_runs"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    triggered_by = Column(String(64), nullable=False)
    mode = Column(String(32), nullable=False, default="delta_poll")
    pipeline = Column(String(32), nullable=True)
    status = Column(String(32), nullable=False, default="running", index=True)
    current_phase = Column(String(64), nullable=True)
    advisory_lock_key = Column(Integer, nullable=True)
    expected_max_duration_minutes = Column(Integer, nullable=True)
    started_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    last_heartbeat_at = Column(DateTime(timezone=True), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    sources_status = Column(JSONB, nullable=True)
    skipped_sources = Column(JSONB, nullable=True)
    error_summary = Column(Text, nullable=True)
    run_metadata = Column("metadata", JSONB, nullable=True)

    logs = relationship("PipelineLog", back_populates="run", cascade="all, delete-orphan")
    raw_artifacts = relationship("RawArtifact", back_populates="run")
    consistencies = relationship("CveConsistency", back_populates="run")

    __table_args__ = (
        CheckConstraint(
            "status IN ('running', 'success', 'partial_failure', 'failed', 'crashed', 'cancelled')",
            name="ck_elt_runs_status",
        ),
        CheckConstraint(
            "mode IN ('bulk_load', 'delta_poll', 'recovery', 'manual')",
            name="ck_elt_runs_mode",
        ),
    )


class PipelineLog(Base):
    __tablename__ = "pipeline_logs"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    elt_run_id = Column(UUID(as_uuid=True), ForeignKey("elt_runs.id", ondelete="CASCADE"), nullable=False)
    cve_id = Column(String(32), nullable=True)
    level = Column(String(16), nullable=False)
    source = Column(String(32), nullable=False)
    event_type = Column(String(64), nullable=False)
    phase = Column(String(64), nullable=True)
    message = Column(Text, nullable=False)
    http_status = Column(Integer, nullable=True)
    attempt_number = Column(Integer, nullable=True)
    duration_ms = Column(Integer, nullable=True)
    request_url = Column(Text, nullable=True)
    response_size_bytes = Column(Integer, nullable=True)
    page_number = Column(Integer, nullable=True)
    s3_key = Column(Text, nullable=True)
    log_metadata = Column("metadata", JSONB, nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False, index=True)

    run = relationship("EltRun", back_populates="logs")

    __table_args__ = (
        CheckConstraint(f"level IN {LOG_LEVELS}", name="ck_pipeline_logs_level"),
        CheckConstraint(f"source IN {PIPELINE_SOURCES}", name="ck_pipeline_logs_source"),
        CheckConstraint(f"event_type IN {PIPELINE_EVENT_TYPES}", name="ck_pipeline_logs_event_type"),
        Index("ix_pipeline_logs_run_event", "elt_run_id", "event_type"),
        Index("ix_pipeline_logs_run_cve_event", "elt_run_id", "cve_id", "event_type"),
        Index("ix_pipeline_logs_source_created", "source", "created_at"),
    )


class RawArtifact(Base):
    __tablename__ = "raw_artifacts"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    elt_run_id = Column(UUID(as_uuid=True), ForeignKey("elt_runs.id", ondelete="CASCADE"), nullable=False)
    source = Column(String(32), nullable=False)
    s3_key = Column(Text, nullable=False, unique=True)
    artifact_type = Column(String(32), nullable=False, default="parquet")
    pass_name = Column(String(32), nullable=True)
    page_number = Column(Integer, nullable=True)
    start_index = Column(Integer, nullable=True)
    records_count = Column(Integer, nullable=True)
    content_hash = Column(String(128), nullable=True)
    source_window_start = Column(DateTime(timezone=True), nullable=True)
    source_window_end = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)

    run = relationship("EltRun", back_populates="raw_artifacts")

    __table_args__ = (
        CheckConstraint(f"source IN {PIPELINE_SOURCES}", name="ck_raw_artifacts_source"),
        Index("ix_raw_artifacts_run_source", "elt_run_id", "source"),
        Index("ix_raw_artifacts_source_page", "source", "page_number"),
    )


class CveEnriched(Base):
    __tablename__ = "cve_enriched"

    cve_id = Column(String(32), primary_key=True)
    source_identifier = Column(Text, nullable=True)
    published_at = Column(DateTime(timezone=True), nullable=True, index=True)
    last_modified_at = Column(DateTime(timezone=True), nullable=True, index=True)
    vuln_status = Column(String(64), nullable=True, index=True)
    description_en = Column(Text, nullable=True)
    descriptions = Column(JSONB, nullable=True)
    evaluator_comment = Column(Text, nullable=True)
    evaluator_impact = Column(Text, nullable=True)
    evaluator_solution = Column(Text, nullable=True)

    cvss_source = Column(Text, nullable=True)
    cvss_type = Column(String(32), nullable=True)
    cvss_version = Column(String(16), nullable=True, index=True)
    cvss_vector = Column(Text, nullable=True)
    cvss_score = Column(Numeric(4, 1), nullable=True, index=True)
    cvss_severity = Column(String(16), nullable=True, index=True)
    exploitability_score = Column(Numeric(4, 2), nullable=True)
    impact_score = Column(Numeric(4, 2), nullable=True)
    exploit_maturity = Column(String(32), nullable=True, index=True)

    attack_vector = Column(String(32), nullable=True, index=True)
    attack_complexity = Column(String(32), nullable=True)
    attack_requirements = Column(String(32), nullable=True)
    privileges_required = Column(String(32), nullable=True, index=True)
    user_interaction = Column(String(32), nullable=True, index=True)
    vulnerable_confidentiality = Column(String(32), nullable=True)
    vulnerable_integrity = Column(String(32), nullable=True)
    vulnerable_availability = Column(String(32), nullable=True)
    subsequent_confidentiality = Column(String(32), nullable=True)
    subsequent_integrity = Column(String(32), nullable=True)
    subsequent_availability = Column(String(32), nullable=True)
    automatable = Column(String(32), nullable=True, index=True)
    safety = Column(String(32), nullable=True)
    recovery = Column(String(32), nullable=True)
    value_density = Column(String(32), nullable=True)
    vulnerability_response_effort = Column(String(32), nullable=True)
    provider_urgency = Column(String(32), nullable=True)

    cwe_ids = Column(ARRAY(String(32)), nullable=True)
    cwe_names = Column(ARRAY(Text), nullable=True)
    configurations = Column(JSONB, nullable=True)
    references = Column(JSONB, nullable=True)
    vendor_comments = Column(JSONB, nullable=True)

    epss_score = Column(Numeric(12, 9), nullable=True, index=True)
    epss_percentile = Column(Numeric(12, 9), nullable=True, index=True)
    epss_score_date = Column(Date, nullable=True)

    is_kev = Column(Boolean, nullable=False, default=False, index=True)
    kev_vendor_project = Column(Text, nullable=True)
    kev_product = Column(Text, nullable=True)
    kev_vulnerability_name = Column(Text, nullable=True)
    kev_date_added = Column(Date, nullable=True, index=True)
    kev_due_date = Column(Date, nullable=True, index=True)
    kev_required_action = Column(Text, nullable=True)
    kev_short_description = Column(Text, nullable=True)
    kev_notes = Column(Text, nullable=True)
    ransomware_known = Column(String(32), nullable=True, index=True)
    kev_cwes = Column(ARRAY(String(32)), nullable=True)

    nvd_cisa_exploit_add = Column(Date, nullable=True)
    nvd_cisa_action_due = Column(Date, nullable=True)
    nvd_cisa_required_action = Column(Text, nullable=True)
    nvd_cisa_vulnerability_name = Column(Text, nullable=True)

    raw_nvd_s3_key = Column(Text, nullable=True)
    raw_epss_s3_key = Column(Text, nullable=True)
    raw_kev_s3_key = Column(Text, nullable=True)
    first_seen_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    last_seen_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    last_transform_run_id = Column(UUID(as_uuid=True), ForeignKey("elt_runs.id"), nullable=True)
    is_updated = Column(Boolean, nullable=False, default=False, index=True)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)

    epss_scores = relationship("EpssScore", back_populates="cve", cascade="all, delete-orphan")
    kev_history = relationship("CveKevHistory", back_populates="cve", cascade="all, delete-orphan")
    cvss_history = relationship("CveCvssHistory", back_populates="cve", cascade="all, delete-orphan")
    status_history = relationship("CveStatusHistory", back_populates="cve", cascade="all, delete-orphan")
    consistencies = relationship("CveConsistency", back_populates="cve", cascade="all, delete-orphan")
    weaknesses = relationship("CveWeakness", back_populates="cve", cascade="all, delete-orphan")

    __table_args__ = (
        CheckConstraint("cvss_score IS NULL OR (cvss_score >= 0 AND cvss_score <= 10)", name="ck_cve_cvss_score_range"),
        CheckConstraint("epss_score IS NULL OR (epss_score >= 0 AND epss_score <= 1)", name="ck_cve_epss_score_range"),
        CheckConstraint("epss_percentile IS NULL OR (epss_percentile >= 0 AND epss_percentile <= 1)", name="ck_cve_epss_percentile_range"),
        Index("ix_cve_enriched_priority", "is_kev", "cvss_severity", "epss_percentile"),
        Index("ix_cve_enriched_status_modified", "vuln_status", "last_modified_at"),
    )



class CveCvssHistory(Base):
    __tablename__ = "cve_cvss_history"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    cve_id = Column(String(32), ForeignKey("cve_enriched.cve_id", ondelete="CASCADE"), nullable=False)
    elt_run_id = Column(UUID(as_uuid=True), ForeignKey("elt_runs.id"), nullable=False)
    old_version = Column(String(16), nullable=True)
    new_version = Column(String(16), nullable=True)
    old_vector = Column(Text, nullable=True)
    new_vector = Column(Text, nullable=True)
    old_score = Column(Numeric(4, 1), nullable=True)
    new_score = Column(Numeric(4, 1), nullable=True)
    old_severity = Column(String(16), nullable=True)
    new_severity = Column(String(16), nullable=True)
    old_attack_vector = Column(String(32), nullable=True)
    new_attack_vector = Column(String(32), nullable=True)
    old_attack_complexity = Column(String(32), nullable=True)
    new_attack_complexity = Column(String(32), nullable=True)
    old_attack_requirements = Column(String(32), nullable=True)
    new_attack_requirements = Column(String(32), nullable=True)
    old_privileges_required = Column(String(32), nullable=True)
    new_privileges_required = Column(String(32), nullable=True)
    old_user_interaction = Column(String(32), nullable=True)
    new_user_interaction = Column(String(32), nullable=True)
    old_exploit_maturity = Column(String(32), nullable=True)
    new_exploit_maturity = Column(String(32), nullable=True)
    change_reason = Column(Text, nullable=True)
    changed_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)

    cve = relationship("CveEnriched", back_populates="cvss_history")

    __table_args__ = (Index("ix_cve_cvss_history_cve_changed", "cve_id", "changed_at"),)


class EpssScore(Base):
    __tablename__ = "epss_scores"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    cve_id = Column(String(32), ForeignKey("cve_enriched.cve_id", ondelete="CASCADE"), nullable=False)
    elt_run_id = Column(UUID(as_uuid=True), ForeignKey("elt_runs.id"), nullable=True)
    score_date = Column(Date, nullable=False)
    epss_score = Column(Numeric(12, 9), nullable=False)
    percentile = Column(Numeric(12, 9), nullable=False)
    raw_s3_key = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)

    cve = relationship("CveEnriched", back_populates="epss_scores")

    __table_args__ = (
        UniqueConstraint("cve_id", "score_date", name="uq_epss_scores_cve_date"),
        CheckConstraint("epss_score >= 0 AND epss_score <= 1", name="ck_epss_scores_score_range"),
        CheckConstraint("percentile >= 0 AND percentile <= 1", name="ck_epss_scores_percentile_range"),
        Index("ix_epss_scores_date_score", "score_date", "epss_score"),
    )


class CveKevHistory(Base):
    __tablename__ = "cve_kev_history"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    cve_id = Column(String(32), ForeignKey("cve_enriched.cve_id", ondelete="CASCADE"), nullable=False)
    elt_run_id = Column(UUID(as_uuid=True), ForeignKey("elt_runs.id"), nullable=False)
    field_changed = Column(String(128), nullable=False)
    old_value = Column(Text, nullable=True)
    new_value = Column(Text, nullable=True)
    source = Column(String(32), nullable=False, default="cisa_kev")
    changed_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)

    cve = relationship("CveEnriched", back_populates="kev_history")

    __table_args__ = (
        CheckConstraint("source IN ('cisa_kev', 'nvd_cves', 'nvd_changes')", name="ck_cve_kev_history_source"),
        Index("ix_cve_kev_history_cve_changed", "cve_id", "changed_at"),
    )


class CveStatusHistory(Base):
    __tablename__ = "cve_status_history"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    cve_id = Column(String(32), ForeignKey("cve_enriched.cve_id", ondelete="CASCADE"), nullable=False)
    elt_run_id = Column(UUID(as_uuid=True), ForeignKey("elt_runs.id"), nullable=False)
    old_status = Column(String(64), nullable=True)
    new_status = Column(String(64), nullable=False)
    event_name = Column(String(128), nullable=True)
    changed_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)

    cve = relationship("CveEnriched", back_populates="status_history")

    __table_args__ = (Index("ix_cve_status_history_cve_changed", "cve_id", "changed_at"),)


class CveConsistency(Base):
    __tablename__ = "cve_consistency"

    cve_id = Column(String(32), ForeignKey("cve_enriched.cve_id", ondelete="CASCADE"), primary_key=True)
    elt_run_id = Column(UUID(as_uuid=True), ForeignKey("elt_runs.id", ondelete="CASCADE"), primary_key=True)
    nvd_ok = Column(Boolean, nullable=False, default=False)
    cvss_resolved = Column(Boolean, nullable=False, default=False)
    epss_ok = Column(Boolean, nullable=False, default=False)
    kev_ok = Column(Boolean, nullable=False, default=False)
    overall_ok = Column(Boolean, Computed("(nvd_ok AND cvss_resolved AND epss_ok AND kev_ok)", persisted=True))
    failure_detail = Column(JSONB, nullable=True)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)

    cve = relationship("CveEnriched", back_populates="consistencies")
    run = relationship("EltRun", back_populates="consistencies")

    __table_args__ = (
        Index("ix_cve_consistency_run_overall", "elt_run_id", "overall_ok"),
        Index("ix_cve_consistency_cve_overall", "cve_id", "overall_ok"),
    )


class CweNormalized(Base):
    __tablename__ = "cwe_normalized"

    cwe_id = Column(String(32), primary_key=True)
    name = Column(Text, nullable=False)
    abstraction = Column(String(64), nullable=True)
    structure = Column(String(64), nullable=True)
    status = Column(String(64), nullable=True)
    description = Column(Text, nullable=True)
    extended_description = Column(Text, nullable=True)
    likelihood_of_exploit = Column(String(64), nullable=True)
    related_weaknesses = Column(JSONB, nullable=True)
    observed_examples = Column(JSONB, nullable=True)
    raw_data = Column(JSONB, nullable=True)
    last_refreshed_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)

    cves = relationship("CveWeakness", back_populates="cwe")


class CveWeakness(Base):
    __tablename__ = "cve_weaknesses"

    cve_id = Column(String(32), ForeignKey("cve_enriched.cve_id", ondelete="CASCADE"), primary_key=True)
    cwe_id = Column(String(32), ForeignKey("cwe_normalized.cwe_id", ondelete="RESTRICT"), primary_key=True)
    source = Column(Text, nullable=True)
    type = Column(String(32), nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)

    cve = relationship("CveEnriched", back_populates="weaknesses")
    cwe = relationship("CweNormalized", back_populates="cves")

    __table_args__ = (Index("ix_cve_weaknesses_cwe", "cwe_id"),)


class CweFetchJob(Base):
    __tablename__ = "cwe_fetch_jobs"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    cwe_id = Column(String(32), nullable=False, index=True)
    requested_by_run_id = Column(UUID(as_uuid=True), ForeignKey("elt_runs.id"), nullable=True)
    status = Column(String(32), nullable=False, default="queued", index=True)
    attempts = Column(Integer, nullable=False, default=0)
    last_error = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    completed_at = Column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        CheckConstraint("status IN ('queued', 'running', 'success', 'failed')", name="ck_cwe_fetch_jobs_status"),
        UniqueConstraint("cwe_id", "status", name="uq_cwe_fetch_jobs_cwe_status"),
    )
