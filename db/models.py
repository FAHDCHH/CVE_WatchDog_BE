import uuid
from datetime import datetime
from sqlalchemy import Column, String, Text, DateTime, JSON
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Column, String, Text, Integer, DateTime, JSON, BigInteger, ForeignKey, Enum as SQLEnum
Base = declarative_base()
class EltRun(Base):
    __tablename__ = "elt_runs"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    triggered_by = Column(String, nullable=False)
    started_at = Column(DateTime(timezone=True), default=datetime.utcnow)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    status = Column(String, nullable=False, default="running")
    sources_status = Column(JSON, nullable=True)
    error_summary = Column(Text, nullable=True)
class PipelineLog(Base):
    __tablename__ = "pipeline_logs"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    elt_run_id = Column(UUID(as_uuid=True), ForeignKey("elt_runs.id"), nullable=False)
    level = Column(SQLEnum("INFO", "WARNING", "ERROR", name="log_level"), nullable=False)
    source = Column(SQLEnum("nvd_cves", "nvd_changes", "epss", "cisa_kev", "system", name="log_source"), nullable=False)
    event_type = Column(SQLEnum("fetch_start", "fetch_success", "retry_attempt", "fetch_failed", "fallback_triggered", "store_success", name="event_type"), nullable=False)
    http_status = Column(Integer, nullable=True)
    attempt_number = Column(Integer, nullable=True)
    message = Column(Text, nullable=False)
    duration_ms = Column(Integer, nullable=True)
    request_url = Column(Text, nullable=True)
    response_size_bytes = Column(Integer, nullable=True)
    page_number = Column(Integer, nullable=True)
    s3_key = Column(Text, nullable=True)
    extra = Column(JSON, nullable=True)
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow)