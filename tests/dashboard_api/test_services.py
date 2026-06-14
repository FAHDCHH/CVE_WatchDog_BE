"""Unit tests for the dashboard API's logic units, in isolation.

No database connection and no network are used. Query-builder logic is exercised
by *compiling* the SQLAlchemy statements against the PostgreSQL dialect
(compilation needs no live connection); this also proves the injection-safety
claim — user input is emitted as bound parameters, never inlined into the SQL.

Covers: config parsing, the error envelope, fail-closed auth, the rate limiter,
filter mapping, CVE query building/sorting, admin query branching, and DTO
serialization (Decimal -> float).
"""
import os
from datetime import date
from decimal import Decimal
from types import SimpleNamespace
from unittest.mock import MagicMock

# The import chain (db.models, dashboard_api.config) reads these; set before import.
os.environ.setdefault("NVD_API_KEY", "test")
os.environ.setdefault("DATABASE_URL", "postgresql://user:pass@localhost/db")
os.environ.setdefault("R2_EXTRACTOR_KEY", "test")
os.environ.setdefault("R2_EXTRACTOR_SECRECT_KEY", "test")
os.environ.setdefault("R2_PL_URL", "https://r2.example.test")
os.environ.setdefault("R2_BUCKET_NAME", "test")

import pytest
from sqlalchemy.dialects import postgresql
from sqlalchemy.orm import Session

import dashboard_api.security as security
from dashboard_api.config import DashboardAPISettings, api_settings
from dashboard_api.errors import APIError, error_envelope, not_found
from dashboard_api.schemas.common import Severity, SortField, SortOrder
from dashboard_api.schemas.cve import CveSummary
from dashboard_api.schemas.filters import CveFilters, cve_filters
from dashboard_api.security import (
    _SlidingWindowLimiter,
    require_admin_key,
    require_api_key,
)
from dashboard_api.services import admin_service, cve_service
from db.models import CveEnriched


def _query():
    """A CveEnriched Query with no bound engine — fine for building/compiling."""
    return Session().query(CveEnriched)


def _compile(query):
    stmt = getattr(query, "statement", query)
    return stmt.compile(dialect=postgresql.dialect())


# --------------------------------------------------------------------------- #
# config: CORS origin parsing
# --------------------------------------------------------------------------- #
def test_cors_origins_star_is_wildcard_list():
    assert DashboardAPISettings(CORS_ALLOW_ORIGINS="*").cors_origins == ["*"]


def test_cors_origins_empty_defaults_to_wildcard():
    assert DashboardAPISettings(CORS_ALLOW_ORIGINS="").cors_origins == ["*"]


def test_cors_origins_csv_is_split_and_trimmed():
    s = DashboardAPISettings(CORS_ALLOW_ORIGINS="https://a.com, https://b.com ,")
    assert s.cors_origins == ["https://a.com", "https://b.com"]


# --------------------------------------------------------------------------- #
# errors: envelope shape + not_found
# --------------------------------------------------------------------------- #
def test_error_envelope_minimal():
    assert error_envelope("c", "m") == {"error": {"code": "c", "message": "m"}}


def test_error_envelope_includes_detail_when_present():
    body = error_envelope("c", "m", [{"field": "severity"}])
    assert body["error"]["detail"] == [{"field": "severity"}]


def test_not_found_builds_404_apierror_naming_the_id():
    err = not_found("CVE", "CVE-2026-0001")
    assert isinstance(err, APIError)
    assert err.status_code == 404
    assert err.code == "not_found"
    assert "CVE-2026-0001" in err.message


# --------------------------------------------------------------------------- #
# security: API-key auth fails closed
# --------------------------------------------------------------------------- #
def test_require_api_key_fails_closed_when_unset(monkeypatch):
    monkeypatch.setattr(api_settings, "DASHBOARD_API_KEY", "")
    with pytest.raises(APIError) as ei:
        require_api_key("anything")
    assert ei.value.status_code == 503


def test_require_api_key_rejects_wrong_key(monkeypatch):
    monkeypatch.setattr(api_settings, "DASHBOARD_API_KEY", "secret")
    with pytest.raises(APIError) as ei:
        require_api_key("nope")
    assert ei.value.status_code == 401


def test_require_api_key_rejects_missing_key(monkeypatch):
    monkeypatch.setattr(api_settings, "DASHBOARD_API_KEY", "secret")
    with pytest.raises(APIError):
        require_api_key(None)


def test_require_api_key_accepts_correct_key(monkeypatch):
    monkeypatch.setattr(api_settings, "DASHBOARD_API_KEY", "secret")
    assert require_api_key("secret") is None


def test_admin_key_is_distinct_from_data_key(monkeypatch):
    monkeypatch.setattr(api_settings, "DASHBOARD_API_KEY", "data")
    monkeypatch.setattr(api_settings, "ADMIN_API_KEY", "admin")
    with pytest.raises(APIError) as ei:
        require_admin_key("data")          # data key must not unlock admin
    assert ei.value.status_code == 401
    assert require_admin_key("admin") is None


# --------------------------------------------------------------------------- #
# security: sliding-window rate limiter
# --------------------------------------------------------------------------- #
def test_rate_limiter_blocks_after_limit():
    lim = _SlidingWindowLimiter(limit=3, window_seconds=60)
    assert [lim.allow("ip") for _ in range(4)] == [True, True, True, False]


def test_rate_limiter_is_per_identity():
    lim = _SlidingWindowLimiter(limit=1, window_seconds=60)
    assert lim.allow("a") is True
    assert lim.allow("b") is True          # different client unaffected
    assert lim.allow("a") is False


def test_rate_limiter_recovers_after_window(monkeypatch):
    clock = {"t": 1000.0}
    monkeypatch.setattr(security.time, "monotonic", lambda: clock["t"])
    lim = _SlidingWindowLimiter(limit=1, window_seconds=10)
    assert lim.allow("ip") is True
    assert lim.allow("ip") is False
    clock["t"] += 11                       # slide past the window
    assert lim.allow("ip") is True


# --------------------------------------------------------------------------- #
# filters: dependency maps params into the dataclass
# --------------------------------------------------------------------------- #
def test_cve_filters_none_lists_become_empty():
    f = cve_filters(severity=None, vuln_status=None,
                    sort=SortField.epss_score, order=SortOrder.asc)
    assert f.severity == []
    assert f.vuln_status == []
    assert f.sort == SortField.epss_score
    assert f.order == SortOrder.asc


def test_cve_filters_passes_through_scalar_values():
    f = cve_filters(severity=[Severity.CRITICAL], cvss_min=7.0, is_kev=True,
                    q="log4j", sort=SortField.cvss_score, order=SortOrder.desc)
    assert f.severity == [Severity.CRITICAL]
    assert f.cvss_min == 7.0
    assert f.is_kev is True
    assert f.q == "log4j"


# --------------------------------------------------------------------------- #
# cve_service: sort + filter query building
# --------------------------------------------------------------------------- #
def test_sort_columns_cover_every_sort_field():
    assert set(cve_service._SORT_COLUMNS.keys()) == set(SortField)


def test_apply_sort_uses_column_nulls_last_then_pk_tiebreak():
    f = CveFilters(sort=SortField.epss_score, order=SortOrder.asc)
    sql = str(_compile(cve_service._apply_sort(_query(), f))).lower()
    assert "epss_score asc" in sql
    assert "nulls last" in sql
    assert "cve_id asc" in sql


def test_apply_filters_no_filters_yields_no_where_clause():
    q = cve_service._apply_filters(_query(), CveFilters())
    assert q.statement.whereclause is None


def test_apply_filters_severity_emits_in_clause():
    f = CveFilters(severity=[Severity.CRITICAL, Severity.HIGH])
    sql = str(_compile(cve_service._apply_filters(_query(), f))).lower()
    assert "cvss_severity in" in sql


def test_apply_filters_parameterizes_input_no_sql_injection():
    payload = "x'; DROP TABLE cve_enriched; --"
    f = CveFilters(q=payload, vendor="acme")
    compiled = _compile(cve_service._apply_filters(_query(), f))
    sql = str(compiled)
    # The raw input is never inlined; it travels as a bound parameter.
    assert payload not in sql
    assert "%(" in sql
    assert any(payload in str(v) for v in compiled.params.values())


# --------------------------------------------------------------------------- #
# admin_service: only the provided filters are applied
# --------------------------------------------------------------------------- #
def _chainable_query_mock(scalar_total, rows):
    db = MagicMock()
    q = db.query.return_value
    q.filter.return_value = q
    q.with_entities.return_value = q
    q.scalar.return_value = scalar_total
    q.order_by.return_value = q
    q.limit.return_value = q
    q.offset.return_value = q
    q.all.return_value = rows
    return db, q


def test_list_logs_applies_only_provided_filters():
    db, q = _chainable_query_mock(7, ["log"])
    rows, total = admin_service.list_logs(
        db, run_id=None, cve_id="CVE-1", level="error",
        source=None, event_type=None, limit=10, offset=0,
    )
    assert (rows, total) == (["log"], 7)
    assert q.filter.call_count == 2        # cve_id + level only


def test_list_runs_applies_only_provided_filters():
    db, q = _chainable_query_mock(3, ["run"])
    rows, total = admin_service.list_runs(
        db, status="success", pipeline=None, limit=5, offset=0,
    )
    assert (rows, total) == (["run"], 3)
    assert q.filter.call_count == 1        # status only


# --------------------------------------------------------------------------- #
# schema: Decimal columns serialize as float
# --------------------------------------------------------------------------- #
def test_cve_summary_coerces_decimal_scores_to_float():
    row = SimpleNamespace(
        cve_id="CVE-2026-0001",
        cvss_score=Decimal("9.8"),
        epss_score=Decimal("0.479100000"),
        epss_percentile=Decimal("0.94"),
        is_kev=True,
    )
    dto = CveSummary.model_validate(row)
    assert isinstance(dto.cvss_score, float) and dto.cvss_score == 9.8
    assert isinstance(dto.epss_score, float)
    assert isinstance(dto.epss_percentile, float)
    assert dto.is_kev is True
