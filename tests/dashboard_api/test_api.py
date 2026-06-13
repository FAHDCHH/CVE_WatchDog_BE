"""HTTP-layer tests for the dashboard API.

These exercise auth, input validation, the error envelope, and 404 vs empty-200
semantics without touching a real database: get_db is overridden and the service
functions are monkeypatched. SQL correctness is covered by a live smoke test.
"""
import os
from unittest.mock import MagicMock

os.environ.setdefault("NVD_API_KEY", "test")
os.environ.setdefault("DATABASE_URL", "postgresql://user:pass@localhost/db")
os.environ.setdefault("R2_EXTRACTOR_KEY", "test")
os.environ.setdefault("R2_EXTRACTOR_SECRECT_KEY", "test")
os.environ.setdefault("R2_PL_URL", "https://r2.example.test")
os.environ.setdefault("R2_BUCKET_NAME", "test")
# Must be set before importing the app (config is a module-level singleton).
os.environ["DASHBOARD_API_KEY"] = "test-key"
os.environ["ADMIN_API_KEY"] = "admin-key"

import pytest
from fastapi.testclient import TestClient

from dashboard_api.dependencies import get_db
from dashboard_api.main import app
from dashboard_api.services import admin_service, cve_service

VALID = {"X-API-Key": "test-key"}
ADMIN = {"X-API-Key": "admin-key"}


def _fake_db():
    yield MagicMock()


@pytest.fixture(autouse=True)
def _override_db():
    app.dependency_overrides[get_db] = _fake_db
    yield
    app.dependency_overrides.clear()


@pytest.fixture
def client():
    return TestClient(app)


def test_health_is_public(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_security_headers_present(client):
    resp = client.get("/health")
    assert resp.headers["X-Content-Type-Options"] == "nosniff"
    assert resp.headers["X-Frame-Options"] == "DENY"


def test_cves_requires_api_key(client):
    resp = client.get("/cves")
    assert resp.status_code == 401
    body = resp.json()
    assert body["error"]["code"] == "unauthorized"


def test_cves_rejects_wrong_key(client):
    resp = client.get("/cves", headers={"X-API-Key": "nope"})
    assert resp.status_code == 401


def test_cves_empty_is_200_not_error(client, monkeypatch):
    monkeypatch.setattr(cve_service, "list_cves", lambda db, f, limit, offset: ([], 0))
    resp = client.get("/cves", headers=VALID)
    assert resp.status_code == 200
    body = resp.json()
    assert body == {"items": [], "total": 0, "limit": 25, "offset": 0}


def test_cves_invalid_severity_is_422(client):
    resp = client.get("/cves", headers=VALID, params={"severity": "SUPERBAD"})
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "validation_error"


def test_cves_limit_over_cap_is_422(client):
    resp = client.get("/cves", headers=VALID, params={"limit": 9999})
    assert resp.status_code == 422


def test_cve_detail_not_found_is_404(client, monkeypatch):
    monkeypatch.setattr(cve_service, "get_cve", lambda db, cve_id: None)
    resp = client.get("/cves/CVE-2026-0001", headers=VALID)
    assert resp.status_code == 404
    body = resp.json()
    assert body["error"]["code"] == "not_found"
    assert "CVE-2026-0001" in body["error"]["message"]


def test_cve_detail_rejects_bad_id_pattern(client):
    resp = client.get("/cves/not a cve!!", headers=VALID)
    assert resp.status_code == 422


def test_admin_runs_requires_admin_key(client):
    resp = client.get("/admin/runs")
    assert resp.status_code == 401
    assert resp.json()["error"]["code"] == "unauthorized"


def test_admin_runs_rejects_data_key(client):
    # The data key must not unlock the admin surface.
    resp = client.get("/admin/runs", headers=VALID)
    assert resp.status_code == 401


def test_admin_runs_ok_with_admin_key(client, monkeypatch):
    monkeypatch.setattr(
        admin_service, "list_runs", lambda db, **kw: ([], 0)
    )
    resp = client.get("/admin/runs", headers=ADMIN)
    assert resp.status_code == 200
    assert resp.json() == {"items": [], "total": 0, "limit": 25, "offset": 0}


def test_admin_logs_ok_with_admin_key(client, monkeypatch):
    monkeypatch.setattr(
        admin_service, "list_logs", lambda db, **kw: ([], 0)
    )
    resp = client.get("/admin/logs", headers=ADMIN, params={"level": "error"})
    assert resp.status_code == 200
    assert resp.json()["total"] == 0


def test_admin_logs_rejects_bad_cve_pattern(client):
    resp = client.get("/admin/logs", headers=ADMIN, params={"cve_id": "bad id!!"})
    assert resp.status_code == 422
