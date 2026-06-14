# CVE_WatchDog_BE

ELT pipeline (NVD 2.0 + EPSS + CISA KEV → enriched Postgres) and a read-only,
API-key-gated **Dashboard API** over the enriched CVE store.

## Dashboard API

A separate FastAPI app under `dashboard_api/`. It shares only `db/models.py`
and `core/config.py`; it never writes. Auth is a single API key in the
`X-API-Key` header (constant-time compare, fails closed), with CORS lock,
per-IP rate limiting, security headers, and a consistent error envelope.

### Configure

Add to `.env` (keys are generated, not guessed — rotate before production):

```
DASHBOARD_API_KEY=<client key>      # required for /cves, /stats, /meta
ADMIN_API_KEY=<admin key>           # required for /admin/* (runs + logs)
CORS_ALLOW_ORIGINS=https://your-frontend.example   # comma-separated; * in dev
```

### Run

```
.venv/Scripts/python -m uvicorn dashboard_api.main:app --reload
```

Interactive docs at `http://127.0.0.1:8000/docs`.

### Endpoints

| Method | Path             | Auth        | Purpose                                 |
|--------|------------------|-------------|-----------------------------------------|
| GET    | `/health`        | public      | Liveness                                |
| GET    | `/ready`         | public      | DB readiness ping                       |
| GET    | `/cves`          | data key    | Filter/sort/paginate CVEs               |
| GET    | `/cves/{cve_id}` | data key    | Single CVE detail (404 if absent)       |
| GET    | `/stats`         | data key    | Dashboard aggregates (cards + charts)   |
| GET    | `/meta/filters`  | data key    | Distinct values for dropdowns           |
| GET    | `/admin/runs`    | admin key   | Recent pipeline runs (status, timing)   |
| GET    | `/admin/logs`    | admin key   | Pipeline logs, filterable + paginated   |

### Example

```
curl -H "X-API-Key: $DASHBOARD_API_KEY" \
  "http://127.0.0.1:8000/cves?severity=CRITICAL&is_kev=true&limit=25"
```

## ELT pipeline

```
.venv/Scripts/python -m pipeline.run <mode> <pipeline>
# mode:     bulk_load | delta_poll
# pipeline: nvd | daily | transform
```
