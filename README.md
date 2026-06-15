# CVE_WatchDog_BE

ELT pipeline (NVD 2.0 + EPSS + CISA KEV → enriched Postgres), a read-only,
API-key-gated **Dashboard API** over the enriched CVE store, and a **Next.js web
console** (`frontend/`) for analysis and pipeline observability.

## Access & roles

Authentication is a single API key sent in the `X-API-Key` header (constant-time
compare, fails closed). There are two keys, and **admin is a superset of user**:

| Role  | Key (`.env`)         | Access                                                  |
|-------|----------------------|---------------------------------------------------------|
| User  | `DASHBOARD_API_KEY`  | CVE dashboards only — `/cves`, `/stats`, `/meta`         |
| Admin | `ADMIN_API_KEY`      | Everything above **plus** `/admin/*` (runs + logs)       |

In the web console you sign in with **one** key; the app detects whether it is a
user or admin key and shows the matching sections (Pipeline Ops is admin-only).

### Demo keys

> ⚠️ These are **demo keys** for local/academic use. Rotate them before any real
> deployment, and keep production keys out of source control.

```
User  (analyst) key :  xvjwrc7Wr-rkAZcdZ1L7btJhaXEZNGUGzdHuU7F44U0
Admin key           :  x8D2IL2jCSWrDFqPgTJjioCrWUtBJTbcAUlwyXHZX38
```

## Web console (frontend)

```
cd frontend
npm install
npm run dev          # http://localhost:3000
```

Pages: **Overview** (aggregate stats + charts), **CVE Explorer** (filter / sort /
paginate, with a per-CVE detail drawer), **Pipeline Ops** (runs + logs, admin only).
Configure the API base URL in `frontend/.env.local`
(`NEXT_PUBLIC_API_BASE_URL=http://127.0.0.1:8000`).

## Dashboard API

A separate FastAPI app under `dashboard_api/`. It shares only `db/models.py`
and `core/config.py`; it never writes. CORS lock, per-IP rate limiting, security
headers, and a consistent error envelope.

### Configure

Add to `.env` (keys are generated, not guessed — rotate before production):

```
DASHBOARD_API_KEY=<user key>        # CVE dashboards: /cves, /stats, /meta
ADMIN_API_KEY=<admin key>           # adds /admin/* (runs + logs); superset of user
CORS_ALLOW_ORIGINS=https://your-frontend.example   # comma-separated; * in dev
```

### Run

```
.venv/Scripts/python -m uvicorn dashboard_api.main:app --reload
```

Interactive docs at `http://127.0.0.1:8000/docs`.

### Endpoints

| Method | Path             | Auth          | Purpose                                 |
|--------|------------------|---------------|-----------------------------------------|
| GET    | `/health`        | public        | Liveness                                |
| GET    | `/ready`         | public        | DB readiness ping                       |
| GET    | `/cves`          | user or admin | Filter/sort/paginate CVEs               |
| GET    | `/cves/{cve_id}` | user or admin | Single CVE detail (404 if absent)       |
| GET    | `/stats`         | user or admin | Dashboard aggregates (cards + charts)   |
| GET    | `/meta/filters`  | user or admin | Distinct values for dropdowns           |
| GET    | `/admin/runs`    | admin only    | Recent pipeline runs (status, timing)   |
| GET    | `/admin/logs`    | admin only    | Pipeline logs, filterable + paginated   |

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

## Nomenclature

The platform fuses four public vulnerability-intelligence standards. Here is what
each one means and the fields the dashboard surfaces.

### CVE — Common Vulnerabilities and Exposures

A **CVE** is a unique public identifier for one disclosed vulnerability, in the
form `CVE-YYYY-NNNNN` (e.g. `CVE-2026-10520`). The catalogue is run by MITRE and
enriched by the NVD (NIST). A CVE record carries a description, affected products,
a status (e.g. *Analyzed*, *Modified*), and the metrics below. In this project,
one CVE = one **enriched record** in `cve_enriched`.

### CVSS — Common Vulnerability Scoring System

**CVSS** rates *technical severity* on a **0–10** scale (we use v3.1). The score
maps to a severity band:

| Severity | Score range |
|----------|-------------|
| NONE     | 0.0         |
| LOW      | 0.1 – 3.9   |
| MEDIUM   | 4.0 – 6.9   |
| HIGH     | 7.0 – 8.9   |
| CRITICAL | 9.0 – 10.0  |

The score is derived from a **vector** such as
`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H`. Its base metrics:

| Code | Metric             | Values (worst → best)                      | Meaning                                              |
|------|--------------------|--------------------------------------------|------------------------------------------------------|
| AV   | Attack Vector      | Network · Adjacent · Local · Physical      | How "remote" the attacker can be                     |
| AC   | Attack Complexity  | Low · High                                 | Conditions outside the attacker's control            |
| PR   | Privileges Required| None · Low · High                          | Privileges the attacker needs first                  |
| UI   | User Interaction   | None · Required                            | Whether a victim must do something                   |
| S    | Scope              | Changed · Unchanged                        | Can the impact cross a security boundary             |
| C    | Confidentiality    | High · Low · None                          | Impact on data disclosure                            |
| I    | Integrity          | High · Low · None                          | Impact on data trustworthiness                       |
| A    | Availability       | High · Low · None                          | Impact on access / uptime                            |

Two sub-scores are also recorded: **Exploitability** (how easy to attack, from
AV/AC/PR/UI) and **Impact** (severity of the consequence, from S/C/I/A). The CVE
Explorer decodes the vector into labelled pills and highlights the high-risk values.

### EPSS — Exploit Prediction Scoring System

**EPSS** (by FIRST.org) estimates the *likelihood* of exploitation, complementing
CVSS's *severity*. Two values:

- **EPSS score** — probability (0–1) the CVE will be exploited **in the wild within
  the next 30 days** (e.g. `0.479` ≈ 47.9%).
- **EPSS percentile** — how that score ranks against all CVEs (e.g. `0.98` = more
  likely to be exploited than 98% of known CVEs).

A high CVSS with a low EPSS is severe-but-unlikely; a high EPSS flags what is
actually being weaponised.

### CISA KEV — Known Exploited Vulnerabilities catalogue

The US **CISA** publishes the **KEV** catalogue: vulnerabilities *confirmed to be
exploited in the wild*. If a CVE is in KEV it is, by definition, an active threat.
Fields surfaced: **vendor / product**, **date added**, **remediation due date**,
**required action**, a short description, and a **ransomware-campaign** flag
(`Known` / `Unknown`). The console shows these as a red "actively exploited" alert.

### CWE — Common Weakness Enumeration

A **CWE** names the *class of flaw* behind a CVE (the root cause), e.g.
`CWE-79` = Cross-site Scripting, `CWE-89` = SQL Injection, `CWE-416` = Use After
Free. One CVE can map to several CWEs. The console resolves CWE ids to readable
names in the Overview's "Top weaknesses" chart and in each CVE's detail view.
