# CVE Watchdog

A data pipeline that collects vulnerability data from public cybersecurity APIs, enriches it using an LLM, and delivers it through a daily newsletter and an interactive dashboard.

---

## What it does

- Pulls CVE data from NVD, exploitation probability scores from EPSS, and known-exploited flags from CISA KEV on a 2-hour schedule
- Stores raw extraction output as Parquet files in Cloudflare R2 object storage
- Normalizes and joins data across three sources in a transformation layer
- Enriches each CVE with a structured LLM-generated article
- Delivers a per-user filtered newsletter and an interactive dashboard

---
 
## Architecture

ELT pipeline (Extract → Load → Transform) with a REST management layer.

```
NVD CVE API
NVD Change History API    →   Extraction layer   →   Cloudflare R2 (raw Parquet)
EPSS bulk CSV                                    →   Transformation + LLM enrichment
CISA KEV (GitHub mirror)                         →   Newsletter · Dashboard

Supabase Postgres   ←   elt_runs · pipeline_logs · cwe_normalized
GitHub Actions      ←   cron every 2h · recovery workflow
FastAPI             ←   trigger and status API
```

---

## Stack

| Concern | Technology |
|---|---|
| Language | Python 3.12 |
| Web framework | FastAPI |
| ORM | SQLAlchemy 2.0 |
| Migrations | Alembic |
| HTTP client | httpx |
| Retry logic | tenacity |
| Raw store | Cloudflare R2 + Apache Parquet |
| Parquet library | pyarrow |
| S3 client | boto3 (R2 endpoint) |
| Relational Database | Supabase Postgres |
| Scheduler | GitHub Actions cron |
| Secrets | GitHub Secrets |
| Config | pydantic-settings |
| Dependency auditing | pip-audit |

---

## Data sources

| Source | What it provides | Pull method |
|---|---|---|
| NVD CVE API | CVE records, CVSS scores, CPE configurations, CWE, vendor notes |  poll every 2h |
| NVD Change History API | Field-level change events per CVE |  24h window |
| EPSS | 30-day exploitation probability score per CVE | Daily bulk CSV download |
| CISA KEV | Known-exploited CVEs with ransomware campaign flags | Full catalog snapshot via GitHub mirror |
| CWE | Weakness descriptions | One-time pull, directly normalized |

---

## Project structure(so far)

```
project/
├── pipeline/
│   ├── __init__.py
│   ├── run.py                  
│   ├── recovery.py             
│   └── extractors/
│       ├── __init__.py
│       ├── base.py             
│       ├── epss.py             
│       ├── cisa_kev.py         
│       ├── nvd_cves.py         
│       └── nvd_changes.py      
├── storage/                    
│   ├── __init__.py
│   ├── parquet.py              
│   └── s3.py                  
├── api/
│   ├── __init__.py
│   ├── main.py                 
│   └── routes/
│       ├── __init__.py
│       └── pipeline.py         
├── db/
│   ├── __init__.py
│   ├── session.py              
│   └── models.py               
├── alembic/
│   ├── env.py
│   └── versions/
├── core/
│   ├── __init__.py
│   ├── config.py               
│   └── security.py             
├── alembic.ini
├── requirements.txt            
├── .env                        
├── .gitignore
└── .github/
    └── workflows/
        ├── elt_pipeline.yml
        └── elt_recovery.yml
```

---



---

## Raw store layout (Cloudflare R2)

```
raw/
  nvd_cves/year=YYYY/month=MM/day=DD/
    run_{id}_pass_CRITICAL_page_{N}.parquet
    run_{id}_pass_HIGH_page_{N}.parquet
    run_{id}_pass_KEV_page_{N}.parquet
  nvd_changes/year=YYYY/month=MM/day=DD/run_{id}_page_{N}.parquet
  epss_scores/year=YYYY/month=MM/day=DD/run_{id}_snapshot.parquet
  cisa_kev/year=YYYY/month=MM/day=DD/run_{id}_snapshot.parquet
```


---

## Security

- Outbound HTTP requests validated against an explicit URL allowlist before every call
- API keys sanitized from headers before any log write
- All FastAPI endpoints protected by bearer token authentication
- Raw SQL uses bound parameters throughout
- CVE description fields treated as untrusted external input — not interpolated into SQL or LLM prompts directly
- Dependencies pinned and audited via `pip-audit` in CI

---
