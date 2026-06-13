







# CVE Watchdog — Final DB Schema

**Last updated:** May 2026  
**Pattern:** Operational Data Store + denormalized serving table  
**Database:** PostgreSQL

---

## Table of Contents

1. [Schema Overview](https://claude.ai/chat/a071d776-ceb2-41a7-a89d-71d65dc96697#schema-overview)
2. [Tables](https://claude.ai/chat/a071d776-ceb2-41a7-a89d-71d65dc96697#tables)
3. [Indexes — Full Explanation](https://claude.ai/chat/a071d776-ceb2-41a7-a89d-71d65dc96697#indexes--full-explanation)
4. [Views](https://claude.ai/chat/a071d776-ceb2-41a7-a89d-71d65dc96697#views)
5. [CVE Inclusion Rules](https://claude.ai/chat/a071d776-ceb2-41a7-a89d-71d65dc96697#cve-inclusion-rules)
6. [Design Questions: Transform, Load, Consistency & Recovery](https://claude.ai/chat/a071d776-ceb2-41a7-a89d-71d65dc96697#design-questions)
7. [Reading Materials](https://claude.ai/chat/a071d776-ceb2-41a7-a89d-71d65dc96697#reading-materials)

---

## Schema Overview

```
cve_enriched          — one row per CVE, upserted every transform run (serving table)
cve_change_events     — append-only, one row per field delta from NVD Change History API
cve_cvss_history      — append-only, one row per CVSS score change
cve_epss_history      — append-only, one row per daily EPSS score snapshot
cve_status_history    — append-only, one row per vuln_status transition
cve_kev_history       — append-only, one row per CISA KEV field change
cwe_normalized        — MITRE CWE lookup, loaded once and refreshed periodically
pipeline_runs         — one row per pipeline execution
pipeline_logs         — append-only event log, per-CVE granularity for recovery
```

---

## Tables

---

### `cve_enriched`

One row per CVE. Upserted on every transform run. This is the read-optimized flat serving table — all dashboard queries hit this table directly with no joins. Wide by design: denormalization is intentional for read performance.

```sql
-- Identity
cve_id                          VARCHAR PRIMARY KEY
published_at                    TIMESTAMPTZ NOT NULL
last_modified_at                TIMESTAMPTZ NOT NULL
first_seen_at                   TIMESTAMPTZ NOT NULL     -- never overwritten on upsert
vuln_status                     VARCHAR NOT NULL
source_identifier               VARCHAR
description                     TEXT
cve_tags                        VARCHAR[]
references                      JSONB

-- CVSS — resolved at transform time
-- Fallback hierarchy: v4.0 → v3.1 → v3.0. v2 skipped entirely.
-- Only the winning version's fields are populated. Others are NULL.
cvss_version_used               VARCHAR                  -- '4.0' | '3.1' | '3.0'
cvss_source                     VARCHAR
cvss_type                       VARCHAR                  -- 'Primary' | 'Secondary'
cvss_score                      NUMERIC(4,1)
cvss_severity                   VARCHAR                  -- 'NONE'|'LOW'|'MEDIUM'|'HIGH'|'CRITICAL'
cvss_vector                     VARCHAR
attack_vector                   VARCHAR
attack_complexity               VARCHAR
attack_requirements             VARCHAR                  -- v4 only; NULL for v3.x
privileges_required             VARCHAR
user_interaction                VARCHAR
conf_impact_direct              VARCHAR                  -- maps to VC in v4; C in v3.x
integrity_impact_direct         VARCHAR                  -- maps to VI in v4; I in v3.x
avail_impact_direct             VARCHAR                  -- maps to VA in v4; A in v3.x
conf_impact_downstream          VARCHAR                  -- v4 only (SC); NULL for v3.x
integrity_impact_downstream     VARCHAR                  -- v4 only (SI); NULL for v3.x
avail_impact_downstream         VARCHAR                  -- v4 only (SA); NULL for v3.x
cvss_scope                      VARCHAR                  -- v3.x only; NULL for v4
exploitability_score            NUMERIC(4,1)
impact_score                    NUMERIC(4,1)

-- Threat (v4 Threat metrics; v3.x temporal equivalent)
exploit_maturity                VARCHAR
provider_urgency                VARCHAR

-- Supplemental (v4 only; do not affect score)
automatable                     VARCHAR
recovery                        VARCHAR
value_density                   VARCHAR
safety                          VARCHAR

-- EPSS
epss_score                      NUMERIC(12,9)
epss_percentile                 NUMERIC(12,9)
epss_date                       DATE

-- CISA KEV
is_kev                          BOOLEAN NOT NULL DEFAULT FALSE
kev_date_added                  DATE
kev_due_date                    DATE
kev_required_action             TEXT
kev_vendor_project              VARCHAR
kev_product                     VARCHAR
kev_vulnerability_name          VARCHAR
kev_short_description           TEXT
ransomware_known                VARCHAR                  -- 'Known' | 'Unknown'

-- Weakness
cwe_ids                         VARCHAR[]
cwe_names                       VARCHAR[]               -- denormalized from cwe_normalized

-- Affected Products
-- Structure per element:
-- {"vendor":"...","product":"...","cpe":"...","version_start":"...",
--  "version_end":"...","version_end_type":"excluding|including","vulnerable":true}
affected_products               JSONB

-- Evaluator Notes (NVD analyst annotations)
evaluator_comment               TEXT
evaluator_impact                TEXT
evaluator_solution              TEXT

-- Pipeline State
consistency_flag                BOOLEAN NOT NULL DEFAULT FALSE
-- false = transform not yet verified; true = all sources joined, no interruption detected
is_updated                      BOOLEAN NOT NULL DEFAULT FALSE

-- Newsletter Deduplication (reserved; not active in current phase)
newsletter_last_run_id          UUID
newsletter_last_published_at    TIMESTAMPTZ
newsletter_last_cvss            NUMERIC(4,1)
newsletter_last_epss            NUMERIC(12,9)
newsletter_last_is_kev          BOOLEAN
newsletter_last_ransomware      VARCHAR

-- Traceability
last_transform_run_id           UUID
raw_nvd_s3_key                  VARCHAR
```

---

### `cve_change_events`

Append-only. One row per field-level delta sourced from the NVD Change History API. The NVD returns bulk change events (one `cveChangeId` per event, covering N field deltas). The composite unique key `(nvd_change_id, detail_index)` prevents duplicate inserts on retry or overlapping extraction windows.

```sql
id                              BIGSERIAL PRIMARY KEY
nvd_change_id                   UUID NOT NULL            -- cveChangeId from NVD API
detail_index                    INTEGER NOT NULL         -- ordinal position in details[]
cve_id                          VARCHAR NOT NULL REFERENCES cve_enriched(cve_id)
event_name                      VARCHAR NOT NULL
-- 'CVE Received' | 'Initial Analysis' | 'Reanalysis' | 'CVE Modified' |
-- 'Modified Analysis' | 'CVE Translated' | 'Vendor Comment' |
-- 'CVE Source Update' | 'CPE Deprecation Remap' | 'CWE Remap' |
-- 'Reference Tag Update' | 'CVE Rejected' | 'CVE Unrejected' | 'CVE CISA KEV Update'
source_identifier               VARCHAR
action                          VARCHAR                  -- 'Added' | 'Changed' | 'Removed'
field_type                      VARCHAR
old_value                       TEXT
new_value                       TEXT
event_created_at                TIMESTAMPTZ NOT NULL
extraction_run_id               UUID NOT NULL

UNIQUE (nvd_change_id, detail_index)
```

---

### `cve_cvss_history`

Append-only. Written by the transform layer whenever the resolved CVSS score changes on a CVE. Stores the **previous** values before `cve_enriched` is overwritten. Enables querying score trajectories, severity band transitions, and score surge events.

```sql
id                              BIGSERIAL PRIMARY KEY
cve_id                          VARCHAR NOT NULL REFERENCES cve_enriched(cve_id)
changed_at                      TIMESTAMPTZ NOT NULL
cvss_version                    VARCHAR NOT NULL         -- '4.0' | '3.1' | '3.0'
cvss_score                      NUMERIC(4,1)
cvss_severity                   VARCHAR
cvss_vector                     VARCHAR
attack_vector                   VARCHAR
attack_complexity               VARCHAR
privileges_required             VARCHAR
user_interaction                VARCHAR
exploit_maturity                VARCHAR
change_trigger                  VARCHAR
-- 'initial_analysis' | 'reanalysis' | 'cna_update' | 'nvd_modified'
transform_run_id                UUID NOT NULL
```

---

### `cve_epss_history`

Append-only. One row per CVE per scoring date. Captures daily EPSS score snapshots, enabling trend detection — e.g. a CVE whose score surges from 0.02 to 0.91 in 72 hours. The unique constraint on `(cve_id, score_date)` prevents duplicate daily entries.

```sql
id                              BIGSERIAL PRIMARY KEY
cve_id                          VARCHAR NOT NULL REFERENCES cve_enriched(cve_id)
epss_score                      NUMERIC(12,9) NOT NULL
epss_percentile                 NUMERIC(12,9) NOT NULL
score_date                      DATE NOT NULL
recorded_at                     TIMESTAMPTZ NOT NULL
transform_run_id                UUID NOT NULL

UNIQUE (cve_id, score_date)
```

---

### `cve_status_history`

Append-only. One row per `vuln_status` transition. Captures when CVEs move between analysis states — particularly the `Awaiting Analysis` → `Analyzed` transition which signals new CVSS/CWE data has become available.

```sql
id                              BIGSERIAL PRIMARY KEY
cve_id                          VARCHAR NOT NULL REFERENCES cve_enriched(cve_id)
old_status                      VARCHAR NOT NULL
new_status                      VARCHAR NOT NULL
changed_at                      TIMESTAMPTZ NOT NULL
transform_run_id                UUID NOT NULL
```

---

### `cve_kev_history`

Append-only. One row per detected CISA KEV field change. Source of truth for ransomware flag escalation timestamps, which are not reliably surfaced by the NVD Change History API. Written before `cve_enriched` is overwritten.

```sql
id                              BIGSERIAL PRIMARY KEY
cve_id                          VARCHAR NOT NULL REFERENCES cve_enriched(cve_id)
field_changed                   VARCHAR NOT NULL
old_value                       TEXT
new_value                       TEXT
detected_at                     TIMESTAMPTZ NOT NULL
source_catalog_version          VARCHAR
```

---

### `cwe_normalized`

CWE lookup table loaded from MITRE bulk XML download. Refreshed periodically. Transform reads this table to resolve `cwe_ids[]` into human-readable `cwe_names[]` and writes the names directly into `cve_enriched` (denormalized for query performance).

```sql
cwe_id                          VARCHAR PRIMARY KEY
name                            VARCHAR NOT NULL
description                     TEXT
last_synced_at                  TIMESTAMPTZ NOT NULL
```

---

### `pipeline_runs`

One row per pipeline execution. The `expected_max_duration_minutes` column is used by the watchdog to detect crashed runs (`status = 'running'` past the threshold).

```sql
id                              UUID PRIMARY KEY
phase                           VARCHAR NOT NULL
source                          VARCHAR NOT NULL
cadence                         VARCHAR NOT NULL
triggered_by                    VARCHAR
started_at                      TIMESTAMPTZ NOT NULL
completed_at                    TIMESTAMPTZ
status                          VARCHAR NOT NULL         -- 'running'|'success'|'failed'|'crashed'
error_summary                   TEXT
expected_max_duration_minutes   INTEGER NOT NULL
```

---

### `pipeline_logs`

Append-only event log at per-CVE granularity. Primary recovery anchor. On a crashed run, the recovery process queries this table to identify which CVEs have `extract_success` but no `load_success` for that run_id.

```sql
id                              BIGSERIAL PRIMARY KEY
run_id                          UUID NOT NULL REFERENCES pipeline_runs(id)
level                           VARCHAR NOT NULL         -- 'info' | 'warn' | 'error'
source                          VARCHAR NOT NULL
event_type                      VARCHAR NOT NULL
-- e.g. 'extract_success' | 'transform_success' | 'load_success' |
--      'kev_diff_applied' | 'cvss_fallback_used' | 'epss_absent' |
--      'consistency_check_passed' | 'recovery_triggered'
message                         TEXT
cve_id                          VARCHAR
duration_ms                     INTEGER
http_status                     INTEGER
attempt_number                  INTEGER
request_url                     TEXT
response_size_bytes             INTEGER
page_number                     INTEGER
s3_key                          VARCHAR
metadata                        JSONB
created_at                      TIMESTAMPTZ NOT NULL
```

---

## Indexes — Full Explanation

Indexes are the most misunderstood part of schema design. The rule is simple: an index is a separate data structure that PostgreSQL maintains alongside your table. It trades write overhead and storage for faster reads. Every index you add slows down inserts and upserts slightly — so you add them only where reads justify the cost.

There are four index types in use here. Understanding which one to use and why:

---

### B-tree — the default, for scalar equality and range queries

B-tree is a sorted tree structure. PostgreSQL can binary-search it in O(log n). It handles: `=`, `<`, `>`, `<=`, `>=`, `BETWEEN`, `ORDER BY`, `IS NULL`.

**Use it when:** you filter or sort on a single scalar column.

```sql
-- On cve_enriched:
-- Every column that appears in a WHERE clause on the dashboard gets a B-tree.
-- Dashboard filters like:
--   WHERE cvss_severity = 'CRITICAL'
--   WHERE attack_vector = 'NETWORK'
--   WHERE is_kev = true
--   WHERE epss_score > 0.5
--   WHERE published_at > '2024-01-01'
-- All of these are B-tree equality or range scans.

CREATE INDEX idx_cve_enriched_published_at        ON cve_enriched (published_at);
CREATE INDEX idx_cve_enriched_last_modified_at    ON cve_enriched (last_modified_at);
CREATE INDEX idx_cve_enriched_vuln_status         ON cve_enriched (vuln_status);
CREATE INDEX idx_cve_enriched_cvss_score          ON cve_enriched (cvss_score);
CREATE INDEX idx_cve_enriched_cvss_severity       ON cve_enriched (cvss_severity);
CREATE INDEX idx_cve_enriched_cvss_version_used   ON cve_enriched (cvss_version_used);
CREATE INDEX idx_cve_enriched_attack_vector       ON cve_enriched (attack_vector);
CREATE INDEX idx_cve_enriched_attack_complexity   ON cve_enriched (attack_complexity);
CREATE INDEX idx_cve_enriched_privileges_required ON cve_enriched (privileges_required);
CREATE INDEX idx_cve_enriched_user_interaction    ON cve_enriched (user_interaction);
CREATE INDEX idx_cve_enriched_exploit_maturity    ON cve_enriched (exploit_maturity);
CREATE INDEX idx_cve_enriched_epss_score          ON cve_enriched (epss_score);
CREATE INDEX idx_cve_enriched_epss_percentile     ON cve_enriched (epss_percentile);
CREATE INDEX idx_cve_enriched_is_kev              ON cve_enriched (is_kev);
CREATE INDEX idx_cve_enriched_kev_date_added      ON cve_enriched (kev_date_added);
CREATE INDEX idx_cve_enriched_ransomware_known    ON cve_enriched (ransomware_known);
CREATE INDEX idx_cve_enriched_is_updated          ON cve_enriched (is_updated);
CREATE INDEX idx_cve_enriched_consistency_flag    ON cve_enriched (consistency_flag);

-- On cve_change_events:
CREATE INDEX idx_change_events_cve_id             ON cve_change_events (cve_id);
CREATE INDEX idx_change_events_event_name         ON cve_change_events (event_name);
CREATE INDEX idx_change_events_event_created_at   ON cve_change_events (event_created_at);

-- On cve_kev_history:
CREATE INDEX idx_kev_history_cve_id               ON cve_kev_history (cve_id);
CREATE INDEX idx_kev_history_detected_at          ON cve_kev_history (detected_at);
CREATE INDEX idx_kev_history_field_changed        ON cve_kev_history (field_changed);

-- On cve_cvss_history:
CREATE INDEX idx_cvss_history_cve_id              ON cve_cvss_history (cve_id);
CREATE INDEX idx_cvss_history_changed_at          ON cve_cvss_history (changed_at);

-- On cve_epss_history:
CREATE INDEX idx_epss_history_cve_id              ON cve_epss_history (cve_id);
CREATE INDEX idx_epss_history_score_date          ON cve_epss_history (score_date);

-- On cve_status_history:
CREATE INDEX idx_status_history_cve_id            ON cve_status_history (cve_id);
CREATE INDEX idx_status_history_changed_at        ON cve_status_history (changed_at);

-- On pipeline_logs:
CREATE INDEX idx_pipeline_logs_run_id             ON pipeline_logs (run_id);
CREATE INDEX idx_pipeline_logs_cve_id             ON pipeline_logs (cve_id);
CREATE INDEX idx_pipeline_logs_event_type         ON pipeline_logs (event_type);
CREATE INDEX idx_pipeline_logs_level              ON pipeline_logs (level);
```

---

### Composite B-tree — for multi-column filter combinations that always appear together

A composite index on `(A, B, C)` is efficient when your query filters on A, or A+B, or A+B+C — in that left-to-right order. It does not help queries that filter on B alone.

The exploitability profile composite is used because these four columns appear together in dashboard filter combinations that define "wormable" CVEs: `AV:N + AC:L + PR:N + UI:N` — the highest-priority exploitation pattern. One composite index serves this entire combination more efficiently than four separate B-trees that the planner must intersect.

```sql
CREATE INDEX idx_exploitability_profile ON cve_enriched
    (attack_vector, attack_complexity, privileges_required, user_interaction);
```

---

### GIN — for multi-valued columns: arrays and JSONB

GIN (Generalized Inverted Index) works like the index at the back of a book. For an array `['CWE-22', 'CWE-79']`, GIN creates an entry for each element pointing back to the row. A query `WHERE cwe_ids @> ARRAY['CWE-22']` (does this array contain CWE-22?) resolves in O(log n) against the GIN index rather than scanning every row.

**Use it when:** the column is an array or JSONB and you query for containment — "does this CVE affect vendor Microsoft?" or "does this CVE have CWE-79?".

GIN is wrong for scalar equality. A `cvss_severity VARCHAR` column does not benefit from GIN — B-tree is the right tool there because there is only one value per row, not a set of values.

```sql
-- cwe_ids: array containment — "give me CVEs with CWE-79"
--   WHERE cwe_ids @> ARRAY['CWE-79']
CREATE INDEX idx_cve_enriched_cwe_ids           ON cve_enriched USING GIN (cwe_ids);

-- cve_tags: array containment — "give me disputed CVEs"
--   WHERE cve_tags @> ARRAY['disputed']
CREATE INDEX idx_cve_enriched_cve_tags          ON cve_enriched USING GIN (cve_tags);

-- references: JSONB containment — "give me CVEs with an Exploit reference tag"
--   WHERE references @> '[{"tags": ["Exploit"]}]'
CREATE INDEX idx_cve_enriched_references        ON cve_enriched USING GIN (references);

-- affected_products: JSONB containment — "give me CVEs affecting Microsoft"
--   WHERE affected_products @> '[{"vendor": "Microsoft"}]'
CREATE INDEX idx_cve_enriched_affected_products ON cve_enriched USING GIN (affected_products);
```

---

### BRIN — for append-only timestamp columns with natural ordering

BRIN (Block Range Index) stores the min and max value of a column for each physical block of pages on disk. It works because append-only tables write new rows at the end — so `created_at` values increase monotonically with physical position. PostgreSQL can skip entire blocks whose max timestamp is earlier than your query's filter.

BRIN is tiny (kilobytes vs. megabytes for B-tree on the same column) and has near-zero write overhead. The tradeoff: it only works well when the column value correlates with physical row order — which is true for append-only logs and naturally true for timestamp columns on tables you never update.

**Use it when:** the table is append-only, the column is a timestamp, and queries filter by recent time ranges (e.g. "logs from the last 7 days").

**Do not use it on:** `cve_enriched`, which is upserted (rows are not physically ordered by time — upserts land wherever the old row was). B-tree is correct for `cve_enriched` timestamps.

```sql
-- pipeline_logs: queries like "show me errors from today's run"
--   WHERE created_at > NOW() - INTERVAL '24 hours'
CREATE INDEX idx_pipeline_logs_created_at_brin
    ON pipeline_logs USING BRIN (created_at);

-- cve_change_events: queries like "show me changes in the last 7 days"
--   WHERE event_created_at > NOW() - INTERVAL '7 days'
CREATE INDEX idx_change_events_created_at_brin
    ON cve_change_events USING BRIN (event_created_at);
```

---

### Partial indexes — indexes over a filtered subset of rows

A partial index only indexes rows matching a WHERE clause. If `is_kev = true` applies to ~1,500 of your 330,000 CVEs, a partial index on that subset is orders of magnitude smaller and faster than a full B-tree on the column.

Particularly useful for recovery queries that scan for `consistency_flag = false` (a small, transient set) rather than the full table.

```sql
-- Only indexes KEV CVEs — used by v_active_kev view and KEV dashboard filter
CREATE INDEX idx_cve_enriched_active_kev
    ON cve_enriched (kev_date_added, kev_due_date)
    WHERE is_kev = true;

-- Only indexes unverified rows — used by recovery process
CREATE INDEX idx_cve_enriched_needs_recovery
    ON cve_enriched (last_transform_run_id)
    WHERE consistency_flag = false;
```

---

## Views

```sql
-- Primary dashboard query surface — projection of cve_enriched, no joins.
-- All dashboard filter combinations resolve against this view.
CREATE VIEW v_dashboard_cve AS
    SELECT * FROM cve_enriched
    WHERE vuln_status NOT IN ('Rejected', 'Deferred', 'Received');

-- Active KEV entries with days until remediation deadline.
CREATE VIEW v_active_kev AS
    SELECT *,
           (kev_due_date - CURRENT_DATE) AS days_to_deadline
    FROM cve_enriched
    WHERE is_kev = true;

-- CVE timeline: current state joined with full change history.
-- Used for per-CVE detail view, not bulk dashboard queries.
CREATE VIEW v_cve_timeline AS
    SELECT
        e.cve_id,
        e.published_at,
        e.vuln_status,
        e.cvss_score,
        e.cvss_severity,
        c.event_name,
        c.action,
        c.field_type,
        c.old_value,
        c.new_value,
        c.event_created_at
    FROM cve_enriched e
    LEFT JOIN cve_change_events c ON e.cve_id = c.cve_id
    ORDER BY c.event_created_at DESC;
```

---

## CVE Inclusion Rules

| vuln_status           | Include  | Notes                                          |
| --------------------- | -------- | ---------------------------------------------- |
| `Analyzed`            | Yes      |                                                |
| `Modified`            | Yes      |                                                |
| `Undergoing Analysis` | Yes      | Deprioritized in dashboard; CVSS may be absent |
| `Awaiting Analysis`   | KEV only | Include only if `is_kev = true`                |
| `Deferred`            | No       |                                                |
| `Rejected`            | No       | Monitor `CVE Unrejected` events to reinstate   |
| `Received`            | No       |                                                |

---

## Design Questions

### 1. Transform Pipeline Structure

- What are your discrete transform phases? Are they sequential or can any run in parallel?
	-  Running them sequentially will take a lot of time , therefore in parallel is best
- What is the unit of work — per CVE, per page of 2,000, per source? 
	-   my first take would be per CVE, but Im not sure if that is the most optimal choice .
- Where does CVSS fallback resolution happen — dedicated function or inline per source handler? I would prefer per source handler, if anything goes wrong  in that specifc step , I would know , I need choices that suppert high modualrity.
- How do you handle a CVE that arrives with no CVSS data? Partial row, or wait?       It still goes on, but simply the cvss won't  be included until it is found in an update
- What triggers a transform run — a schedule, a signal from extraction completing, or both? Both (a schedule(for reruns , recovery, retrieval ) s well as manula for intial early testing, and after an extraction (which is the DEFAULT one))

### 2. Upsert Strategy

- What is your upsert key? Which columns do you update vs. preserve on conflict? I DONT UNDERSTAND THIS
- `first_seen_at` must never be overwritten on upsert. How do you enforce that? From db, and code and excpetions
- `is_updated` flips true when meaningful fields change. What is your explicit list of meaningful fields?
- How do you prevent an upsert from overwriting a `consistency_flag = true` row with stale data from a partially completed run? WHAT ARE MY OPTIONS  and their benefits? 

### 3. History Table Write Order

- For CVSS: do you write to `cve_cvss_history` before or after upserting `cve_enriched`? Before is correct — write the old value, then overwrite. OK THEN
- Same question applies to `cve_kev_history` and `cve_status_history`. OKAY
- What if the history write succeeds but the upsert fails? You now have a history record with no corresponding state change. How do you handle that? I WOULD SAY THAT RECOVERY CLASS OR CLASSES DO A RUN and for wxample if the  last in history matches the exact  value, then we would know something went wrong ? or simply go through the logs (we would know from there) what are the best industry practices

### 4. KEV Diffing

- What does your diff logic look like — hash the full catalog, or field-by-field per CVE ID?
- When a field changes, sequence is: write `cve_kev_history` → upsert `cve_enriched`. Is this wrapped in a transaction?
- What happens if the CISA endpoint is unreachable?try three times first   Skip KEV update and log a warning, or block the run? THE FORMER AND THE RECOVERY WOULD HANDLE IT
- How do you detect a KEV entry removed from the catalog? Does `is_kev` flip back to false? idk
- Should most of these things not apply for the other changes(just as epss and SUCHA ND SUCH) too ?

### 5. Consistency Flag Logic -->consistency score or metrics : for each table and for each of the tables elements coming together to a single onsistency score at the end 

- What is the exact checklist before flipping `consistency_flag = true`?
    - Raw file exists in R2 for this CVE's source page?
    - CVSS resolution completed without falling through to NULL?
    - EPSS join attempted (NULL score is acceptable for new CVEs)?
    - KEV diff completed for this run?
- Who sets the flag — the transform layer per CVE, or a validation pass after the full run?
-Make a composite consistency check for each source ? what are the best practices ? 


### 6. Recovery Design

- Define your `event_type` vocabulary in `pipeline_logs` now, before coding. Suggested minimum: `extract_success`, `transform_success`, `load_success`, `kev_diff_applied`, `cvss_fallback_used`, `epss_absent`, `consistency_check_passed`, `recovery_triggered`.
- On a crashed run, how do you identify which CVEs need reprocessing? Option A: `WHERE consistency_flag = false AND last_transform_run_id = <crashed_run_id>` Option B: `pipeline_logs` — CVEs with `extract_success` but no `load_success` for that run_id. Option C: Both, cross-referenced.
- Do you re-fetch from NVD API on recovery, or re-read from the R2 raw file written during extraction?
- How do you detect and handle a half-written `cve_enriched` row? From the get go, and if it was half enriched because the data was not in the initla source, then simply retry and even schedule extraction to get data. 
-An intensive logs event_type need to be implimented to help the transformation recovery system becasue it is  more complexe than the extraction recovery process.

### 7. Stale Run Detection

- Who sets `expected_max_duration_minutes` — hardcoded per phase, or learned from historical runs? intitially hardcoded then learned from historical runs
- Where does the watchdog run (GITHUB ACTIONS!)— separate cron, Postgres scheduled job, external monitor? I have been thinkin go making it  in a diffrent server and , tied up with the same logs class : make the logs class a package importable and pushing to the same db.
- When stale run detected: update `status = 'crashed'` → log → alert → allow next run to trigger recovery. Is this the right sequence? SURE .
- How do you prevent two runs of the same phase executing simultaneously? Advisory lock? `status = 'running'` pre-check? I dont understand maybe an advisory lock ?= what is that ?

### 8. EPSS Join Timing

- You run every 2 hours; EPSS updates daily. How do you avoid redundant fetches? Track `epss_date` on `cve_enriched` and skip if already today's date?  the extraction fetches epss every day not every two days , there is a daily and every two hours mode, 
- For initial full load: bulk CSV from `epss.empiricalsecurity.com`. For incremental: `days=1` parameter on the API. Is this your strategy? the extraction handles   the bulk load so it will be loaded from the R2, the a 1 day load from R2
- `cve_epss_history` unique constraint is `(cve_id, score_date)`. Only one snapshot per day per CVE. Does that match your intended cadence? me not understand

### 9. CWE Name Resolution

- What happens if a CWE ID from NVD has no match in `cwe_normalized`? Write NULL, write the raw ID as the name, or block and alert? log that, and trigger a cwe  direc extraction from the database
- MITRE CWE source: `https://cwe.mitre.org/data/downloads.html` — XML bulk download. What is your refresh cadence for `cwe_normalized`? the frequncy of their updates

### 10. Log Retention

- `pipeline_logs` at per-CVE granularity across 12 runs/day will grow fast. What is your retention policy — 30 days in Postgres, archive older rows to R2(that one is acually good)?
- Do all runs log at the same verbosity, or do recovery runs log at debug level? SOUNDS GOOD



REVIEW MY DECISONS  , cla4rify my quesitons, and review it for best practices as well as the best approach to ensure optimality ,  consistency . proivde a final conpection plan, as well as an exptreemly detailed intiensive logs system description.

---

## Reading Materials

### Transform & Load Patterns

- Idempotent pipeline design (Maxime Beauchemin): https://maximebeauchemin.medium.com/functional-data-engineering-a-modern-paradigm-for-batch-data-processing-2327ec32c42a
- PostgreSQL upsert (`INSERT ... ON CONFLICT`): https://www.postgresql.org/docs/current/sql-insert.html#SQL-ON-CONFLICT

### Recovery & Exactly-Once Semantics

- Designing Data-Intensive Applications — Chapter 11 (Stream Processing), Chapter 10 (Batch Processing): covers exactly-once semantics, checkpointing, and fault tolerance at the conceptual level directly applicable to your recovery design
- Prefect pipeline states and resumption: https://docs.prefect.io/latest/concepts/states/

### PostgreSQL Indexing

- Index types — B-tree, GIN, BRIN, Hash: https://www.postgresql.org/docs/current/indexes-types.html
- Partial indexes: https://www.postgresql.org/docs/current/indexes-partial.html
- GIN indexes for arrays and JSONB: https://www.postgresql.org/docs/current/gin-intro.html
- BRIN indexes — when physical order matches column order: https://www.postgresql.org/docs/current/brin-intro.html
- MVCC and autovacuum tuning (critical for upsert-heavy tables): https://www.postgresql.org/docs/current/routine-vacuuming.html

### CISA KEV & NVD Integration

- NVD API v2.0 official documentation: https://nvd.nist.gov/developers/vulnerabilities
- EPSS model documentation: https://www.first.org/epss/model
- CISA KEV catalog schema: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities_schema.json