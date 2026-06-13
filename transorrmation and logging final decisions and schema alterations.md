A lot to work through. Let me go section by section — correct what's solid, fix what's wrong, answer what you don't understand, and close with the logging system design.

---

## 1. Transform Pipeline Structure

**Parallel — correct, but you need to understand the constraint.**

You cannot parallelize blindly. The dependency chain is:

```
NVD extract complete
        ↓
CVSS resolution + CWE name resolution    ← can run in parallel with each other
        ↓
EPSS join                                ← needs CVE row to exist first
        ↓
KEV diff + upsert                        ← needs CVE row to exist first
        ↓
Consistency check                        ← needs all above complete
```

EPSS and KEV can run in parallel with each other but both depend on the NVD transform completing first. You are not parallelizing the entire pipeline — you are parallelizing within stages where there are no dependencies.

**Unit of work — per page, not per CVE.**

Per CVE means 330,000 individual units of work to track, log, and coordinate. That is operationally expensive. Per page of 2,000 is the right granularity — it matches how NVD delivers the data, your R2 files are stored per page, and recovery can resume from the last successfully processed page. Per CVE granularity lives in `pipeline_logs` for observability, but the unit of work the pipeline coordinates around is the page.

**CVSS fallback in dedicated function — correct.**

Not per source handler. One dedicated function that takes a raw CVE object and returns the resolved CVSS block. Every source handler calls the same function. Modularity comes from isolating the logic in one place, not from duplicating it per handler. If the fallback logic needs to change, you change it once.

**No CVSS data — partial row — correct.**

Write the row with NULLs in CVSS columns. `vuln_status` will be `Undergoing Analysis` or `Awaiting Analysis`. The dashboard deprioritizes it. When the next run picks up an `Initial Analysis` or `Reanalysis` change event for that CVE, the transform fills in the CVSS columns and writes to `cve_cvss_history`.

**Trigger — both — correct.**

Schedule for recovery and reruns. Signal from extraction completing for the default path. Add one constraint: the scheduled run must check whether a signal-triggered run is already in progress before starting. This connects to the advisory lock question in section 7.

---

## 2. Upsert Strategy

**You said you don't understand the upsert key question. Here is what it means.**

An upsert is INSERT — but if a row with the same key already exists, UPDATE instead. In PostgreSQL:

```sql
INSERT INTO cve_enriched (cve_id, cvss_score, cvss_severity, ...)
VALUES ('CVE-2024-1234', 9.8, 'CRITICAL', ...)
ON CONFLICT (cve_id)
DO UPDATE SET
    cvss_score = EXCLUDED.cvss_score,
    cvss_severity = EXCLUDED.cvss_severity,
    last_modified_at = EXCLUDED.last_modified_at;
```

`EXCLUDED` refers to the row you tried to insert. `ON CONFLICT (cve_id)` means: if a row with this `cve_id` already exists, run the UPDATE instead.

The question is: which columns do you update, and which do you leave alone?

- `first_seen_at` — never update. Enforce it by simply not including it in the `DO UPDATE SET` list. Postgres will leave the existing value untouched.
- `consistency_flag` — do not update it to `false` if the existing row has `true`. More on this below.
- Everything else — update with new values from the source.

**Meaningful fields for `is_updated`:**

```
cvss_score
cvss_severity
cvss_vector
exploit_maturity
epss_score
epss_percentile
is_kev
ransomware_known
vuln_status
```

Anything that would change the dashboard display or risk assessment. Not `last_transform_run_id`, not `raw_nvd_s3_key` — those are housekeeping columns.

**Preventing stale upsert from overwriting `consistency_flag = true`:**

Your two options:

Option A — conditional update in the upsert itself:
```sql
ON CONFLICT (cve_id) DO UPDATE SET
    consistency_flag = CASE
        WHEN cve_enriched.consistency_flag = true THEN true
        ELSE EXCLUDED.consistency_flag
    END
```
Once a row is marked consistent, it stays consistent until explicitly reset by the pipeline at the start of a new run.

Option B — reset `consistency_flag = false` explicitly at the start of each run for only the CVEs being processed in that run, then flip it back to true at the end. Never let the upsert itself make the decision.

Option B is cleaner. The flag lifecycle is: start of run sets it false for affected CVEs → processing happens → validation sets it true. The upsert never touches it.

---

## 3. History Write Order

**Your instinct is correct but incomplete.**

The right answer is: wrap both operations in a single database transaction.

```
BEGIN
  INSERT INTO cve_cvss_history (old values)
  UPDATE cve_enriched (new values)
COMMIT
```

If the history write succeeds and the upsert fails, the transaction rolls back both. You never have a history record without a corresponding state change. This is the industry standard answer — it is not a recovery problem, it is a transaction problem. Do not rely on the recovery system to detect this. Prevent it from happening at the database level.

This applies identically to `cve_kev_history` and `cve_status_history`.

---

## 4. KEV Diffing

**Diff logic — field-by-field per CVE ID.**

Hashing the full catalog tells you something changed but not what. You need to know which field changed to write a useful `cve_kev_history` row. The process:

```
1. Download current CISA KEV catalog
2. For each entry, look up the CVE in cve_enriched
3. Compare field-by-field: is_kev, ransomware_known, kev_due_date, kev_required_action
4. For any field that differs: write cve_kev_history, then upsert cve_enriched
5. All of step 4 inside a transaction
```

**CISA unreachable — your answer is correct.**

Retry three times with exponential backoff. If all three fail, log a warning, skip KEV update for this run, set a flag in `pipeline_runs` indicating KEV was skipped. The next run will catch it. Do not block the entire pipeline because one source was unavailable.

**KEV entry removed from catalog:**

Yes, `is_kev` flips back to `false`. The diff logic must also check for CVEs currently marked `is_kev = true` in your database that are no longer present in the downloaded catalog. That is a removal. When detected: write to `cve_kev_history` with `field_changed = 'is_kev'`, `old_value = 'true'`, `new_value = 'false'`, then upsert `cve_enriched`.

**Your question about whether this applies to other sources:**

Yes. The same pattern — retry on failure, skip and log if all retries fail, recovery handles the gap — applies to NVD and EPSS too. The diff pattern specifically (download, compare, write history, upsert) applies to any source where silent field changes can occur. For NVD you rely on the Change History API rather than diffing yourself. For EPSS you are not diffing — you are appending a daily snapshot. KEV is the only source requiring a full diff because it has no delta feed.

---

## 5. Consistency — Rethink the Design

**You proposed a composite consistency score per source. This is the right instinct.**

Replace the single `consistency_flag` boolean with a structured approach. Instead of one boolean on `cve_enriched`, track consistency per source per run, then derive an overall state.

Add a `cve_consistency` table:

```sql
cve_id                  VARCHAR NOT NULL REFERENCES cve_enriched(cve_id)
run_id                  UUID NOT NULL REFERENCES pipeline_runs(id)
nvd_ok                  BOOLEAN NOT NULL DEFAULT FALSE
cvss_resolved           BOOLEAN NOT NULL DEFAULT FALSE
epss_ok                 BOOLEAN NOT NULL DEFAULT FALSE
kev_ok                  BOOLEAN NOT NULL DEFAULT FALSE
overall_ok              BOOLEAN GENERATED ALWAYS AS
                            (nvd_ok AND cvss_resolved AND epss_ok AND kev_ok) STORED

PRIMARY KEY (cve_id, run_id)
```

`overall_ok` is a generated column — Postgres computes it automatically from the other four. You never set it manually. Each source handler sets its own flag when it completes successfully. The consistency check is just querying `WHERE overall_ok = false`.

Remove `consistency_flag` from `cve_enriched`. It does not belong there — it is a per-run operational state, not a property of the CVE itself.

**Who sets each flag:**

Each source handler sets its own flag immediately after successfully completing its work for that CVE. Not a separate validation pass at the end — that introduces a window where the run could crash between the work completing and the validation running.

---

## 6. Recovery Design

**Recovery identification — Option C, but with priority.**

Use Option A first: `WHERE overall_ok = false AND run_id = <crashed_run_id>` on `cve_consistency`. Fast, indexed, direct.

Use Option B as verification: cross-reference against `pipeline_logs` to confirm the extract actually completed for those CVEs. If `extract_success` is missing from logs, you need to re-extract from NVD, not just re-transform from R2. If `extract_success` is present but `load_success` is missing, re-read from R2 and re-transform.

This gives you two distinct recovery paths:
- **Extract missing** → re-fetch from NVD API, write to R2, then transform
- **Transform incomplete** → read existing R2 file, re-run transform only

**Half-written row detection:**

A half-written row means some columns updated, transaction did not complete. If you wrap every upsert in a transaction (which you must), half-written rows cannot exist at the database level — the transaction either commits fully or rolls back fully. This is not a detection problem, it is a transaction discipline problem. Enforce transactions and you eliminate the scenario.

---

## 7. Stale Run Detection

**GitHub Actions for the watchdog — workable but has a gap.**

GitHub Actions has a minimum schedule granularity of every 5 minutes. If your watchdog needs to fire within 2 minutes of a stale run being detected, Actions is not reliable enough. It is also subject to GitHub's own availability.

A better pattern for the watchdog: run it as a lightweight process on the same server as your pipeline, on its own cron, completely independent of the pipeline process. The shared logging package idea is correct — make `pipeline_logs` writes importable so both the pipeline and the watchdog write to the same table. The watchdog reads `pipeline_runs` and writes to `pipeline_logs`. That is the right architecture.

**Advisory lock — what it is:**

A PostgreSQL advisory lock is a named lock you acquire explicitly in your code. Unlike row locks which Postgres manages automatically, advisory locks are application-level signals.

```sql
SELECT pg_try_advisory_lock(12345);  -- returns true if lock acquired, false if already held
```

You pick an arbitrary integer as the lock identifier — one per pipeline phase. Before starting a run, the pipeline tries to acquire the lock. If it gets it, proceed. If another process already holds it, the run exits immediately without starting. When the run completes or crashes, the lock is released (automatically on connection close, or explicitly).

This is cleaner than a `status = 'running'` pre-check because a pre-check has a race condition — two processes could both read `status != 'running'` in the same millisecond and both proceed. An advisory lock is atomic at the database level.

---

## 8. EPSS Join Timing

**Your extraction architecture clarification changes the transform logic.**

If extraction handles the daily EPSS bulk fetch and writes it to R2, the transform layer reads from R2, not from the EPSS API directly. That is correct separation of concerns.

**The unique constraint `(cve_id, score_date)` — what it means:**

`score_date` is the date the EPSS score was calculated — one per day. The unique constraint says: for a given CVE, only one score snapshot per calendar day. If the transform runs 12 times today and tries to insert today's EPSS score 12 times, only the first insert succeeds. The other 11 hit the unique constraint and are ignored (`ON CONFLICT DO NOTHING`). This is the correct behavior — you want one snapshot per day, not 12 duplicates.

---

## 9. CWE Name Resolution

**Your answer — trigger a direct extraction — is correct.**

Log the missing CWE ID, insert a job into a queue to fetch it from MITRE, write it to `cwe_normalized`, then on the next transform run the name resolves. In the meantime, write the raw CWE ID string into `cwe_names` as a placeholder so the row is not incomplete.

**Refresh cadence — MITRE updates CWE irregularly**, roughly monthly. Poll weekly. The cost is low — it is a single XML file download.

---

## 10. Log Retention

**30 days in Postgres, archive to R2 — correct.**

Implement this as a scheduled job that runs nightly:
```
INSERT INTO R2 archive all pipeline_logs WHERE created_at < NOW() - INTERVAL '30 days'
DELETE FROM pipeline_logs WHERE created_at < NOW() - INTERVAL '30 days'
```
Keep the last 30 days hot in Postgres for recovery and debugging. Everything older goes to R2 as compressed JSON.

**Verbosity — recovery runs at debug, normal runs at info — correct.**

---

## Logging System Design

This is the most critical operational component. Define it completely before writing any pipeline code.

---

### Event Type Vocabulary

Every `pipeline_logs` entry has an `event_type`. Define these exhaustively now:

**Extraction events** (written by extraction layer):
```
extract_started           — page fetch initiated
extract_success           — page fetched, written to R2
extract_failed            — page fetch failed after all retries
extract_rate_limited      — HTTP 429 or 403 received, backing off
extract_retry             — retry attempt N of max
```

**Transform events** (written by transform layer):
```
transform_started         — CVE transform initiated
transform_success         — CVE fully transformed, ready for load
transform_failed          — transform error, CVE skipped
cvss_resolved             — CVSS fallback completed, version used logged in metadata
cvss_fallback_used        — v4 absent, fell back to v3.1 or v3.0
cvss_absent               — no CVSS data available, partial row written
cwe_resolved              — all CWE IDs matched in cwe_normalized
cwe_missing               — one or more CWE IDs not found, extraction queued
epss_joined               — EPSS score found and applied
epss_absent               — no EPSS score for this CVE, NULL written
kev_matched               — CVE found in KEV catalog
kev_field_changed         — KEV field changed, history written
kev_removed               — CVE removed from KEV catalog
kev_skipped               — KEV source unavailable, skipped for this run
status_changed            — vuln_status transition detected, history written
```

**Load events** (written by load layer):
```
load_started              — upsert initiated
load_success              — upsert committed
load_failed               — upsert failed, transaction rolled back
history_written           — history table row committed (specify which table in metadata)
```

**Consistency events** (written by consistency checker):
```
consistency_check_started — consistency evaluation begun for this CVE
consistency_check_passed  — all source flags true, overall_ok set true
consistency_check_failed  — one or more source flags false, logged with detail
```

**Recovery events** (written by recovery process):
```
recovery_triggered        — recovery process started for a crashed run
recovery_cve_identified   — specific CVE identified as needing reprocessing
recovery_path_extract     — CVE requires re-extraction from NVD
recovery_path_transform   — CVE requires re-transform from R2 only
recovery_success          — CVE successfully reprocessed
recovery_failed           — CVE reprocessing failed, requires manual intervention
```

**Watchdog events** (written by watchdog process):
```
watchdog_check            — watchdog ran, no stale runs detected
stale_run_detected        — run exceeded expected_max_duration_minutes
run_marked_crashed        — pipeline_runs.status set to 'crashed'
watchdog_alert_sent       — external alert dispatched
```

---

### Metadata Field Usage

The `metadata JSONB` column carries structured context that does not fit named columns. Define what goes in it per event type:

```
cvss_resolved:        {"version_used": "3.1", "versions_present": ["3.1"], "v4_absent": true}
cvss_fallback_used:   {"attempted": "4.0", "fell_back_to": "3.1", "reason": "v4_not_present"}
cwe_missing:          {"missing_ids": ["CWE-1234"], "extraction_queued": true}
epss_absent:          {"cve_age_days": 3, "likely_reason": "too_new"}
kev_field_changed:    {"field": "ransomware_known", "old": "Unknown", "new": "Known"}
load_failed:          {"error_type": "unique_violation", "constraint": "...", "attempt": 1}
consistency_check_failed: {"failed_sources": ["epss", "kev"], "run_id": "..."}
recovery_cve_identified:  {"reason": "load_success_missing", "last_event": "transform_success"}
stale_run_detected:   {"run_id": "...", "phase": "transform", "elapsed_minutes": 47, "threshold": 30}
```

---

### Log Levels

```
info    — normal operation events: extract_success, load_success, consistency_check_passed
warn    — degraded but recoverable: epss_absent, kev_skipped, cvss_fallback_used, cwe_missing
error   — failures requiring action: extract_failed, load_failed, transform_failed, recovery_failed
debug   — only during recovery runs: every CVE evaluated, every decision logged
```

---

### What This Gives You

With this vocabulary fully implemented, your recovery process reduces to two queries:

```sql
-- Which CVEs need reprocessing?
SELECT cve_id FROM pipeline_logs
WHERE run_id = '<crashed_run_id>'
  AND event_type = 'extract_success'
  AND cve_id NOT IN (
      SELECT cve_id FROM pipeline_logs
      WHERE run_id = '<crashed_run_id>'
        AND event_type = 'load_success'
  );

-- Which of those need re-extraction vs re-transform only?
SELECT cve_id FROM pipeline_logs
WHERE run_id = '<crashed_run_id>'
  AND event_type = 'extract_failed';
```

Your entire recovery logic is readable from the logs table. No guessing, no manual inspection, no delete-and-restart.

---

**Reading materials:**

- Kleppmann Chapter 8 — The Trouble with Distributed Systems: directly covers the failure modes your watchdog and recovery system are designed to handle
- PostgreSQL transactions and advisory locks: