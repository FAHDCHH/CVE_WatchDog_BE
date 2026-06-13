# CVE Watchdog Transform/Load Prompt Pack

Use these prompts one at a time. Attach the full design document as Markdown
when you paste each prompt into Codex.

Each prompt is intentionally strict: it tells Codex what to inspect, what to
modify, what not to touch, and how to verify the step before stopping.

## Review Notes Before Using These Prompts

The design document is strong, but it has a few conflicts or stale assumptions.
The prompts below normalize those decisions so Codex does not blindly implement
contradictory instructions.

- Prefer the current repo layout unless the prompt explicitly creates a new
  package. The repo currently uses `pipeline/extractors/`, not
  `pipeline/extract/`.
- For CWE XML parsing, do not hardcode `cwe-6` or `cwe-7`. Detect the namespace
  dynamically from the XML root tag.
- Do not subclass `BaseExtractor` for the CWE extractor unless a later prompt
  explicitly asks for that. The design says dependency injection and a standalone
  class.
- The document conflicts on history write failure. Use Part 16 as the final
  policy: history write failure is serious but non-fatal; log it, append an
  error to the transform result, and continue to the main upsert.
- The repo exception base may be `PipelineException`, not `CveWatchdogError`.
  Follow the actual repo while preserving the named exception classes.
- The document mentions `cvss_metrics` as present, but that may already be
  removed. Read `db/models.py` before writing any prompt step.
- `cvss_score = Numeric(3, 1)` is a schema bug because CVSS can be `10.0`.
  Fix this with a migration before writing the production upsert.
- Do not let any transform pure function do I/O, logging, mutation of globals,
  network calls, or DB writes.

---

## Prompt 00 - Repo Audit And Conflict Report Only

```text
You are working in the CVE Watchdog backend repo. I am attaching a Markdown
design document for the transform/load layer.

TASK:
Review the design document against the current repository. Do not edit files.
Produce a precise implementation audit and conflict report.

READ THESE FILES FIRST:
- db/models.py
- core/exceptions/exceptions.py
- core/constants.py
- db/session.py
- pipeline/logs/base_logs.py
- pipeline/logs/pipeline_logs.py
- pipeline/extractors/base.py
- pipeline/extractors/cwe.py if it exists
- storage/s3.py
- pyproject.toml / requirements files if present

WHAT TO REPORT:
1. Current repository layout versus the design document layout.
2. Existing classes/functions that already satisfy part of the design.
3. Missing files that need to be created.
4. Schema mismatches, especially:
   - cvss_score precision
   - cvss_metrics presence/absence
   - CVSS history flat metric columns
   - CweFetchJob constraints
   - Pipeline log allowed sources/event types
5. Exception hierarchy mismatches.
6. Any design contradiction. In particular:
   - history failure policy: Part 16 wins over earlier abort wording
   - CWE extractor path/name mismatch
   - hardcoded CWE XML namespace must be dynamic
7. Recommended implementation order with one sentence of risk per step.

STRICT RULES:
- Do not modify code.
- Do not create files.
- Do not run network requests.
- Do not speculate. Every finding must cite a local file path and line number
  or quote the design section being referenced.

OUTPUT FORMAT:
- Findings first, ordered by severity.
- Then "Existing Assets".
- Then "Missing Work".
- Then "Recommended Step Order".
- Then "Questions / Ambiguities".
```

---

## Prompt 01 - Schema And Constants Preflight

```text
You are working in the CVE Watchdog backend repo. I am attaching the transform
and load design document as Markdown.

TASK:
Implement only the schema/constants preflight changes required before the
transform/load layer can safely write data.

READ FIRST:
- db/models.py
- core/constants.py
- alembic/env.py and alembic/versions/* if Alembic exists
- pipeline/logs/pipeline_logs.py
- pipeline/logs/base_logs.py

REQUIRED CHECKS:
1. Confirm `PIPELINE_SOURCES` contains every source needed by the design:
   `nvd_cves`, `nvd_changes`, `epss`, `cisa_kev`, `cwe`, `cwe_fetch`,
   `transform`, `load`, `consistency`, `recovery`, `watchdog`, `pipeline`,
   `system`.
2. Confirm `PIPELINE_EVENT_TYPES` contains all event types referenced in the
   design document, especially transform/load/consistency/CWE events.
3. Confirm `CveEnriched.cvss_score` can store `10.0`. If it is still
   `Numeric(3, 1)`, create an Alembic migration changing it to `Numeric(4, 1)`.
4. Confirm `cvss_metrics` is absent from `CveEnriched`. If present, create an
   Alembic migration to remove it and update the model.
5. Confirm `CveCvssHistory` has the 12 flat old/new metric columns:
   attack_vector, attack_complexity, attack_requirements,
   privileges_required, user_interaction, exploit_maturity.
6. Confirm `BaseLogger._sanitize_url` exists and `PipelineLogger.log()`
   sanitizes `request_url`.

STRICT RULES:
- Do not implement transform/load logic in this step.
- Do not touch extractor code.
- Do not rename existing models.
- Do not delete existing migrations.
- If no migration framework exists, stop and report exactly what migration
  would be required instead of inventing a framework.

VALIDATION:
- Run syntax/import checks for modified files.
- If Alembic exists, run the repository's migration validation command if one
  exists. If not, run an offline import/syntax check.
- Report every changed file.
```

---

## Prompt 02 - Exception Hierarchy

```text
You are working in the CVE Watchdog backend repo. I am attaching the transform
and load design document as Markdown.

TASK:
Implement the exception hierarchy needed by the transform/load/R2/CWE layers.
Keep it compatible with the current repository's existing base exception.

READ FIRST:
- core/exceptions/exceptions.py
- any existing core/exceptions/*.py
- all current imports of exceptions across the repo

IMPLEMENT:
Add missing exception classes for:
- R2Error
- R2ReadError
- R2WriteError
- TransformError
- CVSSResolutionError
- InclusionFilterError
- EPSSTransformError
- KEVTransformError
- CWEResolutionError
- LoadError
- UpsertError
- HistoryWriteError
- TransactionError
- ConsistencyError
- CweExtractionError if missing

CONSTRUCTOR CONTRACT:
Every new exception should accept:
- message: str
- cve_id: str | None = None

It must store `self.cve_id = cve_id` and preserve normal Exception behavior.
If the repo's current exception style is simpler, adapt minimally while keeping
this contract.

STRICT RULES:
- Modify only exception files.
- Do not change behavior of existing exception classes unless needed for
  compatibility.
- Do not update transform/load code in this step.
- Do not create tests unless the repo already has a clear matching test pattern.

VALIDATION:
- Run syntax check for exception files.
- Run `rg` to verify the new class names are defined exactly once.
- Import every new exception class from Python.
```

---

## Prompt 03 - Shared Transform Dataclasses

```text
You are working in the CVE Watchdog backend repo. I am attaching the transform
and load design document as Markdown.

TASK:
Create the shared dataclasses used by the transform/load/consistency layers.

TARGET FILE:
- pipeline/transform/__init__.py

CREATE PACKAGE IF NEEDED:
- pipeline/transform/
- pipeline/transform/__init__.py

IMPLEMENT EXACT DATACLASSES FROM THE DESIGN:
- CVSSResult
- KEVEntry
- KEVDiff
- CWEResolution
- TransformResult
- ConsistencyResult

TYPE RULES:
- Use standard library `@dataclass`.
- Use `Decimal` for CVSS and EPSS scores.
- Use `date` for date-only fields.
- Use `UUID` for run IDs.
- Use `dict`, `list`, and `str | None` style annotations if the repo targets
  Python 3.12+.
- Do not use Pydantic.
- Do not use ORM models here.

STRICT RULES:
- This file should contain dataclasses and imports only.
- Do not add logic methods.
- Do not add DB/session/logger imports.
- Do not create transform modules yet.

VALIDATION:
- Run syntax check.
- Run an import check:
  `from pipeline.transform import CVSSResult, KEVEntry, KEVDiff, CWEResolution, TransformResult, ConsistencyResult`
- Instantiate each dataclass with minimal valid values in a one-off command.
```

---

## Prompt 04 - R2 Client

```text
You are working in the CVE Watchdog backend repo. I am attaching the transform
and load design document as Markdown.

TASK:
Implement the R2 client wrapper as the single object-storage interface for the
new transform/load layer.

READ FIRST:
- storage/s3.py
- core/config.py
- core/exceptions/exceptions.py
- any existing storage or R2 code

TARGET FILES:
- pipeline/r2/__init__.py
- pipeline/r2/client.py

IMPLEMENT:
Class `R2Client` with dependency-injected credentials:

__init__(
    self,
    bucket_name: str,
    endpoint_url: str,
    access_key_id: str,
    secret_access_key: str,
)

Methods:
- read_json(self, key: str) -> dict
- read_csv_lines(self, key: str) -> Iterator[dict]
- read_bytes(self, key: str) -> bytes
- write_json(self, key: str, data: dict | list) -> str
- write_bytes(self, key: str, data: bytes, content_type: str = "application/octet-stream") -> str
- content_hash(self, key: str) -> str
- key_exists(self, key: str) -> bool

BEHAVIOR:
- Use boto3 S3-compatible client for Cloudflare R2.
- Do not read env vars inside this class.
- Do not log or expose credentials.
- `read_csv_lines` should stream and yield dictionaries via csv.DictReader.
- `content_hash` should compute SHA-256 incrementally from streamed object body.
- `key_exists` should use HeadObject and return False for not found.
- Wrap read failures as R2ReadError.
- Wrap write failures as R2WriteError.
- Exception messages may include the object key and safe boto3 error code, but
  must never include credentials or signed URLs.

STRICT RULES:
- Do not modify existing `storage/s3.py` unless absolutely required, and if so
  explain why before editing.
- Do not instantiate Settings inside R2Client.
- Do not implement transform/load modules in this step.

VALIDATION:
- Syntax/import check.
- Fake-client or monkeypatch smoke checks for read/write/key_exists if no test
  framework exists.
- Search generated code for credential variable names in exception strings.
```

---

## Prompt 05 - InclusionFilter

```text
You are working in the CVE Watchdog backend repo. I am attaching the transform
and load design document as Markdown.

TASK:
Implement `pipeline/transform/inclusion.py` with pure inclusion logic.

READ FIRST:
- pipeline/transform/__init__.py
- core/exceptions/exceptions.py

IMPLEMENT:
- INCLUDED_STATUSES = {"Analyzed", "Modified", "Undergoing Analysis"}
- EXCLUDED_STATUSES = {"Rejected", "Deferred", "Received"}
- class InclusionFilter
- method:
  should_include(self, cve_id: str, vuln_status: str, is_kev: bool = False) -> tuple[bool, str | None]

LOGIC:
1. Validate `cve_id` against `^CVE-\d{4}-\d{4,}$`.
   Raise InclusionFilterError if invalid.
2. Included statuses return `(True, None)`.
3. `Awaiting Analysis` returns `(True, None)` only when `is_kev` is True;
   otherwise `(False, "awaiting_analysis_no_kev")`.
4. Excluded statuses return `(False, vuln_status.lower().replace(" ", "_"))`.
5. Anything else returns `(False, "unknown_status")`.

STRICT RULES:
- Pure logic only.
- No DB imports.
- No logger imports.
- No network/R2 access.
- Do not implement any other transform module.

VALIDATION:
- Run syntax/import check.
- Run one-off Python assertions for:
  included statuses, excluded statuses, Awaiting Analysis both ways,
  unknown status, invalid CVE raises, long suffix CVE passes.
```

---

## Prompt 06 - CVSSResolver

```text
You are working in the CVE Watchdog backend repo. I am attaching the transform
and load design document as Markdown.

TASK:
Implement `pipeline/transform/cvss.py` as a pure CVSS resolver.

READ FIRST:
- pipeline/transform/__init__.py
- core/exceptions/exceptions.py
- db/models.py for target flat CVSS fields

IMPLEMENT:
- VERSION_PRIORITY = ["cvssMetricV40", "cvssMetricV31", "cvssMetricV30"]
- VERSION_LABELS = {"cvssMetricV40": "4.0", "cvssMetricV31": "3.1", "cvssMetricV30": "3.0"}
- class CVSSResolver

METHODS:
- resolve(self, cve_id: str, raw_metrics: dict | None) -> CVSSResult | None
- _select_entry(self, entries: list[dict]) -> dict
- _parse_entry(self, cve_id: str, metric_key: str, entry: dict) -> CVSSResult
- _map_v4(self, cvss_data: dict, source: str, cvss_type: str) -> CVSSResult
- _map_v3(self, cvss_data: dict, source: str, cvss_type: str, version: str) -> CVSSResult
- detect_change(self, current: CVSSResult | None, incoming: CVSSResult | None) -> bool
- is_secondary_fallback(self, entry: dict) -> bool

REQUIRED BEHAVIOR:
- Return None for missing/empty metrics.
- Prefer v4.0, then v3.1, then v3.0.
- Prefer Primary entry, else first entry.
- Missing `cvssData` raises CVSSResolutionError(cve_id=cve_id).
- Parse all numeric fields with `Decimal(str(value))`, never `float`.
- v4 maps v4-only fields and sets `cvss_scope=None`.
- v3 maps v3 fields and sets v4-only/supplemental fields to None.
- `detect_change` compares score, severity, vector, and version_used only.

STRICT RULES:
- Pure logic only.
- No DB/session/logger/R2 imports.
- No mutation of module-level state.
- Do not catch errors broadly unless the design explicitly says to.

VALIDATION:
- One-off assertions covering all testing bullets in the design:
  None/empty metrics, version priority, Primary preference, Secondary fallback,
  v4/v3 field differences, Decimal score, missing cvssData exception,
  detect_change cases.
```

---

## Prompt 07 - EPSSTransformer

```text
You are working in the CVE Watchdog backend repo. I am attaching the transform
and load design document as Markdown.

TASK:
Implement `pipeline/transform/epss.py` as a pure EPSS transformer.

READ FIRST:
- pipeline/transform/__init__.py
- core/exceptions/exceptions.py

IMPLEMENT:
- SURGE_THRESHOLD = Decimal("0.3")
- CHANGE_NOISE_THRESHOLD = Decimal("0.001")
- class EPSSTransformer

METHODS:
- apply(self, cve_id: str, epss_row: dict | None, current_score: Decimal | None, current_date: date | None) -> tuple[Decimal | None, Decimal | None, date | None, bool]
- is_surge(self, old_score: Decimal | None, new_score: Decimal | None) -> bool

REQUIRED BEHAVIOR:
- None row returns `(None, None, None, False)`.
- Required keys: `cve`, `epss`, `percentile`, `date`.
- Parse score and percentile with `Decimal(str(value))`.
- Parse date with `date.fromisoformat`.
- Validate score and percentile are between 0 and 1 inclusive.
- Same score date: changed only if score delta is greater than 0.001.
- Different score date: changed is True.
- Raise EPSSTransformError(cve_id=cve_id) for missing keys, parse errors,
  or out-of-range values.
- `is_surge` returns True only when both scores exist and delta >= 0.3.

STRICT RULES:
- Pure logic only.
- No DB/session/logger/R2 imports.
- No floats.

VALIDATION:
- One-off assertions for all design testing bullets.
```

---

## Prompt 08 - KEVTransformer

```text
You are working in the CVE Watchdog backend repo. I am attaching the transform
and load design document as Markdown.

TASK:
Implement `pipeline/transform/kev.py` as pure KEV parsing and diff logic.

READ FIRST:
- pipeline/transform/__init__.py
- core/exceptions/exceptions.py
- db/models.py for KEV column names

IMPLEMENT:
- KEV_DIFFABLE_FIELDS exactly as described in the design.
- class KEVTransformer

METHODS:
- parse_entry(self, raw_entry: dict) -> KEVEntry
- diff(self, cve_id: str, current_row: dict | None, incoming: KEVEntry | None) -> KEVDiff | None
- is_ransomware_escalation(self, diff: KEVDiff | None) -> bool

REQUIRED BEHAVIOR:
- `parse_entry` requires non-empty `cveID`; missing raises KEVTransformError.
- Optional fields become None.
- Strip strings.
- Parse `dateAdded` and `dueDate` with `date.fromisoformat`.
- Map CISA field names to KEVEntry fields exactly.
- `diff` handles the four cases:
  A. removal when incoming None and current is KEV
  B. new entry when incoming exists and current absent/not KEV
  C. field diff when incoming exists and current is KEV
  D. no-op when incoming None and current absent/not KEV
- `is_ransomware_escalation` detects ransomware_known changing to "Known".

STRICT RULES:
- Pure logic only.
- No DB/session/logger/R2 imports.
- Use `.get()` throughout.

VALIDATION:
- One-off assertions for missing cveID, optional fields, date parsing,
  whitespace stripping, all diff cases, and ransomware escalation.
```

---

## Prompt 09 - CWEResolver

```text
You are working in the CVE Watchdog backend repo. I am attaching the transform
and load design document as Markdown.

TASK:
Implement `pipeline/transform/cwe.py` as the DB-backed CWE resolver.

READ FIRST:
- pipeline/transform/__init__.py
- db/models.py
- core/exceptions/exceptions.py

IMPLEMENT:
class CWEResolver:
- __init__(self, db: Session)
- resolve(self, cve_id: str, cwe_entries: list[dict]) -> list[CWEResolution]
- get_missing_ids(self, resolutions: list[CWEResolution]) -> list[str]

REQUIRED BEHAVIOR:
- `cwe_entries` is the raw NVD `weaknesses` array.
- For each entry, find description where `lang == "en"`.
- Extract the `value` as the CWE ID.
- Skip `NVD-CWE-Other` and `NVD-CWE-noinfo`.
- Only standard IDs matching `^CWE-\d+$` are looked up.
- Look up `CweNormalized` by `cwe_id`.
- Found -> CWEResolution(found=True, name=row.name, source=entry source, weakness_type=entry type)
- Missing -> CWEResolution(found=False, name=None, source=entry source, weakness_type=entry type)
- Missing CWE is not an exception.
- Raise CWEResolutionError(cve_id=cve_id) only on DB errors.
- `get_missing_ids` is a pure filter.

STRICT RULES:
- No logging.
- No job queuing.
- No writes.
- No R2/network access.

VALIDATION:
- Use a fake DB/session object if no test framework exists.
- Assert empty input, skipped non-standard IDs, found, missing, mixed,
  missing IDs, no English description, and DB error behavior.
```

---

## Prompt 10 - StatusTracker

```text
You are working in the CVE Watchdog backend repo. I am attaching the transform
and load design document as Markdown.

TASK:
Implement `pipeline/transform/status.py` as pure status transition logic.

IMPLEMENT:
class StatusTracker:
- detect_change(self, cve_id: str, old_status: str | None, new_status: str | None) -> bool
- is_newly_analyzed(self, old_status: str | None, new_status: str | None) -> bool
- is_rejection(self, new_status: str | None) -> bool
- is_reinstatement(self, old_status: str | None, new_status: str | None) -> bool

REQUIRED BEHAVIOR:
- `detect_change` is True only when both statuses are not None and differ.
- `is_newly_analyzed` is True when new is "Analyzed" and old is not "Analyzed".
- `is_rejection` is True only for new status "Rejected".
- `is_reinstatement` is True when old is "Rejected" and new is not "Rejected"
  and new is not None.

STRICT RULES:
- Pure logic only.
- No imports except typing if needed.
- No DB/session/logger/R2.

VALIDATION:
- One-off assertions for every testing bullet in the design.
```

---

## Prompt 11 - HistoryWriter

```text
You are working in the CVE Watchdog backend repo. I am attaching the transform
and load design document as Markdown.

TASK:
Implement `pipeline/load/history.py` for writing history rows.

READ FIRST:
- db/models.py
- pipeline/transform/__init__.py
- pipeline/logs/pipeline_logs.py
- core/exceptions/exceptions.py

CREATE PACKAGE IF NEEDED:
- pipeline/load/__init__.py
- pipeline/load/history.py

IMPLEMENT:
class HistoryWriter:
- __init__(self, db: Session, logger: PipelineLogger)
- write_cvss_history(...)
- write_kev_history(...)
- write_status_history(...)
- write_epss_snapshot(...)

REQUIRED BEHAVIOR:
- CVSS, KEV, and status history writes use explicit `with self.db.begin():`.
- CVSS history writes all old/new score, vector, version, severity, and the 12
  flat metric columns.
- KEV history writes one row per changed field.
- Status history writes one CveStatusHistory row.
- EPSS snapshot uses PostgreSQL insert with ON CONFLICT (cve_id, score_date)
  DO NOTHING.
- On transaction failure, log `load_history_transaction_failed` and raise
  HistoryWriteError(cve_id=cve_id).
- On success, log `load_history_written`.
- EPSS conflict should not raise; log `load_upsert_no_change` if detectable.

STRICT RULES:
- Do not implement CveUpserter in this step.
- Do not make history writes decide whether the main upsert continues. That is
  CveUpserter's job.
- Do not use raw SQL strings.

VALIDATION:
- Syntax/import checks.
- Use fake or mocked DB/logger where possible.
- At minimum, compile the SQLAlchemy insert statements without executing against
  a real database.
```

---

## Prompt 12 - CveUpserter

```text
You are working in the CVE Watchdog backend repo. I am attaching the transform
and load design document as Markdown.

TASK:
Implement `pipeline/load/upsert.py` for writing TransformResult state to
`cve_enriched`, `cve_weaknesses`, and `cwe_fetch_jobs`.

READ FIRST:
- db/models.py
- pipeline/transform/__init__.py
- pipeline/load/history.py
- pipeline/logs/pipeline_logs.py
- core/exceptions/exceptions.py
- Part 16 of the design document

IMPORTANT POLICY:
Use Part 16 as final authority. History write failure is non-fatal:
- log `load_history_failed`
- append a specific error string to `result.errors`
- continue to the main upsert
Do not abort the CVE upsert solely because a history write failed.

IMPLEMENT:
- MEANINGFUL_FIELDS as specified.
- NEVER_UPDATE_FIELDS = {"cve_id", "first_seen_at"}
- class CveUpserter
- __init__(self, db: Session, logger: PipelineLogger, history_writer: HistoryWriter)
- upsert(self, result: TransformResult) -> bool

REQUIRED STEPS:
1. Build insert_dict from TransformResult and raw NVD data.
2. Assert `first_seen_at` is not in insert_dict.
3. Attempt all applicable history writes before main upsert.
4. History failures are logged and appended to result.errors; upsert continues.
5. Detect `is_updated` from MEANINGFUL_FIELDS against previous/current values
   available on TransformResult or reconstructable from the result design.
   If the design lacks current values, stop and report the missing contract
   instead of inventing hidden DB reads.
6. Upsert CveEnriched with PostgreSQL ON CONFLICT DO UPDATE.
7. Assert `first_seen_at` is not in the update SET clause.
8. Upsert CveWeakness rows only for found CWE resolutions.
9. Queue CweFetchJob rows for missing CWEs using ON CONFLICT DO NOTHING.
10. Log load_upsert_started, load_upsert_success, load_upsert_failed,
    load_is_updated_flagged, and load_first_seen_preserved as appropriate.

STRICT RULES:
- No raw SQL strings.
- No direct R2/network access.
- Do not silently cap CVSS 10.0.
- Do not write to `cvss_metrics`.
- Do not overwrite `first_seen_at`.
- Do not implement orchestrator in this step.

VALIDATION:
- Syntax/import checks.
- Compile generated SQLAlchemy insert statements where possible.
- Use fake TransformResult objects to validate insert_dict excludes
  first_seen_at and contains expected traceability fields.
```

---

## Prompt 13 - ConsistencyChecker

```text
You are working in the CVE Watchdog backend repo. I am attaching the transform
and load design document as Markdown.

TASK:
Implement `pipeline/consistency/checker.py`.

READ FIRST:
- db/models.py
- pipeline/transform/__init__.py
- pipeline/logs/pipeline_logs.py
- core/exceptions/exceptions.py

CREATE PACKAGE IF NEEDED:
- pipeline/consistency/__init__.py
- pipeline/consistency/checker.py

IMPLEMENT:
class ConsistencyChecker:
- __init__(self, db: Session, logger: PipelineLogger)
- evaluate(self, result: TransformResult) -> ConsistencyResult
- run_summary(self, run_id: UUID) -> dict

RULES:
- nvd_ok is True if result.raw_nvd is not None and result.new_status is not None.
- cvss_resolved is True if result.cvss is not None OR result.new_status is in
  {"Awaiting Analysis", "Undergoing Analysis"}.
- epss_ok is True if "EPSSTransformError" is not in result.errors.
- kev_ok is True if "KEVTransformError" is not in result.errors.
- Build failure_detail with failed_flags and reasons.
- Upsert CveConsistency by composite key `(cve_id, elt_run_id)`.
- Never set computed column `overall_ok` manually.
- Log consistency_check_passed or consistency_check_failed.
- `run_summary` returns and logs total/passed/failed/failed_nvd/failed_cvss/
  failed_epss/failed_kev.

STRICT RULES:
- No raw SQL strings; use SQLAlchemy expression API.
- No transform/load side effects.
- No R2/network access.

VALIDATION:
- Syntax/import checks.
- Compile upsert statement if possible.
- Fake result assertions for pass/fail cases.
```

---

## Prompt 14 - TransformOrchestrator

```text
You are working in the CVE Watchdog backend repo. I am attaching the transform
and load design document as Markdown.

TASK:
Implement `pipeline/transform/pipeline.py` as the orchestrator for one CVE
and one page of CVEs.

READ FIRST:
- pipeline/transform/__init__.py
- pipeline/transform/inclusion.py
- pipeline/transform/cvss.py
- pipeline/transform/epss.py
- pipeline/transform/kev.py
- pipeline/transform/cwe.py
- pipeline/transform/status.py
- db/models.py
- pipeline/logs/pipeline_logs.py
- Part 14, Part 15, and Part 17 of the design document

IMPLEMENT:
class TransformOrchestrator with dependency injection exactly as described.

METHODS:
- transform_one(...)
- _build_cvss_from_row(...)
- transform_page(...)

REQUIRED FLOW:
Follow steps 0 through 9 from the design:
0. Extract and validate cve_id.
1. Log transform_cve_started.
2. Inclusion check and early skip.
3. Fetch current DB row with OperationalError retry only.
4. Status transition detection and logging.
5. CVSS resolution, fallback/absent/change logging.
6. EPSS transformation, absent/skipped/joined/surge logging.
7. KEV diff and per-field logging.
8. CWE resolution, missing/partial/resolved logging.
9. Assemble TransformResult and log transform_cve_success.

ERROR POLICY:
- Hard abort only for missing/invalid cve_id, InclusionFilterError, and DB
  fetch failure after retries.
- Other transform component errors are appended to result.errors and processing
  continues with partial data.
- LoggingError never aborts transform.
- All recoverability logs must include metadata from Part 17.

STRICT RULES:
- Do not write DB rows except reading current CveEnriched.
- Do not perform load/upsert here.
- Do not read R2 here.
- Do not create dependencies internally. Everything is injected.
- Do not use raw dict indexing on external payloads; use `.get()`.

VALIDATION:
- Syntax/import checks.
- Fake dependencies to test:
  invalid CVE abort,
  excluded CVE skip,
  happy path TransformResult,
  EPSS failure continues,
  KEV failure continues,
  CWE DB error continues,
  transform_page logs completed vs partial.
```

---

## Prompt 15 - CWE Bulk Extractor

```text
You are working in the CVE Watchdog backend repo. I am attaching the transform
and load design document as Markdown.

TASK:
Implement or repair the CWE bulk extractor.

READ FIRST:
- pipeline/extractors/cwe.py
- db/models.py
- pipeline/logs/pipeline_logs.py
- core/exceptions/exceptions.py
- pipeline/r2/client.py if it exists
- storage/s3.py only for reference

TARGET:
Use the repo's current extractor path unless instructed otherwise. If the file
already exists at `pipeline/extractors/cwe.py`, repair that file instead of
creating `pipeline/extract/cwe_extractor.py`.

IMPLEMENT:
- MITRE_CWE_URL = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"
- CWE_BULK_R2_KEY = "cwe/bulk/cwec_latest.xml"
- class CweExtractor with injected db, logger, r2, run_id
- run_bulk_refresh(self) -> int
- process_pending_jobs(self) -> int
- private helpers for download/decompress, parse XML, extract text, element to dict

CRITICAL RULES:
- Do not subclass BaseExtractor.
- Do not import storage.s3 or storage.parquet.
- Do not use lxml.
- Do not use tenacity.
- Do not hardcode CWE XML namespace version. Detect namespace dynamically from
  root.tag and element.tag.
- Retry manually on 429, 500, 502, 503, 504 and timeout.
- Do not retry 400, 403, 404.
- Write parsed CWE rows to `cwe_normalized`.
- Write raw XML bytes to R2 via `r2.write_bytes(CWE_BULK_R2_KEY, xml_bytes)`.
- Commit once after all CWE upserts.
- Commit once after all pending jobs are processed.

VALIDATION:
- Syntax/import check.
- Fake HTTP ZIP test.
- Fake no-XML ZIP raises CweExtractionError.
- Fake retry path logs warn and then succeeds.
- Fake retry exhaustion logs error and raises CweExtractionError.
- Fixture XML parse for cwe-6, cwe-7, and no namespace.
- If network is available and approved, live MITRE ZIP parse should return
  hundreds of records, not zero.
```

---

## Prompt 16 - Full Transform Runner Integration

```text
You are working in the CVE Watchdog backend repo. I am attaching the transform
and load design document as Markdown.

TASK:
Implement the high-level transform execution flow that connects artifacts,
R2 reads, transform orchestration, load upsert, and consistency checking.

READ FIRST:
- db/models.py
- db/session.py
- pipeline/r2/client.py
- pipeline/transform/pipeline.py
- pipeline/load/upsert.py
- pipeline/consistency/checker.py
- pipeline/logs/pipeline_logs.py
- any existing runner scripts
- Part 12 of the design document

BEFORE EDITING:
Find the existing pipeline entrypoint style. If no runner convention exists,
propose the minimal file to add and stop for confirmation unless the repo has
an obvious `pipeline/runners` or similar package.

IMPLEMENT FLOW:
1. Create or receive an EltRun.
2. Acquire advisory lock if the repo already has a lock helper; otherwise
   report missing lock infrastructure instead of inventing broad DB logic.
3. Query RawArtifacts for the run.
4. Build EPSS lookup from R2 CSV lines.
5. Build KEV lookup from R2 JSON.
6. For each NVD page artifact:
   - deduplicate by content_hash against previous artifact
   - read page JSON from R2
   - transform page
   - upsert each result
   - evaluate consistency for each result
7. Run consistency summary.
8. Mark EltRun success/partial/failed according to actual outcomes.
9. Release advisory lock if acquired.

STRICT RULES:
- Do not rewrite already implemented pure transform modules.
- Do not hide source failures: log pipeline_source_unavailable and continue
  where the design says source failure is non-blocking.
- Do not read env vars directly; pass Settings-derived values from the runner.
- Do not use raw SQL strings.

VALIDATION:
- Syntax/import checks.
- Dry-run with fake R2 and fake DB objects if feasible.
- At minimum, unit-level smoke check that dependencies can be constructed.
```

---

## Prompt 17 - Logging Metadata Contract Pass

```text
You are working in the CVE Watchdog backend repo. I am attaching the transform
and load design document as Markdown.

TASK:
Audit and repair logging metadata contracts for transform/load/consistency.

READ FIRST:
- core/constants.py
- pipeline/logs/base_logs.py
- pipeline/logs/pipeline_logs.py
- all implemented files under pipeline/transform, pipeline/load,
  pipeline/consistency, pipeline/extractors/cwe.py
- Part 17 of the design document

IMPLEMENT:
For each event type used by the new code:
1. Ensure the event type is in PIPELINE_EVENT_TYPES.
2. Ensure `source` is valid and in PIPELINE_SOURCES.
3. Ensure required metadata fields from Part 17 are present.
4. Ensure request URLs are sanitized before database write.
5. Ensure no credential-like values are logged.

STRICT RULES:
- Do not change business logic.
- Do not add new event names if an existing design event name fits.
- Do not weaken validation to make logs pass.
- Do not remove logs that recovery depends on.

VALIDATION:
- `rg` all `event_type=` usages and compare against core/constants.py.
- Smoke test PipelineLogger validation with representative event/source pairs.
- Report any event contract that cannot be satisfied because required data is
  not available in the current code.
```

---

## Prompt 18 - Test Suite For Implemented Transform/Load Layer

```text
You are working in the CVE Watchdog backend repo. I am attaching the transform
and load design document as Markdown.

TASK:
Create focused tests for the implemented transform/load/R2/CWE modules.

READ FIRST:
- existing tests directory and conventions
- pyproject.toml / pytest config / requirements
- all implemented pipeline/r2, pipeline/transform, pipeline/load,
  pipeline/consistency, pipeline/extractors/cwe.py files

TEST SCOPE:
Write tests for:
- R2Client safe wrapper behavior with mocked boto3 client
- InclusionFilter
- CVSSResolver
- EPSSTransformer
- KEVTransformer
- CWEResolver with fake DB
- StatusTracker
- TransformOrchestrator with fake dependencies
- HistoryWriter statement behavior where possible
- CveUpserter insert dict/upsert behavior where possible
- ConsistencyChecker rules
- CweExtractor XML parsing, ZIP extraction, retry behavior, pending jobs

STRICT RULES:
- Do not hit real MITRE, real R2, or real Postgres in unit tests.
- Mock network, boto3, logger, and DB.
- Tests must be deterministic.
- Do not change production code unless a test reveals a real bug; if so, fix
  the smallest possible production code and explain it.

VALIDATION:
- Run the targeted test suite.
- If dependencies are missing, report the exact missing package/command instead
  of silently skipping.
- Provide a summary of pass/fail and the highest-risk untested behavior.
```

---

## Prompt 19 - Final Integration Review

```text
You are working in the CVE Watchdog backend repo. I am attaching the transform
and load design document as Markdown.

TASK:
Perform a final code-review pass on the entire transform/load implementation.
Do not start by changing code. Review first.

REVIEW SCOPE:
- core/constants.py
- core/exceptions/*
- db/models.py and migrations
- pipeline/r2/*
- pipeline/transform/*
- pipeline/load/*
- pipeline/consistency/*
- pipeline/extractors/cwe.py
- pipeline/logs/*
- runner/integration files touched by prior prompts
- tests

FINDINGS TO PRIORITIZE:
1. Data loss or silent partial data bugs.
2. Non-idempotent writes.
3. Wrong transaction boundaries.
4. History failure policy violations.
5. `first_seen_at` overwritten.
6. CVSS 10.0 schema/storage bug.
7. Missing or invalid recovery logs.
8. Credential leaks.
9. Use of float for scores.
10. Raw SQL or unsafe query construction.
11. Real network/R2/DB calls in unit tests.

OUTPUT:
- Findings first, with file/line references.
- Then missing tests.
- Then small recommended fixes.

ONLY AFTER REVIEW:
If findings are straightforward and localized, apply the minimal fixes and run
targeted tests. If a finding requires a design decision, stop and ask.
```

