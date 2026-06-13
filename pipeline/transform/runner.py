"""
pipeline/transform/runner.py

The transform runner — the integration keystone that ties the pure transform
modules, the loader, and the consistency checker into a single per-page flow.

Flow (unit of work = one NVD page of up to 2000 CVEs, per design):
    1. Build EPSS + KEV lookups once from their R2 snapshots.
    2. For each NVD page in R2:
         a. bulk-fetch existing cve_enriched rows for change detection
         b. for each CVE:  inclusion -> cvss -> epss -> kev -> cwe -> status
            -> assemble a TransformResult
            -> CveUpserter.upsert(result)        (load + histories)
            -> ConsistencyChecker.evaluate(result)
    3. Emit a per-run consistency summary.

Per-CVE failures are caught and recorded on the TransformResult (so the
consistency checker can flag them) without aborting the page — matching the
"retry/skip/log, recovery handles the gap" policy in the design doc.
"""
from __future__ import annotations

import io
import re
from datetime import date, datetime
from uuid import UUID

import pyarrow.parquet as pq
from sqlalchemy import inspect as sa_inspect

from core.config import settings
from core.exceptions.exceptions import (
    CVSSResolutionError,
    CWEResolutionError,
    EPSSTransformError,
    InclusionFilterError,
    KEVTransformError,
    UpsertError,
)
from db.models import CveEnriched
from pipeline.consistency.checker import ConsistencyChecker
from pipeline.load.history import HistoryWriter
from pipeline.load.upsert import CveUpserter
from pipeline.logs.pipeline_logs import PipelineLogger
from pipeline.r2.client import R2Client
from pipeline.transform import KEVEntry, TransformResult
from pipeline.transform.cvss import CVSSResolver
from pipeline.transform.cwe import CWEResolver
from pipeline.transform.epss import EPSSTransformer
from pipeline.transform.inclusion import InclusionFilter
from pipeline.transform.kev import KEVTransformer
from pipeline.transform.status import StatusTracker

_DATE_IN_KEY = re.compile(r"year=(\d{4})/month=(\d{2})/day=(\d{2})")


def build_r2_client() -> R2Client:
    """Construct an R2Client from settings (dependency-injected boto3 config)."""
    return R2Client(
        bucket_name=settings.R2_BUCKET_NAME,
        endpoint_url=settings.R2_PL_URL,
        access_key_id=settings.R2_EXTRACTOR_KEY,
        secret_access_key=settings.R2_EXTRACTOR_SECRECT_KEY,
    )


class TransformRunner:
    def __init__(self, db, run_id, logger: PipelineLogger | None = None, r2: R2Client | None = None):
        self.db = db
        self.run_id = run_id if isinstance(run_id, UUID) else UUID(str(run_id))
        self.logger = logger or PipelineLogger(db=db, elt_run_id=str(self.run_id))
        self.r2 = r2 or build_r2_client()

        self.inclusion = InclusionFilter()
        self.resolver = CVSSResolver()
        self.epss_t = EPSSTransformer()
        self.kev_t = KEVTransformer()
        self.cwe_r = CWEResolver(db)
        self.status_t = StatusTracker()
        self.history = HistoryWriter(db, self.logger)
        self.upserter = CveUpserter(db, self.logger, self.history)
        self.checker = ConsistencyChecker(db, self.logger)

    # -- public entrypoint ---------------------------------------------------
    def run(
        self,
        nvd_keys: list[str] | None = None,
        epss_key: str | None = None,
        kev_key: str | None = None,
    ) -> dict:
        nvd_keys = nvd_keys or self._discover_latest_nvd_keys()
        epss_key = epss_key or self._latest_key("raw/epss/")
        kev_key = kev_key or self._latest_key("raw/cisa_kev/")

        self._safe_log(
            level="info", source="transform", event_type="transform_started",
            message="Transform run started",
            metadata={"pages": len(nvd_keys), "epss_key": epss_key, "kev_key": kev_key},
        )

        epss_lookup, epss_date = self._build_epss_lookup(epss_key)
        kev_lookup = self._build_kev_lookup(kev_key)

        counts = {"pages": 0, "seen": 0, "included": 0, "skipped": 0, "loaded": 0, "failed": 0}
        for key in nvd_keys:
            self._process_page(
                key, epss_lookup, epss_date, epss_key, kev_lookup, kev_key, counts
            )
            counts["pages"] += 1

        summary = self.checker.run_summary(self.run_id)
        self._safe_log(
            level="info", source="transform", event_type="transform_completed",
            message="Transform run completed",
            metadata={**counts, "consistency": summary},
        )
        return {**counts, "consistency": summary}

    # -- per page ------------------------------------------------------------
    def _process_page(self, key, epss_lookup, epss_date, epss_key, kev_lookup, kev_key, counts):
        records = self._read_parquet(key)
        cve_ids = []
        for wrapper in records:
            cve = self._unwrap(wrapper)
            if cve.get("id"):
                cve_ids.append(cve["id"])
        current_map = self._bulk_current_values(cve_ids)

        for wrapper in records:
            counts["seen"] += 1
            cve = self._unwrap(wrapper)
            cve_id = cve.get("id")
            if not cve_id:
                counts["skipped"] += 1
                continue
            try:
                loaded = self._transform_one(
                    cve_id, cve, wrapper, key, epss_lookup, epss_date, epss_key,
                    kev_lookup, kev_key, current_map.get(cve_id),
                )
                if loaded == "skipped":
                    counts["skipped"] += 1
                else:
                    counts["included"] += 1
                    counts["loaded"] += 1
            except Exception:
                counts["failed"] += 1
                self._safe_log(
                    level="error", source="transform", event_type="transform_cve_failed",
                    message="CVE transform/load failed", cve_id=cve_id,
                )

    # -- per CVE -------------------------------------------------------------
    def _transform_one(
        self, cve_id, cve, wrapper, nvd_key, epss_lookup, epss_date, epss_key,
        kev_lookup, kev_key, current_values,
    ) -> str:
        vuln_status = cve.get("vulnStatus")
        kev_entry = kev_lookup.get(cve_id)

        # 1. inclusion
        try:
            include, skip_reason = self.inclusion.should_include(
                cve_id, vuln_status, is_kev=kev_entry is not None
            )
        except InclusionFilterError:
            return "skipped"
        if not include:
            self._safe_log(
                level="info", source="transform", event_type="transform_cve_skipped",
                message="CVE excluded by inclusion filter", cve_id=cve_id,
                metadata={"reason": skip_reason, "vuln_status": vuln_status},
            )
            return "skipped"

        result = TransformResult(
            cve_id=cve_id, run_id=self.run_id, raw_nvd=wrapper,
            current_values=current_values,
            raw_nvd_s3_key=nvd_key, raw_epss_s3_key=epss_key, raw_kev_s3_key=kev_key,
        )

        # 2. status
        old_status = (current_values or {}).get("vuln_status")
        result.old_status = old_status
        result.new_status = vuln_status
        result.status_changed = self.status_t.detect_change(cve_id, old_status, vuln_status)

        # 3. CVSS
        try:
            result.cvss = self.resolver.resolve(cve_id, cve.get("metrics"))
            if result.cvss is not None and current_values:
                result.cvss_changed = self._cvss_changed(current_values, result.cvss)
        except CVSSResolutionError:
            result.errors.append("CVSSResolutionError")

        # 4. EPSS
        epss_row = epss_lookup.get(cve_id)
        if epss_row is not None:
            row = {**epss_row, "date": epss_date.isoformat()}
            try:
                score, pct, score_date, changed = self.epss_t.apply(
                    cve_id, row,
                    (current_values or {}).get("epss_score"),
                    (current_values or {}).get("epss_score_date"),
                )
                result.epss_score = score
                result.epss_percentile = pct
                result.epss_score_date = score_date
                result.epss_changed = changed
            except EPSSTransformError:
                result.errors.append("EPSSTransformError")

        # 5. KEV
        result.kev_entry = kev_entry
        try:
            result.kev_diff = self.kev_t.diff(cve_id, current_values, kev_entry)
        except KEVTransformError:
            result.errors.append("KEVTransformError")

        # 6. CWE (from NVD weaknesses; cwe_normalized lookup)
        try:
            result.cwe_resolutions = self.cwe_r.resolve(cve_id, cve.get("weaknesses"))
        except CWEResolutionError:
            result.errors.append("CWEResolutionError")

        # 7. load + consistency
        try:
            self.upserter.upsert(result)
        except UpsertError:
            self.checker.evaluate(result)
            raise
        self.checker.evaluate(result)
        return "loaded"

    # -- lookups -------------------------------------------------------------
    def _build_epss_lookup(self, epss_key: str | None) -> tuple[dict, date]:
        if not epss_key:
            return {}, datetime.utcnow().date()
        score_date = self._date_from_key(epss_key)
        lookup: dict[str, dict] = {}
        for r in self._read_parquet(epss_key):
            cve = r.get("cve")
            if cve:
                lookup[cve] = {"cve": cve, "epss": r.get("epss"), "percentile": r.get("percentile")}
        self._safe_log(
            level="info", source="transform", event_type="transform_epss_lookup_built",
            message="EPSS lookup built", metadata={"entries": len(lookup), "score_date": score_date.isoformat()},
        )
        return lookup, score_date

    def _build_kev_lookup(self, kev_key: str | None) -> dict[str, KEVEntry]:
        if not kev_key:
            return {}
        lookup: dict[str, KEVEntry] = {}
        for raw in self._read_parquet(kev_key):
            try:
                entry = self.kev_t.parse_entry(raw)
                lookup[entry.cve_id] = entry
            except KEVTransformError:
                continue
        self._safe_log(
            level="info", source="transform", event_type="transform_kev_lookup_built",
            message="KEV lookup built", metadata={"entries": len(lookup)},
        )
        return lookup

    def _bulk_current_values(self, cve_ids: list[str]) -> dict[str, dict]:
        if not cve_ids:
            return {}
        out: dict[str, dict] = {}
        rows = self.db.query(CveEnriched).filter(CveEnriched.cve_id.in_(cve_ids)).all()
        for row in rows:
            out[row.cve_id] = {
                col.key: getattr(row, col.key)
                for col in sa_inspect(row).mapper.column_attrs
            }
        return out

    # -- helpers -------------------------------------------------------------
    def _cvss_changed(self, current: dict, incoming) -> bool:
        return (
            self._norm(current.get("cvss_score")) != self._norm(incoming.score)
            or current.get("cvss_severity") != incoming.severity
            or current.get("cvss_vector") != incoming.vector
            or current.get("cvss_version") != incoming.version_used
        )

    @staticmethod
    def _norm(value):
        return None if value is None else str(value)

    @staticmethod
    def _unwrap(wrapper: dict) -> dict:
        cve = wrapper.get("cve") if isinstance(wrapper, dict) else None
        return cve if isinstance(cve, dict) else (wrapper or {})

    def _read_parquet(self, key: str) -> list[dict]:
        data = self.r2.read_bytes(key)
        return pq.read_table(io.BytesIO(data)).to_pylist()

    def _discover_latest_nvd_keys(self) -> list[str]:
        keys = self.r2.list_keys("raw/nvd_cves/")
        if not keys:
            return []
        # Prefer this run's own pages (extraction + transform share one EltRun).
        own = [k for k in keys if str(self.run_id) in k]
        if own:
            return own
        # Otherwise fall back to the most-recent run's pages by run_<uuid> token.
        latest_run_token = None
        for key in reversed(keys):
            match = re.search(r"run_([0-9a-f\-]{36})", key)
            if match:
                latest_run_token = match.group(1)
                break
        if latest_run_token is None:
            return keys
        return [k for k in keys if latest_run_token in k]

    def _latest_key(self, prefix: str) -> str | None:
        keys = self.r2.list_keys(prefix)
        return keys[-1] if keys else None

    def _date_from_key(self, key: str) -> date:
        match = _DATE_IN_KEY.search(key)
        if match:
            return date(int(match.group(1)), int(match.group(2)), int(match.group(3)))
        return datetime.utcnow().date()

    def _safe_log(self, **fields) -> None:
        try:
            self.logger.log(**fields)
        except Exception:
            return
