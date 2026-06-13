from datetime import date, datetime
from decimal import Decimal

from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from core.exceptions.exceptions import HistoryWriteError, UpsertError
from db.models import CveEnriched, CweFetchJob, CveWeakness, utcnow
from pipeline.load.history import HistoryWriter
from pipeline.logs.pipeline_logs import PipelineLogger
from pipeline.transform import CWEResolution, KEVEntry, TransformResult

MEANINGFUL_FIELDS = {
    "cvss_score",
    "cvss_severity",
    "cvss_vector",
    "exploit_maturity",
    "epss_score",
    "epss_percentile",
    "is_kev",
    "ransomware_known",
    "vuln_status",
}
NEVER_UPDATE_FIELDS = {"cve_id", "first_seen_at"}


class CveUpserter:
    def __init__(
        self,
        db: Session,
        logger: PipelineLogger,
        history_writer: HistoryWriter,
    ):
        self.db = db
        self.logger = logger
        self.history_writer = history_writer

    def upsert(self, result: TransformResult) -> bool:
        self._safe_log(
            level="info",
            source="load",
            event_type="load_upsert_started",
            message="CVE upsert started",
            cve_id=result.cve_id,
        )
        try:
            insert_dict = self._build_insert_dict(result)
            self._write_histories(result)
            result.is_updated = self._detect_is_updated(
                result.current_values, insert_dict
            )
            insert_dict["is_updated"] = result.is_updated
            stmt = pg_insert(CveEnriched).values(**insert_dict)
            update_dict = {
                key: value
                for key, value in insert_dict.items()
                if key not in NEVER_UPDATE_FIELDS
            }
            stmt = stmt.on_conflict_do_update(
                index_elements=["cve_id"],
                set_=update_dict,
            )
            with self._transaction():
                self.db.execute(stmt)
                self._upsert_weaknesses(result.cve_id, result.cwe_resolutions)
                self._queue_missing_cwes(result)
            if result.is_updated:
                self._safe_log(
                    level="info",
                    source="load",
                    event_type="load_is_updated_flagged",
                    message="Meaningful CVE fields changed",
                    cve_id=result.cve_id,
                )
            self._safe_log(
                level="info",
                source="load",
                event_type="load_first_seen_preserved",
                message="first_seen_at excluded from upsert update set",
                cve_id=result.cve_id,
            )
            self._safe_log(
                level="info",
                source="load",
                event_type="load_upsert_success",
                message="CVE upsert completed",
                cve_id=result.cve_id,
            )
            return True
        except Exception as exc:
            self.db.rollback()
            self._safe_log(
                level="error",
                source="load",
                event_type="load_upsert_failed",
                message="CVE upsert failed",
                cve_id=result.cve_id,
                metadata={"error_type": exc.__class__.__name__},
            )
            raise UpsertError("CVE upsert failed", cve_id=result.cve_id) from exc

    def _build_insert_dict(self, result: TransformResult) -> dict:
        raw = self._raw_cve(result.raw_nvd)
        insert_dict = {
            "cve_id": result.cve_id,
            "source_identifier": raw.get("sourceIdentifier"),
            "published_at": self._parse_datetime(raw.get("published")),
            "last_modified_at": self._parse_datetime(raw.get("lastModified")),
            "vuln_status": result.new_status or raw.get("vulnStatus"),
            "description_en": self._english_description(raw.get("descriptions")),
            "descriptions": raw.get("descriptions"),
            "evaluator_comment": raw.get("evaluatorComment"),
            "evaluator_impact": raw.get("evaluatorImpact"),
            "evaluator_solution": raw.get("evaluatorSolution"),
            "configurations": raw.get("configurations"),
            "references": raw.get("references"),
            "vendor_comments": raw.get("vendorComments"),
            "nvd_cisa_exploit_add": self._parse_date(raw.get("cisaExploitAdd")),
            "nvd_cisa_action_due": self._parse_date(raw.get("cisaActionDue")),
            "nvd_cisa_required_action": raw.get("cisaRequiredAction"),
            "nvd_cisa_vulnerability_name": raw.get("cisaVulnerabilityName"),
            "epss_score": result.epss_score,
            "epss_percentile": result.epss_percentile,
            "epss_score_date": result.epss_score_date,
            "raw_nvd_s3_key": result.raw_nvd_s3_key,
            "raw_epss_s3_key": result.raw_epss_s3_key,
            "raw_kev_s3_key": result.raw_kev_s3_key,
            "last_transform_run_id": result.run_id,
            "last_seen_at": utcnow(),
            "updated_at": utcnow(),
        }
        insert_dict.update(self._cvss_fields(result))
        insert_dict.update(self._kev_fields(result))
        insert_dict.update(self._cwe_fields(result.cwe_resolutions))
        if "first_seen_at" in insert_dict:
            raise UpsertError("first_seen_at must not be set by upsert", cve_id=result.cve_id)
        return insert_dict

    def _write_histories(self, result: TransformResult) -> None:
        history_calls = []
        if result.cvss_changed and result.cvss is not None:
            history_calls.append(
                lambda: self.history_writer.write_cvss_history(
                    result.cve_id,
                    result.run_id,
                    result.current_values,
                    result.cvss,
                    change_reason="transform_detected_change",
                )
            )
        if result.kev_diff is not None:
            history_calls.append(
                lambda: self.history_writer.write_kev_history(
                    result.cve_id, result.run_id, result.kev_diff
                )
            )
        if result.status_changed and result.new_status is not None:
            history_calls.append(
                lambda: self.history_writer.write_status_history(
                    result.cve_id,
                    result.run_id,
                    result.old_status,
                    result.new_status,
                )
            )
        if (
            result.epss_score is not None
            and result.epss_percentile is not None
            and result.epss_score_date is not None
        ):
            history_calls.append(
                lambda: self.history_writer.write_epss_snapshot(
                    result.cve_id,
                    result.run_id,
                    result.epss_score,
                    result.epss_percentile,
                    result.epss_score_date,
                    raw_s3_key=result.raw_epss_s3_key,
                )
            )
        for call in history_calls:
            try:
                call()
            except HistoryWriteError as exc:
                result.errors.append(exc.__class__.__name__)
                self._safe_log(
                    level="error",
                    source="load",
                    event_type="load_history_failed",
                    message="History write failed; continuing upsert",
                    cve_id=result.cve_id,
                    metadata={"error_type": exc.__class__.__name__},
                )

    def _detect_is_updated(self, current: dict | None, incoming: dict) -> bool:
        if not current:
            return True
        for field in MEANINGFUL_FIELDS:
            if self._normalize(current.get(field)) != self._normalize(incoming.get(field)):
                return True
        return False

    def _cvss_fields(self, result: TransformResult) -> dict:
        cvss = result.cvss
        if cvss is None:
            return {
                "cvss_source": None,
                "cvss_type": None,
                "cvss_version": None,
                "cvss_vector": None,
                "cvss_score": None,
                "cvss_severity": None,
                "exploitability_score": None,
                "impact_score": None,
                "exploit_maturity": None,
                "attack_vector": None,
                "attack_complexity": None,
                "attack_requirements": None,
                "privileges_required": None,
                "user_interaction": None,
                "vulnerable_confidentiality": None,
                "vulnerable_integrity": None,
                "vulnerable_availability": None,
                "subsequent_confidentiality": None,
                "subsequent_integrity": None,
                "subsequent_availability": None,
                "automatable": None,
                "safety": None,
                "recovery": None,
                "value_density": None,
                "vulnerability_response_effort": None,
                "provider_urgency": None,
            }
        return {
            "cvss_source": cvss.source,
            "cvss_type": cvss.cvss_type,
            "cvss_version": cvss.version_used,
            "cvss_vector": cvss.vector,
            "cvss_score": cvss.score,
            "cvss_severity": cvss.severity,
            "exploitability_score": cvss.exploitability_score,
            "impact_score": cvss.impact_score,
            "exploit_maturity": cvss.exploit_maturity,
            "attack_vector": cvss.attack_vector,
            "attack_complexity": cvss.attack_complexity,
            "attack_requirements": cvss.attack_requirements,
            "privileges_required": cvss.privileges_required,
            "user_interaction": cvss.user_interaction,
            "vulnerable_confidentiality": cvss.vulnerable_confidentiality,
            "vulnerable_integrity": cvss.vulnerable_integrity,
            "vulnerable_availability": cvss.vulnerable_availability,
            "subsequent_confidentiality": cvss.subsequent_confidentiality,
            "subsequent_integrity": cvss.subsequent_integrity,
            "subsequent_availability": cvss.subsequent_availability,
            "automatable": cvss.automatable,
            "safety": cvss.safety,
            "recovery": cvss.recovery,
            "value_density": cvss.value_density,
            "vulnerability_response_effort": cvss.vulnerability_response_effort,
            "provider_urgency": cvss.provider_urgency,
        }

    def _kev_fields(self, result: TransformResult) -> dict:
        if result.kev_diff is not None and result.kev_diff.change_type == "removed":
            return self._empty_kev_fields(is_kev=False)
        if result.kev_entry is None:
            if result.current_values:
                return {"is_kev": bool(result.current_values.get("is_kev"))}
            return self._empty_kev_fields(is_kev=False)
        entry = result.kev_entry
        return {
            "is_kev": True,
            "kev_vendor_project": entry.vendor_project,
            "kev_product": entry.product,
            "kev_vulnerability_name": entry.vulnerability_name,
            "kev_date_added": entry.date_added,
            "kev_due_date": entry.due_date,
            "kev_required_action": entry.required_action,
            "kev_short_description": entry.short_description,
            "kev_notes": entry.notes,
            "ransomware_known": entry.ransomware_known,
            "kev_cwes": entry.cwes,
        }

    def _empty_kev_fields(self, is_kev: bool) -> dict:
        return {
            "is_kev": is_kev,
            "kev_vendor_project": None,
            "kev_product": None,
            "kev_vulnerability_name": None,
            "kev_date_added": None,
            "kev_due_date": None,
            "kev_required_action": None,
            "kev_short_description": None,
            "kev_notes": None,
            "ransomware_known": None,
            "kev_cwes": None,
        }

    def _cwe_fields(self, resolutions: list[CWEResolution]) -> dict:
        found = [resolution for resolution in resolutions if resolution.found]
        return {
            "cwe_ids": [resolution.cwe_id for resolution in resolutions] or None,
            "cwe_names": [resolution.name for resolution in found if resolution.name] or None,
        }

    def _upsert_weaknesses(
        self, cve_id: str, resolutions: list[CWEResolution]
    ) -> None:
        for resolution in resolutions:
            if not resolution.found:
                continue
            stmt = pg_insert(CveWeakness).values(
                cve_id=cve_id,
                cwe_id=resolution.cwe_id,
                source=resolution.source,
                type=resolution.weakness_type,
            )
            stmt = stmt.on_conflict_do_update(
                index_elements=["cve_id", "cwe_id"],
                set_={"source": resolution.source, "type": resolution.weakness_type},
            )
            self.db.execute(stmt)

    def _queue_missing_cwes(self, result: TransformResult) -> None:
        for resolution in result.cwe_resolutions:
            if resolution.found:
                continue
            stmt = pg_insert(CweFetchJob).values(
                cwe_id=resolution.cwe_id,
                requested_by_run_id=result.run_id,
                status="queued",
            )
            stmt = stmt.on_conflict_do_nothing(index_elements=["cwe_id", "status"])
            self.db.execute(stmt)

    def _raw_cve(self, raw_nvd: dict | None) -> dict:
        if not raw_nvd:
            return {}
        cve = raw_nvd.get("cve")
        return cve if isinstance(cve, dict) else raw_nvd

    def _english_description(self, descriptions: list[dict] | None) -> str | None:
        for description in descriptions or []:
            if description.get("lang") == "en":
                return description.get("value")
        return None

    def _parse_datetime(self, value: object) -> datetime | None:
        if value is None:
            return None
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))

    def _parse_date(self, value: object) -> date | None:
        if value is None:
            return None
        return date.fromisoformat(str(value)[:10])

    def _normalize(self, value: object) -> str | None:
        if value is None:
            return None
        if isinstance(value, Decimal):
            return str(value.normalize())
        return str(value)

    def _transaction(self):
        if hasattr(self.db, "in_transaction") and self.db.in_transaction():
            return self.db.begin_nested()
        return self.db.begin()

    def _safe_log(self, **fields) -> None:
        try:
            self.logger.log(**fields)
        except Exception:
            return
