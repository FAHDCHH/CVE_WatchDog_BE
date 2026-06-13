from contextlib import contextmanager
from datetime import date
from decimal import Decimal
from uuid import UUID

from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from core.exceptions.exceptions import HistoryWriteError
from db.models import CveCvssHistory, CveKevHistory, CveStatusHistory, EpssScore
from pipeline.logs.pipeline_logs import PipelineLogger
from pipeline.transform import CVSSResult, KEVDiff


class HistoryWriter:
    def __init__(self, db: Session, logger: PipelineLogger):
        self.db = db
        self.logger = logger

    def write_cvss_history(
        self,
        cve_id: str,
        run_id: UUID,
        old: dict | None,
        new: CVSSResult,
        change_reason: str | None = None,
    ) -> None:
        try:
            with self._transaction():
                self.db.add(
                    CveCvssHistory(
                        cve_id=cve_id,
                        elt_run_id=run_id,
                        old_version=self._old(old, "cvss_version"),
                        new_version=new.version_used,
                        old_vector=self._old(old, "cvss_vector"),
                        new_vector=new.vector,
                        old_score=self._old(old, "cvss_score"),
                        new_score=new.score,
                        old_severity=self._old(old, "cvss_severity"),
                        new_severity=new.severity,
                        old_attack_vector=self._old(old, "attack_vector"),
                        new_attack_vector=new.attack_vector,
                        old_attack_complexity=self._old(old, "attack_complexity"),
                        new_attack_complexity=new.attack_complexity,
                        old_attack_requirements=self._old(old, "attack_requirements"),
                        new_attack_requirements=new.attack_requirements,
                        old_privileges_required=self._old(old, "privileges_required"),
                        new_privileges_required=new.privileges_required,
                        old_user_interaction=self._old(old, "user_interaction"),
                        new_user_interaction=new.user_interaction,
                        old_exploit_maturity=self._old(old, "exploit_maturity"),
                        new_exploit_maturity=new.exploit_maturity,
                        change_reason=change_reason,
                    )
                )
            self._log_written(cve_id, "cve_cvss_history")
        except Exception as exc:
            self._log_transaction_failed(cve_id, "cve_cvss_history", exc)
            raise HistoryWriteError("CVSS history write failed", cve_id=cve_id) from exc

    def write_kev_history(self, cve_id: str, run_id: UUID, diff: KEVDiff) -> None:
        try:
            with self._transaction():
                for field, (old_value, new_value) in diff.changed_fields.items():
                    self.db.add(
                        CveKevHistory(
                            cve_id=cve_id,
                            elt_run_id=run_id,
                            field_changed=field,
                            old_value=old_value,
                            new_value=new_value,
                        )
                    )
            self._log_written(cve_id, "cve_kev_history")
        except Exception as exc:
            self._log_transaction_failed(cve_id, "cve_kev_history", exc)
            raise HistoryWriteError("KEV history write failed", cve_id=cve_id) from exc

    def write_status_history(
        self,
        cve_id: str,
        run_id: UUID,
        old_status: str | None,
        new_status: str,
        event_name: str | None = None,
    ) -> None:
        try:
            with self._transaction():
                self.db.add(
                    CveStatusHistory(
                        cve_id=cve_id,
                        elt_run_id=run_id,
                        old_status=old_status,
                        new_status=new_status,
                        event_name=event_name,
                    )
                )
            self._log_written(cve_id, "cve_status_history")
        except Exception as exc:
            self._log_transaction_failed(cve_id, "cve_status_history", exc)
            raise HistoryWriteError("Status history write failed", cve_id=cve_id) from exc

    def write_epss_snapshot(
        self,
        cve_id: str,
        run_id: UUID,
        epss_score: Decimal,
        percentile: Decimal,
        score_date: date,
        raw_s3_key: str | None = None,
    ) -> None:
        try:
            stmt = pg_insert(EpssScore).values(
                cve_id=cve_id,
                elt_run_id=run_id,
                score_date=score_date,
                epss_score=epss_score,
                percentile=percentile,
                raw_s3_key=raw_s3_key,
            )
            stmt = stmt.on_conflict_do_nothing(
                index_elements=["cve_id", "score_date"]
            )
            with self._transaction():
                result = self.db.execute(stmt)
            if getattr(result, "rowcount", None) == 0:
                self._safe_log(
                    level="info",
                    source="load",
                    event_type="load_upsert_no_change",
                    message="EPSS snapshot already exists",
                    cve_id=cve_id,
                    metadata={"table": "epss_scores", "score_date": str(score_date)},
                )
            else:
                self._log_written(cve_id, "epss_scores")
        except Exception as exc:
            self._log_transaction_failed(cve_id, "epss_scores", exc)
            raise HistoryWriteError("EPSS history write failed", cve_id=cve_id) from exc

    @contextmanager
    def _transaction(self):
        if hasattr(self.db, "in_transaction") and self.db.in_transaction():
            with self.db.begin_nested():
                yield
        else:
            with self.db.begin():
                yield

    def _old(self, old: dict | None, field: str):
        return (old or {}).get(field)

    def _log_written(self, cve_id: str, table: str) -> None:
        self._safe_log(
            level="info",
            source="load",
            event_type="load_history_written",
            message=f"History row written to {table}",
            cve_id=cve_id,
            metadata={"table": table},
        )

    def _log_transaction_failed(self, cve_id: str, table: str, exc: Exception) -> None:
        self._safe_log(
            level="error",
            source="load",
            event_type="load_history_transaction_failed",
            message=f"History write failed for {table}",
            cve_id=cve_id,
            metadata={"table": table, "error_type": exc.__class__.__name__},
        )

    def _safe_log(self, **fields) -> None:
        try:
            self.logger.log(**fields)
        except Exception:
            return
