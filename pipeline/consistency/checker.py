from uuid import UUID

from sqlalchemy import case, func
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from core.exceptions.exceptions import ConsistencyError
from db.models import CveConsistency
from pipeline.logs.pipeline_logs import PipelineLogger
from pipeline.transform import ConsistencyResult, TransformResult


class ConsistencyChecker:
    def __init__(self, db: Session, logger: PipelineLogger):
        self.db = db
        self.logger = logger

    def evaluate(self, result: TransformResult) -> ConsistencyResult:
        nvd_ok = result.raw_nvd is not None and result.new_status is not None
        cvss_resolved = result.cvss is not None or result.new_status in {
            "Awaiting Analysis",
            "Undergoing Analysis",
        }
        epss_ok = "EPSSTransformError" not in result.errors
        kev_ok = "KEVTransformError" not in result.errors
        flags = {
            "nvd_ok": nvd_ok,
            "cvss_resolved": cvss_resolved,
            "epss_ok": epss_ok,
            "kev_ok": kev_ok,
        }
        failure_detail = {
            "failed_flags": [key for key, value in flags.items() if not value],
            "errors": result.errors,
        }
        overall_ok = all(flags.values())
        consistency = ConsistencyResult(
            cve_id=result.cve_id,
            run_id=result.run_id,
            nvd_ok=nvd_ok,
            cvss_resolved=cvss_resolved,
            epss_ok=epss_ok,
            kev_ok=kev_ok,
            overall_ok=overall_ok,
            failure_detail=failure_detail,
        )
        try:
            stmt = pg_insert(CveConsistency).values(
                cve_id=result.cve_id,
                elt_run_id=result.run_id,
                nvd_ok=nvd_ok,
                cvss_resolved=cvss_resolved,
                epss_ok=epss_ok,
                kev_ok=kev_ok,
                failure_detail=failure_detail,
            )
            stmt = stmt.on_conflict_do_update(
                index_elements=["cve_id", "elt_run_id"],
                set_={
                    "nvd_ok": nvd_ok,
                    "cvss_resolved": cvss_resolved,
                    "epss_ok": epss_ok,
                    "kev_ok": kev_ok,
                    "failure_detail": failure_detail,
                },
            )
            self.db.execute(stmt)
            self.db.commit()
        except Exception as exc:
            self.db.rollback()
            raise ConsistencyError("Consistency upsert failed", cve_id=result.cve_id) from exc
        self._safe_log(
            level="info" if overall_ok else "warn",
            source="consistency",
            event_type="consistency_check_passed" if overall_ok else "consistency_check_failed",
            message="Consistency check passed" if overall_ok else "Consistency check failed",
            cve_id=result.cve_id,
            metadata=failure_detail,
        )
        return consistency

    def run_summary(self, run_id: UUID) -> dict:
        total = func.count(CveConsistency.cve_id)
        passed = func.sum(case((CveConsistency.overall_ok.is_(True), 1), else_=0))
        failed_nvd = func.sum(case((CveConsistency.nvd_ok.is_(False), 1), else_=0))
        failed_cvss = func.sum(case((CveConsistency.cvss_resolved.is_(False), 1), else_=0))
        failed_epss = func.sum(case((CveConsistency.epss_ok.is_(False), 1), else_=0))
        failed_kev = func.sum(case((CveConsistency.kev_ok.is_(False), 1), else_=0))
        row = (
            self.db.query(total, passed, failed_nvd, failed_cvss, failed_epss, failed_kev)
            .filter(CveConsistency.elt_run_id == run_id)
            .one()
        )
        summary = {
            "total": row[0] or 0,
            "passed": row[1] or 0,
            "failed": (row[0] or 0) - (row[1] or 0),
            "failed_nvd": row[2] or 0,
            "failed_cvss": row[3] or 0,
            "failed_epss": row[4] or 0,
            "failed_kev": row[5] or 0,
        }
        self._safe_log(
            level="info",
            source="consistency",
            event_type="consistency_run_summary",
            message="Consistency run summary",
            metadata={"run_id": str(run_id), **summary},
        )
        return summary

    def _safe_log(self, **fields) -> None:
        try:
            self.logger.log(**fields)
        except Exception:
            return
