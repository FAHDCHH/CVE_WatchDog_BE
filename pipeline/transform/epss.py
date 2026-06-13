from datetime import date
from decimal import Decimal, InvalidOperation

from core.exceptions.exceptions import EPSSTransformError

SURGE_THRESHOLD = Decimal("0.3")
CHANGE_NOISE_THRESHOLD = Decimal("0.001")


class EPSSTransformer:
    def apply(
        self,
        cve_id: str,
        epss_row: dict | None,
        current_score: Decimal | None,
        current_date: date | None,
    ) -> tuple[Decimal | None, Decimal | None, date | None, bool]:
        if epss_row is None:
            return None, None, None, False
        try:
            row_cve = epss_row["cve"]
            if row_cve != cve_id:
                raise EPSSTransformError("EPSS row CVE mismatch", cve_id=cve_id)
            score = Decimal(str(epss_row["epss"]))
            percentile = Decimal(str(epss_row["percentile"]))
            score_date = date.fromisoformat(str(epss_row["date"]))
        except KeyError as exc:
            raise EPSSTransformError("Missing EPSS field", cve_id=cve_id) from exc
        except (InvalidOperation, ValueError) as exc:
            raise EPSSTransformError("Invalid EPSS field", cve_id=cve_id) from exc
        if not Decimal("0") <= score <= Decimal("1"):
            raise EPSSTransformError("EPSS score out of range", cve_id=cve_id)
        if not Decimal("0") <= percentile <= Decimal("1"):
            raise EPSSTransformError("EPSS percentile out of range", cve_id=cve_id)
        changed = self._changed(current_score, current_date, score, score_date)
        return score, percentile, score_date, changed

    def is_surge(self, old_score: Decimal | None, new_score: Decimal | None) -> bool:
        if old_score is None or new_score is None:
            return False
        return new_score - old_score >= SURGE_THRESHOLD

    def _changed(
        self,
        current_score: Decimal | None,
        current_date: date | None,
        incoming_score: Decimal,
        incoming_date: date,
    ) -> bool:
        if current_score is None or current_date is None:
            return True
        if current_date != incoming_date:
            return True
        return abs(incoming_score - current_score) > CHANGE_NOISE_THRESHOLD
