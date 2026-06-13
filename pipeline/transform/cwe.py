import re

from sqlalchemy.orm import Session

from core.exceptions.exceptions import CWEResolutionError
from db.models import CweNormalized
from pipeline.transform import CWEResolution

STANDARD_CWE_RE = re.compile(r"^CWE-\d+$")
SKIPPED_CWE_IDS = {"NVD-CWE-Other", "NVD-CWE-noinfo"}


class CWEResolver:
    def __init__(self, db: Session):
        self.db = db

    def resolve(self, cve_id: str, cwe_entries: list[dict]) -> list[CWEResolution]:
        resolutions: list[CWEResolution] = []
        try:
            for entry in cwe_entries or []:
                cwe_id = self._english_value(entry)
                if cwe_id is None or cwe_id in SKIPPED_CWE_IDS:
                    continue
                if not STANDARD_CWE_RE.match(cwe_id):
                    continue
                row = self.db.get(CweNormalized, cwe_id)
                resolutions.append(
                    CWEResolution(
                        cwe_id=cwe_id,
                        found=row is not None,
                        name=row.name if row is not None else None,
                        source=entry.get("source"),
                        weakness_type=entry.get("type"),
                    )
                )
        except Exception as exc:
            raise CWEResolutionError("CWE resolution failed", cve_id=cve_id) from exc
        return resolutions

    def get_missing_ids(self, resolutions: list[CWEResolution]) -> list[str]:
        return [result.cwe_id for result in resolutions if not result.found]

    def _english_value(self, entry: dict) -> str | None:
        for description in entry.get("description", []) or []:
            if description.get("lang") == "en":
                return description.get("value")
        return None
