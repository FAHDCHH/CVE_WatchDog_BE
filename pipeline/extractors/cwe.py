import io
import time
import zipfile
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from uuid import UUID

import httpx
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from core.exceptions.exceptions import CweExtractionError
from db.models import CweNormalized, CweFetchJob, utcnow
from pipeline.logs.pipeline_logs import PipelineLogger
from pipeline.extractors.base import BaseExtractor

MITRE_CWE_URL = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"
CWE_BULK_R2_KEY = "cwe/bulk/cwec_latest.xml"
CWE_XML_NAMESPACE = "http://cwe.mitre.org/cwe-6"


class CweExtractor():
    def __init__(
        self,
        db: Session,
        logger: PipelineLogger,
        r2: object,
        run_id: UUID,
    ):
        self.db = db
        self.logger = logger
        self.r2 = r2
        self.run_id = run_id

    def run_bulk_refresh(self) -> int:
        self.logger.log(
            level="info",
            source="cwe",
            event_type="extract_cwe_triggered",
            message="CWE bulk refresh started",
        )
        xml_bytes = self._download_and_decompress()
        records = self._parse_xml(xml_bytes)
        for record in records:
            stmt = pg_insert(CweNormalized).values(**record)
            stmt = stmt.on_conflict_do_update(
                index_elements=["cwe_id"],
                set_={
                    "name": stmt.excluded.name,
                    "abstraction": stmt.excluded.abstraction,
                    "structure": stmt.excluded.structure,
                    "status": stmt.excluded.status,
                    "description": stmt.excluded.description,
                    "extended_description": stmt.excluded.extended_description,
                    "likelihood_of_exploit": stmt.excluded.likelihood_of_exploit,
                    "raw_data": stmt.excluded.raw_data,
                    "last_refreshed_at": utcnow(),
                },
            )
            self.db.execute(stmt)
        self.db.commit()
        self.r2.write_bytes(CWE_BULK_R2_KEY, xml_bytes)
        self.logger.log(
            level="info",
            source="cwe",
            event_type="extract_cwe_success",
            message=f"CWE bulk refresh complete",
            metadata={"count": len(records)},
        )
        return len(records)

    def process_pending_jobs(self) -> int:
        jobs = self.db.query(CweFetchJob).filter(CweFetchJob.status == "queued").all()
        for job in jobs:
            job.status = "running"
            job.attempts = job.attempts + 1
            self.db.flush()
            cwe = self.db.get(CweNormalized, job.cwe_id)
            if cwe:
                job.status = "success"
                job.completed_at = utcnow()
                self.db.flush()
                self.logger.log(
                    level="info",
                    source="cwe",
                    event_type="extract_cwe_success",
                    message=f"CWE {job.cwe_id} resolved from normalized table",
                )
            else:
                job.status = "failed"
                job.last_error = "not_found_in_mitre_catalog"
                job.completed_at = utcnow()
                self.db.flush()
                self.logger.log(
                    level="warn",
                    source="cwe",
                    event_type="extract_cwe_failed",
                    message=f"CWE {job.cwe_id} not found in MITRE catalog after bulk refresh",
                )
        self.db.commit()
        return len(jobs)

    def _download_and_decompress(self) -> bytes:
        retry_statuses = {429, 500, 502, 503, 504}
        waits = (5, 10, 20)
        response_bytes = None
        for attempt in range(1, 5):
            try:
                response = httpx.get(MITRE_CWE_URL, timeout=60)
                if response.status_code in retry_statuses:
                    if attempt < 4:
                        self.logger.log(
                            level="warn",
                            source="cwe",
                            event_type="extract_cwe_failed",
                            message=f"Attempt {attempt} failed, retrying",
                        )
                        time.sleep(waits[attempt - 1])
                        continue
                    self.logger.log(
                        level="error",
                        source="cwe",
                        event_type="extract_cwe_failed",
                        message="MITRE download failed after 3 attempts",
                    )
                    raise CweExtractionError("MITRE download failed after 3 attempts")
                if response.status_code in {400, 403, 404}:
                    self.logger.log(
                        level="error",
                        source="cwe",
                        event_type="extract_cwe_failed",
                        message="MITRE download failed after 3 attempts",
                    )
                    raise CweExtractionError("MITRE download failed after 3 attempts")
                response.raise_for_status()
                response_bytes = response.content
                break
            except httpx.TimeoutException as exc:
                if attempt < 4:
                    self.logger.log(
                        level="warn",
                        source="cwe",
                        event_type="extract_cwe_failed",
                        message=f"Attempt {attempt} failed, retrying",
                    )
                    time.sleep(waits[attempt - 1])
                    continue
                self.logger.log(
                    level="error",
                    source="cwe",
                    event_type="extract_cwe_failed",
                    message="MITRE download failed after 3 attempts",
                )
                raise CweExtractionError("MITRE download failed after 3 attempts") from exc
            except httpx.HTTPStatusError as exc:
                self.logger.log(
                    level="error",
                    source="cwe",
                    event_type="extract_cwe_failed",
                    message="MITRE download failed after 3 attempts",
                )
                raise CweExtractionError("MITRE download failed after 3 attempts") from exc
        with zipfile.ZipFile(io.BytesIO(response_bytes)) as z:
            xml_files = [name for name in z.namelist() if name.endswith(".xml")]
            if not xml_files:
                raise CweExtractionError("No XML file found in ZIP")
            return z.read(xml_files[0])

    def _parse_xml(self, xml_bytes: bytes) -> list[dict]:
        root = ET.fromstring(xml_bytes)
        namespace = root.tag[1:].split("}", 1)[0] if root.tag.startswith("{") else None
        weaknesses_tag = f"{{{namespace}}}Weaknesses" if namespace else "Weaknesses"
        weakness_tag = f"{{{namespace}}}Weakness" if namespace else "Weakness"
        records = []
        for weaknesses in root.findall(weaknesses_tag):
            for element in weaknesses.findall(weakness_tag):
                try:
                    records.append(
                        {
                            "cwe_id": "CWE-" + element.get("ID"),
                            "name": element.get("Name"),
                            "abstraction": element.get("Abstraction"),
                            "structure": element.get("Structure"),
                            "status": element.get("Status"),
                            "description": self._extract_text(element, "Description"),
                            "extended_description": self._extract_text(element, "Extended_Description"),
                            "likelihood_of_exploit": self._extract_text(element, "Likelihood_Of_Exploit"),
                            "raw_data": self._element_to_dict(element),
                        }
                    )
                except Exception:
                    continue
        return records

    def _extract_text(self, element, tag: str) -> str | None:
        namespace = element.tag[1:].split("}", 1)[0] if element.tag.startswith("{") else None
        child_tag = f"{{{namespace}}}{tag}" if namespace else tag
        child = element.find(child_tag)
        if child is None or child.text is None:
            return None
        return " ".join(child.text.split())

    def _element_to_dict(self, element) -> dict:
        return {
            "tag": element.tag,
            "attrib": dict(element.attrib),
            "children": [
                {"tag": child.tag, "attrib": dict(child.attrib), "text": child.text}
                for child in element
            ],
        }
