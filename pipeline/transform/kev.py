from datetime import date

from core.exceptions.exceptions import KEVTransformError
from pipeline.transform import KEVDiff, KEVEntry

KEV_DIFFABLE_FIELDS: dict[str, str] = {
    "vendor_project": "kev_vendor_project",
    "product": "kev_product",
    "vulnerability_name": "kev_vulnerability_name",
    "date_added": "kev_date_added",
    "due_date": "kev_due_date",
    "required_action": "kev_required_action",
    "short_description": "kev_short_description",
    "ransomware_known": "ransomware_known",
    "notes": "kev_notes",
    "cwes": "kev_cwes",
}


class KEVTransformer:
    def parse_entry(self, raw_entry: dict) -> KEVEntry:
        cve_id = self._clean(raw_entry.get("cveID"))
        if not cve_id:
            raise KEVTransformError("Missing KEV cveID")
        return KEVEntry(
            cve_id=cve_id,
            vendor_project=self._clean(raw_entry.get("vendorProject")),
            product=self._clean(raw_entry.get("product")),
            vulnerability_name=self._clean(raw_entry.get("vulnerabilityName")),
            date_added=self._parse_date(raw_entry.get("dateAdded"), cve_id),
            due_date=self._parse_date(raw_entry.get("dueDate"), cve_id),
            required_action=self._clean(raw_entry.get("requiredAction")),
            short_description=self._clean(raw_entry.get("shortDescription")),
            ransomware_known=self._clean(raw_entry.get("knownRansomwareCampaignUse")),
            notes=self._clean(raw_entry.get("notes")),
            cwes=list(raw_entry.get("cwes") or []),
        )

    def diff(
        self,
        cve_id: str,
        current_row: dict | None,
        incoming: KEVEntry | None,
    ) -> KEVDiff | None:
        current_is_kev = bool((current_row or {}).get("is_kev"))
        if incoming is None and current_is_kev:
            return KEVDiff(cve_id, "removed", {"is_kev": ("true", "false")}, None)
        if incoming is None:
            return None
        if not current_is_kev:
            return KEVDiff(cve_id, "new", {"is_kev": ("false", "true")}, incoming)

        changed_fields = {}
        for entry_field, db_field in KEV_DIFFABLE_FIELDS.items():
            old_value = (current_row or {}).get(db_field)
            new_value = getattr(incoming, entry_field)
            if self._stringify(old_value) != self._stringify(new_value):
                changed_fields[db_field] = (
                    self._stringify(old_value),
                    self._stringify(new_value),
                )
        if not changed_fields:
            return None
        return KEVDiff(cve_id, "changed", changed_fields, incoming)

    def is_ransomware_escalation(self, diff: KEVDiff | None) -> bool:
        if diff is None:
            return False
        values = diff.changed_fields.get("ransomware_known")
        return values is not None and values[1] == "Known"

    def _clean(self, value: object) -> str | None:
        if value is None:
            return None
        cleaned = str(value).strip()
        return cleaned or None

    def _parse_date(self, value: object, cve_id: str) -> date | None:
        cleaned = self._clean(value)
        if cleaned is None:
            return None
        try:
            return date.fromisoformat(cleaned)
        except ValueError as exc:
            raise KEVTransformError("Invalid KEV date", cve_id=cve_id) from exc

    def _stringify(self, value: object) -> str | None:
        if value is None:
            return None
        if isinstance(value, list):
            return ",".join(str(item) for item in value)
        return str(value)
