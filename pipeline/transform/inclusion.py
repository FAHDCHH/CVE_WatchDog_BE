import re

from core.exceptions.exceptions import InclusionFilterError

INCLUDED_STATUSES = {"Analyzed", "Modified", "Undergoing Analysis"}
EXCLUDED_STATUSES = {"Rejected", "Deferred", "Received"}
CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")


class InclusionFilter:
    def should_include(
        self, cve_id: str, vuln_status: str, is_kev: bool = False
    ) -> tuple[bool, str | None]:
        if not CVE_ID_RE.match(cve_id):
            raise InclusionFilterError("Invalid CVE ID", cve_id=cve_id)
        if vuln_status in INCLUDED_STATUSES:
            return True, None
        if vuln_status == "Awaiting Analysis":
            return (True, None) if is_kev else (False, "awaiting_analysis_no_kev")
        if vuln_status in EXCLUDED_STATUSES:
            return False, vuln_status.lower().replace(" ", "_")
        return False, "unknown_status"
