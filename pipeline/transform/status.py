class StatusTracker:
    def detect_change(self, cve_id: str, old_status: str | None, new_status: str | None) -> bool:
        return old_status is not None and new_status is not None and old_status != new_status

    def is_newly_analyzed(self, old_status: str | None, new_status: str | None) -> bool:
        return new_status == "Analyzed" and old_status != "Analyzed"

    def is_rejection(self, new_status: str | None) -> bool:
        return new_status == "Rejected"

    def is_reinstatement(self, old_status: str | None, new_status: str | None) -> bool:
        return old_status == "Rejected" and new_status is not None and new_status != "Rejected"
