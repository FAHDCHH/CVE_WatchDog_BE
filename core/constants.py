LOG_LEVELS: tuple[str, ...] = (
    "debug",
    "info",
    "warn",
    "error",
)

PIPELINE_SOURCES: tuple[str, ...] = (
    "nvd_cves",
    "nvd_changes",
    "epss",
    "cisa_kev",
    "cwe",
    "cwe_fetch",
    "transform",
    "load",
    "consistency",
    "recovery",
    "watchdog",
    "pipeline",
    "system",
)

PIPELINE_EVENT_TYPES: tuple[str, ...] = (
    # --- PIPELINE CONTROL ---
    "pipeline_run_started",
    "pipeline_run_completed",
    "pipeline_run_failed",
    "pipeline_lock_acquired",
    "pipeline_lock_failed",
    "pipeline_run_skipped",
    "pipeline_phase_started",
    "pipeline_phase_completed",
    "pipeline_phase_failed",
    "pipeline_source_unavailable",
    "pipeline_source_recovered",

    # --- EXTRACTION — GENERAL ---
    "extract_page_started",
    "extract_page_success",
    "extract_page_failed",
    "extract_page_retry",
    "extract_page_rate_limited",
    "extract_page_empty",
    "extract_cve_received",
    "extract_cve_excluded",
    "extract_r2_write_success",
    "extract_r2_write_failed",

    # --- EXTRACTION — EPSS ---
    "extract_epss_bulk_started",
    "extract_epss_bulk_success",
    "extract_epss_bulk_failed",
    "extract_epss_incremental_started",
    "extract_epss_incremental_success",
    "extract_epss_incremental_failed",

    # --- EXTRACTION — KEV ---
    "extract_kev_started",
    "extract_kev_success",
    "extract_kev_failed",
    "extract_kev_retry",

    # --- EXTRACTION — CWE ---
    "extract_cwe_triggered",
    "extract_cwe_success",
    "extract_cwe_failed",

    # --- EXTRACTION — CHANGE HISTORY ---
    "extract_change_history_started",
    "extract_change_history_success",
    "extract_change_history_failed",
    "extract_change_history_unrejected",

    # --- TRANSFORM — RUN LEVEL ---
    "transform_started",
    "transform_completed",
    "transform_epss_lookup_built",
    "transform_kev_lookup_built",

    # --- TRANSFORM — CVE CORE ---
    "transform_cve_started",
    "transform_cve_success",
    "transform_cve_failed",
    "transform_cve_skipped",
    "transform_cve_unrejected",
    "transform_page_started",
    "transform_page_completed",
    "transform_page_partial",

    # --- TRANSFORM — CVSS ---
    "transform_cvss_resolved",
    "transform_cvss_fallback_used",
    "transform_cvss_absent",
    "transform_cvss_secondary_used",
    "transform_cvss_score_changed",
    "transform_cvss_severity_changed",
    "transform_cvss_version_upgraded",

    # --- TRANSFORM — EPSS ---
    "transform_epss_joined",
    "transform_epss_absent",
    "transform_epss_skipped",
    "transform_epss_score_changed",
    "transform_epss_surge_detected",

    # --- TRANSFORM — KEV ---
    "transform_kev_matched",
    "transform_kev_new_entry",
    "transform_kev_removed",
    "transform_kev_field_changed",
    "transform_kev_ransomware_escalated",
    "transform_kev_skipped",
    "transform_kev_source_unavailable",

    # --- TRANSFORM — CWE ---
    "transform_cwe_resolved",
    "transform_cwe_partial",
    "transform_cwe_missing",
    "transform_cwe_placeholder_written",
    "transform_cwe_extraction_queued",

    # --- TRANSFORM — STATUS ---
    "transform_status_changed",
    "transform_status_analysis_complete",
    "transform_status_rejected",
    "transform_status_unrejected",

    # --- LOAD ---
    "load_upsert_started",
    "load_upsert_success",
    "load_upsert_failed",
    "load_upsert_no_change",
    "load_history_written",
    "load_history_failed",
    "load_history_transaction_failed",
    "load_is_updated_flagged",
    "load_first_seen_preserved",

    # --- CONSISTENCY ---
    "consistency_check_started",
    "consistency_check_passed",
    "consistency_check_failed",
    "consistency_nvd_ok",
    "consistency_cvss_ok",
    "consistency_epss_ok",
    "consistency_kev_ok",
    "consistency_run_summary",

    # --- RECOVERY ---
    "recovery_run_started",
    "recovery_cve_identified",
    "recovery_path_transform_only",
    "recovery_path_full_extract",
    "recovery_path_consistency_only",
    "recovery_cve_success",
    "recovery_cve_failed",
    "recovery_run_completed",
    "recovery_prioritized",

    # --- WATCHDOG ---
    "watchdog_check_started",
    "watchdog_check_clean",
    "watchdog_stale_run_detected",
    "watchdog_run_marked_crashed",
    "watchdog_alert_sent",
    "watchdog_check_failed",
)
