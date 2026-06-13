"""dashboard_api — read-only HTTP query layer over the enriched CVE store.

Strictly separate from the ELT pipeline: the pipeline writes, this API reads.
Shares only db.models and core.config with the rest of the codebase.
"""
