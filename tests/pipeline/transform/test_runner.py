"""Unit test for the TransformRunner keystone — no DB, no network.

Verifies the per-page orchestration: inclusion -> skip vs load, that the
upserter is called once per included CVE, and that the run summary counts
are assembled correctly. R2 and the DB session are fully mocked.
"""
import io
import os
from unittest import TestCase
from unittest.mock import MagicMock, patch
from uuid import uuid4

import pyarrow as pa
import pyarrow.parquet as pq

os.environ.setdefault("NVD_API_KEY", "test")
os.environ.setdefault("DATABASE_URL", "postgresql://user:pass@localhost/db")
os.environ.setdefault("R2_EXTRACTOR_KEY", "test")
os.environ.setdefault("R2_EXTRACTOR_SECRECT_KEY", "test")
os.environ.setdefault("R2_PL_URL", "https://r2.example.test")
os.environ.setdefault("R2_BUCKET_NAME", "test")

from pipeline.transform.runner import TransformRunner


def _nvd_parquet_bytes(records: list[dict]) -> bytes:
    table = pa.Table.from_pylist(records)
    buf = io.BytesIO()
    pq.write_table(table, buf)
    return buf.getvalue()


class TransformRunnerTests(TestCase):
    def setUp(self):
        self.run_id = uuid4()
        self.db = MagicMock()
        # No existing rows -> current_values is empty for all CVEs.
        self.db.query.return_value.filter.return_value.all.return_value = []
        self.r2 = MagicMock()
        self.r2.list_keys.return_value = []
        self.logger = MagicMock()

    def _runner(self) -> TransformRunner:
        return TransformRunner(self.db, self.run_id, logger=self.logger, r2=self.r2)

    def test_included_cve_is_upserted_and_counted(self):
        nvd_page = _nvd_parquet_bytes([
            {"cve": {"id": "CVE-2026-0001", "vulnStatus": "Analyzed",
                     "metrics": None, "weaknesses": None}},
            {"cve": {"id": "CVE-2026-0002", "vulnStatus": "Rejected",
                     "metrics": None, "weaknesses": None}},
        ])
        # epss/kev empty parquet snapshots.
        empty = _nvd_parquet_bytes([{"cve": "CVE-X", "epss": 0.0, "percentile": 0.0}])

        def read_bytes(key):
            if "nvd" in key:
                return nvd_page
            return empty

        self.r2.read_bytes.side_effect = read_bytes

        runner = self._runner()
        runner.upserter = MagicMock()
        runner.checker = MagicMock()
        runner.checker.run_summary.return_value = {"ok": True}

        summary = runner.run(
            nvd_keys=["raw/nvd_cves/run_x/page.parquet"],
            epss_key="raw/epss/year=2026/month=06/day=12/epss.parquet",
            kev_key="raw/cisa_kev/kev.parquet",
        )

        self.assertEqual(summary["seen"], 2)
        self.assertEqual(summary["included"], 1)   # Analyzed
        self.assertEqual(summary["skipped"], 1)    # Rejected
        self.assertEqual(summary["loaded"], 1)
        self.assertEqual(summary["failed"], 0)
        self.assertEqual(runner.upserter.upsert.call_count, 1)
        self.assertEqual(runner.checker.evaluate.call_count, 1)

    def test_upsert_failure_is_counted_not_fatal(self):
        nvd_page = _nvd_parquet_bytes([
            {"cve": {"id": "CVE-2026-0001", "vulnStatus": "Analyzed",
                     "metrics": None, "weaknesses": None}},
        ])
        self.r2.read_bytes.return_value = nvd_page

        runner = self._runner()
        runner.upserter = MagicMock()
        runner.upserter.upsert.side_effect = RuntimeError("db down")
        runner.checker = MagicMock()
        runner.checker.run_summary.return_value = {}

        summary = runner.run(nvd_keys=["raw/nvd_cves/run_x/page.parquet"],
                             epss_key=None, kev_key=None)

        self.assertEqual(summary["failed"], 1)
        self.assertEqual(summary["loaded"], 0)
