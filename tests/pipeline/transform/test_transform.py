"""Pure unit tests for the transform layer (no DB, no network)."""
import os
from datetime import date
from decimal import Decimal
from unittest import TestCase

os.environ.setdefault("NVD_API_KEY", "test")
os.environ.setdefault("DATABASE_URL", "postgresql://user:pass@localhost/db")
os.environ.setdefault("R2_EXTRACTOR_KEY", "test")
os.environ.setdefault("R2_EXTRACTOR_SECRECT_KEY", "test")
os.environ.setdefault("R2_PL_URL", "https://r2.example.test")
os.environ.setdefault("R2_BUCKET_NAME", "test")

from core.exceptions.exceptions import EPSSTransformError, InclusionFilterError
from pipeline.transform.cvss import CVSSResolver
from pipeline.transform.epss import EPSSTransformer
from pipeline.transform.inclusion import InclusionFilter
from pipeline.transform.kev import KEVTransformer


def _metric(version_key, base_score, severity, mtype="Primary"):
    data = {"vectorString": f"VECTOR/{version_key}", "baseScore": base_score}
    if version_key == "cvssMetricV2":
        return {"type": mtype, "source": "nvd@nist.gov", "baseSeverity": severity,
                "cvssData": {**data, "accessVector": "NETWORK"}}
    data["baseSeverity"] = severity
    return {"type": mtype, "source": "nvd@nist.gov", "cvssData": data}


class CVSSResolverTests(TestCase):
    def setUp(self):
        self.r = CVSSResolver()

    def test_returns_none_when_no_metrics(self):
        self.assertIsNone(self.r.resolve("CVE-x", None))
        self.assertIsNone(self.r.resolve("CVE-x", {}))

    def test_v4_preferred_over_v31_and_v2(self):
        metrics = {
            "cvssMetricV40": [_metric("cvssMetricV40", 9.8, "CRITICAL")],
            "cvssMetricV31": [_metric("cvssMetricV31", 7.5, "HIGH")],
            "cvssMetricV2": [_metric("cvssMetricV2", 5.0, "MEDIUM")],
        }
        result = self.r.resolve("CVE-x", metrics)
        self.assertEqual(result.version_used, "4.0")
        self.assertEqual(result.score, Decimal("9.8"))

    def test_v2_fallback_when_only_v2_present(self):
        metrics = {"cvssMetricV2": [_metric("cvssMetricV2", 7.5, "HIGH")]}
        result = self.r.resolve("CVE-x", metrics)
        self.assertEqual(result.version_used, "2.0")
        self.assertEqual(result.score, Decimal("7.5"))
        self.assertEqual(result.severity, "HIGH")
        self.assertEqual(result.attack_vector, "NETWORK")

    def test_score_ten_is_preserved(self):
        metrics = {"cvssMetricV31": [_metric("cvssMetricV31", 10.0, "CRITICAL")]}
        result = self.r.resolve("CVE-x", metrics)
        self.assertEqual(result.score, Decimal("10.0"))

    def test_primary_entry_preferred_over_secondary(self):
        metrics = {"cvssMetricV31": [
            _metric("cvssMetricV31", 4.0, "MEDIUM", mtype="Secondary"),
            _metric("cvssMetricV31", 8.8, "HIGH", mtype="Primary"),
        ]}
        result = self.r.resolve("CVE-x", metrics)
        self.assertEqual(result.score, Decimal("8.8"))


class InclusionFilterTests(TestCase):
    def setUp(self):
        self.f = InclusionFilter()

    def test_analyzed_included(self):
        self.assertEqual(self.f.should_include("CVE-2026-0001", "Analyzed"), (True, None))

    def test_rejected_excluded(self):
        include, reason = self.f.should_include("CVE-2026-0001", "Rejected")
        self.assertFalse(include)
        self.assertEqual(reason, "rejected")

    def test_invalid_cve_id_raises(self):
        with self.assertRaises(InclusionFilterError):
            self.f.should_include("NOT-A-CVE", "Analyzed")

    def test_awaiting_analysis_included_only_if_kev(self):
        self.assertEqual(
            self.f.should_include("CVE-2026-0001", "Awaiting Analysis", is_kev=True),
            (True, None),
        )
        include, _ = self.f.should_include("CVE-2026-0001", "Awaiting Analysis", is_kev=False)
        self.assertFalse(include)


class EPSSTransformerTests(TestCase):
    def setUp(self):
        self.t = EPSSTransformer()

    def _row(self, score=0.5, pct=0.9):
        return {"cve": "CVE-2026-0001", "epss": score, "percentile": pct, "date": "2026-06-12"}

    def test_valid_row_parsed(self):
        score, pct, d, changed = self.t.apply("CVE-2026-0001", self._row(), None, None)
        self.assertEqual(score, Decimal("0.5"))
        self.assertEqual(pct, Decimal("0.9"))
        self.assertEqual(d, date(2026, 6, 12))
        self.assertTrue(changed)

    def test_none_row_returns_empty(self):
        self.assertEqual(self.t.apply("CVE-x", None, None, None), (None, None, None, False))

    def test_out_of_range_score_raises(self):
        with self.assertRaises(EPSSTransformError):
            self.t.apply("CVE-2026-0001", self._row(score=1.5), None, None)

    def test_cve_mismatch_raises(self):
        row = self._row()
        with self.assertRaises(EPSSTransformError):
            self.t.apply("CVE-2026-9999", row, None, None)

    def test_surge_detection(self):
        self.assertTrue(self.t.is_surge(Decimal("0.1"), Decimal("0.5")))
        self.assertFalse(self.t.is_surge(Decimal("0.1"), Decimal("0.2")))


class KEVTransformerTests(TestCase):
    def setUp(self):
        self.t = KEVTransformer()

    def _raw(self):
        return {"cveID": "CVE-2026-0001", "vendorProject": "Acme", "product": "Widget",
                "vulnerabilityName": "RCE", "dateAdded": "2026-06-01", "dueDate": "2026-06-21",
                "requiredAction": "Patch", "shortDescription": "bad", "knownRansomwareCampaignUse": "Known",
                "notes": "", "cwes": ["CWE-79"]}

    def test_parse_entry(self):
        entry = self.t.parse_entry(self._raw())
        self.assertEqual(entry.cve_id, "CVE-2026-0001")
        self.assertEqual(entry.date_added, date(2026, 6, 1))
        self.assertEqual(entry.ransomware_known, "Known")
        self.assertEqual(entry.cwes, ["CWE-79"])

    def test_diff_new_entry(self):
        entry = self.t.parse_entry(self._raw())
        diff = self.t.diff("CVE-2026-0001", {"is_kev": False}, entry)
        self.assertEqual(diff.change_type, "new")

    def test_diff_removed(self):
        diff = self.t.diff("CVE-2026-0001", {"is_kev": True}, None)
        self.assertEqual(diff.change_type, "removed")

    def test_diff_no_change_returns_none(self):
        diff = self.t.diff("CVE-2026-0001", None, None)
        self.assertIsNone(diff)
