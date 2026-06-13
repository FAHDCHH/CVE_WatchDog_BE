import gzip
import os
from datetime import datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import Mock, patch

import httpx

os.environ.setdefault("NVD_API_KEY", "test")
os.environ.setdefault("DATABASE_URL", "postgresql://user:pass@localhost/db")
os.environ.setdefault("R2_EXTRACTOR_KEY", "test")
os.environ.setdefault("R2_EXTRACTOR_SECRECT_KEY", "test")
os.environ.setdefault("R2_PL_URL", "https://r2.example.test")
os.environ.setdefault("R2_BUCKET_NAME", "test")

from core.exceptions.exceptions import (
    ExtractionError,
    RateLimitError,
    URLNotAllowedError,
)
from core.security import is_allowed_url, sanitize_headers
from pipeline.extractors.cisa_kev import CISA_KEVExtractor
from pipeline.extractors.epss import EPSSextractor
from pipeline.extractors.nvd_changes import NVD_Changes_Extractor
from pipeline.extractors.nvd_cves import NVDCVEsExtractor


class ExtractorTests(TestCase):
    def test_nvd_cves_bulk_fetches_critical_high_and_kev_pages(self) -> None:
        extractor = NVDCVEsExtractor("run-1", mode="bulk_load")
        response = httpx.Response(
            200,
            json={
                "vulnerabilities": [{"cve": {"id": "CVE-2026-0001"}}],
                "totalResults": 1,
            },
        )
        extractor._request = Mock(return_value=response)
        extractor._store = Mock()

        extractor.fetch()

        urls = [call.args[0] for call in extractor._request.call_args_list]
        stored_keys = [call.args[1] for call in extractor._store.call_args_list]

        self.assertEqual(len(urls), 3)
        self.assertIn("cvssV3Severity=CRITICAL", urls[0])
        self.assertIn("cvssV3Severity=HIGH", urls[1])
        self.assertIn("hasKev=", urls[2])
        self.assertTrue(any("bulk_critical_page_001" in key for key in stored_keys))
        self.assertTrue(any("bulk_high_page_001" in key for key in stored_keys))
        self.assertTrue(any("bulk_kev_page_001" in key for key in stored_keys))

    def test_nvd_delta_params_use_last_modified_window(self) -> None:
        extractor = NVDCVEsExtractor("run-1", mode="delta_poll", db=object())

        params = extractor._build_params(start_date="2026-06-12T00:00:00.000Z")

        self.assertEqual(params["lastModStartDate"], "2026-06-12T00:00:00.000Z")
        self.assertIn("lastModEndDate", params)

    def test_nvd_changes_uses_change_history_window(self) -> None:
        extractor = NVD_Changes_Extractor("run-1", mode="bulk_load")

        params = extractor._build_params("2026-06-12T00:00:00.000Z")

        self.assertEqual(params["changeStartDate"], "2026-06-12T00:00:00.000Z")
        self.assertIn("changeEndDate", params)
        self.assertEqual(params["resultsPerPage"], 5000)

    def test_nvd_changes_delta_first_run_uses_lookback_not_crash(self) -> None:
        # Fresh DB: no prior successful run. Must fall back to a lookback
        # window instead of crashing on None.started_at.
        db = Mock()
        db.query.return_value.filter.return_value.order_by.return_value.first.return_value = None
        extractor = NVD_Changes_Extractor("run-1", mode="delta_poll", db=db)
        response = httpx.Response(
            200, json={"cveChanges": [], "totalResults": 0}
        )
        extractor._request = Mock(return_value=response)
        extractor._store = Mock()

        extractor.fetch()  # must not raise AttributeError

        requested_url = extractor._request.call_args.args[0]
        self.assertIn("changeStartDate=", requested_url)
        extractor._store.assert_called_once()

    def test_daily_extractors_are_snapshot_sources(self) -> None:
        epss = EPSSextractor("run-1")
        kev = CISA_KEVExtractor("run-1")
        yesterday = (datetime.now() - timedelta(days=1)).strftime("%Y-%m-%d")

        self.assertEqual(epss.source, "epss")
        self.assertEqual(kev.source, "cisa_kev")
        self.assertIn(f"epss_scores-{yesterday}.csv.gz", epss.build_url())
        self.assertIn("known_exploited_vulnerabilities.json", kev.build_url("primary"))

    def test_epss_parser_reads_bulk_csv_gzip(self) -> None:
        extractor = EPSSextractor("run-1")
        content = gzip.compress(
            b"# metadata\ncve,epss,percentile\nCVE-2026-0001,0.123,0.987\n"
        )
        response = httpx.Response(200, content=content)

        records = extractor._parser(response)

        self.assertEqual(records, [{"cve": "CVE-2026-0001", "epss": 0.123, "percentile": 0.987}])

    def test_cisa_kev_falls_back_to_secondary_url(self) -> None:
        extractor = CISA_KEVExtractor("run-1")
        secondary_response = httpx.Response(
            200,
            json={"vulnerabilities": [{"cveID": "CVE-2026-0001"}]},
        )
        extractor._request = Mock(side_effect=[RuntimeError("primary failed"), secondary_response])
        extractor._store = Mock()

        extractor.fetch()

        requested_urls = [call.args[0] for call in extractor._request.call_args_list]
        stored_records = extractor._store.call_args.args[0]

        self.assertIn("raw.githubusercontent.com", requested_urls[0])
        self.assertIn("www.cisa.gov", requested_urls[1])
        self.assertEqual(stored_records, [{"cveID": "CVE-2026-0001"}])


class SecurityGuardTests(TestCase):
    """SSRF allowlist + credential redaction — the security defense story."""

    def test_allowlist_accepts_known_hosts(self) -> None:
        self.assertTrue(is_allowed_url("https://services.nvd.nist.gov/rest/json/cves/2.0"))
        self.assertTrue(is_allowed_url("https://www.cisa.gov/feeds/kev.json"))

    def test_allowlist_rejects_unknown_host(self) -> None:
        self.assertFalse(is_allowed_url("https://evil.example.com/steal"))
        self.assertFalse(is_allowed_url("http://169.254.169.254/latest/meta-data/"))

    def test_sanitize_headers_redacts_credentials(self) -> None:
        redacted = sanitize_headers({"Authorization": "Bearer secret", "Accept": "json"})
        self.assertEqual(redacted["Authorization"], "[REDACTED]")
        self.assertEqual(redacted["Accept"], "json")

    def test_request_blocks_disallowed_url_without_network_call(self) -> None:
        extractor = NVDCVEsExtractor("run-1", mode="bulk_load")
        with patch("pipeline.extractors.base.httpx.get") as mock_get:
            with self.assertRaises(URLNotAllowedError):
                extractor._request("https://evil.example.com/x")
            mock_get.assert_not_called()

    def test_request_raises_ratelimit_on_403_without_retry(self) -> None:
        extractor = NVDCVEsExtractor("run-1", mode="bulk_load")
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        with patch("pipeline.extractors.base.httpx.get") as mock_get:
            mock_get.return_value = httpx.Response(403, request=httpx.Request("GET", url))
            with self.assertRaises(RateLimitError):
                extractor._request(url)
            self.assertEqual(mock_get.call_count, 1)

    def test_request_retries_transient_then_succeeds(self) -> None:
        extractor = NVDCVEsExtractor("run-1", mode="bulk_load")
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        ok = httpx.Response(200, json={"ok": True}, request=httpx.Request("GET", url))
        with patch("pipeline.extractors.base.httpx.get") as mock_get:
            mock_get.side_effect = [httpx.ConnectError("boom"), ok]
            response = extractor._request(url)
            self.assertEqual(response.status_code, 200)
            self.assertEqual(mock_get.call_count, 2)

    def test_request_gives_up_after_three_attempts(self) -> None:
        extractor = NVDCVEsExtractor("run-1", mode="bulk_load")
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        with patch("pipeline.extractors.base.httpx.get") as mock_get:
            mock_get.side_effect = httpx.ConnectError("boom")
            with self.assertRaises(ExtractionError):
                extractor._request(url)
            self.assertEqual(mock_get.call_count, 3)


class ScheduleTests(TestCase):
    def test_workflows_split_two_hour_nvd_from_daily_snapshots(self) -> None:
        root = Path(__file__).resolve().parents[3]
        nvd_workflow = (root / ".github" / "workflows" / "elt_nvd.yml").read_text()
        daily_workflow = (root / ".github" / "workflows" / "elt_daily.yml").read_text()

        self.assertIn("cron: '0 */2 * * *'", nvd_workflow)
        self.assertIn("python -m pipeline.run delta_poll nvd", nvd_workflow)
        self.assertIn("cron: '0 6 * * *'", daily_workflow)
        self.assertIn("python -m pipeline.run delta_poll daily", daily_workflow)
