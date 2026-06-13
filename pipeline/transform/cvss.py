from decimal import Decimal, InvalidOperation

from core.exceptions.exceptions import CVSSResolutionError
from pipeline.transform import CVSSResult

VERSION_PRIORITY = ["cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]
VERSION_LABELS = {
    "cvssMetricV40": "4.0",
    "cvssMetricV31": "3.1",
    "cvssMetricV30": "3.0",
    "cvssMetricV2": "2.0",
}


class CVSSResolver:
    def resolve(self, cve_id: str, raw_metrics: dict | None) -> CVSSResult | None:
        if not raw_metrics:
            return None
        for metric_key in VERSION_PRIORITY:
            entries = raw_metrics.get(metric_key)
            if entries:
                return self._parse_entry(cve_id, metric_key, self._select_entry(entries))
        return None

    def _select_entry(self, entries: list[dict]) -> dict:
        for entry in entries:
            if str(entry.get("type", "")).lower() == "primary":
                return entry
        return entries[0]

    def _parse_entry(self, cve_id: str, metric_key: str, entry: dict) -> CVSSResult:
        cvss_data = entry.get("cvssData")
        if not isinstance(cvss_data, dict):
            raise CVSSResolutionError("Missing cvssData", cve_id=cve_id)
        source = entry.get("source")
        cvss_type = entry.get("type")
        if metric_key == "cvssMetricV40":
            return self._map_v4(cvss_data, source, cvss_type)
        if metric_key == "cvssMetricV2":
            return self._map_v2(cvss_data, entry, source, cvss_type)
        return self._map_v3(cvss_data, source, cvss_type, VERSION_LABELS[metric_key])

    def _map_v4(
        self, cvss_data: dict, source: str | None, cvss_type: str | None
    ) -> CVSSResult:
        vector = cvss_data.get("vectorString")
        metrics = self._parse_vector(vector)
        return CVSSResult(
            version_used="4.0",
            source=source,
            cvss_type=cvss_type,
            vector=vector,
            score=self._decimal(cvss_data.get("baseScore")),
            severity=cvss_data.get("baseSeverity"),
            attack_vector=cvss_data.get("attackVector") or metrics.get("AV"),
            attack_complexity=cvss_data.get("attackComplexity") or metrics.get("AC"),
            attack_requirements=cvss_data.get("attackRequirements") or metrics.get("AT"),
            privileges_required=cvss_data.get("privilegesRequired") or metrics.get("PR"),
            user_interaction=cvss_data.get("userInteraction") or metrics.get("UI"),
            vulnerable_confidentiality=(
                cvss_data.get("vulnerableSystemConfidentiality") or metrics.get("VC")
            ),
            vulnerable_integrity=(
                cvss_data.get("vulnerableSystemIntegrity") or metrics.get("VI")
            ),
            vulnerable_availability=(
                cvss_data.get("vulnerableSystemAvailability") or metrics.get("VA")
            ),
            subsequent_confidentiality=(
                cvss_data.get("subsequentSystemConfidentiality") or metrics.get("SC")
            ),
            subsequent_integrity=(
                cvss_data.get("subsequentSystemIntegrity") or metrics.get("SI")
            ),
            subsequent_availability=(
                cvss_data.get("subsequentSystemAvailability") or metrics.get("SA")
            ),
            exploitability_score=self._decimal(cvss_data.get("exploitabilityScore")),
            impact_score=self._decimal(cvss_data.get("impactScore")),
            exploit_maturity=cvss_data.get("exploitMaturity") or metrics.get("E"),
            provider_urgency=cvss_data.get("providerUrgency") or metrics.get("U"),
            automatable=cvss_data.get("automatable") or metrics.get("AU"),
            recovery=cvss_data.get("recovery") or metrics.get("R"),
            value_density=cvss_data.get("valueDensity") or metrics.get("V"),
            safety=cvss_data.get("safety") or metrics.get("S"),
            vulnerability_response_effort=(
                cvss_data.get("vulnerabilityResponseEffort") or metrics.get("RE")
            ),
        )

    def _map_v3(
        self,
        cvss_data: dict,
        source: str | None,
        cvss_type: str | None,
        version: str,
    ) -> CVSSResult:
        return CVSSResult(
            version_used=version,
            source=source,
            cvss_type=cvss_type,
            vector=cvss_data.get("vectorString"),
            score=self._decimal(cvss_data.get("baseScore")),
            severity=cvss_data.get("baseSeverity"),
            attack_vector=cvss_data.get("attackVector"),
            attack_complexity=cvss_data.get("attackComplexity"),
            privileges_required=cvss_data.get("privilegesRequired"),
            user_interaction=cvss_data.get("userInteraction"),
            vulnerable_confidentiality=cvss_data.get("confidentialityImpact"),
            vulnerable_integrity=cvss_data.get("integrityImpact"),
            vulnerable_availability=cvss_data.get("availabilityImpact"),
            cvss_scope=cvss_data.get("scope"),
            exploitability_score=self._decimal(cvss_data.get("exploitabilityScore")),
            impact_score=self._decimal(cvss_data.get("impactScore")),
            exploit_maturity=cvss_data.get("exploitCodeMaturity"),
        )

    def _map_v2(
        self,
        cvss_data: dict,
        entry: dict,
        source: str | None,
        cvss_type: str | None,
    ) -> CVSSResult:
        # CVSS v2 stores baseSeverity and the sub-scores at the ENTRY level,
        # not inside cvssData. It uses access* terminology, which we map onto
        # the closest flat attack_* columns. Richer v3/v4-only fields stay None.
        return CVSSResult(
            version_used="2.0",
            source=source,
            cvss_type=cvss_type,
            vector=cvss_data.get("vectorString"),
            score=self._decimal(cvss_data.get("baseScore")),
            severity=entry.get("baseSeverity"),
            attack_vector=cvss_data.get("accessVector"),
            attack_complexity=cvss_data.get("accessComplexity"),
            privileges_required=cvss_data.get("authentication"),
            vulnerable_confidentiality=cvss_data.get("confidentialityImpact"),
            vulnerable_integrity=cvss_data.get("integrityImpact"),
            vulnerable_availability=cvss_data.get("availabilityImpact"),
            exploitability_score=self._decimal(entry.get("exploitabilityScore")),
            impact_score=self._decimal(entry.get("impactScore")),
        )

    def detect_change(
        self, current: CVSSResult | None, incoming: CVSSResult | None
    ) -> bool:
        if current is None or incoming is None:
            return current is not incoming
        return (
            current.score != incoming.score
            or current.severity != incoming.severity
            or current.vector != incoming.vector
            or current.version_used != incoming.version_used
        )

    def is_secondary_fallback(self, entry: dict) -> bool:
        return str(entry.get("type", "")).lower() != "primary"

    def _decimal(self, value: object) -> Decimal | None:
        if value is None:
            return None
        try:
            return Decimal(str(value))
        except (InvalidOperation, ValueError) as exc:
            raise CVSSResolutionError("Invalid CVSS numeric value") from exc

    def _parse_vector(self, vector: str | None) -> dict[str, str]:
        if not vector:
            return {}
        parts = vector.split("/")
        result = {}
        for part in parts[1:]:
            key, sep, value = part.partition(":")
            if sep:
                result[key] = value
        return result
