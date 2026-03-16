from __future__ import annotations

import asyncio
import json
from typing import Any, Dict, List, Optional

import httpx

from models.vulnerability import Vulnerability, VulnerabilitySeverity, VulnerabilitySource
from utils.config import get_settings
from utils.logger import get_logger

logger = get_logger("securefix.scanner.osv")

_SEVERITY_MAP = {
    "CRITICAL": VulnerabilitySeverity.CRITICAL,
    "HIGH": VulnerabilitySeverity.HIGH,
    "MEDIUM": VulnerabilitySeverity.MODERATE,
    "MODERATE": VulnerabilitySeverity.MODERATE,
    "LOW": VulnerabilitySeverity.LOW,
}

# OSV ecosystem names
_ECOSYSTEM_MAP = {
    "npm": "npm",
    "pypi": "PyPI",
    "maven": "Maven",
    "go": "Go",
    "cargo": "crates.io",
    "rubygems": "RubyGems",
}


class OsvScanner:
    """
    Queries the OSV (Open Source Vulnerabilities) API for a list of
    package/version pairs. Used both as a primary scanner and to enrich
    results from npm/pip scanners with additional metadata.

    API docs: https://google.github.io/osv.dev/api/
    """

    def __init__(self) -> None:
        self._settings = get_settings()
        self._base_url = self._settings.osv_api_url
        self._timeout = httpx.Timeout(self._settings.scan_timeout_seconds)

    async def scan_packages(
        self,
        packages: List[Dict[str, str]],
        ecosystem: str,
    ) -> List[Vulnerability]:
        """
        Scan a list of {name, version} dicts against the OSV API.

        Args:
            packages:  List of {"name": str, "version": str} dicts.
            ecosystem: Ecosystem string (npm, pypi, etc.).
        """
        if not packages:
            return []

        osv_ecosystem = _ECOSYSTEM_MAP.get(ecosystem.lower(), ecosystem)
        logger.info("osv_scan_starting", ecosystem=osv_ecosystem, package_count=len(packages))

        tasks = [
            self._query_single(pkg["name"], pkg["version"], osv_ecosystem)
            for pkg in packages
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)

        vulns: List[Vulnerability] = []
        for result in results:
            if isinstance(result, Exception):
                logger.warning("osv_query_error", error=str(result))
                continue
            vulns.extend(result)

        logger.info("osv_scan_complete", vulnerability_count=len(vulns))
        return vulns

    async def enrich_vulnerability(
        self,
        vuln_id: str,
    ) -> Optional[Dict[str, Any]]:
        """
        Fetch full OSV advisory details for a given vulnerability ID (CVE / GHSA / OSV-ID).
        """
        url = f"{self._base_url}/vulns/{vuln_id}"
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            try:
                resp = await client.get(url)
                resp.raise_for_status()
                return resp.json()
            except httpx.HTTPStatusError as exc:
                logger.warning("osv_enrich_error", vuln_id=vuln_id, status=exc.response.status_code)
                return None
            except httpx.RequestError as exc:
                logger.warning("osv_request_error", vuln_id=vuln_id, error=str(exc))
                return None

    async def _query_single(
        self,
        package_name: str,
        version: str,
        ecosystem: str,
    ) -> List[Vulnerability]:
        url = f"{self._base_url}/query"
        payload = {
            "version": version,
            "package": {
                "name": package_name,
                "ecosystem": ecosystem,
            },
        }

        async with httpx.AsyncClient(timeout=self._timeout) as client:
            try:
                resp = await client.post(url, json=payload)
                resp.raise_for_status()
                data = resp.json()
            except httpx.HTTPStatusError as exc:
                logger.warning(
                    "osv_query_http_error",
                    package=package_name,
                    status=exc.response.status_code,
                )
                return []
            except httpx.RequestError as exc:
                logger.warning("osv_query_request_error", package=package_name, error=str(exc))
                return []

        return self._parse_osv_response(data, package_name, version)

    def _parse_osv_response(
        self,
        data: Dict[str, Any],
        package_name: str,
        current_version: str,
    ) -> List[Vulnerability]:
        vulns: List[Vulnerability] = []

        for entry in data.get("vulns", []):
            osv_id = entry.get("id", "")
            summary = entry.get("summary", "")
            details = entry.get("details", "")

            # Extract severity from CVSS
            severity = VulnerabilitySeverity.UNKNOWN
            cvss_score: Optional[float] = None
            for sev_entry in entry.get("severity", []):
                if sev_entry.get("type") == "CVSS_V3":
                    cvss_score = self._parse_cvss_score(sev_entry.get("score", ""))
                    severity = self._cvss_to_severity(cvss_score)
                    break

            # Extract fixed version from affected ranges
            fixed_version = self._extract_fixed_version(entry.get("affected", []), package_name)

            # Extract aliases (CVEs)
            aliases = entry.get("aliases", [])
            cve_id = next((a for a in aliases if a.startswith("CVE-")), None)

            # References
            references = [r.get("url", "") for r in entry.get("references", []) if r.get("url")]

            vuln = Vulnerability(
                id=osv_id,
                package_name=package_name,
                ecosystem=entry.get("affected", [{}])[0]
                .get("package", {})
                .get("ecosystem", "")
                .lower(),
                severity=severity,
                source=VulnerabilitySource.OSV,
                current_version=current_version,
                fixed_version=fixed_version,
                title=summary[:200] if summary else "",
                description=details[:1000] if details else "",
                cve_id=cve_id,
                cvss_score=cvss_score,
                references=references[:5],
            )
            vulns.append(vuln)

        return vulns

    def _extract_fixed_version(
        self,
        affected: List[Dict[str, Any]],
        package_name: str,
    ) -> Optional[str]:
        for pkg_affected in affected:
            for rng in pkg_affected.get("ranges", []):
                for event in rng.get("events", []):
                    fixed = event.get("fixed")
                    if fixed:
                        return fixed
        return None

    @staticmethod
    def _parse_cvss_score(cvss_string: str) -> Optional[float]:
        """Extract the base score from a CVSS v3 vector string."""
        # Some OSV entries embed the numeric score directly
        try:
            return float(cvss_string)
        except (ValueError, TypeError):
            pass
        return None

    @staticmethod
    def _cvss_to_severity(score: Optional[float]) -> VulnerabilitySeverity:
        if score is None:
            return VulnerabilitySeverity.UNKNOWN
        if score >= 9.0:
            return VulnerabilitySeverity.CRITICAL
        if score >= 7.0:
            return VulnerabilitySeverity.HIGH
        if score >= 4.0:
            return VulnerabilitySeverity.MODERATE
        return VulnerabilitySeverity.LOW
