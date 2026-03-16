from __future__ import annotations

import json
import os
from pathlib import Path
from typing import List

from models.vulnerability import Vulnerability, VulnerabilitySeverity, VulnerabilitySource
from utils.logger import get_logger
from utils.shell import run_command_async

logger = get_logger("securefix.scanner.npm")

_SEVERITY_MAP = {
    "critical": VulnerabilitySeverity.CRITICAL,
    "high": VulnerabilitySeverity.HIGH,
    "moderate": VulnerabilitySeverity.MODERATE,
    "low": VulnerabilitySeverity.LOW,
    "info": VulnerabilitySeverity.LOW,
}


class NpmScanner:
    """
    Runs `npm audit --json` against a repository and parses the output
    into a normalised list of Vulnerability objects.

    Supports npm audit v6 (npm 6) and v7+ (npm 7/8/9/10) output formats.
    """

    def __init__(self, repo_path: str) -> None:
        self._repo_path = Path(repo_path)

    async def scan(self) -> List[Vulnerability]:
        package_json = self._repo_path / "package.json"
        if not package_json.exists():
            logger.debug("npm_scan_skipped", reason="no package.json", path=str(self._repo_path))
            return []

        logger.info("npm_audit_starting", path=str(self._repo_path))

        result = await run_command_async(
            ["npm", "audit", "--json"],
            cwd=str(self._repo_path),
            timeout=120,
        )

        if not result.stdout.strip():
            logger.warning("npm_audit_empty_output", stderr=result.stderr[:300])
            return []

        try:
            audit_data = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            logger.error("npm_audit_parse_error", error=str(exc), raw=result.stdout[:500])
            return []

        vulns = self._parse_audit_output(audit_data)
        logger.info("npm_audit_complete", vulnerability_count=len(vulns))
        return vulns

    def _parse_audit_output(self, data: dict) -> List[Vulnerability]:
        vulns: List[Vulnerability] = []

        # npm v7+ uses `vulnerabilities` key; v6 uses `advisories`
        if "vulnerabilities" in data:
            vulns = self._parse_v7(data["vulnerabilities"])
        elif "advisories" in data:
            vulns = self._parse_v6(data["advisories"])
        else:
            logger.warning("npm_audit_unknown_format", keys=list(data.keys()))

        return vulns

    def _parse_v7(self, vulnerabilities: dict) -> List[Vulnerability]:
        results: List[Vulnerability] = []
        for pkg_name, details in vulnerabilities.items():
            severity_raw = details.get("severity", "unknown").lower()
            severity = _SEVERITY_MAP.get(severity_raw, VulnerabilitySeverity.UNKNOWN)

            via = details.get("via", [])
            advisory_list = [v for v in via if isinstance(v, dict)]

            if not advisory_list:
                # Transitive only — create a single entry from package metadata
                vuln = Vulnerability(
                    id=f"npm-{pkg_name}-transitive",
                    package_name=pkg_name,
                    ecosystem="npm",
                    severity=severity,
                    source=VulnerabilitySource.NPM_AUDIT,
                    current_version=details.get("range", ""),
                    fixed_version=details.get("fixAvailable", {}).get("version")
                    if isinstance(details.get("fixAvailable"), dict)
                    else None,
                    title=f"Transitive vulnerability in {pkg_name}",
                    dependency_path=str(self._repo_path / "package.json"),
                )
                results.append(vuln)
                continue

            for advisory in advisory_list:
                vuln_id = str(advisory.get("ghAdvisoryId") or advisory.get("source") or f"npm-{pkg_name}")
                fix_info = details.get("fixAvailable")
                fixed_version: str | None = None
                if isinstance(fix_info, dict):
                    fixed_version = fix_info.get("version")

                vuln = Vulnerability(
                    id=vuln_id,
                    package_name=advisory.get("name", pkg_name),
                    ecosystem="npm",
                    severity=_SEVERITY_MAP.get(
                        advisory.get("severity", severity_raw).lower(),
                        VulnerabilitySeverity.UNKNOWN,
                    ),
                    source=VulnerabilitySource.NPM_AUDIT,
                    current_version=details.get("range", ""),
                    vulnerable_versions=advisory.get("range", ""),
                    fixed_version=fixed_version,
                    title=advisory.get("title", ""),
                    description=advisory.get("url", ""),
                    cvss_score=advisory.get("cvss", {}).get("score") if advisory.get("cvss") else None,
                    references=[advisory.get("url", "")] if advisory.get("url") else [],
                    dependency_path=str(self._repo_path / "package.json"),
                )
                results.append(vuln)

        return results

    def _parse_v6(self, advisories: dict) -> List[Vulnerability]:
        results: List[Vulnerability] = []
        for advisory_id, advisory in advisories.items():
            severity_raw = advisory.get("severity", "unknown").lower()
            severity = _SEVERITY_MAP.get(severity_raw, VulnerabilitySeverity.UNKNOWN)

            patched = advisory.get("patched_versions", "")
            fixed_version: str | None = None
            if patched and patched != "<0.0.0":
                # Extract first semver from patched range, e.g. ">=4.17.21" → "4.17.21"
                import re
                match = re.search(r"(\d+\.\d+\.\d+)", patched)
                if match:
                    fixed_version = match.group(1)

            cve_list = advisory.get("cves", [])
            cve_id = cve_list[0] if cve_list else None

            vuln = Vulnerability(
                id=advisory.get("github_advisory_id") or f"npm-advisory-{advisory_id}",
                package_name=advisory.get("module_name", ""),
                ecosystem="npm",
                severity=severity,
                source=VulnerabilitySource.NPM_AUDIT,
                current_version="",
                vulnerable_versions=advisory.get("vulnerable_versions", ""),
                fixed_version=fixed_version,
                title=advisory.get("title", ""),
                description=advisory.get("overview", ""),
                cve_id=cve_id,
                cvss_score=advisory.get("cvss", {}).get("score") if advisory.get("cvss") else None,
                references=[r.get("url", "") for r in advisory.get("references", []) if r.get("url")],
                dependency_path=str(self._repo_path / "package.json"),
            )
            results.append(vuln)

        return results
