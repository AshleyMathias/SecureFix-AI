"""
Unit tests for SecureFix AI scanners.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

# Ensure the project root is on the path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from models.vulnerability import VulnerabilitySeverity, VulnerabilitySource
from scanners.npm_scanner import NpmScanner
from scanners.python_scanner import PythonScanner


# ── npm scanner ───────────────────────────────────────────────────────────────

NPM_AUDIT_V7_OUTPUT = {
    "auditReportVersion": 2,
    "vulnerabilities": {
        "lodash": {
            "name": "lodash",
            "severity": "high",
            "isDirect": True,
            "via": [
                {
                    "source": 1091,
                    "name": "lodash",
                    "dependency": "lodash",
                    "title": "Prototype Pollution in lodash",
                    "url": "https://github.com/advisories/GHSA-35jh-r3h4-6jhm",
                    "severity": "high",
                    "range": "<4.17.21",
                    "ghAdvisoryId": "GHSA-35jh-r3h4-6jhm",
                }
            ],
            "effects": [],
            "range": "<4.17.21",
            "nodes": ["node_modules/lodash"],
            "fixAvailable": {"name": "lodash", "version": "4.17.21"},
        }
    },
    "metadata": {"vulnerabilities": {"total": 1, "high": 1}},
}

NPM_AUDIT_V6_OUTPUT = {
    "advisories": {
        "1091": {
            "github_advisory_id": "GHSA-35jh-r3h4-6jhm",
            "module_name": "lodash",
            "severity": "high",
            "title": "Prototype Pollution in lodash",
            "overview": "Versions of lodash prior to 4.17.21 are vulnerable.",
            "vulnerable_versions": "<4.17.21",
            "patched_versions": ">=4.17.21",
            "cves": ["CVE-2021-23337"],
            "references": [{"url": "https://nvd.nist.gov/vuln/detail/CVE-2021-23337"}],
            "cvss": {"score": 7.2},
        }
    }
}


class TestNpmScanner:
    def test_parse_v7_format(self, tmp_path: Path) -> None:
        scanner = NpmScanner(str(tmp_path))
        vulns = scanner._parse_audit_output(NPM_AUDIT_V7_OUTPUT)

        assert len(vulns) == 1
        v = vulns[0]
        assert v.package_name == "lodash"
        assert v.severity == VulnerabilitySeverity.HIGH
        assert v.fixed_version == "4.17.21"
        assert v.id == "GHSA-35jh-r3h4-6jhm"
        assert v.source == VulnerabilitySource.NPM_AUDIT

    def test_parse_v6_format(self, tmp_path: Path) -> None:
        scanner = NpmScanner(str(tmp_path))
        vulns = scanner._parse_audit_output(NPM_AUDIT_V6_OUTPUT)

        assert len(vulns) == 1
        v = vulns[0]
        assert v.package_name == "lodash"
        assert v.severity == VulnerabilitySeverity.HIGH
        assert v.cve_id == "CVE-2021-23337"
        assert v.fixed_version == "4.17.21"
        assert v.cvss_score == 7.2

    def test_no_package_json_returns_empty(self, tmp_path: Path) -> None:
        """Scanner must not fail on repositories without package.json."""
        scanner = NpmScanner(str(tmp_path))
        # Patch scan to be synchronous-compatible for this test
        import asyncio
        result = asyncio.run(scanner.scan())
        assert result == []

    def test_empty_vulnerabilities(self, tmp_path: Path) -> None:
        scanner = NpmScanner(str(tmp_path))
        vulns = scanner._parse_audit_output({"vulnerabilities": {}, "auditReportVersion": 2})
        assert vulns == []


# ── python scanner ────────────────────────────────────────────────────────────

PIP_AUDIT_OUTPUT = [
    {
        "name": "Pillow",
        "version": "8.2.0",
        "vulns": [
            {
                "id": "GHSA-xvch-5gv4-984h",
                "description": "Buffer overflow in Pillow.",
                "fix_versions": ["9.0.0"],
                "aliases": ["CVE-2022-22815"],
                "link": "https://github.com/advisories/GHSA-xvch-5gv4-984h",
            }
        ],
    }
]


class TestPythonScanner:
    def test_parse_pip_audit(self, tmp_path: Path) -> None:
        scanner = PythonScanner(str(tmp_path))
        vulns = scanner._parse_pip_audit(PIP_AUDIT_OUTPUT, str(tmp_path / "requirements.txt"))

        assert len(vulns) == 1
        v = vulns[0]
        assert v.package_name == "Pillow"
        assert v.current_version == "8.2.0"
        assert v.fixed_version == "9.0.0"
        assert v.cve_id == "CVE-2022-22815"
        assert v.source == VulnerabilitySource.PIP_AUDIT

    def test_no_requirements_returns_empty(self, tmp_path: Path) -> None:
        import asyncio
        scanner = PythonScanner(str(tmp_path))
        result = asyncio.run(scanner.scan())
        assert result == []

    def test_parse_safety_legacy_format(self, tmp_path: Path) -> None:
        scanner = PythonScanner(str(tmp_path))
        data = [["Pillow", "<9.0.0", "8.2.0", "Buffer overflow vulnerability", "44587"]]
        vulns = scanner._parse_safety_output(data, str(tmp_path / "requirements.txt"))

        assert len(vulns) == 1
        assert vulns[0].package_name == "Pillow"
        assert vulns[0].source == VulnerabilitySource.SAFETY
