from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import List, Optional

from models.vulnerability import Vulnerability, VulnerabilitySeverity, VulnerabilitySource
from utils.logger import get_logger
from utils.shell import run_command_async

logger = get_logger("securefix.scanner.python")

_SEVERITY_MAP = {
    "critical": VulnerabilitySeverity.CRITICAL,
    "high": VulnerabilitySeverity.HIGH,
    "medium": VulnerabilitySeverity.MODERATE,
    "moderate": VulnerabilitySeverity.MODERATE,
    "low": VulnerabilitySeverity.LOW,
    "unknown": VulnerabilitySeverity.UNKNOWN,
}

_DEPENDENCY_FILES = [
    "requirements.txt",
    "requirements-dev.txt",
    "requirements/base.txt",
    "requirements/prod.txt",
    "pyproject.toml",
    "Pipfile",
    "setup.py",
    "setup.cfg",
]


class PythonScanner:
    """
    Runs pip-audit and/or safety against a Python project and normalises
    the output into Vulnerability objects.

    pip-audit is preferred as it supports pyproject.toml, Pipfile, and
    requirements.txt out of the box. Safety is run as a secondary scanner.
    """

    def __init__(
        self,
        repo_path: str,
        enable_pip_audit: bool = True,
        enable_safety: bool = True,
    ) -> None:
        self._repo_path = Path(repo_path)
        self._enable_pip_audit = enable_pip_audit
        self._enable_safety = enable_safety

    async def scan(self) -> List[Vulnerability]:
        dep_file = self._find_dependency_file()
        if not dep_file:
            logger.debug(
                "python_scan_skipped",
                reason="no recognised dependency file",
                path=str(self._repo_path),
            )
            return []

        vulns: List[Vulnerability] = []

        if self._enable_pip_audit:
            pip_vulns = await self._run_pip_audit(dep_file)
            vulns.extend(pip_vulns)

        if self._enable_safety:
            safety_vulns = await self._run_safety(dep_file)
            # Deduplicate by id
            existing_ids = {v.id for v in vulns}
            vulns.extend(v for v in safety_vulns if v.id not in existing_ids)

        logger.info("python_scan_complete", vulnerability_count=len(vulns))
        return vulns

    def _find_dependency_file(self) -> Optional[Path]:
        for fname in _DEPENDENCY_FILES:
            candidate = self._repo_path / fname
            if candidate.exists():
                return candidate
        return None

    async def _run_pip_audit(self, dep_file: Path) -> List[Vulnerability]:
        logger.info("pip_audit_starting", dep_file=str(dep_file))

        # Use current Python and -m pip_audit so it works when pip-audit isn't on PATH (e.g. Windows)
        req_path = dep_file.resolve().as_posix()
        # --no-deps required with --disable-pip for plain (non-hashed) requirements files
        args = [
            sys.executable,
            "-m",
            "pip_audit",
            "--format",
            "json",
            "--requirement",
            req_path,
            "--no-deps",
            "--disable-pip",
        ]

        result = await run_command_async(
            args,
            cwd=str(self._repo_path),
            timeout=180,
        )

        # pip-audit exits 1 when vulns are found; JSON can be on stdout or (on some setups) stderr
        raw = result.stdout.strip()
        if not raw and result.stderr.strip():
            se = result.stderr.strip()
            if se.startswith("{") or se.startswith("["):
                raw = se
        if not raw:
            logger.warning("pip_audit_empty_output", stderr=result.stderr[:300])
            return []

        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            logger.error("pip_audit_parse_error", error=str(exc), raw=raw[:500])
            return []

        return self._parse_pip_audit(data, str(dep_file))

    def _parse_pip_audit(self, data: list | dict, dep_file: str) -> List[Vulnerability]:
        vulns: List[Vulnerability] = []

        # pip-audit returns a list of dicts with "name", "version", "vulns"
        items = data if isinstance(data, list) else data.get("dependencies", [])

        for pkg in items:
            pkg_name = pkg.get("name", "")
            current_version = pkg.get("version", "")

            for finding in pkg.get("vulns", []):
                vuln_id = finding.get("id", f"pip-audit-{pkg_name}")
                aliases = finding.get("aliases", [])
                cve_id = next((a for a in aliases if a.startswith("CVE-")), None)
                fixed_versions = finding.get("fix_versions", [])
                fixed_version = fixed_versions[0] if fixed_versions else None

                vuln = Vulnerability(
                    id=vuln_id,
                    package_name=pkg_name,
                    ecosystem="pypi",
                    severity=VulnerabilitySeverity.UNKNOWN,
                    source=VulnerabilitySource.PIP_AUDIT,
                    current_version=current_version,
                    fixed_version=fixed_version,
                    title=finding.get("description", "")[:100],
                    description=finding.get("description", ""),
                    cve_id=cve_id,
                    references=[finding.get("link", "")] if finding.get("link") else [],
                    dependency_path=dep_file,
                )
                vulns.append(vuln)

        return vulns

    async def _run_safety(self, dep_file: Path) -> List[Vulnerability]:
        logger.info("safety_scan_starting", dep_file=str(dep_file))

        cwd = str(self._repo_path)
        file_path = dep_file.resolve().as_posix()

        # Use "safety check --file ... --json" (2.x style). Safety 3.x "safety scan" often
        # times out or requires auth; check is fast and works when available.
        result = await run_command_async(
            ["safety", "check", "--file", file_path, "--json"],
            cwd=cwd,
            timeout=60,
        )
        raw = result.stdout.strip() or result.stderr.strip()
        if not raw:
            return []
        data = self._parse_safety_json(raw)
        if data is not None:
            return self._parse_safety_output(data, str(dep_file))
        return []

    def _parse_safety_json(self, raw: str) -> list | dict | None:
        if not raw:
            return None
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return None

    def _parse_safety_output(self, data: list | dict, dep_file: str) -> List[Vulnerability]:
        vulns: List[Vulnerability] = []

        # safety < 2.x returns a bare list; 2.x+ wraps in {"vulnerabilities": [...]}
        items: list = []
        if isinstance(data, list):
            items = data
        elif isinstance(data, dict):
            items = data.get("vulnerabilities", data.get("affected", []))

        for item in items:
            if isinstance(item, list):
                # Legacy format: [package, affected, installed, description, id]
                if len(item) < 5:
                    continue
                pkg_name, affected, installed, description, safety_id = item[:5]
                vuln = Vulnerability(
                    id=f"safety-{safety_id}",
                    package_name=pkg_name,
                    ecosystem="pypi",
                    severity=VulnerabilitySeverity.UNKNOWN,
                    source=VulnerabilitySource.SAFETY,
                    current_version=installed,
                    vulnerable_versions=affected,
                    title=description[:100],
                    description=description,
                    dependency_path=dep_file,
                )
            elif isinstance(item, dict):
                pkg_name = item.get("package_name", item.get("name", ""))
                vuln = Vulnerability(
                    id=item.get("vulnerability_id", f"safety-{pkg_name}"),
                    package_name=pkg_name,
                    ecosystem="pypi",
                    severity=_SEVERITY_MAP.get(
                        str(item.get("severity", "unknown")).lower(),
                        VulnerabilitySeverity.UNKNOWN,
                    ),
                    source=VulnerabilitySource.SAFETY,
                    current_version=item.get("installed_version", ""),
                    vulnerable_versions=item.get("affected_versions", ""),
                    fixed_version=item.get("fixed_versions", [None])[0]
                    if item.get("fixed_versions")
                    else None,
                    title=item.get("advisory", "")[:100],
                    description=item.get("advisory", ""),
                    cve_id=item.get("cve") or None,
                    references=item.get("more_info_url", [])
                    if isinstance(item.get("more_info_url"), list)
                    else ([item["more_info_url"]] if item.get("more_info_url") else []),
                    dependency_path=dep_file,
                )
            else:
                continue

            vulns.append(vuln)

        return vulns
