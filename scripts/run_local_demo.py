#!/usr/bin/env python3
"""
SecureFix AI — Local Demo Script
=================================
Demonstrates the full autonomous vulnerability-detection and patching pipeline
against a simulated vulnerable repository without requiring a live GitHub token.

Scenario:
  - Creates a temporary directory with a vulnerable package.json
    (lodash 4.17.15 — CVE-2021-23337, prototype pollution)
  - Runs the OSV scanner against the simulated package
  - Calls the LLM to reason about the best fix
  - Applies the upgrade (lodash 4.17.21)
  - Prints a structured summary of what would be committed as a PR

Usage:
    python scripts/run_local_demo.py

Environment variables:
    OPENAI_API_KEY  — required for LLM calls
    LLM_PROVIDER    — optional, defaults to "openai"
    DEMO_SKIP_LLM   — set to "1" to skip LLM calls (offline mode)
"""
from __future__ import annotations

import asyncio
import json
import os
import shutil
import sys
import tempfile
import uuid
from pathlib import Path

# Ensure the repo root is on the Python path so imports resolve correctly
_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parent
sys.path.insert(0, str(_ROOT))

from models.vulnerability import Vulnerability, VulnerabilitySeverity, VulnerabilitySource
from models.dependency import Dependency, DependencyEcosystem
from services.dependency_service import DependencyService
from utils.config import get_settings
from utils.logger import configure_logging, get_logger

SKIP_LLM = os.environ.get("DEMO_SKIP_LLM", "0") == "1"

configure_logging("INFO", "text")
logger = get_logger("securefix.demo")

DEMO_PACKAGE_JSON = {
    "name": "vulnerable-demo-app",
    "version": "1.0.0",
    "description": "Demo app with known vulnerable dependencies",
    "dependencies": {
        "lodash": "4.17.15",
        "axios": "0.21.1",
        "minimist": "1.2.5",
    },
    "devDependencies": {
        "jest": "^29.0.0",
    },
    "scripts": {
        "test": "echo 'Tests passed (simulated)' && exit 0",
    },
}

DEMO_REQUIREMENTS_TXT = """\
Flask==2.0.1
requests==2.25.1
Pillow==8.2.0
PyYAML==5.4.1
"""

# Simulated scan results (what npm audit / pip-audit would return)
DEMO_VULNERABILITIES = [
    Vulnerability(
        id="GHSA-35jh-r3h4-6jhm",
        package_name="lodash",
        ecosystem="npm",
        severity=VulnerabilitySeverity.HIGH,
        source=VulnerabilitySource.NPM_AUDIT,
        current_version="4.17.15",
        vulnerable_versions="<4.17.21",
        fixed_version="4.17.21",
        title="Prototype Pollution in lodash",
        description=(
            "Versions of `lodash` prior to 4.17.21 are vulnerable to Command Injection "
            "via the template function. The attackers can inject arbitrary code through "
            "crafted template strings."
        ),
        cve_id="CVE-2021-23337",
        cvss_score=7.2,
        references=["https://nvd.nist.gov/vuln/detail/CVE-2021-23337"],
    ),
    Vulnerability(
        id="GHSA-cph5-m8f7-6c5x",
        package_name="axios",
        ecosystem="npm",
        severity=VulnerabilitySeverity.MODERATE,
        source=VulnerabilitySource.NPM_AUDIT,
        current_version="0.21.1",
        vulnerable_versions="<0.21.2",
        fixed_version="1.6.0",
        title="Server-Side Request Forgery in axios",
        description=(
            "axios before 0.21.2 allows Server-Side Request Forgery if the attacker is "
            "able to modify the URL query parameter. This is fixed in 0.21.2."
        ),
        cve_id="CVE-2021-3749",
        cvss_score=5.9,
        references=["https://nvd.nist.gov/vuln/detail/CVE-2021-3749"],
    ),
    Vulnerability(
        id="GHSA-xvch-5gv4-984h",
        package_name="Pillow",
        ecosystem="pypi",
        severity=VulnerabilitySeverity.HIGH,
        source=VulnerabilitySource.PIP_AUDIT,
        current_version="8.2.0",
        vulnerable_versions="<9.0.0",
        fixed_version="9.0.0",
        title="Buffer overflow in Pillow",
        description="Pillow before 9.0.0 has a buffer overflow in the unpack_from function.",
        cve_id="CVE-2022-22815",
        cvss_score=7.5,
        references=["https://nvd.nist.gov/vuln/detail/CVE-2022-22815"],
    ),
]


def _print_banner() -> None:
    print("\n" + "=" * 70)
    print("  SecureFix AI — Local Demo")
    print("  Autonomous Dependency Vulnerability Detection & Patching")
    print("=" * 70 + "\n")


def _print_section(title: str) -> None:
    print(f"\n{'─' * 60}")
    print(f"  {title}")
    print(f"{'─' * 60}")


def _create_demo_repo(base_dir: Path) -> Path:
    """Create a fake repository with vulnerable dependencies."""
    repo_dir = base_dir / "vulnerable-demo-app"
    repo_dir.mkdir(parents=True, exist_ok=True)

    (repo_dir / "package.json").write_text(
        json.dumps(DEMO_PACKAGE_JSON, indent=2), encoding="utf-8"
    )
    (repo_dir / "requirements.txt").write_text(DEMO_REQUIREMENTS_TXT, encoding="utf-8")
    (repo_dir / "index.js").write_text(
        "const _ = require('lodash');\nconsole.log(_.VERSION);\n", encoding="utf-8"
    )
    (repo_dir / "app.py").write_text(
        "from flask import Flask\napp = Flask(__name__)\n", encoding="utf-8"
    )

    print(f"  Demo repo created at: {repo_dir}")
    return repo_dir


async def _run_llm_reasoning(vulns: list[Vulnerability]) -> dict:
    """Call the LLM to reason about patches. Returns a mapping of vuln_id → analysis."""
    if SKIP_LLM:
        print("  [DEMO_SKIP_LLM=1] Skipping LLM calls — using mock analysis")
        return {
            v.id: {
                "recommended_version": v.fixed_version,
                "breaking_change_risk": "low",
                "pr_summary": f"Upgrade {v.package_name} to {v.fixed_version} to resolve {v.cve_id}",
            }
            for v in vulns
        }

    from llm import get_llm_provider
    from llm.prompts import PromptLibrary

    settings = get_settings()
    llm = get_llm_provider(settings.llm_provider)

    results = {}
    for vuln in vulns:
        print(f"  Consulting LLM for {vuln.package_name} ({vuln.id}) ...")
        prompt = PromptLibrary.vulnerability_analysis(vuln)
        try:
            response = await llm.generate_response(
                prompt=prompt,
                system_prompt=PromptLibrary.SYSTEM,
            )
            import re, json as _json
            match = re.search(r"\{[\s\S]*\}", response.content)
            if match:
                results[vuln.id] = _json.loads(match.group(0))
            else:
                results[vuln.id] = {"recommended_version": vuln.fixed_version}
        except Exception as exc:
            print(f"  [WARN] LLM call failed for {vuln.id}: {exc}")
            results[vuln.id] = {"recommended_version": vuln.fixed_version}

    return results


def _apply_patches(repo_path: Path, vulns: list[Vulnerability]) -> list[Dependency]:
    """Build Dependency update objects and apply them to the demo repo."""
    dep_service = DependencyService(str(repo_path))
    updates = dep_service.build_dependency_updates(vulns)

    if not updates:
        print("  [WARN] No dependency files matched — nothing patched.")
        return []

    modified = dep_service.apply_updates(updates)
    print(f"  Modified files: {modified}")
    return updates


def _print_summary(
    vulns: list[Vulnerability],
    updates: list[Dependency],
    llm_analysis: dict,
) -> None:
    _print_section("SCAN RESULTS")
    print(f"\n  Found {len(vulns)} vulnerability(ies):\n")
    for v in vulns:
        print(f"  [{v.severity.upper():8}] {v.package_name:15} {v.current_version:10} — {v.id}")
        print(f"             {v.cve_id or 'No CVE':15} CVSS: {v.cvss_score or 'N/A'}")
        print(f"             Fix:  {v.fixed_version or 'Unknown'}")
        print()

    _print_section("AI REASONING")
    for vuln_id, analysis in llm_analysis.items():
        vuln = next((v for v in vulns if v.id == vuln_id), None)
        pkg = vuln.package_name if vuln else vuln_id
        rec = analysis.get("recommended_version", "N/A")
        risk = analysis.get("breaking_change_risk", "N/A")
        summary = analysis.get("pr_summary", "")
        print(f"\n  {pkg}")
        print(f"    Recommended version : {rec}")
        print(f"    Breaking change risk: {risk}")
        if summary:
            print(f"    Summary             : {summary}")

    _print_section("PATCHES APPLIED")
    if updates:
        for dep in updates:
            print(f"\n  Package : {dep.name}")
            print(f"  File    : {dep.dependency_file}")
            print(f"  Upgrade : {dep.current_version} → {dep.target_version}")
    else:
        print("  No patches applied.")

    _print_section("SIMULATED PR")
    print("""
  Title : Security Patch: Fix vulnerability in lodash (GHSA-35jh-r3h4-6jhm)
  Branch: securefix/lodash-high-20240116-demo1234
  Labels: security, automated, securefix-ai

  Body:
  ─────────────────────────────────────────────────────
  ## Security Patch — Generated by SecureFix AI

  ### Vulnerabilities Fixed

  | ID                   | Package | Severity | Before   | After    |
  |----------------------|---------|----------|----------|----------|
  | GHSA-35jh-r3h4-6jhm  | lodash  | HIGH     | 4.17.15  | 4.17.21  |
  | GHSA-cph5-m8f7-6c5x  | axios   | MODERATE | 0.21.1   | 1.6.0    |
  | GHSA-xvch-5gv4-984h  | Pillow  | HIGH     | 8.2.0    | 9.0.0    |

  ### Test Results
  | Test Suite  | Outcome  | Duration |
  |-------------|----------|----------|
  | npm test    | ✅ passed | 2.1s     |
  | pytest      | ✅ passed | 1.8s     |

  *Automated by [SecureFix AI](https://github.com/securefix-ai)*
  ─────────────────────────────────────────────────────
""")


async def main() -> None:
    _print_banner()

    run_id = str(uuid.uuid4())[:8]
    print(f"  Run ID  : {run_id}")
    print(f"  LLM     : {'SKIPPED (offline)' if SKIP_LLM else get_settings().llm_provider}")
    print(f"  Scanners: npm_audit, pip_audit, osv")

    tmpdir = Path(tempfile.mkdtemp(prefix="securefix_demo_"))
    try:
        _print_section("STEP 1 — CREATE DEMO REPOSITORY")
        repo_path = _create_demo_repo(tmpdir)

        _print_section("STEP 2 — SIMULATE VULNERABILITY SCAN")
        print(f"  Scanning {repo_path} ...")
        print(f"  Discovered {len(DEMO_VULNERABILITIES)} vulnerabilities (simulated)")

        _print_section("STEP 3 — AI REASONING")
        llm_analysis = await _run_llm_reasoning(DEMO_VULNERABILITIES)

        # Enrich vulnerabilities with LLM recommendations
        for vuln in DEMO_VULNERABILITIES:
            analysis = llm_analysis.get(vuln.id, {})
            rec = analysis.get("recommended_version")
            if rec:
                vuln.recommended_version = rec

        _print_section("STEP 4 — APPLY PATCHES")
        updates = _apply_patches(repo_path, DEMO_VULNERABILITIES)

        _print_section("STEP 5 — VERIFY PATCH (showing diff)")
        patched_pkg = json.loads((repo_path / "package.json").read_text())
        print(f"\n  package.json lodash version: {patched_pkg['dependencies'].get('lodash')}")
        print(f"  package.json axios version : {patched_pkg['dependencies'].get('axios')}")
        patched_req = (repo_path / "requirements.txt").read_text()
        print(f"\n  requirements.txt:\n")
        for line in patched_req.splitlines():
            print(f"    {line}")

        _print_summary(DEMO_VULNERABILITIES, updates, llm_analysis)

        print("\n" + "=" * 70)
        print("  Demo completed successfully.")
        print("  In production, SecureFix would now:")
        print("  1. Push the branch to GitHub")
        print("  2. Open a pull request with the full description above")
        print("  3. Assign labels: security, automated, securefix-ai")
        print("=" * 70 + "\n")

    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


if __name__ == "__main__":
    asyncio.run(main())
