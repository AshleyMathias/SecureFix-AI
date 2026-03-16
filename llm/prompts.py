from __future__ import annotations

from string import Template
from typing import Dict, List, Optional

from models.vulnerability import Vulnerability
from models.dependency import Dependency


# ── System Prompt ─────────────────────────────────────────────────────────────

SECUREFIX_SYSTEM_PROMPT = """You are SecureFix AI, an expert DevSecOps engineer and security analyst.
Your role is to:
1. Analyze software dependency vulnerabilities with precision
2. Recommend the safest upgrade path that minimises breaking changes
3. Explain security risks in clear, actionable language
4. Generate detailed pull request descriptions for automated security patches

You MUST:
- Prioritise security without introducing regressions
- Cite CVE/GHSA IDs and CVSS scores when available
- Assess semver compatibility before recommending upgrades
- Flag any potential breaking changes with HIGH confidence

You MUST NOT:
- Recommend downgrades unless no fix is available
- Suggest workarounds that mask vulnerabilities
- Fabricate version numbers or CVE IDs
"""


# ── Vulnerability Analysis ────────────────────────────────────────────────────

VULNERABILITY_ANALYSIS_TEMPLATE = Template("""Analyze the following dependency vulnerability and recommend the safest upgrade strategy.

## Vulnerability Details
- **Package**: $package_name ($ecosystem)
- **Current Version**: $current_version
- **Vulnerability ID**: $vuln_id
- **CVE**: $cve_id
- **Severity**: $severity (CVSS: $cvss_score)
- **Affected Versions**: $vulnerable_versions
- **Known Fixed Version**: $fixed_version

## Description
$description

## Task
1. Assess the actual exploitability and impact of this vulnerability
2. Recommend the MINIMUM version upgrade that resolves the issue
3. Evaluate the risk of breaking changes between $current_version and your recommended version
4. Provide a plain-English summary suitable for a pull request

## Response Format (JSON)
{
  "recommended_version": "<semver>",
  "breaking_change_risk": "low|medium|high",
  "breaking_change_notes": "<what might break, if anything>",
  "severity_assessment": "<your analysis>",
  "patch_rationale": "<why this version was chosen>",
  "pr_summary": "<1-2 sentence PR description>"
}
""")

MULTI_VULNERABILITY_ANALYSIS_TEMPLATE = Template("""Analyze the following $count dependency vulnerabilities detected in a $ecosystem project.
Prioritize them by severity and recommend patch order.

## Vulnerabilities
$vulnerabilities_json

## Task
1. Rank vulnerabilities by risk priority (critical → low)
2. Identify any shared packages that can be patched once
3. Flag any vulnerabilities where no safe fix is available
4. Recommend batch patching order to minimise disruption

## Response Format (JSON)
{
  "prioritized_ids": ["<id1>", "<id2>", ...],
  "patch_strategy": "batch|sequential|individual",
  "high_risk_count": <n>,
  "no_fix_available": ["<id>", ...],
  "notes": "<strategic patching notes>"
}
""")


# ── Patch Reasoning ───────────────────────────────────────────────────────────

PATCH_REASONING_TEMPLATE = Template("""You are reviewing a proposed dependency upgrade for a $ecosystem project.

## Proposed Upgrade
- **Package**: $package_name
- **From**: $from_version → **To**: $to_version
- **Reason**: Fix $vuln_id ($severity vulnerability)
- **Dependency File**: $dependency_file

## Changelog / Release Notes
$changelog

## Project Context
- Direct dependency: $is_direct
- Used in: $usage_context

## Task
Reason about whether this upgrade is safe to apply automatically:
1. Are there known breaking API changes between the versions?
2. Does the package follow semver? Is this a patch/minor/major bump?
3. What is the likelihood of test failures after upgrading?
4. Should this be flagged for manual review?

## Response Format (JSON)
{
  "safe_to_auto_patch": true|false,
  "confidence": "high|medium|low",
  "breaking_changes": ["<change1>", ...],
  "semver_compliance": true|false,
  "bump_type": "patch|minor|major",
  "manual_review_required": true|false,
  "reasoning": "<detailed explanation>"
}
""")


# ── PR Description ────────────────────────────────────────────────────────────

PR_DESCRIPTION_TEMPLATE = Template("""Generate a detailed GitHub pull request description for the following security patch.

## Patch Information
- **Repository**: $repo_name
- **Packages Patched**: $packages_summary
- **Branch**: $branch_name
- **Triggered By**: Automated SecureFix AI scan

## Vulnerabilities Fixed
$vulnerabilities_list

## Changes Applied
$changes_list

## Test Results
$test_results

## AI Reasoning Summary
$ai_reasoning

## Instructions
Write a professional GitHub PR description that includes:
1. A clear title (already set — just write the body)
2. Executive summary of what was fixed and why it matters
3. A vulnerability table (ID | Package | Severity | Before | After)
4. Explanation of breaking change risk assessment
5. Test coverage summary
6. Instructions for the reviewer

Use GitHub Markdown. Be concise but thorough.
""")

# ── Comment Templates ─────────────────────────────────────────────────────────

SCAN_COMPLETE_COMMENT_TEMPLATE = Template("""## 🔒 SecureFix AI — Security Scan Complete

**Run ID**: `$run_id`
**Scanned**: $repo_name
**Duration**: $duration

### Results
| Metric | Count |
|--------|-------|
| Vulnerabilities detected | $vuln_count |
| Patchable automatically | $patchable_count |
| Requiring manual review | $manual_count |

$vuln_table

*Powered by [SecureFix AI](https://github.com/securefix-ai)*
""")

NO_VULNERABILITIES_COMMENT = """## ✅ SecureFix AI — No Vulnerabilities Detected

All dependency scans passed clean. No security patches required at this time.

*Powered by SecureFix AI*
"""


class PromptLibrary:
    """Centralised access to all SecureFix prompts."""

    SYSTEM = SECUREFIX_SYSTEM_PROMPT

    @staticmethod
    def vulnerability_analysis(vuln: Vulnerability) -> str:
        return VULNERABILITY_ANALYSIS_TEMPLATE.substitute(
            package_name=vuln.package_name,
            ecosystem=vuln.ecosystem,
            current_version=vuln.current_version,
            vuln_id=vuln.id,
            cve_id=vuln.cve_id or "N/A",
            severity=vuln.severity,
            cvss_score=vuln.cvss_score or "N/A",
            vulnerable_versions=vuln.vulnerable_versions or "N/A",
            fixed_version=vuln.fixed_version or "Unknown",
            description=vuln.description or "No description available.",
        )

    @staticmethod
    def multi_vulnerability_analysis(
        vulns: List[Vulnerability],
        ecosystem: str,
    ) -> str:
        import json
        vulns_data = [
            {
                "id": v.id,
                "package": v.package_name,
                "severity": v.severity,
                "current_version": v.current_version,
                "fixed_version": v.fixed_version,
                "description": v.description[:200] if v.description else "",
            }
            for v in vulns
        ]
        return MULTI_VULNERABILITY_ANALYSIS_TEMPLATE.substitute(
            count=len(vulns),
            ecosystem=ecosystem,
            vulnerabilities_json=json.dumps(vulns_data, indent=2),
        )

    @staticmethod
    def patch_reasoning(
        dep: Dependency,
        vuln: Vulnerability,
        changelog: str = "Not available",
        usage_context: str = "application code",
    ) -> str:
        return PATCH_REASONING_TEMPLATE.substitute(
            ecosystem=dep.ecosystem,
            package_name=dep.name,
            from_version=dep.current_version,
            to_version=dep.target_version,
            vuln_id=vuln.id,
            severity=vuln.severity,
            dependency_file=dep.dependency_file,
            changelog=changelog,
            is_direct=str(dep.is_direct),
            usage_context=usage_context,
        )

    @staticmethod
    def pr_description(
        repo_name: str,
        branch_name: str,
        vulns: List[Vulnerability],
        deps: List[Dependency],
        test_results: str,
        ai_reasoning: str,
    ) -> str:
        packages_summary = ", ".join(
            f"{d.name} ({d.current_version}→{d.target_version})" for d in deps
        )
        vuln_lines = "\n".join(
            f"- **{v.id}** | {v.package_name} | {v.severity.upper()} | "
            f"{v.current_version} → {v.target_version or 'N/A'} | {v.title or v.description[:80]}"
            for v in vulns
        )
        changes_lines = "\n".join(
            f"- `{d.dependency_file}`: `{d.name}` {d.current_version} → {d.target_version}"
            for d in deps
        )
        return PR_DESCRIPTION_TEMPLATE.substitute(
            repo_name=repo_name,
            packages_summary=packages_summary,
            branch_name=branch_name,
            vulnerabilities_list=vuln_lines,
            changes_list=changes_lines,
            test_results=test_results,
            ai_reasoning=ai_reasoning,
        )
