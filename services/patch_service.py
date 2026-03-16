from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import List, Optional

from models.dependency import Dependency
from models.patch_result import PatchResult, PatchStatus
from models.vulnerability import Vulnerability
from services.dependency_service import DependencyService
from services.repository_service import RepositoryService
from utils.config import get_settings
from utils.logger import get_logger, EventLogger

logger = get_logger("securefix.service.patch")
events = EventLogger("patch_service")


class PatchService:
    """
    Applies dependency upgrades to a local repository clone:
    1. Creates a feature branch
    2. Modifies dependency files via DependencyService
    3. Commits the changes
    4. Pushes the branch to the remote

    Does NOT create pull requests (that is handled by GitHubService).
    """

    def __init__(self, repo_path: str, run_id: str) -> None:
        self._repo_path = repo_path
        self._run_id = run_id
        self._settings = get_settings()
        self._dep_service = DependencyService(repo_path)
        self._repo_service = RepositoryService()

    def generate_branch_name(self, vulns: List[Vulnerability]) -> str:
        """
        Generate a deterministic, human-readable branch name.
        e.g. securefix/lodash-high-20240116-abc123
        """
        if len(vulns) == 1:
            pkg = vulns[0].package_name.replace("/", "-").replace("@", "").lower()
            severity = vulns[0].severity
            tag = f"{pkg}-{severity}"
        else:
            tag = f"batch-{len(vulns)}-packages"

        date_tag = datetime.now(timezone.utc).strftime("%Y%m%d")
        short_id = self._run_id[:8]
        return f"{self._settings.patch_branch_prefix}{tag}-{date_tag}-{short_id}"

    async def apply_patch(
        self,
        vulnerabilities: List[Vulnerability],
        dependency_updates: List[Dependency],
        base_branch: str = "main",
    ) -> List[PatchResult]:
        """
        Full patch pipeline: branch → modify files → commit → push.
        Returns a PatchResult per Dependency update.
        """
        if not dependency_updates:
            logger.info("no_patches_to_apply", run_id=self._run_id)
            return []

        branch_name = self.generate_branch_name(vulnerabilities)

        logger.info(
            "patch_starting",
            run_id=self._run_id,
            branch=branch_name,
            updates=len(dependency_updates),
        )

        # Create branch
        try:
            self._repo_service.create_branch(self._repo_path, branch_name)
        except Exception as exc:
            logger.error("branch_creation_failed", error=str(exc))
            return [
                PatchResult(
                    vulnerability_id=dep.vulnerability_ids[0] if dep.vulnerability_ids else "",
                    package_name=dep.name,
                    from_version=dep.current_version,
                    to_version=dep.target_version,
                    dependency_file=dep.dependency_file,
                    status=PatchStatus.FAILED,
                    error_message=f"Branch creation failed: {exc}",
                )
                for dep in dependency_updates
            ]

        # Apply file modifications
        modified_files = self._dep_service.apply_updates(dependency_updates)
        if not modified_files:
            logger.warning("no_files_modified", run_id=self._run_id)

        # Commit
        commit_message = self._build_commit_message(vulnerabilities, dependency_updates)
        try:
            commit_sha = self._repo_service.commit_changes(
                self._repo_path,
                message=commit_message,
                paths=modified_files if modified_files else None,
            )
        except Exception as exc:
            logger.error("commit_failed", error=str(exc))
            commit_sha = ""

        # Push
        try:
            self._repo_service.push_branch(self._repo_path, branch_name)
        except Exception as exc:
            logger.error("push_failed", branch=branch_name, error=str(exc))
            return self._build_failed_results(dependency_updates, str(exc))

        results: List[PatchResult] = []
        for dep in dependency_updates:
            vuln_id = dep.vulnerability_ids[0] if dep.vulnerability_ids else ""
            result = PatchResult(
                vulnerability_id=vuln_id,
                package_name=dep.name,
                from_version=dep.current_version,
                to_version=dep.target_version,
                dependency_file=dep.dependency_file,
                status=PatchStatus.APPLIED,
                branch_name=branch_name,
                commit_sha=commit_sha,
                applied_at=datetime.now(timezone.utc),
            )
            results.append(result)

            events.patch_applied(
                self._run_id,
                dep.name,
                dep.current_version,
                dep.target_version,
                branch_name,
            )

        logger.info(
            "patch_complete",
            run_id=self._run_id,
            branch=branch_name,
            commit=commit_sha[:8] if commit_sha else "N/A",
            patches=len(results),
        )
        return results

    def _build_commit_message(
        self,
        vulns: List[Vulnerability],
        deps: List[Dependency],
    ) -> str:
        if len(deps) == 1:
            dep = deps[0]
            vuln = next((v for v in vulns if dep.name == v.package_name), None)
            severity = vuln.severity.upper() if vuln else "UNKNOWN"
            source = vuln.source if vuln else "scanner"
            lines = [
                f"fix(security): patch {dep.name} vulnerability",
                "",
                f"Upgrade {dep.name} from {dep.current_version} → {dep.target_version}",
                f"Severity: {severity}",
                f"Source: {source}",
            ]
            if vuln and vuln.id:
                lines.append(f"Vulnerability: {vuln.id}")
        else:
            lines = [
                f"fix(security): patch {len(deps)} dependency vulnerabilities",
                "",
                "Upgrades:",
            ]
            for dep in deps:
                lines.append(f"  - {dep.name}: {dep.current_version} → {dep.target_version}")

        return "\n".join(lines)

    @staticmethod
    def _build_failed_results(deps: List[Dependency], error: str) -> List[PatchResult]:
        return [
            PatchResult(
                vulnerability_id=dep.vulnerability_ids[0] if dep.vulnerability_ids else "",
                package_name=dep.name,
                from_version=dep.current_version,
                to_version=dep.target_version,
                dependency_file=dep.dependency_file,
                status=PatchStatus.FAILED,
                error_message=error,
            )
            for dep in deps
        ]
