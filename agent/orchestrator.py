from __future__ import annotations

import json
from datetime import datetime
from typing import Any, Dict, List, Optional

from models.dependency import Dependency
from models.patch_result import PatchStatus
from models.vulnerability import Vulnerability
from services.dependency_service import DependencyService
from services.github_service import GitHubService
from services.patch_service import PatchService
from services.repository_service import RepositoryService
from services.test_service import TestService
from services.vulnerability_service import VulnerabilityService
from llm import get_llm_provider
from llm.prompts import PromptLibrary
from utils.config import get_settings
from utils.logger import get_logger, EventLogger
from agent.state import SecureFixState

logger = get_logger("securefix.orchestrator")
events = EventLogger("orchestrator")


class SecureFixOrchestrator:
    """
    Contains the implementation of every LangGraph node.
    Each method receives the current SecureFixState, performs its work,
    and returns a partial state dict with only the updated fields.

    LangGraph merges the returned dict into the existing state.
    """

    def __init__(self) -> None:
        self._settings = get_settings()
        self._gh_service = GitHubService()
        self._repo_service = RepositoryService()
        self._llm = get_llm_provider(self._settings.llm_provider)
        logger.info(
            "orchestrator_initialized",
            llm_provider=self._llm.provider_name,
            llm_model=self._llm.model_name,
        )

    # ── Node 0: Initialize ────────────────────────────────────────────────────

    async def initialize(self, state: SecureFixState) -> Dict[str, Any]:
        """Parse the repo URL, clone the repository, resolve owner/name."""
        run_id = state["run_id"]
        repo_url = state["repo_url"]

        logger.info("node_initialize", run_id=run_id, repo_url=repo_url)

        try:
            owner, repo_name = self._gh_service.parse_repo_url(repo_url)
        except ValueError as exc:
            return {"should_abort": True, "error_message": str(exc), "status": "failed"}

        try:
            local_path = self._repo_service.clone_repository(repo_url, run_id)
        except RuntimeError as exc:
            return {"should_abort": True, "error_message": str(exc), "status": "failed"}

        return {
            "repo_owner": owner,
            "repo_name": repo_name,
            "local_repo_path": local_path,
            "status": "scanning",
            "current_node": "initialize",
        }

    # ── Node 1: Detect Vulnerabilities ────────────────────────────────────────

    async def detect_vulnerabilities(self, state: SecureFixState) -> Dict[str, Any]:
        """Run all enabled scanners and return the discovered vulnerabilities."""
        run_id = state["run_id"]
        local_path = state.get("local_repo_path", "")

        logger.info("node_detect", run_id=run_id)

        scanner = VulnerabilityService(local_path, run_id)

        try:
            vulns: List[Vulnerability] = await scanner.scan_all()
        except Exception as exc:
            logger.error("scan_failed", run_id=run_id, error=str(exc))
            return {
                "should_abort": True,
                "error_message": f"Scan failed: {exc}",
                "status": "failed",
                "vulnerabilities": [],
            }

        logger.info(
            "detection_complete",
            run_id=run_id,
            total=len(vulns),
            patchable=sum(1 for v in vulns if v.is_patchable),
        )

        return {
            "vulnerabilities": vulns,
            "status": "reasoning" if vulns else "completed",
            "current_node": "detect_vulnerabilities",
        }

    # ── Node 2: AI Reasoning ──────────────────────────────────────────────────

    async def ai_reasoning(self, state: SecureFixState) -> Dict[str, Any]:
        """
        Use the LLM to assess each vulnerability and determine
        the safest upgrade version.
        """
        run_id = state["run_id"]
        vulns: List[Vulnerability] = state.get("vulnerabilities", [])

        logger.info("node_ai_reasoning", run_id=run_id, vuln_count=len(vulns))

        enriched_vulns: List[Vulnerability] = []
        reasoning_parts: List[str] = []

        for vuln in vulns:
            if not vuln.is_patchable:
                logger.debug("vuln_not_patchable", id=vuln.id)
                enriched_vulns.append(vuln)
                continue

            try:
                prompt = PromptLibrary.vulnerability_analysis(vuln)
                response = await self._llm.generate_response(
                    prompt=prompt,
                    system_prompt=PromptLibrary.SYSTEM,
                )

                # Parse JSON response
                llm_data = self._parse_llm_json(response.content)
                if llm_data:
                    rec_version = llm_data.get("recommended_version", vuln.target_version)
                    if rec_version:
                        vuln.recommended_version = rec_version

                    risk = llm_data.get("breaking_change_risk", "unknown")
                    pr_summary = llm_data.get("pr_summary", "")
                    reasoning_parts.append(
                        f"**{vuln.package_name}** ({vuln.id}): {pr_summary} "
                        f"[Breaking change risk: {risk}]"
                    )

                    if risk == "high" and self._settings.skip_breaking_changes:
                        logger.warning(
                            "skipping_high_risk_patch",
                            package=vuln.package_name,
                            risk=risk,
                        )
                        continue

            except Exception as exc:
                logger.warning("llm_reasoning_error", vuln_id=vuln.id, error=str(exc))

            enriched_vulns.append(vuln)

        summary = "\n".join(reasoning_parts) if reasoning_parts else "AI reasoning completed."

        logger.info(
            "ai_reasoning_complete",
            run_id=run_id,
            enriched=len(enriched_vulns),
        )

        return {
            "vulnerabilities": enriched_vulns,
            "ai_reasoning_summary": summary,
            "status": "patching",
            "current_node": "ai_reasoning",
        }

    # ── Node 3: Update Dependencies ───────────────────────────────────────────

    async def update_dependencies(self, state: SecureFixState) -> Dict[str, Any]:
        """Compute the list of Dependency objects to be upgraded."""
        run_id = state["run_id"]
        vulns: List[Vulnerability] = state.get("vulnerabilities", [])
        local_path = state.get("local_repo_path", "")

        logger.info("node_update_deps", run_id=run_id)

        dep_service = DependencyService(local_path)
        updates: List[Dependency] = dep_service.build_dependency_updates(vulns)

        if not updates:
            logger.info("no_dependency_updates", run_id=run_id)
            return {
                "dependency_updates": [],
                "should_abort": True,
                "error_message": "No patchable dependency updates identified.",
                "status": "aborted",
                "current_node": "update_dependencies",
            }

        logger.info("dependency_updates_built", run_id=run_id, count=len(updates))

        # Optionally enrich updates with LLM patch reasoning
        for dep in updates:
            vuln = next((v for v in vulns if v.package_name == dep.name), None)
            if vuln:
                try:
                    prompt = PromptLibrary.patch_reasoning(dep, vuln)
                    response = await self._llm.generate_response(
                        prompt=prompt,
                        system_prompt=PromptLibrary.SYSTEM,
                    )
                    data = self._parse_llm_json(response.content)
                    if data:
                        dep.breaking_change_risk = data.get("breaking_change_risk")
                        dep.patch_notes = data.get("reasoning", "")[:500]
                except Exception as exc:
                    logger.debug("patch_reasoning_failed", package=dep.name, error=str(exc))

        return {
            "dependency_updates": updates,
            "status": "patching",
            "current_node": "update_dependencies",
        }

    # ── Node 4: Apply Patch ───────────────────────────────────────────────────

    async def apply_patch(self, state: SecureFixState) -> Dict[str, Any]:
        """Create a git branch, apply file changes, commit and push."""
        run_id = state["run_id"]
        local_path = state.get("local_repo_path", "")
        vulns: List[Vulnerability] = state.get("vulnerabilities", [])
        updates: List[Dependency] = state.get("dependency_updates", [])
        base_branch = state.get("base_branch", "main")

        logger.info("node_apply_patch", run_id=run_id)

        patch_svc = PatchService(local_path, run_id)
        patch_results = await patch_svc.apply_patch(vulns, updates, base_branch)

        # Determine branch name from results
        branch_name = ""
        applied = [r for r in patch_results if r.status == PatchStatus.APPLIED]
        if applied:
            branch_name = applied[0].branch_name or ""

        patch_success = bool(applied)

        if not patch_success:
            failed_msgs = [r.error_message for r in patch_results if r.error_message]
            return {
                "patch_results": patch_results,
                "patch_success": False,
                "branch_name": branch_name,
                "error_message": "; ".join(failed_msgs) or "Patch application failed.",
                "status": "failed",
                "current_node": "apply_patch",
            }

        return {
            "patch_results": patch_results,
            "patch_success": True,
            "branch_name": branch_name,
            "status": "testing",
            "current_node": "apply_patch",
        }

    # ── Node 5: Run Tests ─────────────────────────────────────────────────────

    async def run_tests(self, state: SecureFixState) -> Dict[str, Any]:
        """Execute the repository's test suite against the patched code."""
        run_id = state["run_id"]
        local_path = state.get("local_repo_path", "")

        logger.info("node_run_tests", run_id=run_id)

        if self._settings.skip_tests_on_patch:
            logger.info("tests_skipped_by_config")
            return {
                "test_results": [],
                "tests_passed": True,
                "status": "creating_pr",
                "current_node": "run_tests",
            }

        test_svc = TestService(local_path, run_id)
        test_results = await test_svc.run_tests()

        all_passed = all(
            r.passed or r.outcome in ("skipped", "not_run")
            for r in test_results
        )

        return {
            "test_results": test_results,
            "tests_passed": all_passed,
            "status": "creating_pr" if all_passed else "failed",
            "current_node": "run_tests",
        }

    # ── Node 6: Create Pull Request ───────────────────────────────────────────

    async def create_pull_request(self, state: SecureFixState) -> Dict[str, Any]:
        """Generate a PR description via LLM and open the pull request."""
        run_id = state["run_id"]
        owner = state.get("repo_owner", "")
        repo_name = state.get("repo_name", "")
        branch_name = state.get("branch_name", "")
        base_branch = state.get("base_branch", "main")
        vulns: List[Vulnerability] = state.get("vulnerabilities", [])
        updates: List[Dependency] = state.get("dependency_updates", [])
        test_results = state.get("test_results", [])
        ai_summary = state.get("ai_reasoning_summary", "")

        logger.info("node_create_pr", run_id=run_id, branch=branch_name)

        if not branch_name:
            return {
                "should_abort": True,
                "error_message": "No branch name found — cannot create PR.",
                "status": "failed",
                "current_node": "create_pull_request",
            }

        # Build PR body via LLM
        test_summary = TestService.format_test_summary(test_results)
        pr_prompt = PromptLibrary.pr_description(
            repo_name=f"{owner}/{repo_name}",
            branch_name=branch_name,
            vulns=vulns,
            deps=updates,
            test_results=test_summary,
            ai_reasoning=ai_summary or "See vulnerability analysis above.",
        )

        try:
            pr_response = await self._llm.generate_response(
                prompt=pr_prompt,
                system_prompt=PromptLibrary.SYSTEM,
            )
            pr_body = pr_response.content
        except Exception as exc:
            logger.warning("pr_body_generation_failed", error=str(exc))
            pr_body = self._fallback_pr_body(vulns, updates, test_summary, ai_summary)

        # Build PR title
        if len(vulns) == 1:
            title = f"Security Patch: Fix vulnerability in {vulns[0].package_name} ({vulns[0].id})"
        else:
            title = f"Security Patch: Fix {len(vulns)} dependency vulnerabilities"

        try:
            repo = self._gh_service.get_repository(owner, repo_name)
            pr = self._gh_service.create_pull_request(
                repo=repo,
                title=title,
                body=pr_body,
                head_branch=branch_name,
                base_branch=base_branch,
                labels=self._settings.pr_labels_list,
                draft=self._settings.pr_draft,
            )

            events.pull_request_created(run_id, f"{owner}/{repo_name}", pr.number, pr.html_url)

            return {
                "pr_created": True,
                "pr_url": pr.html_url,
                "pr_number": pr.number,
                "pr_body": pr_body,
                "status": "completed",
                "current_node": "create_pull_request",
            }

        except Exception as exc:
            logger.error("pr_creation_failed", error=str(exc))
            return {
                "pr_created": False,
                "error_message": f"PR creation failed: {exc}",
                "status": "failed",
                "current_node": "create_pull_request",
            }

    # ── Node 7: Complete ──────────────────────────────────────────────────────

    async def complete(self, state: SecureFixState) -> Dict[str, Any]:
        """Final cleanup node. Removes the local repository clone if configured."""
        run_id = state["run_id"]
        local_path = state.get("local_repo_path")

        logger.info(
            "workflow_completed",
            run_id=run_id,
            pr_url=state.get("pr_url"),
            vulnerabilities=len(state.get("vulnerabilities", [])),
        )

        if local_path and self._settings.cleanup_after_run:
            self._repo_service.cleanup(local_path)

        events.workflow_completed(
            run_id,
            status="completed",
            extra={
                "pr_url": state.get("pr_url"),
                "patch_count": len(state.get("patch_results", [])),
            },
        )

        return {"status": "completed", "current_node": "complete"}

    # ── Node 8: Abort ─────────────────────────────────────────────────────────

    async def abort(self, state: SecureFixState) -> Dict[str, Any]:
        """Graceful abort: log error, cleanup, record final status."""
        run_id = state["run_id"]
        error = state.get("error_message", "Unknown error")
        local_path = state.get("local_repo_path")

        logger.error("workflow_aborted", run_id=run_id, error=error)

        if local_path and self._settings.cleanup_after_run:
            self._repo_service.cleanup(local_path)

        events.workflow_completed(run_id, status="aborted", extra={"error": error})

        return {"status": "aborted", "current_node": "abort"}

    # ── Helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _parse_llm_json(content: str) -> Optional[Dict[str, Any]]:
        """Extract the first JSON object from an LLM response string."""
        import re
        match = re.search(r"\{[\s\S]*\}", content)
        if not match:
            return None
        try:
            return json.loads(match.group(0))
        except json.JSONDecodeError:
            return None

    @staticmethod
    def _fallback_pr_body(
        vulns: List[Vulnerability],
        deps: List[Dependency],
        test_summary: str,
        ai_summary: str,
    ) -> str:
        lines = [
            "## Security Patch — Generated by SecureFix AI",
            "",
            "### Vulnerabilities Fixed",
            "",
            "| ID | Package | Severity | Before | After |",
            "|---|---------|----------|--------|-------|",
        ]
        for v in vulns:
            target = v.target_version or "N/A"
            lines.append(f"| {v.id} | {v.package_name} | {v.severity} | {v.current_version} | {target} |")

        lines += ["", "### Changes", ""]
        for d in deps:
            lines.append(f"- `{d.dependency_file}`: `{d.name}` {d.current_version} → {d.target_version}")

        lines += ["", "### Test Results", "", test_summary, "", "### AI Analysis", "", ai_summary or "_N/A_"]
        return "\n".join(lines)
