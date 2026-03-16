from __future__ import annotations

from typing import Any, Dict, List, Optional

from typing_extensions import TypedDict

from models.vulnerability import Vulnerability
from models.dependency import Dependency
from models.patch_result import PatchResult, TestResult


class SecureFixState(TypedDict, total=False):
    """
    LangGraph state object representing the full context of a SecureFix workflow.

    This TypedDict is passed between all LangGraph nodes. Each node reads
    relevant fields and returns a partial dict with updated values.
    Using TypedDict (not Pydantic) is the LangGraph-idiomatic approach
    since LangGraph uses shallow merging of state updates.
    """

    # ── Identity ──────────────────────────────────────────────────────────────
    run_id: str
    repo_url: str
    repo_owner: str
    repo_name: str
    base_branch: str
    branch_name: str
    local_repo_path: Optional[str]

    # ── Workflow control ──────────────────────────────────────────────────────
    status: str
    current_node: str
    error_message: Optional[str]
    retry_count: int
    should_abort: bool

    # ── Detection outputs ─────────────────────────────────────────────────────
    vulnerabilities: List[Vulnerability]

    # ── AI reasoning outputs ──────────────────────────────────────────────────
    dependency_updates: List[Dependency]
    ai_reasoning_summary: Optional[str]

    # ── Patch outputs ─────────────────────────────────────────────────────────
    patch_results: List[PatchResult]
    patch_success: bool

    # ── Test outputs ──────────────────────────────────────────────────────────
    test_results: List[TestResult]
    tests_passed: bool

    # ── PR outputs ────────────────────────────────────────────────────────────
    pr_created: bool
    pr_url: Optional[str]
    pr_number: Optional[int]
    pr_body: Optional[str]

    # ── Trigger metadata ──────────────────────────────────────────────────────
    triggered_by: str
    webhook_event: Optional[str]
    webhook_payload: Dict[str, Any]

    # ── Telemetry ─────────────────────────────────────────────────────────────
    metadata: Dict[str, Any]


def initial_state(
    run_id: str,
    repo_url: str,
    base_branch: str = "main",
    triggered_by: str = "webhook",
    webhook_event: Optional[str] = None,
    webhook_payload: Optional[Dict[str, Any]] = None,
) -> SecureFixState:
    """Factory: create a fully-initialised SecureFixState for a new workflow run."""
    return SecureFixState(
        run_id=run_id,
        repo_url=repo_url,
        repo_owner="",
        repo_name="",
        base_branch=base_branch,
        branch_name="",
        local_repo_path=None,
        status="initializing",
        current_node="",
        error_message=None,
        retry_count=0,
        should_abort=False,
        vulnerabilities=[],
        dependency_updates=[],
        ai_reasoning_summary=None,
        patch_results=[],
        patch_success=False,
        test_results=[],
        tests_passed=False,
        pr_created=False,
        pr_url=None,
        pr_number=None,
        pr_body=None,
        triggered_by=triggered_by,
        webhook_event=webhook_event,
        webhook_payload=webhook_payload or {},
        metadata={},
    )
