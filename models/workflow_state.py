from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field

from .vulnerability import Vulnerability
from .dependency import Dependency
from .patch_result import PatchResult, TestResult


class WorkflowStatus(str, Enum):
    INITIALIZING = "initializing"
    SCANNING = "scanning"
    REASONING = "reasoning"
    PATCHING = "patching"
    TESTING = "testing"
    CREATING_PR = "creating_pr"
    COMPLETED = "completed"
    FAILED = "failed"
    ABORTED = "aborted"


class WorkflowState(BaseModel):
    """
    Pydantic model representing the full state of a SecureFix workflow run.
    Serializable for LangGraph state persistence.
    """
    run_id: str = Field(..., description="Unique workflow run identifier")
    repo_url: str = Field(..., description="GitHub repository URL")
    repo_owner: str = Field(default="", description="Repository owner/org")
    repo_name: str = Field(default="", description="Repository name")
    base_branch: str = Field(default="main", description="Target branch for PR")
    branch_name: str = Field(default="", description="Patch branch name")
    local_repo_path: Optional[str] = Field(default=None, description="Local clone path")

    status: WorkflowStatus = Field(default=WorkflowStatus.INITIALIZING)
    current_node: str = Field(default="", description="Currently executing LangGraph node")

    vulnerabilities: List[Vulnerability] = Field(default_factory=list)
    dependency_updates: List[Dependency] = Field(default_factory=list)
    patch_results: List[PatchResult] = Field(default_factory=list)
    test_results: List[TestResult] = Field(default_factory=list)

    patch_success: bool = Field(default=False)
    tests_passed: bool = Field(default=False)
    pr_created: bool = Field(default=False)
    pr_url: Optional[str] = Field(default=None)
    pr_number: Optional[int] = Field(default=None)

    ai_reasoning_summary: Optional[str] = Field(default=None)
    error_message: Optional[str] = Field(default=None)
    retry_count: int = Field(default=0)
    max_retries: int = Field(default=3)

    triggered_by: str = Field(default="webhook", description="Trigger source")
    webhook_event: Optional[str] = Field(default=None)
    webhook_payload: Dict[str, Any] = Field(default_factory=dict)

    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: Optional[datetime] = Field(default=None)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(use_enum_values=True)

    @property
    def duration_seconds(self) -> Optional[float]:
        if self.completed_at:
            return (self.completed_at - self.started_at).total_seconds()
        return None

    @property
    def vulnerability_count(self) -> int:
        return len(self.vulnerabilities)

    @property
    def patchable_count(self) -> int:
        return sum(1 for v in self.vulnerabilities if v.is_patchable)

    def mark_completed(self) -> None:
        self.status = WorkflowStatus.COMPLETED
        self.completed_at = datetime.now(timezone.utc)

    def mark_failed(self, error: str) -> None:
        self.status = WorkflowStatus.FAILED
        self.error_message = error
        self.completed_at = datetime.now(timezone.utc)

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump(mode="json")
