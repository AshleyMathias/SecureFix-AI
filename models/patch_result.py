from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field


class PatchStatus(str, Enum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    APPLIED = "applied"
    FAILED = "failed"
    SKIPPED = "skipped"
    REVERTED = "reverted"


class TestOutcome(str, Enum):
    PASSED = "passed"
    FAILED = "failed"
    SKIPPED = "skipped"
    NOT_RUN = "not_run"
    ERROR = "error"


class TestResult(BaseModel):
    command: str = Field(..., description="Test command executed")
    outcome: TestOutcome = Field(...)
    exit_code: int = Field(default=0)
    stdout: str = Field(default="")
    stderr: str = Field(default="")
    duration_seconds: float = Field(default=0.0)
    ecosystem: str = Field(default="")

    @property
    def passed(self) -> bool:
        return self.outcome == TestOutcome.PASSED


class PatchResult(BaseModel):
    vulnerability_id: str = Field(..., description="ID of the resolved vulnerability")
    package_name: str = Field(...)
    from_version: str = Field(...)
    to_version: str = Field(...)
    dependency_file: str = Field(...)
    status: PatchStatus = Field(default=PatchStatus.PENDING)
    branch_name: Optional[str] = Field(default=None, description="Git branch created for this patch")
    commit_sha: Optional[str] = Field(default=None)
    pull_request_url: Optional[str] = Field(default=None)
    pull_request_number: Optional[int] = Field(default=None)
    test_results: List[TestResult] = Field(default_factory=list)
    ai_reasoning: Optional[str] = Field(default=None, description="LLM explanation of the fix")
    error_message: Optional[str] = Field(default=None)
    applied_at: Optional[datetime] = Field(default=None)
    metadata: Dict = Field(default_factory=dict)

    model_config = ConfigDict(use_enum_values=True)

    @property
    def all_tests_passed(self) -> bool:
        if not self.test_results:
            return True
        return all(r.passed for r in self.test_results if r.outcome != TestOutcome.NOT_RUN)

    @property
    def summary(self) -> str:
        return (
            f"Patched {self.package_name}: {self.from_version} → {self.to_version} "
            f"[{self.status}]"
        )
