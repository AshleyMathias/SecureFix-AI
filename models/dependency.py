from __future__ import annotations

from enum import Enum
from typing import Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field


class DependencyEcosystem(str, Enum):
    NPM = "npm"
    PYPI = "pypi"
    MAVEN = "maven"
    CARGO = "cargo"
    GO = "go"
    RUBYGEMS = "rubygems"
    UNKNOWN = "unknown"


class DependencyFile(str, Enum):
    PACKAGE_JSON = "package.json"
    PACKAGE_LOCK_JSON = "package-lock.json"
    YARN_LOCK = "yarn.lock"
    REQUIREMENTS_TXT = "requirements.txt"
    PYPROJECT_TOML = "pyproject.toml"
    POETRY_LOCK = "poetry.lock"
    PIPFILE = "Pipfile"
    PIPFILE_LOCK = "Pipfile.lock"
    SETUP_PY = "setup.py"
    SETUP_CFG = "setup.cfg"


class Dependency(BaseModel):
    name: str = Field(..., description="Package name")
    ecosystem: DependencyEcosystem = Field(..., description="Package ecosystem")
    current_version: str = Field(..., description="Currently pinned version")
    target_version: str = Field(..., description="Version to upgrade to")
    dependency_file: str = Field(..., description="File containing this dependency")
    is_dev_dependency: bool = Field(default=False)
    is_direct: bool = Field(default=True, description="Direct vs transitive dependency")
    vulnerability_ids: List[str] = Field(default_factory=list, description="Related vulnerability IDs")
    breaking_change_risk: Optional[str] = Field(
        default=None,
        description="LLM assessment of breaking change risk (low/medium/high)"
    )
    patch_notes: Optional[str] = Field(default=None, description="Notes about the patch")
    metadata: Dict = Field(default_factory=dict)

    model_config = ConfigDict(use_enum_values=True)

    @property
    def upgrade_spec(self) -> str:
        return f"{self.name}=={self.target_version}" if self.ecosystem == DependencyEcosystem.PYPI else f"{self.name}@{self.target_version}"

    def __repr__(self) -> str:
        return (
            f"Dependency(name={self.name!r}, {self.current_version!r} -> {self.target_version!r}, "
            f"file={self.dependency_file!r})"
        )
