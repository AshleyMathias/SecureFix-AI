from __future__ import annotations

from functools import lru_cache
from typing import Literal, Optional

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── Application ──────────────────────────────────────────────────────────
    app_name: str = Field(default="SecureFix AI")
    app_version: str = Field(default="1.0.0")
    environment: Literal["development", "staging", "production"] = Field(default="development")
    debug: bool = Field(default=False)
    log_level: str = Field(default="INFO")
    log_format: Literal["json", "text"] = Field(default="json")

    # ── Server ────────────────────────────────────────────────────────────────
    host: str = Field(default="0.0.0.0")
    port: int = Field(default=8000)
    workers: int = Field(default=1)

    # ── GitHub ────────────────────────────────────────────────────────────────
    github_token: str = Field(default="", description="GitHub personal access token")
    github_webhook_secret: Optional[str] = Field(default=None, description="Webhook HMAC secret")
    github_app_id: Optional[str] = Field(default=None)
    github_app_private_key: Optional[str] = Field(default=None)
    github_api_url: str = Field(default="https://api.github.com")
    git_committer_name: str = Field(default="SecureFix AI")
    git_committer_email: str = Field(default="securefix-ai@noreply.github.com")

    # ── LLM ───────────────────────────────────────────────────────────────────
    llm_provider: Literal["openai", "anthropic"] = Field(
        default="openai",
        description="Active LLM provider. Switch via LLM_PROVIDER env var."
    )
    openai_api_key: Optional[str] = Field(default=None)
    openai_model: str = Field(default="gpt-4o")
    openai_max_tokens: int = Field(default=4096)
    openai_temperature: float = Field(default=0.1, ge=0.0, le=2.0)

    anthropic_api_key: Optional[str] = Field(default=None)
    anthropic_model: str = Field(default="claude-3-5-sonnet-20241022")
    anthropic_max_tokens: int = Field(default=4096)
    anthropic_temperature: float = Field(default=0.1, ge=0.0, le=1.0)

    # ── Scanning ──────────────────────────────────────────────────────────────
    osv_api_url: str = Field(default="https://api.osv.dev/v1")
    scan_timeout_seconds: int = Field(default=120)
    enable_npm_audit: bool = Field(default=True)
    enable_pip_audit: bool = Field(default=True)
    enable_safety: bool = Field(default=True)
    enable_osv: bool = Field(default=True)

    # ── Patching ──────────────────────────────────────────────────────────────
    patch_branch_prefix: str = Field(default="securefix/")
    max_vulnerabilities_per_run: int = Field(default=20)
    skip_breaking_changes: bool = Field(default=False)
    auto_merge_pr: bool = Field(default=False)
    pr_draft: bool = Field(default=False)
    pr_labels: str = Field(default="security,automated,securefix-ai")

    # ── Testing ───────────────────────────────────────────────────────────────
    test_timeout_seconds: int = Field(default=300)
    skip_tests_on_patch: bool = Field(default=False)
    abort_on_test_failure: bool = Field(default=True)

    # ── Repository ────────────────────────────────────────────────────────────
    repo_clone_base_dir: str = Field(default="/tmp/securefix_repos")
    cleanup_after_run: bool = Field(default=True)

    @field_validator("pr_labels", mode="before")
    @classmethod
    def parse_labels(cls, v: str) -> str:
        return v.strip()

    @property
    def pr_labels_list(self) -> list[str]:
        return [lbl.strip() for lbl in self.pr_labels.split(",") if lbl.strip()]

    @property
    def is_production(self) -> bool:
        return self.environment == "production"


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
