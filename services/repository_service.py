from __future__ import annotations

import os
import re
import shutil
import tempfile
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

import git
from git import Repo

from utils.config import get_settings
from utils.logger import get_logger

logger = get_logger("securefix.service.repository")


def _sanitize_repo_path(path: str) -> Path:
    """
    Resolve the path and ensure it stays within the base clone directory.
    Raises ValueError on path traversal attempts.
    """
    settings = get_settings()
    base = Path(settings.repo_clone_base_dir).resolve()
    resolved = Path(path).resolve()
    try:
        resolved.relative_to(base)
    except ValueError:
        raise ValueError(
            f"Path '{resolved}' is outside the allowed base directory '{base}'. "
            "Potential path traversal detected."
        )
    return resolved


def _validate_github_url(url: str) -> None:
    """Allow only github.com HTTPS URLs to prevent SSRF."""
    parsed = urlparse(url)
    if parsed.scheme not in ("https",):
        raise ValueError(f"Only HTTPS GitHub URLs are permitted. Got scheme: {parsed.scheme!r}")
    if parsed.hostname not in ("github.com",):
        raise ValueError(f"Only github.com repositories are permitted. Got host: {parsed.hostname!r}")
    # Ensure no credential injection in URL
    if parsed.username or parsed.password:
        raise ValueError("Credentials must not be embedded in the repository URL.")


class RepositoryService:
    """
    Handles Git repository lifecycle: clone, branch, commit, push.
    All path operations are validated to prevent traversal attacks.
    """

    def __init__(self) -> None:
        self._settings = get_settings()
        self._base_dir = Path(self._settings.repo_clone_base_dir)
        self._base_dir.mkdir(parents=True, exist_ok=True)
        self._token = self._settings.github_token

    def clone_repository(self, repo_url: str, run_id: str) -> str:
        """
        Clone a GitHub repository into a sandboxed directory.

        Returns the local path of the cloned repository.
        """
        _validate_github_url(repo_url)

        # Inject token into HTTPS URL for authenticated clone.
        # Fine-grained PATs (github_pat_*) need "oauth2:" prefix; classic (ghp_*) use token as-is.
        parsed = urlparse(repo_url)
        token = (self._token or "").strip()
        if token.startswith("github_pat_"):
            auth = f"oauth2:{token}"
        else:
            auth = token
        auth_url = f"https://{auth}@{parsed.hostname}{parsed.path}" if auth else f"https://{parsed.hostname}{parsed.path}"

        repo_name = Path(parsed.path).stem
        clone_dir = self._base_dir / f"{repo_name}_{run_id}"

        # Prevent reuse of stale clones
        if clone_dir.exists():
            shutil.rmtree(clone_dir)

        logger.info("cloning_repository", repo=repo_url, dest=str(clone_dir))

        try:
            Repo.clone_from(auth_url, str(clone_dir), depth=1)
        except git.GitCommandError as exc:
            logger.error("clone_failed", repo=repo_url, error=str(exc))
            raise RuntimeError(f"Failed to clone repository: {exc}") from exc

        logger.info("clone_complete", path=str(clone_dir))
        return str(clone_dir)

    def create_branch(self, repo_path: str, branch_name: str) -> None:
        """Create and checkout a new branch in the local repository."""
        _sanitize_repo_path(repo_path)
        self._validate_branch_name(branch_name)

        repo = Repo(repo_path)
        if branch_name in [b.name for b in repo.branches]:
            logger.warning("branch_already_exists", branch=branch_name)
            repo.git.checkout(branch_name)
            return

        repo.git.checkout("-b", branch_name)
        logger.info("branch_created", branch=branch_name, path=repo_path)

    def commit_changes(
        self,
        repo_path: str,
        message: str,
        paths: Optional[list[str]] = None,
    ) -> str:
        """
        Stage specified paths (or all changes) and create a commit.
        Returns the commit SHA.
        """
        _sanitize_repo_path(repo_path)

        repo = Repo(repo_path)
        repo.config_writer().set_value(
            "user", "name", self._settings.git_committer_name
        ).release()
        repo.config_writer().set_value(
            "user", "email", self._settings.git_committer_email
        ).release()

        if paths:
            repo.index.add(paths)
        else:
            repo.git.add(A=True)

        commit = repo.index.commit(message)
        logger.info("commit_created", sha=commit.hexsha[:8], message=message[:60])
        return commit.hexsha

    def push_branch(self, repo_path: str, branch_name: str) -> None:
        """Push the branch to the origin remote."""
        _sanitize_repo_path(repo_path)
        self._validate_branch_name(branch_name)

        repo = Repo(repo_path)
        origin = repo.remote("origin")

        logger.info("pushing_branch", branch=branch_name)
        origin.push(refspec=f"{branch_name}:{branch_name}")
        logger.info("branch_pushed", branch=branch_name)

    def cleanup(self, repo_path: str) -> None:
        """Remove the local clone directory."""
        try:
            resolved = Path(repo_path).resolve()
            base = self._base_dir.resolve()
            resolved.relative_to(base)  # safety check
            shutil.rmtree(resolved, ignore_errors=True)
            logger.info("repo_cleanup_complete", path=str(resolved))
        except (ValueError, Exception) as exc:
            logger.warning("repo_cleanup_failed", error=str(exc))

    @staticmethod
    def _validate_branch_name(name: str) -> None:
        """Reject branch names containing shell metacharacters."""
        if re.search(r"[^\w.\-/]", name):
            raise ValueError(
                f"Branch name '{name}' contains invalid characters. "
                "Only alphanumeric, dot, dash, underscore, and slash are permitted."
            )
