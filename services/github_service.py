from __future__ import annotations

from typing import List, Optional

from github import Github, GithubException
from github.Repository import Repository
from github.PullRequest import PullRequest

from utils.config import get_settings
from utils.logger import get_logger

logger = get_logger("securefix.service.github")


class GitHubService:
    """
    Wraps PyGithub to provide all GitHub API operations required by SecureFix AI:
    branch management, pull request creation, commenting, and label management.
    """

    def __init__(self) -> None:
        self._settings = get_settings()
        self._gh = Github(self._settings.github_token)

    def get_repository(self, owner: str, repo_name: str) -> Repository:
        """Return a PyGithub Repository object."""
        try:
            repo = self._gh.get_repo(f"{owner}/{repo_name}")
            logger.debug("github_repo_fetched", repo=f"{owner}/{repo_name}")
            return repo
        except GithubException as exc:
            logger.error("github_repo_fetch_failed", repo=f"{owner}/{repo_name}", error=str(exc))
            raise

    def create_pull_request(
        self,
        repo: Repository,
        title: str,
        body: str,
        head_branch: str,
        base_branch: str = "main",
        labels: Optional[List[str]] = None,
        draft: bool = False,
    ) -> PullRequest:
        """
        Create a pull request. Ensures required labels exist before assigning them.
        """
        logger.info(
            "creating_pull_request",
            repo=repo.full_name,
            head=head_branch,
            base=base_branch,
            title=title[:60],
        )

        try:
            pr = repo.create_pull(
                title=title,
                body=body,
                head=head_branch,
                base=base_branch,
                draft=draft,
            )
        except GithubException as exc:
            logger.error("pr_creation_failed", error=str(exc))
            raise

        if labels:
            self._ensure_labels_exist(repo, labels)
            pr.set_labels(*labels)

        logger.info("pull_request_created", pr_number=pr.number, url=pr.html_url)
        return pr

    def add_pr_comment(self, pr: PullRequest, comment: str) -> None:
        """Post a comment on an existing pull request."""
        try:
            pr.create_issue_comment(comment)
            logger.debug("pr_comment_added", pr_number=pr.number)
        except GithubException as exc:
            logger.warning("pr_comment_failed", pr_number=pr.number, error=str(exc))

    def add_issue_comment(self, repo: Repository, issue_number: int, comment: str) -> None:
        """Add a comment to any GitHub issue or PR by number."""
        try:
            issue = repo.get_issue(issue_number)
            issue.create_comment(comment)
        except GithubException as exc:
            logger.warning("issue_comment_failed", issue=issue_number, error=str(exc))

    def get_default_branch(self, repo: Repository) -> str:
        """Return the repository's default branch name."""
        return repo.default_branch

    def branch_exists(self, repo: Repository, branch_name: str) -> bool:
        """Check if a branch already exists in the remote repository."""
        try:
            repo.get_branch(branch_name)
            return True
        except GithubException:
            return False

    def get_open_prs_for_branch(self, repo: Repository, branch_name: str) -> List[PullRequest]:
        """Return open PRs from the given head branch."""
        return list(
            repo.get_pulls(state="open", head=f"{repo.owner.login}:{branch_name}")
        )

    def _ensure_labels_exist(self, repo: Repository, label_names: List[str]) -> None:
        """Create labels if they don't exist. Assigns default colours."""
        _default_colors = {
            "security": "d73a4a",
            "automated": "0075ca",
            "securefix-ai": "7057ff",
        }
        existing = {lbl.name for lbl in repo.get_labels()}

        for name in label_names:
            if name not in existing:
                color = _default_colors.get(name, "ededed")
                try:
                    repo.create_label(name=name, color=color)
                    logger.debug("github_label_created", label=name)
                except GithubException as exc:
                    logger.warning("github_label_create_failed", label=name, error=str(exc))

    def parse_repo_url(self, url: str) -> tuple[str, str]:
        """
        Parse a GitHub URL into (owner, repo_name).
        Supports https://github.com/owner/repo and github.com/owner/repo formats.
        """
        url = url.rstrip("/").removesuffix(".git")
        parts = url.split("/")
        if len(parts) < 2:
            raise ValueError(f"Cannot parse repository URL: {url!r}")
        return parts[-2], parts[-1]
