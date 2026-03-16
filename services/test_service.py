from __future__ import annotations

import time
from pathlib import Path
from typing import List, Optional

from models.patch_result import TestOutcome, TestResult
from utils.config import get_settings
from utils.logger import get_logger, EventLogger
from utils.shell import run_command_async

logger = get_logger("securefix.service.test")
events = EventLogger("test_service")


class TestService:
    """
    Executes repository test suites after a dependency patch is applied.
    Supports both npm (JavaScript) and Python (pytest) projects.

    If no recognisable test configuration is found, tests are marked as skipped
    rather than failing the workflow.
    """

    def __init__(self, repo_path: str, run_id: str) -> None:
        self._repo_path = Path(repo_path)
        self._run_id = run_id
        self._settings = get_settings()

    async def run_tests(self) -> List[TestResult]:
        """Detect ecosystem and run all applicable test suites."""
        results: List[TestResult] = []

        if (self._repo_path / "package.json").exists():
            result = await self._run_npm_tests()
            results.append(result)

        if self._has_python_project():
            install_result = await self._pip_install()
            results.append(install_result)
            if install_result.passed:
                test_result = await self._run_pytest()
                results.append(test_result)

        if not results:
            logger.info("no_test_suite_detected", path=str(self._repo_path))
            results.append(
                TestResult(
                    command="(no test suite detected)",
                    outcome=TestOutcome.SKIPPED,
                    ecosystem="unknown",
                )
            )

        for result in results:
            if result.passed:
                events.tests_passed(self._run_id, result.ecosystem)
            elif result.outcome == TestOutcome.FAILED:
                events.tests_failed(self._run_id, result.ecosystem, result.stderr)

        return results

    async def _run_npm_tests(self) -> TestResult:
        """Run npm install followed by npm test."""
        # Install dependencies first
        install_start = time.monotonic()
        install_result = await run_command_async(
            ["npm", "install", "--prefer-offline"],
            cwd=str(self._repo_path),
            timeout=self._settings.test_timeout_seconds,
        )
        if not install_result.success:
            return TestResult(
                command="npm install",
                outcome=TestOutcome.ERROR,
                exit_code=install_result.exit_code,
                stdout=install_result.stdout,
                stderr=install_result.stderr,
                duration_seconds=time.monotonic() - install_start,
                ecosystem="npm",
            )

        test_start = time.monotonic()
        result = await run_command_async(
            ["npm", "test", "--", "--passWithNoTests"],
            cwd=str(self._repo_path),
            timeout=self._settings.test_timeout_seconds,
        )
        duration = time.monotonic() - test_start

        outcome = TestOutcome.PASSED if result.success else TestOutcome.FAILED
        logger.info("npm_tests_done", outcome=outcome, duration=round(duration, 2))

        return TestResult(
            command="npm test",
            outcome=outcome,
            exit_code=result.exit_code,
            stdout=result.stdout[-3000:],
            stderr=result.stderr[-2000:],
            duration_seconds=duration,
            ecosystem="npm",
        )

    async def _pip_install(self) -> TestResult:
        """Install Python dependencies."""
        req_file = self._repo_path / "requirements.txt"
        dev_req_file = self._repo_path / "requirements-dev.txt"

        args = ["pip", "install", "-r", str(req_file)]
        if dev_req_file.exists():
            args += ["-r", str(dev_req_file)]

        start = time.monotonic()
        result = await run_command_async(
            args,
            cwd=str(self._repo_path),
            timeout=self._settings.test_timeout_seconds,
        )
        duration = time.monotonic() - start
        outcome = TestOutcome.PASSED if result.success else TestOutcome.FAILED

        return TestResult(
            command=" ".join(args),
            outcome=outcome,
            exit_code=result.exit_code,
            stdout=result.stdout[-2000:],
            stderr=result.stderr[-1000:],
            duration_seconds=duration,
            ecosystem="python",
        )

    async def _run_pytest(self) -> TestResult:
        """Run pytest with a pass-with-no-tests flag."""
        start = time.monotonic()
        result = await run_command_async(
            ["pytest", "--tb=short", "-q", "--no-header"],
            cwd=str(self._repo_path),
            timeout=self._settings.test_timeout_seconds,
        )
        duration = time.monotonic() - start

        # pytest exits 5 when no tests collected — treat as skipped not failed
        if result.exit_code == 5:
            outcome = TestOutcome.SKIPPED
        elif result.success:
            outcome = TestOutcome.PASSED
        else:
            outcome = TestOutcome.FAILED

        logger.info("pytest_done", outcome=outcome, duration=round(duration, 2))

        return TestResult(
            command="pytest --tb=short -q",
            outcome=outcome,
            exit_code=result.exit_code,
            stdout=result.stdout[-3000:],
            stderr=result.stderr[-1000:],
            duration_seconds=duration,
            ecosystem="python",
        )

    def _has_python_project(self) -> bool:
        indicators = [
            "requirements.txt",
            "pyproject.toml",
            "setup.py",
            "setup.cfg",
            "Pipfile",
        ]
        return any((self._repo_path / f).exists() for f in indicators)

    @staticmethod
    def format_test_summary(results: List[TestResult]) -> str:
        """Produce a markdown table suitable for PR descriptions."""
        if not results:
            return "_No tests executed._"

        lines = [
            "| Test Suite | Outcome | Duration |",
            "|-----------|---------|----------|",
        ]
        for r in results:
            icon = {"passed": "✅", "failed": "❌", "skipped": "⏭️", "error": "⚠️"}.get(
                r.outcome, "❓"
            )
            lines.append(
                f"| `{r.command[:40]}` | {icon} {r.outcome} | {r.duration_seconds:.1f}s |"
            )
        return "\n".join(lines)
