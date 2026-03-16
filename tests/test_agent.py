"""
Unit tests for the LangGraph agent state and graph structure.
"""
from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agent.state import SecureFixState, initial_state
from agent.graph_builder import (
    _route_after_detection,
    _route_after_patch,
    _route_after_tests,
)
from models.vulnerability import Vulnerability, VulnerabilitySeverity, VulnerabilitySource


# ── State factory ─────────────────────────────────────────────────────────────

class TestInitialState:
    def test_creates_required_fields(self) -> None:
        state = initial_state(
            run_id="test-run-001",
            repo_url="https://github.com/owner/repo",
        )
        assert state["run_id"] == "test-run-001"
        assert state["repo_url"] == "https://github.com/owner/repo"
        assert state["base_branch"] == "main"
        assert state["status"] == "initializing"
        assert state["vulnerabilities"] == []
        assert state["patch_success"] is False
        assert state["tests_passed"] is False
        assert state["pr_created"] is False

    def test_custom_base_branch(self) -> None:
        state = initial_state(run_id="r", repo_url="https://github.com/a/b", base_branch="develop")
        assert state["base_branch"] == "develop"


# ── Routing functions ─────────────────────────────────────────────────────────

def _make_vuln(patchable: bool = True) -> Vulnerability:
    return Vulnerability(
        id="TEST-001",
        package_name="pkg",
        ecosystem="npm",
        severity=VulnerabilitySeverity.HIGH,
        source=VulnerabilitySource.NPM_AUDIT,
        current_version="1.0.0",
        fixed_version="1.0.1" if patchable else None,
    )


class TestRoutingFunctions:
    def test_route_after_detection_no_vulns(self) -> None:
        state = initial_state("r", "https://github.com/a/b")
        state["vulnerabilities"] = []
        assert _route_after_detection(state) == "complete"

    def test_route_after_detection_patchable(self) -> None:
        state = initial_state("r", "https://github.com/a/b")
        state["vulnerabilities"] = [_make_vuln(patchable=True)]
        assert _route_after_detection(state) == "reason"

    def test_route_after_detection_no_patchable(self) -> None:
        state = initial_state("r", "https://github.com/a/b")
        state["vulnerabilities"] = [_make_vuln(patchable=False)]
        assert _route_after_detection(state) == "complete"

    def test_route_after_detection_abort(self) -> None:
        state = initial_state("r", "https://github.com/a/b")
        state["should_abort"] = True
        assert _route_after_detection(state) == "abort"

    def test_route_after_patch_success(self) -> None:
        state = initial_state("r", "https://github.com/a/b")
        state["patch_success"] = True
        assert _route_after_patch(state) == "test"

    def test_route_after_patch_failure(self) -> None:
        state = initial_state("r", "https://github.com/a/b")
        state["patch_success"] = False
        assert _route_after_patch(state) == "abort"

    def test_route_after_tests_passed(self) -> None:
        state = initial_state("r", "https://github.com/a/b")
        state["tests_passed"] = True
        # Settings default: abort_on_test_failure=True, but tests passed so goes to pr
        result = _route_after_tests(state)
        assert result == "pr"

    def test_route_after_tests_abort_on_failure(self) -> None:
        state = initial_state("r", "https://github.com/a/b")
        state["tests_passed"] = False

        mock_cfg = MagicMock()
        mock_cfg.abort_on_test_failure = True
        with patch("agent.graph_builder.get_settings", return_value=mock_cfg):
            assert _route_after_tests(state) == "abort"

    def test_route_after_tests_continue_on_failure(self) -> None:
        state = initial_state("r", "https://github.com/a/b")
        state["tests_passed"] = False

        mock_cfg = MagicMock()
        mock_cfg.abort_on_test_failure = False
        with patch("agent.graph_builder.get_settings", return_value=mock_cfg):
            assert _route_after_tests(state) == "pr"
