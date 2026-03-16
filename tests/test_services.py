"""
Unit tests for SecureFix AI services.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from unittest.mock import MagicMock, patch

from models.vulnerability import Vulnerability, VulnerabilitySeverity, VulnerabilitySource
from models.dependency import DependencyEcosystem
from services.dependency_service import DependencyService
from services.patch_service import PatchService


# ── DependencyService ─────────────────────────────────────────────────────────

class TestDependencyService:
    @pytest.fixture()
    def npm_repo(self, tmp_path: Path) -> Path:
        pkg = {
            "name": "test-app",
            "dependencies": {"lodash": "^4.17.15", "axios": "~0.21.1"},
            "devDependencies": {"jest": "^29.0.0"},
        }
        (tmp_path / "package.json").write_text(json.dumps(pkg, indent=2))
        return tmp_path

    @pytest.fixture()
    def python_repo(self, tmp_path: Path) -> Path:
        (tmp_path / "requirements.txt").write_text(
            "Flask==2.0.1\nrequests==2.25.1\nPillow==8.2.0\n"
        )
        return tmp_path

    def test_update_package_json(self, npm_repo: Path) -> None:
        svc = DependencyService(str(npm_repo))
        svc._update_package_json(npm_repo / "package.json", "lodash", "4.17.21")

        data = json.loads((npm_repo / "package.json").read_text())
        assert data["dependencies"]["lodash"] == "^4.17.21"

    def test_update_requirements_txt(self, python_repo: Path) -> None:
        svc = DependencyService(str(python_repo))
        svc._update_requirements_txt(python_repo / "requirements.txt", "Pillow", "9.0.0")

        content = (python_repo / "requirements.txt").read_text()
        assert "Pillow==9.0.0" in content
        assert "8.2.0" not in content

    def test_build_dependency_updates_npm(self, npm_repo: Path) -> None:
        svc = DependencyService(str(npm_repo))
        vuln = Vulnerability(
            id="GHSA-35jh-r3h4-6jhm",
            package_name="lodash",
            ecosystem="npm",
            severity=VulnerabilitySeverity.HIGH,
            source=VulnerabilitySource.NPM_AUDIT,
            current_version="4.17.15",
            fixed_version="4.17.21",
        )
        updates = svc.build_dependency_updates([vuln])
        assert len(updates) == 1
        assert updates[0].name == "lodash"
        assert updates[0].target_version == "4.17.21"
        assert updates[0].ecosystem == DependencyEcosystem.NPM

    def test_build_dependency_updates_no_fix(self, npm_repo: Path) -> None:
        """Vulnerabilities without fixed_version must not produce updates."""
        svc = DependencyService(str(npm_repo))
        vuln = Vulnerability(
            id="TEST-001",
            package_name="lodash",
            ecosystem="npm",
            severity=VulnerabilitySeverity.LOW,
            source=VulnerabilitySource.NPM_AUDIT,
            current_version="4.17.15",
            fixed_version=None,
        )
        updates = svc.build_dependency_updates([vuln])
        assert updates == []

    def test_requirements_txt_case_insensitive(self, python_repo: Path) -> None:
        svc = DependencyService(str(python_repo))
        # Package name with different casing
        svc._update_requirements_txt(python_repo / "requirements.txt", "pillow", "10.0.0")
        content = (python_repo / "requirements.txt").read_text()
        assert "10.0.0" in content


# ── PatchService ──────────────────────────────────────────────────────────────

def _mock_settings():
    cfg = MagicMock()
    cfg.patch_branch_prefix = "securefix/"
    cfg.github_token = "test-token"
    cfg.git_committer_name = "SecureFix AI"
    cfg.git_committer_email = "securefix@test.com"
    cfg.repo_clone_base_dir = "/tmp/securefix_repos"
    cfg.cleanup_after_run = False
    cfg.skip_tests_on_patch = False
    cfg.abort_on_test_failure = True
    return cfg


class TestPatchService:
    def test_generate_branch_name_single_vuln(self, tmp_path: Path) -> None:
        with patch("services.patch_service.get_settings", return_value=_mock_settings()):
            svc = PatchService(str(tmp_path), run_id="abc12345")
            vuln = Vulnerability(
                id="TEST-001",
                package_name="lodash",
                ecosystem="npm",
                severity=VulnerabilitySeverity.HIGH,
                source=VulnerabilitySource.NPM_AUDIT,
                current_version="4.17.15",
            )
            branch = svc.generate_branch_name([vuln])
        assert branch.startswith("securefix/")
        assert "lodash" in branch
        assert "high" in branch
        assert "abc12345"[:8] in branch

    def test_generate_branch_name_batch(self, tmp_path: Path) -> None:
        with patch("services.patch_service.get_settings", return_value=_mock_settings()):
            svc = PatchService(str(tmp_path), run_id="xyz99999")
            vulns = [
                Vulnerability(
                    id=f"TEST-00{i}",
                    package_name=f"pkg{i}",
                    ecosystem="npm",
                    severity=VulnerabilitySeverity.HIGH,
                    source=VulnerabilitySource.NPM_AUDIT,
                    current_version="1.0.0",
                )
                for i in range(3)
            ]
            branch = svc.generate_branch_name(vulns)
        assert "batch-3" in branch
