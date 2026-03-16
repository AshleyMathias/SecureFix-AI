from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from models.dependency import Dependency, DependencyEcosystem
from models.vulnerability import Vulnerability
from utils.logger import get_logger

logger = get_logger("securefix.service.dependency")


class DependencyService:
    """
    Reads and writes dependency manifest files to apply version upgrades.

    Supported formats:
    - package.json      (npm)
    - requirements.txt  (pip)
    - pyproject.toml    (Poetry / PEP 621)
    """

    def __init__(self, repo_path: str) -> None:
        self._repo_path = Path(repo_path)

    def build_dependency_updates(
        self,
        vulnerabilities: List[Vulnerability],
    ) -> List[Dependency]:
        """
        Convert a list of vulnerabilities into Dependency update objects
        by matching them to actual dependency files in the repository.
        """
        updates: List[Dependency] = []

        for vuln in vulnerabilities:
            if not vuln.target_version:
                logger.debug("no_fix_available", vuln_id=vuln.id, package=vuln.package_name)
                continue

            dep_file, ecosystem = self._locate_dependency(vuln.package_name, vuln.ecosystem)
            if not dep_file:
                logger.warning(
                    "dependency_file_not_found",
                    package=vuln.package_name,
                    ecosystem=vuln.ecosystem,
                )
                continue

            dep = Dependency(
                name=vuln.package_name,
                ecosystem=ecosystem,
                current_version=vuln.current_version,
                target_version=vuln.target_version,
                dependency_file=str(dep_file.relative_to(self._repo_path)),
                vulnerability_ids=[vuln.id],
            )
            updates.append(dep)

        # Deduplicate: if same package appears in multiple vulns, keep latest target
        return self._deduplicate_updates(updates)

    def apply_updates(self, updates: List[Dependency]) -> List[str]:
        """
        Modify dependency files in place for each update.
        Returns a list of modified file paths (relative to repo root).
        """
        modified_files: list[str] = []

        for dep in updates:
            file_path = self._repo_path / dep.dependency_file
            if not file_path.exists():
                logger.warning("dep_file_missing", path=str(file_path))
                continue

            try:
                if dep.dependency_file.endswith("package.json"):
                    self._update_package_json(file_path, dep.name, dep.target_version)
                elif dep.dependency_file.endswith("requirements.txt") or "requirements" in dep.dependency_file:
                    self._update_requirements_txt(file_path, dep.name, dep.target_version)
                elif dep.dependency_file.endswith("pyproject.toml"):
                    self._update_pyproject_toml(file_path, dep.name, dep.target_version)
                else:
                    logger.warning("unsupported_dep_file", file=dep.dependency_file)
                    continue

                modified_files.append(dep.dependency_file)
                logger.info(
                    "dependency_updated",
                    package=dep.name,
                    from_v=dep.current_version,
                    to_v=dep.target_version,
                    file=dep.dependency_file,
                )
            except Exception as exc:
                logger.error(
                    "dependency_update_failed",
                    package=dep.name,
                    file=dep.dependency_file,
                    error=str(exc),
                )

        return list(set(modified_files))

    # ── package.json ─────────────────────────────────────────────────────────

    def _update_package_json(self, file_path: Path, package: str, version: str) -> None:
        content = json.loads(file_path.read_text(encoding="utf-8"))

        updated = False
        for section in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
            if package in content.get(section, {}):
                old = content[section][package]
                # Preserve range prefixes (^, ~, >=)
                prefix = re.match(r"^[~^>=<]*", old).group(0) if re.match(r"^[~^>=<]*", old) else ""
                content[section][package] = f"{prefix}{version}"
                logger.debug("package_json_updated", package=package, old=old, new=content[section][package])
                updated = True

        if not updated:
            logger.warning("package_not_found_in_json", package=package, file=str(file_path))
            return

        file_path.write_text(
            json.dumps(content, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )

    # ── requirements.txt ─────────────────────────────────────────────────────

    def _update_requirements_txt(self, file_path: Path, package: str, version: str) -> None:
        lines = file_path.read_text(encoding="utf-8").splitlines(keepends=True)
        new_lines = []
        updated = False

        for line in lines:
            stripped = line.strip()
            if stripped.startswith("#") or not stripped:
                new_lines.append(line)
                continue

            # Match package name (case-insensitive, supports extras e.g. requests[security])
            match = re.match(
                rf"^({re.escape(package)}(\[[\w,\s]+\])?\s*)([=<>!~]+\s*[\d.*]+)?",
                stripped,
                re.IGNORECASE,
            )
            if match:
                pkg_part = match.group(1).rstrip()
                new_lines.append(f"{pkg_part}=={version}\n")
                updated = True
            else:
                new_lines.append(line)

        if not updated:
            logger.warning("package_not_found_in_requirements", package=package, file=str(file_path))
            return

        file_path.write_text("".join(new_lines), encoding="utf-8")

    # ── pyproject.toml ────────────────────────────────────────────────────────

    def _update_pyproject_toml(self, file_path: Path, package: str, version: str) -> None:
        content = file_path.read_text(encoding="utf-8")
        # Use regex to replace version in [tool.poetry.dependencies] or [project.dependencies]
        # This avoids requiring tomlkit and handles both Poetry and PEP 621 style.
        pattern = re.compile(
            rf'({re.escape(package)}\s*=\s*)"[^"]*"',
            re.IGNORECASE,
        )
        alt_pattern = re.compile(
            rf'({re.escape(package)}\s*=\s*)\{{[^}}]*version\s*=\s*"[^"]*"',
            re.IGNORECASE,
        )

        if pattern.search(content):
            new_content = pattern.sub(rf'\1"^{version}"', content)
        elif alt_pattern.search(content):
            new_content = re.sub(
                rf'(version\s*=\s*)"[^"]*"',
                f'"^{version}"',
                content,
            )
        else:
            logger.warning("package_not_found_in_pyproject", package=package, file=str(file_path))
            return

        file_path.write_text(new_content, encoding="utf-8")

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _locate_dependency(
        self, package_name: str, ecosystem: str
    ) -> Tuple[Optional[Path], DependencyEcosystem]:
        eco = ecosystem.lower()

        if eco == "npm":
            candidate = self._repo_path / "package.json"
            if candidate.exists():
                return candidate, DependencyEcosystem.NPM

        elif eco in ("pypi", "pip", "python"):
            for fname in ("requirements.txt", "pyproject.toml", "requirements/base.txt"):
                candidate = self._repo_path / fname
                if candidate.exists():
                    return candidate, DependencyEcosystem.PYPI

        return None, DependencyEcosystem.UNKNOWN

    @staticmethod
    def _deduplicate_updates(updates: List[Dependency]) -> List[Dependency]:
        """Keep one update per package, preferring newer target versions."""
        seen: Dict[str, Dependency] = {}
        for dep in updates:
            key = f"{dep.name}:{dep.dependency_file}"
            if key not in seen:
                seen[key] = dep
            else:
                # Naive version comparison: prefer higher string (works for semver)
                existing = seen[key]
                if dep.target_version > existing.target_version:
                    dep.vulnerability_ids = list(
                        set(existing.vulnerability_ids + dep.vulnerability_ids)
                    )
                    seen[key] = dep
        return list(seen.values())
