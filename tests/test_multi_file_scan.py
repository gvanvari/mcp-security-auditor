"""
Tests for P2-1 — Package / multi-file scanning.

Validates that scan_all:
  - Finds .py files recursively in subdirectories.
  - Excludes configured directories (.venv, __pycache__, tests, etc.).
  - Reports findings attributed to the correct file (relative path).
  - Handles packages with no findings cleanly.

All tests use temporary directories — no real MCP corpus files are needed.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from mcp_auditor.analyzer import Analyzer


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_CLEAN_SOURCE = """\
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("clean")

@mcp.tool()
def add(a: int, b: int) -> int:
    return a + b
"""

_VULNERABLE_SOURCE = """\
from mcp.server.fastmcp import FastMCP
import subprocess
mcp = FastMCP("vuln")

@mcp.tool()
def run(cmd: str) -> str:
    subprocess.run(cmd, shell=True)
    return ""
"""


def _make_package(structure: dict[str, str]) -> Path:
    """
    Create a temp directory tree from a {relative_path: source} dict.
    Returns the root directory path.
    """
    root = Path(tempfile.mkdtemp())
    for rel, src in structure.items():
        target = root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(src, encoding="utf-8")
    return root


def _collect_findings(root: Path) -> dict[str, list]:
    """
    Mirror the core of scan_all — collect findings per relative .py file,
    respecting the exclusion rules.  Returns {rel_path_str: findings_list}.
    """
    from mcp_auditor.analyzer import _EXCLUDED_DIRS_SET  # imported below

    analyzer = Analyzer()
    results: dict[str, list] = {}

    def _is_excluded(path: Path) -> bool:
        return any(part in _EXCLUDED_DIRS_SET for part in path.relative_to(root).parts)

    for py_file in sorted(root.rglob("*.py")):
        if not _is_excluded(py_file):
            rel = str(py_file.relative_to(root))
            results[rel] = analyzer.analyze(str(py_file))
    return results


# ---------------------------------------------------------------------------
# Unit: _EXCLUDED_DIRS_SET is exported so tests can reuse it
# ---------------------------------------------------------------------------

class TestExcludedDirsExported:
    def test_excluded_dirs_set_importable(self):
        from mcp_auditor.analyzer import _EXCLUDED_DIRS_SET
        assert isinstance(_EXCLUDED_DIRS_SET, frozenset)
        assert ".venv" in _EXCLUDED_DIRS_SET
        assert "__pycache__" in _EXCLUDED_DIRS_SET
        assert "tests" in _EXCLUDED_DIRS_SET


# ---------------------------------------------------------------------------
# TestRecursiveDiscovery
# ---------------------------------------------------------------------------

class TestRecursiveDiscovery:
    """Vulnerable files in subdirectories must be found."""

    def test_subdir_file_is_scanned(self):
        root = _make_package({
            "tools/dangerous.py": _VULNERABLE_SOURCE,
        })
        results = _collect_findings(root)
        assert "tools/dangerous.py" in results

    def test_findings_from_subdir_are_non_empty(self):
        root = _make_package({
            "tools/dangerous.py": _VULNERABLE_SOURCE,
        })
        results = _collect_findings(root)
        assert len(results["tools/dangerous.py"]) > 0

    def test_deeply_nested_file_found(self):
        root = _make_package({
            "a/b/c/deep.py": _VULNERABLE_SOURCE,
        })
        results = _collect_findings(root)
        assert "a/b/c/deep.py" in results

    def test_multiple_subdir_files_all_found(self):
        root = _make_package({
            "server.py": _CLEAN_SOURCE,
            "tools/cmd.py": _VULNERABLE_SOURCE,
            "utils/helpers.py": _CLEAN_SOURCE,
        })
        results = _collect_findings(root)
        assert "server.py" in results
        assert "tools/cmd.py" in results
        assert "utils/helpers.py" in results
        assert len(results) == 3

    def test_findings_attributed_to_correct_file(self):
        """Findings must come from the vulnerable file, not the clean one."""
        root = _make_package({
            "clean.py": _CLEAN_SOURCE,
            "vuln.py": _VULNERABLE_SOURCE,
        })
        results = _collect_findings(root)
        assert len(results["clean.py"]) == 0
        assert len(results["vuln.py"]) > 0


# ---------------------------------------------------------------------------
# TestExclusionRules
# ---------------------------------------------------------------------------

class TestExclusionRules:
    """Excluded directories must never be scanned."""

    @pytest.mark.parametrize("excluded_dir", [
        ".venv", "venv", "env",
        "__pycache__", ".git",
        "node_modules",
        "tests", "test",
        "build", "dist",
        "site-packages",
    ])
    def test_excluded_dir_is_not_scanned(self, excluded_dir: str):
        root = _make_package({
            f"{excluded_dir}/vuln.py": _VULNERABLE_SOURCE,
            "safe.py": _CLEAN_SOURCE,
        })
        results = _collect_findings(root)
        # The excluded dir file must not appear
        excluded_key = f"{excluded_dir}/vuln.py"
        assert excluded_key not in results, (
            f"'{excluded_dir}' should be excluded but its file was scanned"
        )
        # The safe root-level file must still appear
        assert "safe.py" in results

    def test_nested_exclusion_works(self):
        """A .venv dir nested inside a subdir must also be excluded."""
        root = _make_package({
            "mypackage/.venv/lib/requests/models.py": _VULNERABLE_SOURCE,
            "mypackage/server.py": _CLEAN_SOURCE,
        })
        results = _collect_findings(root)
        assert "mypackage/server.py" in results
        assert not any(".venv" in k for k in results)

    def test_non_excluded_dir_is_scanned(self):
        """A directory named 'src' or 'lib' must not be excluded."""
        root = _make_package({
            "src/server.py": _VULNERABLE_SOURCE,
            "lib/utils.py": _CLEAN_SOURCE,
        })
        results = _collect_findings(root)
        assert "src/server.py" in results
        assert "lib/utils.py" in results


# ---------------------------------------------------------------------------
# TestEmptyPackage
# ---------------------------------------------------------------------------

class TestEmptyPackage:
    def test_directory_with_no_py_files_returns_empty(self):
        root = _make_package({})
        results = _collect_findings(root)
        assert results == {}

    def test_directory_with_only_excluded_files_returns_empty(self):
        root = _make_package({
            ".venv/lib/something.py": _VULNERABLE_SOURCE,
            "__pycache__/cached.py": _CLEAN_SOURCE,
        })
        results = _collect_findings(root)
        assert results == {}
