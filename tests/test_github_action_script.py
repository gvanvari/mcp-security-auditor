"""
Tests for P2-4 — scripts/run-scan.sh, the script action.yml's composite
"Run scan" step invokes.

Runs the real script via subprocess against temp fixture files so these
tests catch shell portability bugs (e.g. bash-3.2-incompatible constructs —
GitHub runners ship a modern bash, but this repo's dev machines may not)
that a pure-Python reimplementation would hide.
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import jsonschema
import pytest

SCRIPT = Path(__file__).parent.parent / "scripts" / "run-scan.sh"
SCHEMA = json.loads(
    (Path(__file__).parent / "schemas" / "sarif-2.1.0.schema.json").read_text(encoding="utf-8")
)

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


def _run_script(cwd: Path, env_overrides: dict) -> tuple[int, dict, str]:
    """Run run-scan.sh with GITHUB_OUTPUT captured to a temp file; return
    (exit_code, parsed key=value output pairs, combined stdout+stderr)."""
    github_output = cwd / "github_output.txt"
    github_output.write_text("", encoding="utf-8")

    env = os.environ.copy()
    env["GITHUB_OUTPUT"] = str(github_output)
    env.update(env_overrides)

    proc = subprocess.run(
        ["bash", str(SCRIPT)],
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )

    outputs = {}
    for line in github_output.read_text(encoding="utf-8").splitlines():
        if "=" in line:
            key, _, value = line.partition("=")
            outputs[key] = value

    return proc.returncode, outputs, proc.stdout + proc.stderr


class TestRunScanScript:
    def test_single_clean_file_exits_0(self, tmp_path):
        server = tmp_path / "server.py"
        server.write_text(_CLEAN_SOURCE, encoding="utf-8")

        rc, outputs, log = _run_script(
            tmp_path,
            {
                "INPUT_PATH": str(server),
                "INPUT_FORMAT": "markdown",
                "INPUT_FAIL_ON": "high",
                "INPUT_LLM": "false",
                "INPUT_BASELINE": "",
            },
        )
        assert rc == 0, log
        assert outputs["findings-count"] == "0"
        sarif = json.loads(Path(outputs["sarif-path"]).read_text(encoding="utf-8"))
        jsonschema.validate(sarif, SCHEMA)

    def test_single_vulnerable_file_exits_1_by_default(self, tmp_path):
        server = tmp_path / "server.py"
        server.write_text(_VULNERABLE_SOURCE, encoding="utf-8")

        rc, outputs, log = _run_script(
            tmp_path,
            {
                "INPUT_PATH": str(server),
                "INPUT_FORMAT": "none",
                "INPUT_FAIL_ON": "high",
                "INPUT_LLM": "false",
                "INPUT_BASELINE": "",
            },
        )
        assert rc == 1, log
        assert int(outputs["findings-count"]) >= 1

    def test_fail_on_none_always_exits_0(self, tmp_path):
        server = tmp_path / "server.py"
        server.write_text(_VULNERABLE_SOURCE, encoding="utf-8")

        rc, outputs, log = _run_script(
            tmp_path,
            {
                "INPUT_PATH": str(server),
                "INPUT_FORMAT": "none",
                "INPUT_FAIL_ON": "none",
                "INPUT_LLM": "false",
                "INPUT_BASELINE": "",
            },
        )
        assert rc == 0, log
        assert int(outputs["findings-count"]) >= 1

    def test_directory_scan_merges_sarif_across_files(self, tmp_path):
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        (pkg / "clean.py").write_text(_CLEAN_SOURCE, encoding="utf-8")
        (pkg / "vuln.py").write_text(_VULNERABLE_SOURCE, encoding="utf-8")

        rc, outputs, log = _run_script(
            tmp_path,
            {
                "INPUT_PATH": str(pkg),
                "INPUT_FORMAT": "none",
                "INPUT_FAIL_ON": "critical",  # HIGH finding shouldn't trip this
                "INPUT_LLM": "false",
                "INPUT_BASELINE": "",
            },
        )
        assert rc == 0, log
        sarif = json.loads(Path(outputs["sarif-path"]).read_text(encoding="utf-8"))
        jsonschema.validate(sarif, SCHEMA)
        # Exactly one run: GitHub Code Scanning rejects multiple runs sharing
        # an upload category, so per-file SARIF runs must collapse into one.
        assert len(sarif["runs"]) == 1
        total_results = len(sarif["runs"][0]["results"])
        assert int(outputs["findings-count"]) == total_results
        assert total_results >= 1

    def test_directory_scan_dedupes_rules_across_files(self, tmp_path):
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        (pkg / "a.py").write_text(_VULNERABLE_SOURCE, encoding="utf-8")
        (pkg / "b.py").write_text(_VULNERABLE_SOURCE, encoding="utf-8")

        rc, outputs, log = _run_script(
            tmp_path,
            {
                "INPUT_PATH": str(pkg),
                "INPUT_FORMAT": "none",
                "INPUT_FAIL_ON": "none",
                "INPUT_LLM": "false",
                "INPUT_BASELINE": "",
            },
        )
        assert rc == 0, log
        sarif = json.loads(Path(outputs["sarif-path"]).read_text(encoding="utf-8"))
        jsonschema.validate(sarif, SCHEMA)
        rule_ids = [r["id"] for r in sarif["runs"][0]["tool"]["driver"]["rules"]]
        assert len(rule_ids) == len(set(rule_ids))
        assert len(sarif["runs"][0]["results"]) == 2  # one finding per file

    def test_directory_scan_excludes_venv(self, tmp_path):
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        (pkg / "clean.py").write_text(_CLEAN_SOURCE, encoding="utf-8")
        venv_dir = pkg / ".venv" / "lib"
        venv_dir.mkdir(parents=True)
        (venv_dir / "vendored.py").write_text(_VULNERABLE_SOURCE, encoding="utf-8")

        rc, outputs, log = _run_script(
            tmp_path,
            {
                "INPUT_PATH": str(pkg),
                "INPUT_FORMAT": "none",
                "INPUT_FAIL_ON": "high",
                "INPUT_LLM": "false",
                "INPUT_BASELINE": "",
            },
        )
        assert rc == 0, log  # only clean.py should have been scanned
        sarif = json.loads(Path(outputs["sarif-path"]).read_text(encoding="utf-8"))
        assert len(sarif["runs"]) == 1

    def test_report_files_written_when_format_not_none(self, tmp_path):
        server = tmp_path / "server.py"
        server.write_text(_VULNERABLE_SOURCE, encoding="utf-8")

        rc, outputs, log = _run_script(
            tmp_path,
            {
                "INPUT_PATH": str(server),
                "INPUT_FORMAT": "markdown",
                "INPUT_FAIL_ON": "none",
                "INPUT_LLM": "false",
                "INPUT_BASELINE": "",
            },
        )
        assert rc == 0, log
        report_dir = Path(outputs["report-path"])
        assert report_dir.is_dir()
        md_files = list(report_dir.glob("*.md"))
        assert len(md_files) == 1

    def test_no_python_files_found(self, tmp_path):
        empty_dir = tmp_path / "empty"
        empty_dir.mkdir()

        rc, outputs, log = _run_script(
            empty_dir.parent,
            {
                "INPUT_PATH": str(empty_dir),
                "INPUT_FORMAT": "markdown",
                "INPUT_FAIL_ON": "high",
                "INPUT_LLM": "false",
                "INPUT_BASELINE": "",
            },
        )
        assert rc == 0, log
        assert outputs["findings-count"] == "0"
        assert outputs["sarif-path"] == ""

    def test_missing_path_errors(self, tmp_path):
        rc, outputs, log = _run_script(
            tmp_path,
            {
                "INPUT_PATH": str(tmp_path / "does-not-exist"),
                "INPUT_FORMAT": "markdown",
                "INPUT_FAIL_ON": "high",
                "INPUT_LLM": "false",
                "INPUT_BASELINE": "",
            },
        )
        assert rc == 1, log
