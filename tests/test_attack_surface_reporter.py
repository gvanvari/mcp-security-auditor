"""
Tests for P2-7 — Attack-surface map (code-KB bridge).

Validates that AttackSurfaceReporter:
  - Lists every @mcp.tool() entry point, including tools with no findings.
  - Attributes findings to the entry point whose line range contains them.
  - Marks a sink-reaching tool as high-risk and a benign tool as trusted.
  - Snapshot-tests the rendered Markdown for a two-tool fixture package.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from mcp_auditor.analyzer import Analyzer
from mcp_auditor.extractors.entry_points import EntryPointExtractor
from mcp_auditor.reporters.attack_surface_reporter import AttackSurfaceReporter

_BENIGN_SOURCE = """\
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("fixture")

@mcp.tool()
def add(a: int, b: int) -> int:
    return a + b
"""

_SINK_SOURCE = """\
from mcp.server.fastmcp import FastMCP
import subprocess
mcp = FastMCP("fixture")

@mcp.tool()
def run(cmd: str) -> str:
    subprocess.run(cmd, shell=True)
    return ""
"""


def _make_package(structure: dict[str, str]) -> Path:
    root = Path(tempfile.mkdtemp())
    for rel, src in structure.items():
        target = root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(src, encoding="utf-8")
    return root


def _scan(root: Path) -> dict[str, list]:
    analyzer = Analyzer()
    results: dict[str, list] = {}
    for py_file in sorted(root.rglob("*.py")):
        rel = str(py_file.relative_to(root))
        results[rel] = analyzer.analyze(str(py_file))
    return results


# ---------------------------------------------------------------------------
# EntryPointExtractor
# ---------------------------------------------------------------------------

class TestEntryPointExtractor:
    def test_extracts_tool_with_params(self, tmp_path):
        f = tmp_path / "server.py"
        f.write_text(_SINK_SOURCE, encoding="utf-8")
        eps = EntryPointExtractor().extract(str(f))
        assert len(eps) == 1
        assert eps[0].name == "run"
        assert eps[0].params == ["cmd"]

    def test_non_tool_functions_are_not_entry_points(self, tmp_path):
        f = tmp_path / "server.py"
        f.write_text(_BENIGN_SOURCE.replace("@mcp.tool()\n", ""), encoding="utf-8")
        eps = EntryPointExtractor().extract(str(f))
        assert eps == []

    def test_line_range_contains_body(self, tmp_path):
        f = tmp_path / "server.py"
        f.write_text(_SINK_SOURCE, encoding="utf-8")
        ep = EntryPointExtractor().extract(str(f))[0]
        # subprocess.run(...) is one line inside the function body
        assert ep.contains_line(ep.lineno + 1)
        assert not ep.contains_line(1)


# ---------------------------------------------------------------------------
# AttackSurfaceReporter — two-tool fixture
# ---------------------------------------------------------------------------

class TestAttackSurfaceMap:
    def test_both_tools_appear_as_entry_points(self):
        root = _make_package({
            "safe.py": _BENIGN_SOURCE,
            "risky.py": _SINK_SOURCE,
        })
        results = _scan(root)
        report = AttackSurfaceReporter().generate(results, root)
        assert "`add`" in report
        assert "`run`" in report

    def test_sink_reaching_tool_is_marked_high_risk(self):
        root = _make_package({
            "safe.py": _BENIGN_SOURCE,
            "risky.py": _SINK_SOURCE,
        })
        results = _scan(root)
        report = AttackSurfaceReporter().generate(results, root)
        lines = {l for l in report.splitlines() if "`run`" in l}
        assert any("High-risk" in l for l in lines)

    def test_benign_tool_is_marked_trusted(self):
        root = _make_package({
            "safe.py": _BENIGN_SOURCE,
            "risky.py": _SINK_SOURCE,
        })
        results = _scan(root)
        report = AttackSurfaceReporter().generate(results, root)
        lines = {l for l in report.splitlines() if "`add`" in l}
        assert any("Trusted" in l for l in lines)

    def test_reachable_sink_rule_id_listed_for_risky_tool(self):
        root = _make_package({"risky.py": _SINK_SOURCE})
        results = _scan(root)
        report = AttackSurfaceReporter().generate(results, root)
        assert "MCP-CMI-002" in report

    def test_package_with_no_entry_points_produces_empty_map(self):
        root = _make_package({"plain.py": "x = 1\n"})
        results = _scan(root)
        report = AttackSurfaceReporter().generate(results, root)
        assert "0** entry point(s) mapped" in report

    def test_snapshot(self):
        """Pin the rendered Markdown for the two-tool fixture package."""
        root = _make_package({
            "safe.py": _BENIGN_SOURCE,
            "risky.py": _SINK_SOURCE,
        })
        results = _scan(root)
        report = AttackSurfaceReporter().generate(results, root)

        assert report == (
            "# Attack Surface Map\n"
            "\n"
            "Every `@mcp.tool()` entry point in this package, the sinks it "
            "reaches (P1-1 reachability graph), and a trust level derived "
            "from the most dangerous confirmed flow.\n"
            "\n"
            "## `risky.py`\n"
            "\n"
            "| Tool | Parameters | Reachable Sinks | Trust Level |\n"
            "|------|------------|------------------|-------------|\n"
            "| `run` | cmd | `MCP-CMI-002` | 🔴 High-risk |\n"
            "\n"
            "## `safe.py`\n"
            "\n"
            "| Tool | Parameters | Reachable Sinks | Trust Level |\n"
            "|------|------------|------------------|-------------|\n"
            "| `add` | a, b | — | 🟢 Trusted |\n"
            "\n"
            "---\n"
            "\n"
            "**2** entry point(s) mapped, **1** high-risk."
        )
