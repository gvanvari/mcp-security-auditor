"""
Tests for P2-2 — baseline / suppression.

Test classes:
  TestExtractLineNumber   — line number extraction across location formats
  TestInlineIgnores       — `# mcp-auditor: ignore[...]` comment parsing + application
  TestFingerprint         — fingerprint stability / sensitivity
  TestBaselineFile        — write/load/apply roundtrip
  TestCLI                 — end-to-end via CliRunner: --baseline / --write-baseline
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest
from click.testing import CliRunner

from mcp_auditor.analyzer import main
from mcp_auditor.extractors.threat_vector import (
    Confidence,
    EnrichedFinding,
    Severity,
    ThreatVector,
    ThreatVectorType,
)
from mcp_auditor.suppression import (
    apply_baseline,
    apply_inline_ignores,
    compute_fingerprint,
    extract_line_number,
    load_baseline,
    parse_inline_ignores,
    write_baseline,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_finding(
    rule_id: str = "MCP-CMI-002",
    location: str = "server.py:8",
    evidence: str = "subprocess.run(cmd, shell=True)",
    severity: Severity = Severity.HIGH,
    reachability: str = "reachable",
) -> EnrichedFinding:
    vector = ThreatVector(
        rule_id=rule_id,
        type=ThreatVectorType.CMD_INJECTION,
        severity=severity,
        confidence=Confidence.PROPOSED,
        location=location,
        evidence=evidence,
        description="subprocess with shell=True detected.",
        reachability=reachability,
    )
    return EnrichedFinding(
        vector=vector,
        rule_title="Command Injection — subprocess shell=True",
        rule_description="Shell injection risk via subprocess.",
        rule_remediation="Pass a list to subprocess. Never use shell=True with user input.",
        rule_references=[],
        routing="NEEDS_CONTEXT",
    )


_VULNERABLE_SOURCE = """\
from mcp.server.fastmcp import FastMCP
import subprocess
mcp = FastMCP("vuln")

@mcp.tool()
def run(cmd: str) -> str:
    subprocess.run(cmd, shell=True)
    return ""
"""


def _write_source(tmp_path: Path, extra_line: str | None = None, ignore_line: int = 7) -> Path:
    """Write _VULNERABLE_SOURCE (finding lands on line 7) to tmp_path, optionally
    inserting `extra_line` as an inline comment at the end of that line."""
    lines = _VULNERABLE_SOURCE.splitlines()
    if extra_line is not None:
        idx = ignore_line - 1
        lines[idx] = lines[idx] + "  " + extra_line
    p = tmp_path / "server.py"
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return p


# ---------------------------------------------------------------------------
# TestExtractLineNumber
# ---------------------------------------------------------------------------

class TestExtractLineNumber:
    def test_path_colon_line(self):
        assert extract_line_number("/tmp/server.py:42") == 42

    def test_path_with_digits_uses_last_number(self):
        assert extract_line_number("/home/user2/v2/server.py:42") == 42

    def test_line_prefix_format(self):
        assert extract_line_number("line 42") == 42

    def test_docstring_tilde_format(self):
        assert extract_line_number("function:add, docstring (line ~12)") == 12

    def test_no_digits_returns_none(self):
        assert extract_line_number("no digits here") is None


# ---------------------------------------------------------------------------
# TestInlineIgnores
# ---------------------------------------------------------------------------

class TestInlineIgnores:
    def test_parse_bare_ignore(self, tmp_path):
        p = tmp_path / "f.py"
        p.write_text("x = 1  # mcp-auditor: ignore\ny = 2\n", encoding="utf-8")
        ignores = parse_inline_ignores(str(p))
        assert ignores == {1: None}

    def test_parse_scoped_ignore(self, tmp_path):
        p = tmp_path / "f.py"
        p.write_text("x = 1  # mcp-auditor: ignore[MCP-CMI-002]\n", encoding="utf-8")
        ignores = parse_inline_ignores(str(p))
        assert ignores == {1: {"MCP-CMI-002"}}

    def test_parse_multi_rule_ignore(self, tmp_path):
        p = tmp_path / "f.py"
        p.write_text("x = 1  # mcp-auditor: ignore[MCP-CMI-002, MCP-SSRF-001]\n", encoding="utf-8")
        ignores = parse_inline_ignores(str(p))
        assert ignores == {1: {"MCP-CMI-002", "MCP-SSRF-001"}}

    def test_no_ignores_returns_empty(self, tmp_path):
        p = tmp_path / "f.py"
        p.write_text("x = 1\n", encoding="utf-8")
        assert parse_inline_ignores(str(p)) == {}

    def test_apply_suppresses_exact_target_only(self, tmp_path):
        p = tmp_path / "f.py"
        p.write_text(
            "a = 1  # mcp-auditor: ignore[MCP-CMI-002]\n"
            "b = 2\n",
            encoding="utf-8",
        )
        target = _make_finding(rule_id="MCP-CMI-002", location=f"{p}:1")
        other_line = _make_finding(rule_id="MCP-CMI-002", location=f"{p}:2")
        other_rule = _make_finding(rule_id="MCP-SSRF-001", location=f"{p}:1")

        result = apply_inline_ignores([target, other_line, other_rule], str(p))

        by_rule_loc = {(f.vector.rule_id, f.vector.location): f for f in result}
        assert by_rule_loc[("MCP-CMI-002", f"{p}:1")].suppressed is True
        assert by_rule_loc[("MCP-CMI-002", f"{p}:1")].suppression_reason == "inline-ignore"
        assert by_rule_loc[("MCP-CMI-002", f"{p}:2")].suppressed is False
        assert by_rule_loc[("MCP-SSRF-001", f"{p}:1")].suppressed is False

    def test_apply_bare_ignore_suppresses_all_rules_on_line(self, tmp_path):
        p = tmp_path / "f.py"
        p.write_text("a = 1  # mcp-auditor: ignore\n", encoding="utf-8")
        f1 = _make_finding(rule_id="MCP-CMI-002", location=f"{p}:1")
        f2 = _make_finding(rule_id="MCP-SSRF-001", location=f"{p}:1")

        result = apply_inline_ignores([f1, f2], str(p))
        assert all(f.suppressed for f in result)

    def test_findings_never_dropped(self, tmp_path):
        p = tmp_path / "f.py"
        p.write_text("a = 1  # mcp-auditor: ignore\n", encoding="utf-8")
        findings = [_make_finding(location=f"{p}:1")]
        result = apply_inline_ignores(findings, str(p))
        assert len(result) == len(findings)


# ---------------------------------------------------------------------------
# TestFingerprint
# ---------------------------------------------------------------------------

class TestFingerprint:
    def test_stable_across_calls(self):
        f = _make_finding()
        assert compute_fingerprint(f, "server.py") == compute_fingerprint(f, "server.py")

    def test_changes_with_evidence(self):
        f1 = _make_finding(evidence="subprocess.run(cmd, shell=True)")
        f2 = _make_finding(evidence="os.system(cmd)")
        assert compute_fingerprint(f1, "server.py") != compute_fingerprint(f2, "server.py")

    def test_changes_with_rule_id(self):
        f1 = _make_finding(rule_id="MCP-CMI-002")
        f2 = _make_finding(rule_id="MCP-SSRF-001")
        assert compute_fingerprint(f1, "server.py") != compute_fingerprint(f2, "server.py")

    def test_changes_with_file_path(self):
        f = _make_finding()
        assert compute_fingerprint(f, "a.py") != compute_fingerprint(f, "b.py")


# ---------------------------------------------------------------------------
# TestBaselineFile
# ---------------------------------------------------------------------------

class TestBaselineFile:
    def test_write_then_load_roundtrip(self, tmp_path):
        baseline_path = tmp_path / ".mcp-auditor-baseline"
        f = _make_finding()
        written = write_baseline([f], "server.py", str(baseline_path))
        assert written == 1
        assert baseline_path.exists()

        fingerprints = load_baseline(str(baseline_path))
        assert compute_fingerprint(f, "server.py") in fingerprints

    def test_load_missing_baseline_returns_empty(self, tmp_path):
        assert load_baseline(str(tmp_path / "does-not-exist")) == set()

    def test_write_baseline_skips_already_suppressed(self, tmp_path):
        baseline_path = tmp_path / ".mcp-auditor-baseline"
        f = _make_finding().model_copy(
            update={"suppressed": True, "suppression_reason": "inline-ignore"}
        )
        written = write_baseline([f], "server.py", str(baseline_path))
        assert written == 0

    def test_apply_baseline_suppresses_matching_only(self):
        known = _make_finding(rule_id="MCP-CMI-002", location="server.py:8")
        new = _make_finding(rule_id="MCP-CMI-002", location="server.py:20")
        baseline_fps = {compute_fingerprint(known, "server.py")}

        result = apply_baseline([known, new], "server.py", baseline_fps)

        by_loc = {f.vector.location: f for f in result}
        assert by_loc["server.py:8"].suppressed is True
        assert by_loc["server.py:8"].suppression_reason == "baseline"
        assert by_loc["server.py:20"].suppressed is False

    def test_apply_baseline_never_drops_findings(self):
        f = _make_finding()
        result = apply_baseline([f], "server.py", set())
        assert len(result) == 1


# ---------------------------------------------------------------------------
# TestCLI
# ---------------------------------------------------------------------------

class TestCLI:
    def setup_method(self):
        self.runner = CliRunner()

    def test_baseline_missing_finding_still_fails(self, tmp_path):
        server = _write_source(tmp_path)
        result = self.runner.invoke(main, [str(server)])
        assert result.exit_code == 1

    def test_write_baseline_creates_file(self, tmp_path):
        server = _write_source(tmp_path)
        baseline = tmp_path / "baseline.json"
        result = self.runner.invoke(
            main, [str(server), "--write-baseline", "--baseline", str(baseline)]
        )
        assert result.exit_code == 0
        assert baseline.exists()
        data = json.loads(baseline.read_text())
        assert len(data["findings"]) >= 1

    def test_baseline_suppresses_known_finding_and_exits_0(self, tmp_path):
        server = _write_source(tmp_path)
        baseline = tmp_path / "baseline.json"

        write_result = self.runner.invoke(
            main, [str(server), "--write-baseline", "--baseline", str(baseline)]
        )
        assert write_result.exit_code == 0

        rerun = self.runner.invoke(main, [str(server), "--baseline", str(baseline)])
        assert rerun.exit_code == 0
        assert "SUPPRESSED" in rerun.output

    def test_baseline_new_finding_still_fails(self, tmp_path):
        server = _write_source(tmp_path)
        # Baseline that doesn't reference any real finding for this file.
        baseline = tmp_path / "baseline.json"
        baseline.write_text(json.dumps({"version": 1, "findings": []}), encoding="utf-8")

        result = self.runner.invoke(main, [str(server), "--baseline", str(baseline)])
        assert result.exit_code == 1

    def test_inline_ignore_suppresses_finding_and_exits_0(self, tmp_path):
        server = _write_source(tmp_path, extra_line="# mcp-auditor: ignore[MCP-CMI-002]")
        result = self.runner.invoke(main, [str(server)])
        assert result.exit_code == 0
        assert "SUPPRESSED" in result.output

    def test_inline_ignore_wrong_rule_id_does_not_suppress(self, tmp_path):
        server = _write_source(tmp_path, extra_line="# mcp-auditor: ignore[MCP-OTHER-999]")
        result = self.runner.invoke(main, [str(server)])
        assert result.exit_code == 1
