"""
Tests for P2-3 — configurable failure threshold (--fail-on).

Test classes:
  TestExceedsThreshold — unit tests for the shared severity-threshold helper
  TestCLIFailOn        — end-to-end via CliRunner: same findings, different
                          --fail-on values produce different exit codes
"""

from __future__ import annotations

from pathlib import Path

import pytest
from click.testing import CliRunner

from mcp_auditor.analyzer import _exceeds_threshold, main
from mcp_auditor.extractors.threat_vector import (
    Confidence,
    EnrichedFinding,
    Severity,
    ThreatVector,
    ThreatVectorType,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_finding(
    severity: Severity,
    reachability: str = "reachable",
    rule_id: str = "MCP-CMI-002",
) -> EnrichedFinding:
    vector = ThreatVector(
        rule_id=rule_id,
        type=ThreatVectorType.CMD_INJECTION,
        severity=severity,
        confidence=Confidence.PROPOSED,
        location="server.py:8",
        evidence="subprocess.run(cmd, shell=True)",
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


# ---------------------------------------------------------------------------
# TestExceedsThreshold
# ---------------------------------------------------------------------------

class TestExceedsThreshold:
    def test_none_never_fails(self):
        findings = [_make_finding(Severity.CRITICAL)]
        assert _exceeds_threshold(findings, "none") is False

    def test_critical_threshold_ignores_high(self):
        findings = [_make_finding(Severity.HIGH)]
        assert _exceeds_threshold(findings, "critical") is False

    def test_critical_threshold_catches_critical(self):
        findings = [_make_finding(Severity.CRITICAL)]
        assert _exceeds_threshold(findings, "critical") is True

    def test_default_high_catches_high_and_critical(self):
        assert _exceeds_threshold([_make_finding(Severity.HIGH)], "high") is True
        assert _exceeds_threshold([_make_finding(Severity.CRITICAL)], "high") is True

    def test_high_ignores_medium(self):
        assert _exceeds_threshold([_make_finding(Severity.MEDIUM)], "high") is False

    def test_medium_catches_medium(self):
        assert _exceeds_threshold([_make_finding(Severity.MEDIUM)], "medium") is True

    def test_low_catches_everything(self):
        for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW):
            assert _exceeds_threshold([_make_finding(sev)], "low") is True

    def test_case_insensitive(self):
        findings = [_make_finding(Severity.CRITICAL)]
        assert _exceeds_threshold(findings, "CRITICAL") is True

    def test_constant_reachability_excluded_regardless_of_threshold(self):
        findings = [_make_finding(Severity.CRITICAL, reachability="constant")]
        assert _exceeds_threshold(findings, "low") is False

    def test_unknown_reachability_counts(self):
        findings = [_make_finding(Severity.CRITICAL, reachability="unknown")]
        assert _exceeds_threshold(findings, "high") is True

    def test_empty_findings_never_fail(self):
        assert _exceeds_threshold([], "low") is False


# ---------------------------------------------------------------------------
# TestCLIFailOn
# ---------------------------------------------------------------------------

_VULNERABLE_SOURCE = """\
from mcp.server.fastmcp import FastMCP
import subprocess
mcp = FastMCP("vuln")

@mcp.tool()
def run(cmd: str) -> str:
    subprocess.run(cmd, shell=True)
    return ""
"""


class TestCLIFailOn:
    def setup_method(self):
        self.runner = CliRunner()

    def _write_vulnerable_file(self, tmp_path: Path) -> Path:
        p = tmp_path / "server.py"
        p.write_text(_VULNERABLE_SOURCE, encoding="utf-8")
        return p

    def test_default_fail_on_high_fails(self, tmp_path):
        server = self._write_vulnerable_file(tmp_path)
        result = self.runner.invoke(main, [str(server)])
        assert result.exit_code == 1

    def test_fail_on_critical_passes_for_high_finding(self, tmp_path):
        server = self._write_vulnerable_file(tmp_path)
        result = self.runner.invoke(main, [str(server), "--fail-on", "critical"])
        assert result.exit_code == 0

    def test_fail_on_medium_still_fails_for_high_finding(self, tmp_path):
        server = self._write_vulnerable_file(tmp_path)
        result = self.runner.invoke(main, [str(server), "--fail-on", "medium"])
        assert result.exit_code == 1

    def test_fail_on_none_always_passes(self, tmp_path):
        server = self._write_vulnerable_file(tmp_path)
        result = self.runner.invoke(main, [str(server), "--fail-on", "none"])
        assert result.exit_code == 0

    def test_invalid_fail_on_value_rejected(self, tmp_path):
        server = self._write_vulnerable_file(tmp_path)
        result = self.runner.invoke(main, [str(server), "--fail-on", "bogus"])
        assert result.exit_code != 0
        assert "Invalid value" in result.output or "invalid choice" in result.output.lower()
