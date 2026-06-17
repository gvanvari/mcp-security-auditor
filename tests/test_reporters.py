"""
Tests for MarkdownReporter and SARIFReporter (PR-8).

Test classes:
  TestMarkdownReporter  — Markdown output structure and content
  TestSARIFReporter     — SARIF 2.1.0 structure and rule deduplication
  TestEmptyFindings     — both reporters handle empty list gracefully
"""

import json
from typing import List

import pytest

from mcp_auditor.extractors.threat_vector import (
    Confidence,
    EnrichedFinding,
    Severity,
    ThreatVector,
    ThreatVectorType,
)
from mcp_auditor.reporters.markdown_reporter import MarkdownReporter
from mcp_auditor.reporters.sarif_reporter import SARIFReporter


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _make_finding(
    rule_id: str = "MCP-TPA-001",
    severity: Severity = Severity.HIGH,
    routing: str = "SELF_CONTAINED",
    llm_analysis: str | None = None,
    evidence: str = "~/.ssh/id_rsa",
    location: str = "function:add, line 3",
) -> EnrichedFinding:
    vector = ThreatVector(
        rule_id=rule_id,
        type=ThreatVectorType.TOOL_POISONING,
        severity=severity,
        confidence=Confidence.VERIFIED,
        location=location,
        evidence=evidence,
        description="Credential path found in tool description.",
        owasp_llm="LLM07",
    )
    return EnrichedFinding(
        vector=vector,
        rule_title="Tool Poisoning — Credential Path",
        rule_description="A credential path was detected in the tool docstring.",
        rule_remediation="Remove all file paths from tool descriptions.",
        rule_references=["https://example.com/mcp-tpa-001"],
        routing=routing,
        llm_analysis=llm_analysis,
    )


def _make_needs_context_finding() -> EnrichedFinding:
    vector = ThreatVector(
        rule_id="MCP-CMI-002",
        type=ThreatVectorType.CMD_INJECTION,
        severity=Severity.MEDIUM,
        confidence=Confidence.PROPOSED,
        location="function:run, line 12",
        evidence="subprocess.run(cmd, shell=True)",
        description="subprocess with shell=True detected.",
    )
    return EnrichedFinding(
        vector=vector,
        rule_title="Command Injection — subprocess shell=True",
        rule_description="Shell injection risk via subprocess.",
        rule_remediation="Pass a list to subprocess. Never use shell=True with user input.",
        rule_references=[],
        routing="NEEDS_CONTEXT",
        llm_analysis="The command argument appears to be caller-controlled, raising real injection risk.",
    )


# ---------------------------------------------------------------------------
# TestMarkdownReporter
# ---------------------------------------------------------------------------

class TestMarkdownReporter:
    def setup_method(self):
        self.reporter = MarkdownReporter()

    def test_header_present(self):
        findings = [_make_finding()]
        md = self.reporter.generate(findings)
        assert "# MCP Security Audit Report" in md

    def test_file_path_shown_when_provided(self):
        findings = [_make_finding()]
        md = self.reporter.generate(findings, file_path="eval/corpus/direct-poisoning.py")
        assert "direct-poisoning.py" in md

    def test_summary_table_contains_severity_labels(self):
        findings = [_make_finding(severity=Severity.CRITICAL), _make_finding(severity=Severity.LOW)]
        md = self.reporter.generate(findings)
        assert "CRITICAL" in md
        assert "LOW" in md

    def test_summary_table_total_count(self):
        findings = [_make_finding(), _make_finding(), _make_finding()]
        md = self.reporter.generate(findings)
        assert "**Total** | **3**" in md

    def test_finding_rule_id_present(self):
        findings = [_make_finding(rule_id="MCP-TPA-001")]
        md = self.reporter.generate(findings)
        assert "MCP-TPA-001" in md

    def test_finding_evidence_in_code_block(self):
        findings = [_make_finding(evidence="~/.ssh/id_rsa")]
        md = self.reporter.generate(findings)
        assert "~/.ssh/id_rsa" in md

    def test_remediation_always_present(self):
        findings = [_make_finding()]
        md = self.reporter.generate(findings)
        assert "Remove all file paths" in md

    def test_reference_link_present(self):
        findings = [_make_finding()]
        md = self.reporter.generate(findings)
        assert "https://example.com/mcp-tpa-001" in md

    def test_llm_analysis_included_when_present(self):
        finding = _make_needs_context_finding()
        md = self.reporter.generate([finding])
        assert "caller-controlled" in md

    def test_llm_analysis_absent_for_self_contained(self):
        finding = _make_finding(routing="SELF_CONTAINED", llm_analysis=None)
        md = self.reporter.generate([finding])
        assert "LLM Analysis" not in md

    def test_critical_finding_before_low(self):
        findings = [
            _make_finding(rule_id="MCP-LOW", severity=Severity.LOW),
            _make_finding(rule_id="MCP-CRIT", severity=Severity.CRITICAL),
        ]
        md = self.reporter.generate(findings)
        assert md.index("MCP-CRIT") < md.index("MCP-LOW")

    def test_owasp_reference_shown(self):
        findings = [_make_finding()]
        md = self.reporter.generate(findings)
        assert "LLM07" in md


# ---------------------------------------------------------------------------
# TestSARIFReporter
# ---------------------------------------------------------------------------

class TestSARIFReporter:
    def setup_method(self):
        self.reporter = SARIFReporter()

    def _parse(self, findings: List[EnrichedFinding], file_path: str = "test.py") -> dict:
        return json.loads(self.reporter.generate(findings, file_path=file_path))

    def test_sarif_version(self):
        sarif = self._parse([_make_finding()])
        assert sarif["version"] == "2.1.0"

    def test_tool_name(self):
        sarif = self._parse([_make_finding()])
        assert sarif["runs"][0]["tool"]["driver"]["name"] == "mcp-security-auditor"

    def test_rule_id_in_driver(self):
        sarif = self._parse([_make_finding(rule_id="MCP-TPA-001")])
        rule_ids = [r["id"] for r in sarif["runs"][0]["tool"]["driver"]["rules"]]
        assert "MCP-TPA-001" in rule_ids

    def test_rules_deduplicated(self):
        # Two findings with same rule_id → only one rule entry
        findings = [_make_finding(rule_id="MCP-TPA-001"), _make_finding(rule_id="MCP-TPA-001")]
        sarif = self._parse(findings)
        rule_ids = [r["id"] for r in sarif["runs"][0]["tool"]["driver"]["rules"]]
        assert rule_ids.count("MCP-TPA-001") == 1

    def test_results_count_matches_findings(self):
        findings = [_make_finding(), _make_finding(), _make_needs_context_finding()]
        sarif = self._parse(findings)
        assert len(sarif["runs"][0]["results"]) == 3

    def test_result_rule_id(self):
        sarif = self._parse([_make_finding(rule_id="MCP-TPA-001")])
        assert sarif["runs"][0]["results"][0]["ruleId"] == "MCP-TPA-001"

    def test_critical_severity_maps_to_error(self):
        sarif = self._parse([_make_finding(severity=Severity.CRITICAL)])
        assert sarif["runs"][0]["results"][0]["level"] == "error"

    def test_medium_severity_maps_to_warning(self):
        sarif = self._parse([_make_finding(severity=Severity.MEDIUM)])
        assert sarif["runs"][0]["results"][0]["level"] == "warning"

    def test_low_severity_maps_to_note(self):
        sarif = self._parse([_make_finding(severity=Severity.LOW)])
        assert sarif["runs"][0]["results"][0]["level"] == "note"

    def test_file_path_in_artifact_location(self):
        sarif = self._parse([_make_finding()], file_path="src/server.py")
        loc = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
        assert loc["artifactLocation"]["uri"] == "src/server.py"

    def test_line_number_parsed_from_location(self):
        sarif = self._parse([_make_finding(location="function:add, line 42")])
        region = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]
        assert region["startLine"] == 42

    def test_llm_analysis_appended_to_message(self):
        finding = _make_needs_context_finding()
        sarif = self._parse([finding])
        msg = sarif["runs"][0]["results"][0]["message"]["text"]
        assert "caller-controlled" in msg

    def test_security_severity_property_present(self):
        sarif = self._parse([_make_finding(severity=Severity.HIGH)])
        rule = sarif["runs"][0]["tool"]["driver"]["rules"][0]
        assert rule["properties"]["security-severity"] == "7.0"


# ---------------------------------------------------------------------------
# TestEmptyFindings
# ---------------------------------------------------------------------------

class TestEmptyFindings:
    def test_markdown_empty(self):
        md = MarkdownReporter().generate([])
        assert "No findings detected" in md

    def test_sarif_empty_results(self):
        sarif = json.loads(SARIFReporter().generate([]))
        assert sarif["runs"][0]["results"] == []
        assert sarif["runs"][0]["tool"]["driver"]["rules"] == []
