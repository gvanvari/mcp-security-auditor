"""
Tests for P2-6 — real precision/recall metrics.

Test classes:
  TestOverallMetrics    — tp/fp/fn, recall, precision computed correctly
  TestBenignFileHandling — the P2-6 bug fix: files with an empty (or
                            missing) EXPECTED.yaml entry must still be
                            checked for false positives
  TestFPRate            — the new FP-rate metric (fraction of benign files
                            that fired at least one unexpected finding)
  TestPerRuleBreakdown  — per-rule precision/recall table
  TestCorpusIntegration — scan_all against the real eval/corpus renders
                            precision/recall, and the checked-in benign
                            fixtures don't tank precision below a target
"""

from __future__ import annotations

import re
import tempfile
from pathlib import Path

import pytest

from mcp_auditor.analyzer import Analyzer
from mcp_auditor.extractors.threat_vector import (
    Confidence,
    EnrichedFinding,
    Severity,
    ThreatVector,
    ThreatVectorType,
)
from mcp_auditor.reporters.metrics_reporter import MetricsReporter

CORPUS_DIR = Path(__file__).parent.parent / "eval" / "corpus"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _finding(rule_id: str, severity: Severity = Severity.HIGH) -> EnrichedFinding:
    vector = ThreatVector(
        rule_id=rule_id,
        type=ThreatVectorType.CMD_INJECTION,
        severity=severity,
        confidence=Confidence.PROPOSED,
        location="server.py:1",
        evidence="evidence",
        description="description",
    )
    return EnrichedFinding(
        vector=vector,
        rule_title="title",
        rule_description="description",
        rule_remediation="remediation",
        rule_references=[],
        routing="SELF_CONTAINED",
    )


def _extract_metric(html: str, label: str) -> str:
    match = re.search(
        r'metric-num">([^<]+)</div>\s*<div class="metric-label">' + re.escape(label),
        html,
    )
    assert match, f"metric '{label}' not found in report"
    return match.group(1)


# ---------------------------------------------------------------------------
# TestOverallMetrics
# ---------------------------------------------------------------------------

class TestOverallMetrics:
    def setup_method(self):
        self.reporter = MetricsReporter()

    def test_perfect_match_100_precision_recall(self):
        scan_results = {"vuln": [_finding("MCP-CMI-001")]}
        expected = {"vuln": [{"rule": "MCP-CMI-001", "severity": "HIGH"}]}
        html = self.reporter.generate(scan_results, expected)
        assert _extract_metric(html, "Recall") == "100.0%"
        assert _extract_metric(html, "Precision") == "100.0%"

    def test_missed_finding_lowers_recall(self):
        scan_results = {"vuln": []}
        expected = {"vuln": [{"rule": "MCP-CMI-001", "severity": "HIGH"}]}
        html = self.reporter.generate(scan_results, expected)
        assert _extract_metric(html, "Recall") == "0.0%"

    def test_unexpected_finding_lowers_precision(self):
        scan_results = {"vuln": [_finding("MCP-CMI-001"), _finding("MCP-SSRF-001")]}
        expected = {"vuln": [{"rule": "MCP-CMI-001", "severity": "HIGH"}]}
        html = self.reporter.generate(scan_results, expected)
        assert _extract_metric(html, "Precision") == "50.0%"

    def test_empty_input_zero_metrics(self):
        html = self.reporter.generate({}, {})
        assert _extract_metric(html, "Recall") == "0%"
        assert _extract_metric(html, "Precision") == "0%"


# ---------------------------------------------------------------------------
# TestBenignFileHandling — the P2-6 bug fix
# ---------------------------------------------------------------------------

class TestBenignFileHandling:
    """
    Before P2-6, scan_all stripped empty-list EXPECTED.yaml entries before
    calling MetricsReporter, so a benign file (expected: []) was invisible
    to the precision calculation no matter what it fired. MetricsReporter
    must independently guarantee this by iterating over every scanned file,
    not just files with at least one expected finding.
    """

    def setup_method(self):
        self.reporter = MetricsReporter()

    def test_fp_on_explicit_empty_expected_list_counts(self):
        scan_results = {"benign": [_finding("MCP-SHADOW-001")]}
        expected = {"benign": []}
        html = self.reporter.generate(scan_results, expected)
        assert _extract_metric(html, "False Positives") == "1"
        assert _extract_metric(html, "Precision") == "0.0%"

    def test_fp_on_file_missing_from_expected_entirely_counts(self):
        # No EXPECTED.yaml entry at all for "benign" — must default to [].
        scan_results = {"benign": [_finding("MCP-SHADOW-001")]}
        expected: dict = {}
        html = self.reporter.generate(scan_results, expected)
        assert _extract_metric(html, "False Positives") == "1"

    def test_clean_benign_file_no_fp(self):
        scan_results = {"benign": []}
        expected = {"benign": []}
        html = self.reporter.generate(scan_results, expected)
        assert _extract_metric(html, "False Positives") == "0"
        assert _extract_metric(html, "Precision") == "0%"  # no findings at all → undefined, reported as 0

    def test_benign_fp_combines_with_real_vulnerability_precision(self):
        scan_results = {
            "vuln": [_finding("MCP-CMI-001")],
            "benign": [_finding("MCP-SHADOW-001")],
        }
        expected = {
            "vuln": [{"rule": "MCP-CMI-001", "severity": "HIGH"}],
            "benign": [],
        }
        html = self.reporter.generate(scan_results, expected)
        # 1 TP, 1 FP → 50% precision. Pre-fix, "benign" would have been
        # stripped and this would incorrectly report 100%.
        assert _extract_metric(html, "Precision") == "50.0%"


# ---------------------------------------------------------------------------
# TestFPRate
# ---------------------------------------------------------------------------

class TestFPRate:
    def setup_method(self):
        self.reporter = MetricsReporter()

    def test_no_benign_files_zero_fp_rate(self):
        scan_results = {"vuln": [_finding("MCP-CMI-001")]}
        expected = {"vuln": [{"rule": "MCP-CMI-001", "severity": "HIGH"}]}
        html = self.reporter.generate(scan_results, expected)
        assert _extract_metric(html, "FP rate") == "0%"

    def test_half_of_benign_files_flagged(self):
        scan_results = {
            "clean-a": [],
            "clean-b": [_finding("MCP-SHADOW-001")],
        }
        expected = {"clean-a": [], "clean-b": []}
        html = self.reporter.generate(scan_results, expected)
        assert _extract_metric(html, "FP rate") == "50.0%"
        assert "1/2 benign files flagged" in html

    def test_files_with_expected_findings_excluded_from_fp_rate(self):
        # A file with real expected vulnerabilities is not a "benign file" —
        # it shouldn't count in the FP-rate denominator even if it also
        # fires an unexpected extra rule.
        scan_results = {"vuln": [_finding("MCP-CMI-001"), _finding("MCP-SSRF-001")]}
        expected = {"vuln": [{"rule": "MCP-CMI-001", "severity": "HIGH"}]}
        html = self.reporter.generate(scan_results, expected)
        assert _extract_metric(html, "FP rate") == "0%"


# ---------------------------------------------------------------------------
# TestPerRuleBreakdown
# ---------------------------------------------------------------------------

class TestPerRuleBreakdown:
    def setup_method(self):
        self.reporter = MetricsReporter()

    def test_per_rule_table_present(self):
        scan_results = {"vuln": [_finding("MCP-CMI-001")]}
        expected = {"vuln": [{"rule": "MCP-CMI-001", "severity": "HIGH"}]}
        html = self.reporter.generate(scan_results, expected)
        assert "Per-Rule Breakdown" in html
        assert "MCP-CMI-001" in html

    def test_per_rule_precision_isolated_per_rule(self):
        scan_results = {
            "a": [_finding("MCP-CMI-001")],
            # "b" correctly fires its expected SSRF-001 but ALSO an
            # unexpected TPA-001 — a false positive attributable to
            # MCP-TPA-001 specifically, not to MCP-SSRF-001 or MCP-CMI-001.
            "b": [_finding("MCP-SSRF-001"), _finding("MCP-TPA-001")],
        }
        expected = {
            "a": [{"rule": "MCP-CMI-001", "severity": "HIGH"}],
            "b": [{"rule": "MCP-SSRF-001", "severity": "HIGH"}],
        }
        html = self.reporter.generate(scan_results, expected)
        # Overall precision should NOT bleed one rule's errors into another.
        table_match = re.search(r"<h2>Per-Rule Breakdown</h2>\s*(<table>.*?</table>)", html, re.S)
        assert table_match
        table = table_match.group(1)
        cmi_row = re.search(r"MCP-CMI-001.*?</tr>", table, re.S).group(0)
        ssrf_row = re.search(r"MCP-SSRF-001.*?</tr>", table, re.S).group(0)
        tpa_row = re.search(r"MCP-TPA-001.*?</tr>", table, re.S).group(0)
        assert "100.0%" in cmi_row
        assert "100.0%" in ssrf_row  # its expected finding fired correctly
        assert "0.0%" in tpa_row  # entirely unexpected → 0% precision

    def test_no_findings_at_all_shows_placeholder(self):
        html = self.reporter.generate({}, {})
        assert "No rules exercised" in html


# ---------------------------------------------------------------------------
# TestCorpusIntegration
# ---------------------------------------------------------------------------

class TestCorpusIntegration:
    """
    Runs the real analyzer against the real eval/corpus fixtures (no LLM) —
    the same inputs `mcp-auditor-all eval/corpus` uses — and checks the
    metrics report this produces.
    """

    def setup_method(self):
        self.analyzer = Analyzer()

    def _scan_corpus(self) -> dict[str, list[EnrichedFinding]]:
        results = {}
        for py_file in sorted(CORPUS_DIR.glob("*.py")):
            results[py_file.stem] = self.analyzer.analyze(str(py_file))
        return results

    def _load_expected(self) -> dict:
        import yaml
        raw = yaml.safe_load((CORPUS_DIR / "EXPECTED.yaml").read_text(encoding="utf-8")) or {}
        return {k.replace(".py", ""): v for k, v in raw.items()}

    def test_scan_all_renders_precision_and_recall(self):
        scan_results = self._scan_corpus()
        expected = self._load_expected()
        html = MetricsReporter().generate(scan_results, expected)
        assert "Recall" in html
        assert "Precision" in html
        assert "FP rate" in html

    def test_recall_is_100_percent_on_corpus(self):
        # Every intentionally-planted vulnerability must still be detected —
        # this is the regression guard against silently losing detections.
        scan_results = self._scan_corpus()
        expected = self._load_expected()
        html = MetricsReporter().generate(scan_results, expected)
        assert _extract_metric(html, "Recall") == "100.0%"

    def test_benign_fixtures_dont_drop_precision_below_target(self):
        """
        Regression guard for P2-6's acceptance criterion: adding a benign
        fixture with a contact email (or the other known-FP-source
        fixtures — hardcoded env read, hardcoded URL, self-describing
        notification tool) must not collapse precision.

        Target is set from the measured corpus baseline (78.9%, 15 TP / 4
        FP — see README "Precision & recall") with headroom for minor KB
        rewording, not an arbitrary aspirational number: it only trips if a
        change meaningfully worsens noise on benign code, which is exactly
        what this ticket exists to catch.
        """
        scan_results = self._scan_corpus()
        expected = self._load_expected()
        html = MetricsReporter().generate(scan_results, expected)
        precision = float(_extract_metric(html, "Precision").rstrip("%"))
        assert precision >= 75.0

    def test_known_benign_fixtures_produce_at_most_one_finding_each(self):
        """
        Pins the exact known-FP-source behavior documented in EXPECTED.yaml:
        each benign fixture fires exactly the one downgraded (LOW/EXPERIMENTAL
        or MEDIUM/EXPERIMENTAL) finding it's meant to demonstrate, not more —
        so a regression that makes these noisier trips this test directly,
        independent of the aggregate precision threshold above.
        """
        for stem in (
            "benign-contact-info",
            "benign-notification",
            "benign-config-read",
            "benign-fixed-endpoint",
        ):
            findings = self.analyzer.analyze(str(CORPUS_DIR / f"{stem}.py"))
            assert len(findings) == 1, f"{stem}.py: expected 1 finding, got {len(findings)}"
            assert findings[0].vector.confidence == Confidence.EXPERIMENTAL

    def test_clean_body_fixture_produces_no_findings(self):
        findings = self.analyzer.analyze(str(CORPUS_DIR / "clean-body.py"))
        assert findings == []
