"""
Corpus tests for ASTExtractor.

Each test class covers one corpus file. Tests assert on:
  - parse_status
  - total finding count (regression guard)
  - specific rule IDs and types present
  - severity and confidence levels

Files:
  eval/corpus/cmd-injection.py  — os.system, subprocess.run(shell=True), subprocess.Popen
  eval/corpus/eval-exec.py      — eval(), exec()
  eval/corpus/env-leak.py       — os.environ[key], os.getenv()
  eval/corpus/http-exfil.py     — requests.get/post (SSRF / exfiltration)
  eval/corpus/clean-body.py     — false positive regression: no dangerous calls
"""

import pytest
from pathlib import Path

from mcp_auditor.extractors.ast_extractor import ASTExtractor
from mcp_auditor.extractors.threat_vector import ThreatVectorType, Severity, Confidence

CORPUS = Path(__file__).parent.parent / "eval" / "corpus"
extractor = ASTExtractor()


# ---------------------------------------------------------------------------
# cmd-injection.py
# ---------------------------------------------------------------------------

class TestCmdInjection:
    """
    What the file does:
      run_command(cmd) — os.system(cmd) + subprocess.run(cmd, shell=True)
      ping_host(host)  — subprocess.Popen(["ping", "-c", "1", host])
    Expected: 3 findings total.
    """

    def setup_method(self):
        self.result = extractor.analyze(str(CORPUS / "cmd-injection.py"))

    def test_parse_succeeds(self):
        assert self.result.parse_status == "ok"

    def test_total_finding_count(self):
        assert len(self.result.findings) == 3

    def test_finds_cmd_injection_type(self):
        types = [f.type for f in self.result.findings]
        assert ThreatVectorType.CMD_INJECTION in types

    def test_os_system_rule_id(self):
        """os.system should produce MCP-CMI-001."""
        rule_ids = [f.rule_id for f in self.result.findings]
        assert "MCP-CMI-001" in rule_ids

    def test_subprocess_shell_true_rule_id(self):
        """subprocess.run(shell=True) should produce MCP-CMI-002."""
        rule_ids = [f.rule_id for f in self.result.findings]
        assert "MCP-CMI-002" in rule_ids

    def test_cmd_injection_severity_is_high_or_medium(self):
        """All cmd injection findings must be HIGH or MEDIUM — not CRITICAL."""
        for f in self.result.findings:
            if f.type == ThreatVectorType.CMD_INJECTION:
                assert f.severity in (Severity.HIGH, Severity.MEDIUM)

    def test_evidence_contains_call_name(self):
        """Each finding's evidence should name the dangerous function."""
        evidence_values = [f.evidence for f in self.result.findings]
        assert any("os.system" in e for e in evidence_values)
        assert any("subprocess.run" in e or "subprocess.Popen" in e for e in evidence_values)


# ---------------------------------------------------------------------------
# eval-exec.py
# ---------------------------------------------------------------------------

class TestEvalExec:
    """
    What the file does:
      evaluate_expression(expression) — eval(expression)
      execute_code(code)              — exec(code)
    Expected: 2 findings total.
    """

    def setup_method(self):
        self.result = extractor.analyze(str(CORPUS / "eval-exec.py"))

    def test_parse_succeeds(self):
        assert self.result.parse_status == "ok"

    def test_total_finding_count(self):
        assert len(self.result.findings) == 2

    def test_finds_deserialization_type(self):
        """eval/exec map to DESERIALIZATION type (code execution via string)."""
        types = [f.type for f in self.result.findings]
        assert ThreatVectorType.DESERIALIZATION in types

    def test_eval_exec_rule_id(self):
        rule_ids = [f.rule_id for f in self.result.findings]
        assert "MCP-CMI-003" in rule_ids

    def test_eval_exec_severity_is_critical(self):
        """eval/exec are always CRITICAL — code execution regardless of context."""
        for f in self.result.findings:
            assert f.severity == Severity.CRITICAL

    def test_evidence_names_builtin(self):
        evidence_values = [f.evidence for f in self.result.findings]
        assert any("eval" in e for e in evidence_values)
        assert any("exec" in e for e in evidence_values)


# ---------------------------------------------------------------------------
# env-leak.py
# ---------------------------------------------------------------------------

class TestEnvLeak:
    """
    What the file does:
      get_config(key)   — os.environ[key]
      get_setting(name) — os.getenv(name)
    Expected: 2 findings total.
    """

    def setup_method(self):
        self.result = extractor.analyze(str(CORPUS / "env-leak.py"))

    def test_parse_succeeds(self):
        assert self.result.parse_status == "ok"

    def test_total_finding_count(self):
        assert len(self.result.findings) == 2

    def test_finds_secret_exposure_type(self):
        types = [f.type for f in self.result.findings]
        assert ThreatVectorType.SECRET_EXPOSURE in types

    def test_env_rule_id(self):
        rule_ids = [f.rule_id for f in self.result.findings]
        assert "MCP-SEC-001" in rule_ids

    def test_severity_is_medium(self):
        for f in self.result.findings:
            assert f.severity == Severity.MEDIUM

    def test_evidence_names_access_pattern(self):
        evidence_values = [f.evidence for f in self.result.findings]
        assert any("os.getenv" in e for e in evidence_values)
        assert any("os.environ" in e for e in evidence_values)


# ---------------------------------------------------------------------------
# http-exfil.py
# ---------------------------------------------------------------------------

class TestHttpExfil:
    """
    What the file does:
      fetch_url(url)             — requests.get(url)
      send_data(endpoint, data)  — requests.post(endpoint, ...)
    Expected: 2 findings total.
    """

    def setup_method(self):
        self.result = extractor.analyze(str(CORPUS / "http-exfil.py"))

    def test_parse_succeeds(self):
        assert self.result.parse_status == "ok"

    def test_total_finding_count(self):
        assert len(self.result.findings) == 2

    def test_finds_ssrf_type(self):
        types = [f.type for f in self.result.findings]
        assert ThreatVectorType.SSRF in types

    def test_ssrf_rule_id(self):
        rule_ids = [f.rule_id for f in self.result.findings]
        assert "MCP-SSRF-001" in rule_ids

    def test_severity_is_high(self):
        for f in self.result.findings:
            assert f.severity == Severity.HIGH

    def test_evidence_names_http_method(self):
        evidence_values = [f.evidence for f in self.result.findings]
        assert any("requests.get" in e for e in evidence_values)
        assert any("requests.post" in e for e in evidence_values)


# ---------------------------------------------------------------------------
# clean-body.py — false positive regression
# ---------------------------------------------------------------------------

class TestCleanBody:
    """
    What the file does:
      add(a, b)      — return a + b
      multiply(a, b) — return a * b
    No dangerous calls anywhere. ASTExtractor must return zero findings.
    """

    def setup_method(self):
        self.result = extractor.analyze(str(CORPUS / "clean-body.py"))

    def test_parse_succeeds(self):
        assert self.result.parse_status == "ok"

    def test_no_findings(self):
        """Zero findings — the most important false-positive guard."""
        assert len(self.result.findings) == 0
