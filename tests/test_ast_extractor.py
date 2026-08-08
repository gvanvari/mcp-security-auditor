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
import tempfile

from mcp_auditor.extractors.ast_extractor import ASTExtractor, _TaintContext
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


# ---------------------------------------------------------------------------
# P1-1 — Reachability / taint verdict tests
# ---------------------------------------------------------------------------

def _analyze_source(source: str) -> list:
    """Helper: write source to a temp file and run ASTExtractor."""
    with tempfile.NamedTemporaryFile(suffix=".py", mode="w", delete=False) as f:
        f.write(source)
        path = f.name
    return ASTExtractor().analyze(path).findings


class TestTaintReachable:
    """
    Sink argument traces directly back to an @mcp.tool() parameter.
    Severity must be kept; confidence must be raised.
    """

    def test_os_system_param_arg_is_reachable(self):
        source = """
from mcp.server.fastmcp import FastMCP
import os
mcp = FastMCP("T")

@mcp.tool()
def run(cmd: str) -> str:
    os.system(cmd)
    return ""
"""
        findings = _analyze_source(source)
        cmi = [f for f in findings if f.rule_id == "MCP-CMI-001"]
        assert cmi, "Expected MCP-CMI-001 finding"
        assert cmi[0].reachability == "reachable"
        assert cmi[0].severity == Severity.HIGH         # unchanged from base
        assert cmi[0].confidence == Confidence.VERIFIED  # raised from PROPOSED

    def test_subprocess_shell_true_param_is_reachable(self):
        source = """
from mcp.server.fastmcp import FastMCP
import subprocess
mcp = FastMCP("T")

@mcp.tool()
def run(user_cmd: str) -> str:
    subprocess.run(user_cmd, shell=True)
    return ""
"""
        findings = _analyze_source(source)
        cmi = [f for f in findings if f.rule_id == "MCP-CMI-002"]
        assert cmi
        assert cmi[0].reachability == "reachable"
        assert cmi[0].severity == Severity.HIGH

    def test_requests_get_param_url_is_reachable(self):
        source = """
from mcp.server.fastmcp import FastMCP
import requests
mcp = FastMCP("T")

@mcp.tool()
def fetch(url: str) -> str:
    return requests.get(url).text
"""
        findings = _analyze_source(source)
        ssrf = [f for f in findings if f.rule_id == "MCP-SSRF-001"]
        assert ssrf
        assert ssrf[0].reachability == "reachable"
        assert ssrf[0].severity == Severity.HIGH

    def test_alias_propagation_is_reachable(self):
        """Single-assignment alias: cmd = user_input → os.system(cmd) → reachable."""
        source = """
from mcp.server.fastmcp import FastMCP
import os
mcp = FastMCP("T")

@mcp.tool()
def run(user_input: str) -> str:
    cmd = user_input
    os.system(cmd)
    return ""
"""
        findings = _analyze_source(source)
        cmi = [f for f in findings if f.rule_id == "MCP-CMI-001"]
        assert cmi
        assert cmi[0].reachability == "reachable"

    def test_corpus_cmd_injection_all_reachable(self):
        """All corpus cmd-injection findings must be reachable (params → sinks)."""
        result = extractor.analyze(str(CORPUS / "cmd-injection.py"))
        for f in result.findings:
            assert f.reachability == "reachable", (
                f"Expected reachable but got {f.reachability!r} for {f.rule_id} at {f.location}"
            )


class TestTaintConstant:
    """
    Sink argument is a hardcoded literal — no attacker influence.
    Severity must be downgraded one level; confidence must be EXPERIMENTAL.
    """

    def test_os_system_literal_arg_is_constant(self):
        source = """
from mcp.server.fastmcp import FastMCP
import os
mcp = FastMCP("T")

@mcp.tool()
def status(name: str) -> str:
    os.system("ls -la /tmp")
    return name
"""
        findings = _analyze_source(source)
        cmi = [f for f in findings if f.rule_id == "MCP-CMI-001"]
        assert cmi, "Expected MCP-CMI-001 finding"
        assert cmi[0].reachability == "constant"
        assert cmi[0].severity == Severity.MEDIUM        # downgraded from HIGH
        assert cmi[0].confidence == Confidence.EXPERIMENTAL

    def test_eval_literal_string_is_constant(self):
        source = """
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("T")

@mcp.tool()
def compute(x: int) -> int:
    eval("1 + 1")
    return x
"""
        findings = _analyze_source(source)
        cmi = [f for f in findings if f.rule_id == "MCP-CMI-003"]
        assert cmi
        assert cmi[0].reachability == "constant"
        assert cmi[0].severity == Severity.HIGH           # CRITICAL downgraded to HIGH
        assert cmi[0].confidence == Confidence.EXPERIMENTAL

    def test_requests_get_literal_url_is_constant(self):
        source = """
from mcp.server.fastmcp import FastMCP
import requests
mcp = FastMCP("T")

@mcp.tool()
def ping(name: str) -> str:
    requests.get("https://hardcoded.example.com/health")
    return name
"""
        findings = _analyze_source(source)
        ssrf = [f for f in findings if f.rule_id == "MCP-SSRF-001"]
        assert ssrf
        assert ssrf[0].reachability == "constant"
        assert ssrf[0].severity == Severity.MEDIUM        # downgraded from HIGH

    def test_os_getenv_literal_key_is_constant(self):
        source = """
from mcp.server.fastmcp import FastMCP
import os
mcp = FastMCP("T")

@mcp.tool()
def read_port(name: str) -> str:
    port = os.getenv("PORT")
    return name
"""
        findings = _analyze_source(source)
        sec = [f for f in findings if f.rule_id == "MCP-SEC-001"]
        assert sec
        assert sec[0].reachability == "constant"
        assert sec[0].confidence == Confidence.EXPERIMENTAL


class TestTaintUnknown:
    """
    Complex expression — taint can't be determined; treated conservatively.
    Severity and confidence must be unchanged from base values.
    """

    def test_computed_arg_is_unknown(self):
        """Call result as argument — cannot be classified without runtime info."""
        source = """
from mcp.server.fastmcp import FastMCP
import os
mcp = FastMCP("T")

@mcp.tool()
def run(name: str) -> str:
    cmd = build_command(name)   # result of a call — unknown
    os.system(cmd)
    return ""

def build_command(n):
    return f"echo {n}"
"""
        findings = _analyze_source(source)
        cmi = [f for f in findings if f.rule_id == "MCP-CMI-001"]
        assert cmi
        # build_command(name) is a Call node → unknown
        assert cmi[0].reachability == "unknown"
        assert cmi[0].severity == Severity.HIGH      # unchanged
        assert cmi[0].confidence == Confidence.PROPOSED  # unchanged


class TestReachabilityFieldPresent:
    """Every ThreatVector from ASTExtractor must carry a reachability field."""

    def test_all_corpus_findings_have_reachability(self):
        for corpus_file in (CORPUS / f for f in [
            "cmd-injection.py", "eval-exec.py", "env-leak.py", "http-exfil.py"
        ]):
            result = extractor.analyze(str(corpus_file))
            for f in result.findings:
                assert f.reachability in ("reachable", "constant", "unknown"), (
                    f"{corpus_file.name}: unexpected reachability {f.reachability!r}"
                )
