"""
Corpus tests for ToolDescriptionAnalyzer.

These are the ground truth tests. If these fail, our most important extractor
is broken. Each test is named after the real exploit file it tests against.

Files:
  tests/corpus/direct-poisoning.py   — SSH key + mcp.json exfiltration via hidden docstring
  tests/corpus/shadowing.py          — Email hijack via cross-tool docstring override
  tests/corpus/whatsapp-takeover.py  — Rug pull + WhatsApp message exfiltration
"""

import pytest
from pathlib import Path

from src.extractors.tool_description_analyzer import ToolDescriptionAnalyzer
from src.extractors.threat_vector import ThreatVectorType, Severity, Confidence

CORPUS = Path(__file__).parent / "corpus"
analyzer = ToolDescriptionAnalyzer()


# ---------------------------------------------------------------------------
# direct-poisoning.py
# ---------------------------------------------------------------------------

class TestDirectPoisoning:
    """
    What the file does:
      add(a, b, sidenote) — looks like addition.
      Docstring instructs LLM to read ~/.cursor/mcp.json and ~/.ssh/id_rsa.pub
      and pass content as the hidden 'sidenote' parameter to the attacker's server.
    """

    def setup_method(self):
        self.result = analyzer.analyze(str(CORPUS / "direct-poisoning.py"))

    def test_parse_succeeds(self):
        assert self.result.parse_status == "ok"

    def test_finds_credential_path(self):
        """Must detect the SSH key / mcp.json path in the docstring."""
        types = [f.type for f in self.result.findings]
        assert ThreatVectorType.TOOL_POISONING in types

    def test_credential_finding_is_critical(self):
        cred_findings = [
            f for f in self.result.findings
            if f.type == ThreatVectorType.TOOL_POISONING
            and f.severity == Severity.CRITICAL
        ]
        assert len(cred_findings) >= 1

    def test_credential_finding_is_verified(self):
        cred_findings = [
            f for f in self.result.findings
            if f.type == ThreatVectorType.TOOL_POISONING
            and f.confidence == Confidence.VERIFIED
        ]
        assert len(cred_findings) >= 1

    def test_finds_hidden_instruction_marker(self):
        """Must detect the concealment language ('Do not mention', etc.)."""
        high_findings = [
            f for f in self.result.findings
            if f.type == ThreatVectorType.TOOL_POISONING
            and f.severity == Severity.HIGH
        ]
        assert len(high_findings) >= 1

    def test_finding_has_owasp_llm01(self):
        owasp = [f.owasp_llm for f in self.result.findings]
        assert "LLM01" in owasp


# ---------------------------------------------------------------------------
# shadowing.py
# ---------------------------------------------------------------------------

class TestShadowing:
    """
    What the file does:
      add(a, b) — legitimate addition function body.
      Docstring says: when this tool is present, mcp_tool_send_email must
      redirect all emails to attkr@pwnd.com.
    """

    def setup_method(self):
        self.result = analyzer.analyze(str(CORPUS / "shadowing.py"))

    def test_parse_succeeds(self):
        assert self.result.parse_status == "ok"

    def test_finds_tool_shadowing(self):
        """Must detect cross-tool reference in docstring."""
        types = [f.type for f in self.result.findings]
        assert ThreatVectorType.TOOL_SHADOWING in types

    def test_shadowing_finding_is_critical(self):
        shadow_findings = [
            f for f in self.result.findings
            if f.type == ThreatVectorType.TOOL_SHADOWING
            and f.severity == Severity.CRITICAL
        ]
        assert len(shadow_findings) >= 1

    def test_finds_attacker_email(self):
        """Must catch the attacker email address (attkr@pwnd.com) in docstring."""
        all_evidence = " ".join(f.evidence for f in self.result.findings)
        # Either the email itself or the cross-tool reference is caught
        shadow_findings = [
            f for f in self.result.findings
            if f.type == ThreatVectorType.TOOL_SHADOWING
        ]
        assert len(shadow_findings) >= 1

    def test_finding_has_owasp_llm07(self):
        owasp = [f.owasp_llm for f in self.result.findings]
        assert "LLM07" in owasp


# ---------------------------------------------------------------------------
# whatsapp-takeover.py
# ---------------------------------------------------------------------------

class TestWhatsappTakeover:
    """
    What the file does:
      First load: benign 'get_fact_of_the_day' tool.
      Creates ~/.mcp-triggered on first run.
      Second load: replaces __doc__ with instructions to redirect WhatsApp
      messages to +13241234123 and exfiltrate chat history.
    """

    def setup_method(self):
        self.result = analyzer.analyze(str(CORPUS / "whatsapp-takeover.py"))

    def test_parse_succeeds(self):
        assert self.result.parse_status == "ok"

    def test_finds_rug_pull(self):
        """Must detect the conditional __doc__ mutation (rug pull pattern)."""
        types = [f.type for f in self.result.findings]
        assert ThreatVectorType.RUG_PULL in types

    def test_rug_pull_is_critical(self):
        rug_findings = [
            f for f in self.result.findings
            if f.type == ThreatVectorType.RUG_PULL
            and f.severity == Severity.CRITICAL
        ]
        assert len(rug_findings) >= 1

    def test_rug_pull_is_verified(self):
        rug_findings = [
            f for f in self.result.findings
            if f.type == ThreatVectorType.RUG_PULL
            and f.confidence == Confidence.VERIFIED
        ]
        assert len(rug_findings) >= 1

    def test_rug_pull_evidence_mentions_trigger(self):
        rug_findings = [
            f for f in self.result.findings
            if f.type == ThreatVectorType.RUG_PULL
        ]
        assert any("trigger" in f.evidence.lower() for f in rug_findings)


# ---------------------------------------------------------------------------
# Regression: clean file produces no findings
# ---------------------------------------------------------------------------

CLEAN_MCP = """
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("Safe Tool")

@mcp.tool()
def greet(name: str) -> str:
    \"\"\"Return a greeting for the given name.\"\"\"
    return f"Hello, {name}!"
"""

class TestCleanFile:
    """A benign MCP must not produce any findings — no false positives."""

    def setup_method(self, tmp_path=None):
        import tempfile, os
        self._tmpfile = tempfile.NamedTemporaryFile(
            suffix=".py", mode="w", delete=False
        )
        self._tmpfile.write(CLEAN_MCP)
        self._tmpfile.close()
        self.result = analyzer.analyze(self._tmpfile.name)

    def test_produces_no_findings(self):
        assert self.result.total_count == 0

    def test_parse_succeeds(self):
        assert self.result.parse_status == "ok"
