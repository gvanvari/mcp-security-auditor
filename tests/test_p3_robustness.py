"""
Tests for P3 — Robustness polish (ride-along).

  P3-1  Dedup merged findings by (location, rule_id)         — analyzer.py
  P3-2  Clean RuntimeError instead of KeyError on missing key — claude_provider.py
  P3-4  Bound read_text() size / warn on very large files     — ast_extractor.py,
                                                                  tool_description_analyzer.py
  P3-5  pickle.loads / unsafe yaml.load detector              — ast_extractor.py

P3-3 (guard non-text first content block) was already covered by
TestCallLLMResponseParsing in test_reasoner.py — no change needed there.
"""

from __future__ import annotations

import os
from unittest.mock import patch

import pytest

from mcp_auditor.analyzer import Analyzer, _dedup_vectors
from mcp_auditor.extractors.ast_extractor import ASTExtractor
from mcp_auditor.extractors.tool_description_analyzer import ToolDescriptionAnalyzer
from mcp_auditor.extractors.threat_vector import (
    Confidence,
    Severity,
    ThreatVector,
    ThreatVectorType,
)
from mcp_auditor.reasoner.claude_provider import ClaudeProvider


# ---------------------------------------------------------------------------
# P3-1 — Dedup merged findings
# ---------------------------------------------------------------------------

def _vector(rule_id: str, location: str, evidence: str = "x") -> ThreatVector:
    return ThreatVector(
        rule_id=rule_id,
        type=ThreatVectorType.CMD_INJECTION,
        severity=Severity.HIGH,
        confidence=Confidence.PROPOSED,
        location=location,
        evidence=evidence,
        description="test",
    )


class TestDedupVectors:
    def test_exact_duplicate_by_location_and_rule_id_is_dropped(self):
        v1 = _vector("MCP-CMI-001", "server.py:10")
        v2 = _vector("MCP-CMI-001", "server.py:10")
        result = _dedup_vectors([v1, v2])
        assert len(result) == 1

    def test_same_location_different_rule_id_both_kept(self):
        v1 = _vector("MCP-CMI-001", "server.py:10")
        v2 = _vector("MCP-CMI-002", "server.py:10")
        result = _dedup_vectors([v1, v2])
        assert len(result) == 2

    def test_same_rule_id_different_location_both_kept(self):
        v1 = _vector("MCP-CMI-001", "server.py:10")
        v2 = _vector("MCP-CMI-001", "server.py:20")
        result = _dedup_vectors([v1, v2])
        assert len(result) == 2

    def test_first_occurrence_order_preserved(self):
        v1 = _vector("MCP-CMI-001", "server.py:10", evidence="first")
        v2 = _vector("MCP-CMI-002", "server.py:20", evidence="second")
        v3 = _vector("MCP-CMI-001", "server.py:10", evidence="duplicate-of-first")
        result = _dedup_vectors([v1, v2, v3])
        assert [v.evidence for v in result] == ["first", "second"]

    def test_empty_list_returns_empty(self):
        assert _dedup_vectors([]) == []


class TestAnalyzerDedupIntegration:
    """
    A file where the AST extractor and the docstring extractor could both
    fire at the same line for the same rule must not double-report it.
    Regression coverage: the two extractors run independently in
    Analyzer.analyze() and their outputs are simply concatenated before
    this fix.
    """

    def test_analyze_never_returns_duplicate_location_rule_pairs(self, tmp_path):
        f = tmp_path / "server.py"
        f.write_text(
            "from mcp.server.fastmcp import FastMCP\n"
            "import subprocess\n"
            "mcp = FastMCP('fixture')\n"
            "\n"
            "@mcp.tool()\n"
            "def run(cmd: str) -> str:\n"
            "    subprocess.run(cmd, shell=True)\n"
            "    return ''\n",
            encoding="utf-8",
        )
        findings = Analyzer().analyze(str(f))
        seen = set()
        for finding in findings:
            key = (finding.vector.location, finding.vector.rule_id)
            assert key not in seen, f"duplicate finding: {key}"
            seen.add(key)


# ---------------------------------------------------------------------------
# P3-2 — Clean RuntimeError on missing API key
# ---------------------------------------------------------------------------

class TestClaudeProviderMissingKey:
    def test_missing_key_raises_runtime_error_not_key_error(self):
        with patch.dict(os.environ, {}, clear=True):
            with pytest.raises(RuntimeError, match="No Anthropic API key"):
                ClaudeProvider()

    def test_explicit_api_key_bypasses_env_lookup(self):
        with patch.dict(os.environ, {}, clear=True):
            provider = ClaudeProvider(api_key="explicit-key")
            assert provider is not None

    def test_env_var_is_used_when_no_explicit_key(self):
        with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "env-key"}, clear=True):
            provider = ClaudeProvider()
            assert provider is not None


# ---------------------------------------------------------------------------
# P3-4 — File size guard
# ---------------------------------------------------------------------------

class TestFileSizeGuard:
    def test_ast_extractor_skips_oversized_file(self, tmp_path):
        f = tmp_path / "huge.py"
        # Write valid-but-huge Python without holding it all in memory twice.
        with f.open("w", encoding="utf-8") as fh:
            fh.write("x = 1\n" * 1_000_000)  # well over the 5MB guard
        result = ASTExtractor().analyze(str(f))
        assert result.parse_status == "failed"
        assert "too large" in result.parse_warning.lower()
        assert result.findings == []

    def test_tool_description_analyzer_skips_oversized_file(self, tmp_path):
        f = tmp_path / "huge.py"
        with f.open("w", encoding="utf-8") as fh:
            fh.write("x = 1\n" * 1_000_000)
        result = ToolDescriptionAnalyzer().analyze(str(f))
        assert result.parse_status == "failed"
        assert "too large" in result.parse_warning.lower()

    def test_normal_sized_file_is_unaffected(self, tmp_path):
        f = tmp_path / "small.py"
        f.write_text("x = 1\n", encoding="utf-8")
        result = ASTExtractor().analyze(str(f))
        assert result.parse_status == "ok"


# ---------------------------------------------------------------------------
# P3-5 — pickle / unsafe yaml.load detector
# ---------------------------------------------------------------------------

_PICKLE_SOURCE = """\
from mcp.server.fastmcp import FastMCP
import pickle
mcp = FastMCP("fixture")

@mcp.tool()
def load_state(blob: bytes):
    return pickle.loads(blob)
"""

_YAML_UNSAFE_SOURCE = """\
from mcp.server.fastmcp import FastMCP
import yaml
mcp = FastMCP("fixture")

@mcp.tool()
def load_config(text: str):
    return yaml.load(text)
"""

_YAML_SAFE_LOADER_SOURCE = """\
from mcp.server.fastmcp import FastMCP
import yaml
mcp = FastMCP("fixture")

@mcp.tool()
def load_config(text: str):
    return yaml.load(text, Loader=yaml.SafeLoader)
"""

_YAML_SAFE_LOAD_SOURCE = """\
from mcp.server.fastmcp import FastMCP
import yaml
mcp = FastMCP("fixture")

@mcp.tool()
def load_config(text: str):
    return yaml.safe_load(text)
"""


class TestUnsafeDeserializationDetector:
    def test_pickle_loads_flagged(self, tmp_path):
        f = tmp_path / "server.py"
        f.write_text(_PICKLE_SOURCE, encoding="utf-8")
        result = ASTExtractor().analyze(str(f))
        rule_ids = [x.rule_id for x in result.findings]
        assert "MCP-DESER-001" in rule_ids

    def test_pickle_loads_is_deserialization_type(self, tmp_path):
        f = tmp_path / "server.py"
        f.write_text(_PICKLE_SOURCE, encoding="utf-8")
        result = ASTExtractor().analyze(str(f))
        finding = next(x for x in result.findings if x.rule_id == "MCP-DESER-001")
        assert finding.type == ThreatVectorType.DESERIALIZATION

    def test_pickle_loads_reachable_from_tool_param(self, tmp_path):
        f = tmp_path / "server.py"
        f.write_text(_PICKLE_SOURCE, encoding="utf-8")
        result = ASTExtractor().analyze(str(f))
        finding = next(x for x in result.findings if x.rule_id == "MCP-DESER-001")
        assert finding.reachability == "reachable"

    def test_yaml_load_without_loader_flagged(self, tmp_path):
        f = tmp_path / "server.py"
        f.write_text(_YAML_UNSAFE_SOURCE, encoding="utf-8")
        result = ASTExtractor().analyze(str(f))
        rule_ids = [x.rule_id for x in result.findings]
        assert "MCP-DESER-002" in rule_ids

    def test_yaml_load_with_safe_loader_not_flagged(self, tmp_path):
        f = tmp_path / "server.py"
        f.write_text(_YAML_SAFE_LOADER_SOURCE, encoding="utf-8")
        result = ASTExtractor().analyze(str(f))
        rule_ids = [x.rule_id for x in result.findings]
        assert "MCP-DESER-002" not in rule_ids

    def test_yaml_safe_load_not_flagged(self, tmp_path):
        f = tmp_path / "server.py"
        f.write_text(_YAML_SAFE_LOAD_SOURCE, encoding="utf-8")
        result = ASTExtractor().analyze(str(f))
        rule_ids = [x.rule_id for x in result.findings]
        assert "MCP-DESER-002" not in rule_ids

    def test_pickle_loads_routes_self_contained(self, tmp_path):
        """DESERIALIZATION findings should map to a real KB rule (not a fallback)."""
        f = tmp_path / "server.py"
        f.write_text(_PICKLE_SOURCE, encoding="utf-8")
        enriched = Analyzer().analyze(str(f))
        finding = next(x for x in enriched if x.vector.rule_id == "MCP-DESER-001")
        assert finding.routing == "SELF_CONTAINED"
        assert "pickle" in finding.rule_title.lower()
