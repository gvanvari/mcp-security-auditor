"""
Tests for KBRouter (PR-5).

All ThreatVector inputs are hand-built fixtures — no extractors used.
This isolates the router: a failure here means the router is broken,
not the extractors.

Test classes:
  TestKBLoading       — YAML files load correctly at startup
  TestRouting         — rule_id → correct routing tier
  TestEnrichedContent — rule fields populate from YAML
  TestFallback        — unknown rule_id gets a safe fallback
  TestRouteFromScan   — route() processes a full ScanResult
"""

import pytest
from pathlib import Path

from kb.router import KBRouter
from src.extractors.threat_vector import (
    Confidence,
    EnrichedFinding,
    ScanResult,
    Severity,
    ThreatVector,
    ThreatVectorType,
)

# All rule IDs we expect the KB to contain
EXPECTED_RULE_IDS = {
    "MCP-TPA-001",
    "MCP-TPA-002",
    "MCP-SHADOW-001",
    "MCP-RUGPULL-001",
    "MCP-CMI-001",
    "MCP-CMI-002",
    "MCP-CMI-003",
    "MCP-SEC-001",
    "MCP-SSRF-001",
}


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

def _make_vector(rule_id: str, threat_type: ThreatVectorType = ThreatVectorType.TOOL_POISONING) -> ThreatVector:
    """Minimal valid ThreatVector for a given rule_id."""
    return ThreatVector(
        rule_id=rule_id,
        type=threat_type,
        severity=Severity.HIGH,
        confidence=Confidence.PROPOSED,
        location="function:test, line 1",
        evidence="test evidence",
        description="test description",
    )


router = KBRouter()


# ---------------------------------------------------------------------------
# TestKBLoading
# ---------------------------------------------------------------------------

class TestKBLoading:
    """The router loads all expected YAML rules from kb/ at startup."""

    def test_loads_all_expected_rules(self):
        loaded = set(router.loaded_rule_ids())
        assert EXPECTED_RULE_IDS == loaded

    def test_loads_nine_rules(self):
        assert len(router.loaded_rule_ids()) == 9


# ---------------------------------------------------------------------------
# TestRouting
# ---------------------------------------------------------------------------

class TestRouting:
    """Each rule_id maps to the correct routing tier."""

    @pytest.mark.parametrize("rule_id", [
        "MCP-TPA-001",
        "MCP-TPA-002",
        "MCP-SHADOW-001",
        "MCP-RUGPULL-001",
        "MCP-CMI-001",
        "MCP-CMI-003",
    ])
    def test_self_contained_rules(self, rule_id):
        vector = _make_vector(rule_id)
        enriched = router.route_vector(vector)
        assert enriched.routing == "SELF_CONTAINED"

    @pytest.mark.parametrize("rule_id", [
        "MCP-CMI-002",
        "MCP-SEC-001",
        "MCP-SSRF-001",
    ])
    def test_needs_context_rules(self, rule_id):
        vector = _make_vector(rule_id)
        enriched = router.route_vector(vector)
        assert enriched.routing == "NEEDS_CONTEXT"


# ---------------------------------------------------------------------------
# TestEnrichedContent
# ---------------------------------------------------------------------------

class TestEnrichedContent:
    """EnrichedFinding fields are populated correctly from the YAML rule."""

    def setup_method(self):
        vector = _make_vector("MCP-TPA-001")
        self.enriched = router.route_vector(vector)

    def test_original_vector_preserved(self):
        """The original ThreatVector must be unchanged."""
        assert self.enriched.vector.rule_id == "MCP-TPA-001"
        assert self.enriched.vector.evidence == "test evidence"

    def test_rule_title_populated(self):
        assert self.enriched.rule_title != ""
        assert "credential" in self.enriched.rule_title.lower()

    def test_rule_description_populated(self):
        assert len(self.enriched.rule_description) > 50

    def test_rule_remediation_populated(self):
        assert len(self.enriched.rule_remediation) > 20

    def test_rule_references_populated(self):
        assert len(self.enriched.rule_references) >= 1
        assert any("OWASP" in ref for ref in self.enriched.rule_references)

    def test_llm_analysis_is_none_by_default(self):
        """LLM analysis is None until the LLM provider runs (PR-6)."""
        assert self.enriched.llm_analysis is None


# ---------------------------------------------------------------------------
# TestFallback
# ---------------------------------------------------------------------------

class TestFallback:
    """Unknown rule_id produces a safe fallback EnrichedFinding."""

    def setup_method(self):
        vector = _make_vector("MCP-UNKNOWN-999")
        self.enriched = router.route_vector(vector)

    def test_returns_enriched_finding(self):
        assert isinstance(self.enriched, EnrichedFinding)

    def test_fallback_routing_is_needs_context(self):
        """Unknown rules must go to LLM — never silently dropped."""
        assert self.enriched.routing == "NEEDS_CONTEXT"

    def test_fallback_title_mentions_rule_id(self):
        assert "MCP-UNKNOWN-999" in self.enriched.rule_title

    def test_original_vector_preserved(self):
        assert self.enriched.vector.rule_id == "MCP-UNKNOWN-999"


# ---------------------------------------------------------------------------
# TestRouteFromScan
# ---------------------------------------------------------------------------

class TestRouteFromScan:
    """route() processes a full ScanResult and returns one EnrichedFinding per vector."""

    def setup_method(self):
        scan = ScanResult(
            file_path="fake.py",
            findings=[
                _make_vector("MCP-TPA-001"),
                _make_vector("MCP-SSRF-001", ThreatVectorType.SSRF),
                _make_vector("MCP-CMI-003", ThreatVectorType.DESERIALIZATION),
            ],
        )
        self.enriched = router.route(scan)

    def test_returns_one_per_finding(self):
        assert len(self.enriched) == 3

    def test_order_preserved(self):
        assert self.enriched[0].vector.rule_id == "MCP-TPA-001"
        assert self.enriched[1].vector.rule_id == "MCP-SSRF-001"
        assert self.enriched[2].vector.rule_id == "MCP-CMI-003"

    def test_mixed_routing_tiers(self):
        routings = [e.routing for e in self.enriched]
        assert "SELF_CONTAINED" in routings
        assert "NEEDS_CONTEXT" in routings

    def test_empty_scan_returns_empty_list(self):
        empty = router.route(ScanResult(file_path="empty.py", findings=[]))
        assert empty == []
