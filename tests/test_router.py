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
import tempfile
from pathlib import Path

from mcp_auditor.kb.router import KBRouter, KBRule, KBValidationError, _load_rule
from mcp_auditor.extractors.threat_vector import (
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


# ---------------------------------------------------------------------------
# TestEffectiveRouting — P1-3
# ---------------------------------------------------------------------------

def _make_vector_with(
    rule_id: str,
    confidence: Confidence = Confidence.PROPOSED,
    reachability: str = "unknown",
) -> ThreatVector:
    """ThreatVector with controllable confidence + reachability."""
    return ThreatVector(
        rule_id=rule_id,
        type=ThreatVectorType.TOOL_POISONING,
        severity=Severity.HIGH,
        confidence=confidence,
        location="function:test, line 1",
        evidence="test evidence",
        description="test description",
        reachability=reachability,
    )


class TestEffectiveRouting:
    """
    P1-3: effective_routing is computed from (kb_routing, confidence, reachability).

    Rule: SELF_CONTAINED + (EXPERIMENTAL OR unknown reachability) → NEEDS_CONTEXT.
    All other combinations keep the KB baseline.
    """

    def test_experimental_on_self_contained_escalates(self):
        """EXPERIMENTAL confidence on a SELF_CONTAINED rule → NEEDS_CONTEXT."""
        vector = _make_vector_with("MCP-TPA-001", confidence=Confidence.EXPERIMENTAL)
        enriched = router.route_vector(vector)
        assert enriched.routing == "SELF_CONTAINED"           # KB baseline unchanged
        assert enriched.effective_routing == "NEEDS_CONTEXT"  # escalated

    def test_unknown_reachability_on_self_contained_escalates(self):
        """unknown reachability on a SELF_CONTAINED rule → NEEDS_CONTEXT."""
        vector = _make_vector_with("MCP-TPA-001", reachability="unknown")
        enriched = router.route_vector(vector)
        assert enriched.routing == "SELF_CONTAINED"
        assert enriched.effective_routing == "NEEDS_CONTEXT"

    def test_verified_reachable_self_contained_stays(self):
        """VERIFIED + reachable on SELF_CONTAINED → stays SELF_CONTAINED."""
        vector = _make_vector_with(
            "MCP-TPA-001",
            confidence=Confidence.VERIFIED,
            reachability="reachable",
        )
        enriched = router.route_vector(vector)
        assert enriched.effective_routing == "SELF_CONTAINED"

    def test_proposed_reachable_self_contained_stays(self):
        """PROPOSED + reachable → SELF_CONTAINED (PROPOSED is not EXPERIMENTAL)."""
        vector = _make_vector_with(
            "MCP-TPA-001",
            confidence=Confidence.PROPOSED,
            reachability="reachable",
        )
        enriched = router.route_vector(vector)
        assert enriched.effective_routing == "SELF_CONTAINED"

    def test_constant_reachability_keeps_routing(self):
        """constant reachability does NOT escalate routing (handled at exit-code level)."""
        vector = _make_vector_with("MCP-TPA-001", reachability="constant")
        enriched = router.route_vector(vector)
        assert enriched.effective_routing == "SELF_CONTAINED"

    def test_needs_context_rule_always_stays_needs_context(self):
        """A NEEDS_CONTEXT KB rule stays NEEDS_CONTEXT regardless of confidence."""
        vector = _make_vector_with("MCP-SSRF-001", confidence=Confidence.EXPERIMENTAL)
        enriched = router.route_vector(vector)
        assert enriched.routing == "NEEDS_CONTEXT"
        assert enriched.effective_routing == "NEEDS_CONTEXT"

    def test_fallback_effective_routing_is_needs_context(self):
        """Unknown rule_id → effective_routing == NEEDS_CONTEXT."""
        vector = _make_vector_with("MCP-UNKNOWN-999")
        enriched = router.route_vector(vector)
        assert enriched.effective_routing == "NEEDS_CONTEXT"

    def test_effective_routing_field_always_present(self):
        """Every enriched finding must carry a non-None effective_routing."""
        for rule_id in router.loaded_rule_ids():
            enriched = router.route_vector(_make_vector(rule_id))
            assert enriched.effective_routing is not None


class TestEffectiveRoutingDefaultsToRouting:
    """
    EnrichedFinding created directly (e.g. in tests) with only `routing` set
    must have effective_routing default to the same value as routing.
    """

    def test_needs_context_defaults(self):
        vector = _make_vector("MCP-SSRF-001", ThreatVectorType.SSRF)
        enriched = EnrichedFinding(
            vector=vector,
            rule_title="T",
            rule_description="D",
            rule_remediation="R",
            routing="NEEDS_CONTEXT",
        )
        assert enriched.effective_routing == "NEEDS_CONTEXT"

    def test_self_contained_defaults(self):
        vector = _make_vector("MCP-TPA-001")
        enriched = EnrichedFinding(
            vector=vector,
            rule_title="T",
            rule_description="D",
            rule_remediation="R",
            routing="SELF_CONTAINED",
        )
        assert enriched.effective_routing == "SELF_CONTAINED"


# ---------------------------------------------------------------------------
# TestExitCodeCriteria — P1-3
# ---------------------------------------------------------------------------

def _exit1_eligible(finding: "EnrichedFinding") -> bool:
    """Mirror the exit-1 logic from analyzer.py for unit testing."""
    return (
        finding.vector.severity.value in ("CRITICAL", "HIGH")
        and finding.vector.reachability in ("reachable", "unknown")
    )


class TestExitCodeCriteria:
    """
    P1-3: exit 1 only fires for reachable-or-unknown CRITICAL/HIGH findings.
    constant-reachability findings are excluded from CI failure.
    """

    def test_reachable_critical_triggers_exit(self):
        v = _make_vector_with("MCP-TPA-001", reachability="reachable")
        v = v.model_copy(update={"severity": Severity.CRITICAL})
        f = router.route_vector(v)
        assert _exit1_eligible(f)

    def test_reachable_high_triggers_exit(self):
        v = _make_vector_with("MCP-TPA-001", reachability="reachable")
        f = router.route_vector(v)
        assert _exit1_eligible(f)

    def test_unknown_reachability_high_triggers_exit(self):
        """unknown = conservative → treated like reachable for exit code."""
        v = _make_vector_with("MCP-TPA-001", reachability="unknown")
        f = router.route_vector(v)
        assert _exit1_eligible(f)

    def test_constant_critical_excluded_from_exit(self):
        """constant reachability → excluded from exit-1 even if CRITICAL."""
        v = _make_vector_with("MCP-TPA-001", reachability="constant")
        v = v.model_copy(update={"severity": Severity.CRITICAL})
        f = router.route_vector(v)
        assert not _exit1_eligible(f), (
            "constant-reachability CRITICAL must not trigger exit 1"
        )

    def test_constant_high_excluded_from_exit(self):
        v = _make_vector_with("MCP-TPA-001", reachability="constant")
        f = router.route_vector(v)
        assert not _exit1_eligible(f)

    def test_reachable_medium_excluded_from_exit(self):
        """Severity MEDIUM never triggers exit 1 regardless of reachability."""
        v = _make_vector_with("MCP-TPA-001", reachability="reachable")
        v = v.model_copy(update={"severity": Severity.MEDIUM})
        f = router.route_vector(v)
        assert not _exit1_eligible(f)


# ---------------------------------------------------------------------------
# TestKBRuleSchema — P1-4
# ---------------------------------------------------------------------------

_VALID_RULE_YAML = """\
id: MCP-TEST-001
title: "Test rule"
description: "A test rule for unit testing."
remediation: "Fix it."
severity: HIGH
owasp_llm: LLM01
cwe: CWE-99
references:
  - "https://example.com"
llm_routing: SELF_CONTAINED
"""


def _write_temp_yaml(content: str) -> Path:
    """Write content to a temp .yaml file and return its path."""
    f = tempfile.NamedTemporaryFile(suffix=".yaml", mode="w", delete=False)
    f.write(content)
    f.flush()
    f.close()
    return Path(f.name)


class TestKBRuleSchema:
    """KBRule Pydantic model validates all required fields."""

    def test_valid_rule_loads_cleanly(self):
        path = _write_temp_yaml(_VALID_RULE_YAML)
        rule = _load_rule(path)
        assert rule.id == "MCP-TEST-001"
        assert rule.title == "Test rule"
        assert rule.severity == "HIGH"
        assert rule.cwe == "CWE-99"
        assert rule.llm_routing == "SELF_CONTAINED"
        assert rule.references == ["https://example.com"]

    def test_missing_remediation_raises_kb_validation_error(self):
        yaml_no_rem = _VALID_RULE_YAML.replace("remediation: \"Fix it.\"\n", "")
        path = _write_temp_yaml(yaml_no_rem)
        with pytest.raises(KBValidationError) as exc_info:
            _load_rule(path)
        assert "remediation" in str(exc_info.value)

    def test_error_names_the_file(self):
        yaml_bad = _VALID_RULE_YAML.replace("title: \"Test rule\"\n", "")
        path = _write_temp_yaml(yaml_bad)
        with pytest.raises(KBValidationError) as exc_info:
            _load_rule(path)
        assert path.name in str(exc_info.value)

    def test_invalid_llm_routing_rejected(self):
        yaml_bad = _VALID_RULE_YAML.replace(
            "llm_routing: SELF_CONTAINED", "llm_routing: INVALID_TIER"
        )
        path = _write_temp_yaml(yaml_bad)
        with pytest.raises(KBValidationError) as exc_info:
            _load_rule(path)
        assert "llm_routing" in str(exc_info.value)

    def test_invalid_severity_rejected(self):
        yaml_bad = _VALID_RULE_YAML.replace("severity: HIGH", "severity: EXTREME")
        path = _write_temp_yaml(yaml_bad)
        with pytest.raises(KBValidationError) as exc_info:
            _load_rule(path)
        assert "severity" in str(exc_info.value)

    def test_missing_id_raises(self):
        yaml_bad = _VALID_RULE_YAML.replace("id: MCP-TEST-001\n", "")
        path = _write_temp_yaml(yaml_bad)
        with pytest.raises(KBValidationError):
            _load_rule(path)

    def test_missing_cwe_raises(self):
        yaml_bad = _VALID_RULE_YAML.replace("cwe: CWE-99\n", "")
        path = _write_temp_yaml(yaml_bad)
        with pytest.raises(KBValidationError) as exc_info:
            _load_rule(path)
        assert "cwe" in str(exc_info.value)

    def test_references_optional_defaults_to_empty(self):
        yaml_no_refs = _VALID_RULE_YAML.replace("references:\n  - \"https://example.com\"\n", "")
        path = _write_temp_yaml(yaml_no_refs)
        rule = _load_rule(path)
        assert rule.references == []

    def test_all_valid_routing_tiers_accepted(self):
        for tier in ("SELF_CONTAINED", "NEEDS_CONTEXT", "NEEDS_ANALYSIS", "NEEDS_CHAIN"):
            yaml_t = _VALID_RULE_YAML.replace("llm_routing: SELF_CONTAINED", f"llm_routing: {tier}")
            path = _write_temp_yaml(yaml_t)
            rule = _load_rule(path)
            assert rule.llm_routing == tier

    def test_all_valid_severity_levels_accepted(self):
        for sev in ("LOW", "MEDIUM", "HIGH", "CRITICAL"):
            yaml_s = _VALID_RULE_YAML.replace("severity: HIGH", f"severity: {sev}")
            path = _write_temp_yaml(yaml_s)
            rule = _load_rule(path)
            assert rule.severity == sev


class TestKBLoadsShippedRulesClean:
    """Every shipped YAML rule in kb/ must validate against KBRule schema."""

    def test_all_shipped_rules_load_without_error(self):
        """KBRouter.__init__ would already blow up if any rule was invalid,
        but this makes the invariant explicit and documents the intent."""
        kb_dir = Path(__file__).parent.parent / "mcp_auditor" / "kb"
        for yaml_file in sorted(kb_dir.glob("*.yaml")):
            rule = _load_rule(yaml_file)
            assert rule.id, f"{yaml_file.name}: id is empty"
            assert rule.cwe, f"{yaml_file.name}: cwe is missing"
            assert rule.llm_routing in (
                "SELF_CONTAINED", "NEEDS_CONTEXT", "NEEDS_ANALYSIS", "NEEDS_CHAIN"
            ), f"{yaml_file.name}: invalid llm_routing"

    def test_router_init_does_not_raise(self):
        """If the KB is valid, KBRouter() must not raise."""
        try:
            KBRouter()
        except KBValidationError as exc:
            pytest.fail(f"Shipped KB rule failed validation: {exc}")


class TestCWEPropagation:
    """CWE from the KB rule propagates into EnrichedFinding.rule_cwe (feeds P2-5 SARIF)."""

    def test_rule_cwe_populated_for_known_rule(self):
        vector = _make_vector("MCP-SSRF-001", ThreatVectorType.SSRF)
        enriched = router.route_vector(vector)
        assert enriched.rule_cwe == "CWE-918"

    def test_rule_cwe_populated_for_cmd_injection(self):
        vector = _make_vector("MCP-CMI-001")
        enriched = router.route_vector(vector)
        assert enriched.rule_cwe == "CWE-78"

    def test_rule_cwe_is_none_for_unknown_rule(self):
        vector = _make_vector("MCP-UNKNOWN-999")
        enriched = router.route_vector(vector)
        assert enriched.rule_cwe is None

    def test_all_shipped_rules_have_cwe_in_finding(self):
        for rule_id in router.loaded_rule_ids():
            enriched = router.route_vector(_make_vector(rule_id))
            assert enriched.rule_cwe is not None, (
                f"{rule_id}: rule_cwe is None in EnrichedFinding"
            )
            assert enriched.rule_cwe.startswith("CWE-"), (
                f"{rule_id}: rule_cwe '{enriched.rule_cwe}' does not start with 'CWE-'"
            )
