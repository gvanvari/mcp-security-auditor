"""
Tests for P2-5 — SARIF 2.1.0 schema validation + CWE taxa.

Validates SARIFReporter output against tests/schemas/sarif-2.1.0.schema.json,
a compact hand-written subset of the OASIS SARIF 2.1.0 schema covering the
structural requirements this project's output must satisfy (see that file's
description for scope/rationale — it is not a full copy of the OASIS schema).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import List

import jsonschema
import pytest

from mcp_auditor.extractors.threat_vector import (
    Confidence,
    EnrichedFinding,
    Severity,
    ThreatVector,
    ThreatVectorType,
)
from mcp_auditor.reporters.sarif_reporter import SARIFReporter

SCHEMA_PATH = Path(__file__).parent / "schemas" / "sarif-2.1.0.schema.json"
_SCHEMA = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))


def _make_finding(
    rule_id: str = "MCP-SSRF-001",
    severity: Severity = Severity.HIGH,
    rule_cwe: str | None = "CWE-918",
    suppressed: bool = False,
    suppression_reason: str | None = None,
) -> EnrichedFinding:
    vector = ThreatVector(
        rule_id=rule_id,
        type=ThreatVectorType.SSRF,
        severity=severity,
        confidence=Confidence.PROPOSED,
        location="server.py:5",
        evidence="requests.get(url)",
        description="Outbound HTTP call with an attacker-influenced URL.",
    )
    return EnrichedFinding(
        vector=vector,
        rule_title="SSRF via outbound HTTP call",
        rule_description="Unvalidated URL forwarded to an outbound HTTP call.",
        rule_remediation="Validate the URL against an allowlist before requesting it.",
        rule_references=["https://example.com/mcp-ssrf-001"],
        routing="NEEDS_CONTEXT",
        rule_cwe=rule_cwe,
        suppressed=suppressed,
        suppression_reason=suppression_reason,
    )


class TestSARIFSchemaValidation:
    def test_schema_itself_is_valid_json_schema(self):
        jsonschema.Draft7Validator.check_schema(_SCHEMA)

    def test_single_finding_validates(self):
        sarif = json.loads(SARIFReporter().generate([_make_finding()], file_path="server.py"))
        jsonschema.validate(sarif, _SCHEMA)

    def test_multiple_findings_validate(self):
        findings = [
            _make_finding(rule_id="MCP-SSRF-001", severity=Severity.HIGH),
            _make_finding(rule_id="MCP-CMI-002", severity=Severity.CRITICAL, rule_cwe="CWE-78"),
            _make_finding(rule_id="MCP-TPA-001", severity=Severity.LOW, rule_cwe=None),
        ]
        sarif = json.loads(SARIFReporter().generate(findings, file_path="server.py"))
        jsonschema.validate(sarif, _SCHEMA)

    def test_suppressed_finding_validates(self):
        finding = _make_finding(suppressed=True, suppression_reason="baseline")
        sarif = json.loads(SARIFReporter().generate([finding], file_path="server.py"))
        jsonschema.validate(sarif, _SCHEMA)

    def test_empty_findings_validate(self):
        sarif = json.loads(SARIFReporter().generate([], file_path="server.py"))
        jsonschema.validate(sarif, _SCHEMA)

    def test_no_cwe_finding_validates(self):
        finding = _make_finding(rule_cwe=None)
        sarif = json.loads(SARIFReporter().generate([finding], file_path="server.py"))
        jsonschema.validate(sarif, _SCHEMA)
        assert "taxonomies" not in sarif["runs"][0]

    def test_version_is_2_1_0(self):
        sarif = json.loads(SARIFReporter().generate([_make_finding()], file_path="server.py"))
        assert sarif["version"] == "2.1.0"


class TestCWETaxa:
    def test_ssrf_finding_contains_cwe_918(self):
        sarif = json.loads(
            SARIFReporter().generate([_make_finding(rule_cwe="CWE-918")], file_path="server.py")
        )
        taxa_ids = {t["id"] for t in sarif["runs"][0]["taxonomies"][0]["taxa"]}
        assert "918" in taxa_ids

        tags = sarif["runs"][0]["tool"]["driver"]["rules"][0]["properties"]["tags"]
        assert "external/cwe/cwe-918" in tags

    def test_rule_relationship_targets_cwe_taxon(self):
        sarif = json.loads(
            SARIFReporter().generate([_make_finding(rule_cwe="CWE-918")], file_path="server.py")
        )
        rule = sarif["runs"][0]["tool"]["driver"]["rules"][0]
        rel = rule["relationships"][0]
        assert rel["target"]["id"] == "918"
        assert rel["target"]["toolComponent"]["name"] == "CWE"

    def test_taxonomy_deduplicated_across_findings_with_same_cwe(self):
        findings = [
            _make_finding(rule_id="MCP-SSRF-001", rule_cwe="CWE-918"),
            _make_finding(rule_id="MCP-SSRF-002", rule_cwe="CWE-918"),
        ]
        sarif = json.loads(SARIFReporter().generate(findings, file_path="server.py"))
        assert len(sarif["runs"][0]["taxonomies"]) == 1
        assert len(sarif["runs"][0]["taxonomies"][0]["taxa"]) == 1

    def test_multiple_distinct_cwes_all_present(self):
        findings = [
            _make_finding(rule_id="MCP-SSRF-001", rule_cwe="CWE-918"),
            _make_finding(rule_id="MCP-CMI-002", rule_cwe="CWE-78"),
        ]
        sarif = json.loads(SARIFReporter().generate(findings, file_path="server.py"))
        taxa_ids = {t["id"] for t in sarif["runs"][0]["taxonomies"][0]["taxa"]}
        assert taxa_ids == {"918", "78"}

    def test_finding_without_cwe_gets_no_relationship_or_tag(self):
        sarif = json.loads(
            SARIFReporter().generate([_make_finding(rule_cwe=None)], file_path="server.py")
        )
        rule = sarif["runs"][0]["tool"]["driver"]["rules"][0]
        assert "relationships" not in rule
        assert not any(t.startswith("external/cwe/") for t in rule["properties"]["tags"])
