"""
SARIFReporter — Phase 4 output for GitHub Code Scanning / VS Code integration.

Produces SARIF 2.1.0 JSON. When uploaded to GitHub as a workflow artifact,
findings appear as inline annotations on the offending lines in PRs.

Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
"""

from __future__ import annotations

import json
from typing import Any, Dict, List

from mcp_auditor.extractors.threat_vector import EnrichedFinding, Severity

_TOOL_NAME = "mcp-security-auditor"
_TOOL_VERSION = "0.1.0"
_SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
_SARIF_VERSION = "2.1.0"

# Map our severity enum to SARIF notification levels
_SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
}

# Map our severity to SARIF security-severity score (CVSS-like 0.0–10.0)
_SECURITY_SEVERITY = {
    Severity.CRITICAL: "9.0",
    Severity.HIGH: "7.0",
    Severity.MEDIUM: "5.0",
    Severity.LOW: "3.0",
}


class SARIFReporter:
    def generate(self, findings: List[EnrichedFinding], file_path: str = "") -> str:
        """Return a SARIF 2.1.0 JSON string for the given findings."""
        rules = self._build_rules(findings)
        results = self._build_results(findings, file_path)

        sarif: Dict[str, Any] = {
            "$schema": _SARIF_SCHEMA,
            "version": _SARIF_VERSION,
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": _TOOL_NAME,
                            "version": _TOOL_VERSION,
                            "informationUri": "https://github.com/gvanvari/mcp-security-auditor",
                            "rules": rules,
                        }
                    },
                    "results": results,
                }
            ],
        }
        return json.dumps(sarif, indent=2)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _build_rules(self, findings: List[EnrichedFinding]) -> List[Dict[str, Any]]:
        """Deduplicated rule descriptors — one per unique rule_id."""
        seen: set[str] = set()
        rules: List[Dict[str, Any]] = []
        for f in findings:
            rid = f.vector.rule_id
            if rid in seen:
                continue
            seen.add(rid)
            rules.append(
                {
                    "id": rid,
                    "name": f.rule_title.replace(" ", ""),
                    "shortDescription": {"text": f.rule_title},
                    "fullDescription": {"text": f.rule_description},
                    "helpUri": f.rule_references[0] if f.rule_references else "",
                    "help": {"text": f.rule_remediation, "markdown": f.rule_remediation},
                    "properties": {
                        "security-severity": _SECURITY_SEVERITY[f.vector.severity],
                        "tags": ["security", "mcp", f.vector.type.value],
                    },
                    "defaultConfiguration": {"level": _SARIF_LEVEL[f.vector.severity]},
                }
            )
        return rules

    def _build_results(
        self, findings: List[EnrichedFinding], file_path: str
    ) -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []
        for f in findings:
            v = f.vector
            # Parse line number from location string if possible (e.g. "line 42")
            line = self._parse_line(v.location)

            message_text = v.description
            if f.llm_analysis:
                message_text = f"{message_text}\n\nLLM Analysis: {f.llm_analysis.strip()}"

            result: Dict[str, Any] = {
                "ruleId": v.rule_id,
                "level": _SARIF_LEVEL[v.severity],
                "message": {"text": message_text},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": file_path,
                                "uriBaseId": "%SRCROOT%",
                            },
                            "region": {"startLine": line},
                        }
                    }
                ],
                "properties": {
                    "confidence": v.confidence.value,
                    "routing": f.routing,
                },
            }
            results.append(result)
        return results

    def _parse_line(self, location: str) -> int:
        """Extract the first integer from a location string, default 1."""
        import re
        match = re.search(r"\d+", location)
        return int(match.group()) if match else 1
