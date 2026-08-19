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

# CWE taxonomy (P2-5) — referenced by rule `relationships` so GitHub Code
# Scanning can group findings by CWE. Mirrors the shape CodeQL emits.
_CWE_TAXONOMY_NAME = "CWE"
_CWE_TAXONOMY_VERSION = "4.9"


class SARIFReporter:
    def generate(self, findings: List[EnrichedFinding], file_path: str = "") -> str:
        """Return a SARIF 2.1.0 JSON string for the given findings."""
        rules = self._build_rules(findings)
        results = self._build_results(findings, file_path)
        taxonomies = self._build_taxonomies(findings)

        run: Dict[str, Any] = {
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
        if taxonomies:
            run["taxonomies"] = taxonomies

        sarif: Dict[str, Any] = {
            "$schema": _SARIF_SCHEMA,
            "version": _SARIF_VERSION,
            "runs": [run],
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

            tags = ["security", "mcp", f.vector.type.value]
            cwe_num = self._cwe_number(f.rule_cwe)
            if cwe_num:
                # GitHub Code Scanning parses "external/cwe/cwe-N" tags to
                # group and link findings by CWE.
                tags.append(f"external/cwe/cwe-{cwe_num}")

            rule: Dict[str, Any] = {
                "id": rid,
                "name": f.rule_title.replace(" ", ""),
                "shortDescription": {"text": f.rule_title},
                "fullDescription": {"text": f.rule_description},
                "help": {"text": f.rule_remediation, "markdown": f.rule_remediation},
                "properties": {
                    "security-severity": _SECURITY_SEVERITY[f.vector.severity],
                    "tags": tags,
                },
                "defaultConfiguration": {"level": _SARIF_LEVEL[f.vector.severity]},
            }

            help_uri = self._help_uri(f.rule_references)
            if help_uri:
                rule["helpUri"] = help_uri

            if cwe_num:
                rule["relationships"] = [
                    {
                        "target": {
                            "id": cwe_num,
                            "toolComponent": {"name": _CWE_TAXONOMY_NAME},
                        },
                        "kinds": ["superset"],
                    }
                ]

            rules.append(rule)
        return rules

    def _build_taxonomies(self, findings: List[EnrichedFinding]) -> List[Dict[str, Any]]:
        """CWE taxonomy (P2-5) — one taxon per distinct CWE id referenced by findings."""
        cwe_nums = sorted(
            {self._cwe_number(f.rule_cwe) for f in findings if self._cwe_number(f.rule_cwe)},
            key=int,
        )
        if not cwe_nums:
            return []
        return [
            {
                "name": _CWE_TAXONOMY_NAME,
                "version": _CWE_TAXONOMY_VERSION,
                "organization": "MITRE",
                "shortDescription": {"text": "The MITRE Common Weakness Enumeration"},
                "taxa": [{"id": n, "name": f"CWE-{n}"} for n in cwe_nums],
            }
        ]

    def _help_uri(self, references: List[str]) -> str:
        """
        First actual URL in `references`, else "".

        rule_references mixes plain-text citations ("OWASP LLM08: Excessive
        Agency", "CWE-918: Server-Side Request Forgery") with real URLs.
        `helpUri` must be a URI per the SARIF schema — GitHub Code Scanning's
        SARIF ingestion warns and drops the field otherwise, so filter to
        http(s) links rather than blindly taking references[0].
        """
        for ref in references:
            if ref.startswith("http://") or ref.startswith("https://"):
                return ref
        return ""

    def _cwe_number(self, cwe: str | None) -> str | None:
        """'CWE-918' -> '918'. None/malformed input -> None."""
        if not cwe:
            return None
        num = cwe.upper().removeprefix("CWE-")
        return num if num.isdigit() else None

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

            # P2-2 — suppressed findings stay in results (still visible in
            # GitHub Code Scanning as "dismissed") rather than being dropped.
            if f.suppressed:
                result["suppressions"] = [
                    {
                        "kind": "inSource" if f.suppression_reason == "inline-ignore" else "external",
                        "justification": f"Suppressed via {f.suppression_reason}",
                    }
                ]

            results.append(result)
        return results

    def _parse_line(self, location: str) -> int:
        """
        Extract the line number from a location string, default 1.

        Location formats vary by extractor ("path:N", "line N", "... (line
        ~N)"), but every format ends with the relevant line number, so the
        LAST integer wins — the first would misfire on any digit earlier in
        the string (e.g. a workspace path like "/tmp/tmp.0_xyz/server.py:7"
        would otherwise report line 0, which SARIF's schema rejects outright).
        """
        import re
        matches = re.findall(r"\d+", location)
        return int(matches[-1]) if matches else 1
