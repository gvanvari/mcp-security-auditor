"""
KBRouter — Phase 2 of the pipeline.

Loads all YAML rules from the kb/ directory at startup, then for each
ThreatVector produced by Phase 1 extractors, looks up the matching rule
and produces an EnrichedFinding with:
  - the original ThreatVector (unchanged)
  - the KB rule content (title, description, remediation, references)
  - the routing decision (SELF_CONTAINED / NEEDS_CONTEXT / ...)

Findings with no matching KB rule are routed as NEEDS_CONTEXT so the
LLM provider can attempt to describe them rather than silently dropping.
"""

from __future__ import annotations

from pathlib import Path
from typing import List

import yaml

from src.extractors.threat_vector import EnrichedFinding, ScanResult, ThreatVector

# Default kb/ directory — adjacent to this file's parent (project root/kb/)
_DEFAULT_KB_DIR = Path(__file__).parent.parent / "kb"


class KBRouter:
    """
    Loads KB rules once at init, routes ThreatVectors to EnrichedFindings.

    Usage:
        router = KBRouter()
        enriched = router.route(scan_result)
    """

    def __init__(self, kb_dir: Path = _DEFAULT_KB_DIR) -> None:
        self._rules: dict[str, dict] = {}
        for yaml_file in sorted(kb_dir.glob("*.yaml")):
            rule = yaml.safe_load(yaml_file.read_text(encoding="utf-8"))
            self._rules[rule["id"]] = rule

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def route(self, scan_result: ScanResult) -> list[EnrichedFinding]:
        """
        Enrich all findings in a ScanResult with KB rule data.

        Returns one EnrichedFinding per ThreatVector. Order is preserved.
        Findings whose rule_id has no matching KB entry are given a
        fallback rule and routed as NEEDS_CONTEXT.
        """
        return [self._enrich(vector) for vector in scan_result.findings]

    def route_vector(self, vector: ThreatVector) -> EnrichedFinding:
        """Enrich a single ThreatVector. Useful for testing."""
        return self._enrich(vector)

    def loaded_rule_ids(self) -> list[str]:
        """Return the list of rule IDs loaded from the KB."""
        return list(self._rules.keys())

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _enrich(self, vector: ThreatVector) -> EnrichedFinding:
        rule = self._rules.get(vector.rule_id)

        if rule is None:
            # No KB entry — route to LLM for best-effort description
            return EnrichedFinding(
                vector=vector,
                rule_title=f"Unknown rule: {vector.rule_id}",
                rule_description=(
                    f"No KB entry found for rule_id '{vector.rule_id}'. "
                    f"LLM analysis required to describe this finding."
                ),
                rule_remediation="Review manually — no remediation guidance available.",
                rule_references=[],
                routing="NEEDS_CONTEXT",
            )

        return EnrichedFinding(
            vector=vector,
            rule_title=rule["title"],
            rule_description=rule["description"].strip(),
            rule_remediation=rule["remediation"].strip(),
            rule_references=rule.get("references", []),
            routing=rule["llm_routing"],
        )
