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
from typing import List, Literal, Optional

import yaml
from pydantic import BaseModel, ValidationError

from mcp_auditor.extractors.threat_vector import Confidence, EnrichedFinding, ScanResult, ThreatVector

# Default kb/ directory — same directory as this file (mcp_auditor/kb/)
_DEFAULT_KB_DIR = Path(__file__).parent

# Valid routing tiers — kept in sync with EnrichedFinding.routing
_VALID_ROUTING = {"SELF_CONTAINED", "NEEDS_CONTEXT", "NEEDS_ANALYSIS", "NEEDS_CHAIN"}

# Valid severity values — kept in sync with Severity enum
_VALID_SEVERITY = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}


# ---------------------------------------------------------------------------
# KB rule schema (P1-4)
# ---------------------------------------------------------------------------

class KBRule(BaseModel):
    """
    Typed contract for a single KB YAML rule file.

    Every field is required. A missing or invalid field raises a
    ``KBValidationError`` that names the file and the field — not a
    ``KeyError`` traceback.

    Fields
    ------
    id          : Unique rule identifier, e.g. "MCP-SSRF-001".
    title       : Short human-readable rule name.
    description : Full explanation of the threat.
    remediation : Actionable fix guidance.
    severity    : Base severity: LOW | MEDIUM | HIGH | CRITICAL.
    owasp_llm   : OWASP LLM Top-10 reference, e.g. "LLM02".
    cwe         : CWE identifier, e.g. "CWE-918".  Used in SARIF output (P2-5).
    references  : List of external reference strings / URLs.
    llm_routing : Routing tier: SELF_CONTAINED | NEEDS_CONTEXT |
                  NEEDS_ANALYSIS | NEEDS_CHAIN.
    """

    id: str
    title: str
    description: str
    remediation: str
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    owasp_llm: str
    cwe: str
    references: List[str] = []
    llm_routing: Literal["SELF_CONTAINED", "NEEDS_CONTEXT", "NEEDS_ANALYSIS", "NEEDS_CHAIN"]


class KBValidationError(ValueError):
    """
    Raised when a KB YAML file fails schema validation.

    The message names the file and the specific field(s) that are invalid
    so the developer can fix the rule without digging into a traceback.
    """


def _load_rule(yaml_file: Path) -> KBRule:
    """
    Parse and validate one KB YAML file.

    Raises ``KBValidationError`` with the file name and Pydantic error
    details when the rule does not conform to the schema.
    """
    raw = yaml.safe_load(yaml_file.read_text(encoding="utf-8"))
    try:
        return KBRule.model_validate(raw)
    except ValidationError as exc:
        # Build a concise, actionable error message
        field_errors = "; ".join(
            f"{'.'.join(str(loc) for loc in e['loc'])}: {e['msg']}"
            for e in exc.errors()
        )
        raise KBValidationError(
            f"KB rule file '{yaml_file.name}' failed validation — {field_errors}"
        ) from exc


class KBRouter:
    """
    Loads KB rules once at init, routes ThreatVectors to EnrichedFindings.

    Each YAML file is validated against the ``KBRule`` schema on load.
    A malformed rule raises ``KBValidationError`` immediately — the tool
    fails fast rather than crashing later with a ``KeyError``.

    Usage:
        router = KBRouter()
        enriched = router.route(scan_result)
    """

    def __init__(self, kb_dir: Path = _DEFAULT_KB_DIR) -> None:
        self._rules: dict[str, KBRule] = {}
        for yaml_file in sorted(kb_dir.glob("*.yaml")):
            rule = _load_rule(yaml_file)
            self._rules[rule.id] = rule

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

    def get_rule(self, rule_id: str) -> Optional[KBRule]:
        """Return the KBRule for rule_id, or None if not found."""
        return self._rules.get(rule_id)

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
                effective_routing="NEEDS_CONTEXT",
            )

        base_routing = rule.llm_routing
        effective_routing = self._compute_effective_routing(
            base_routing, vector.confidence, vector.reachability
        )

        return EnrichedFinding(
            vector=vector,
            rule_title=rule.title,
            rule_description=rule.description.strip(),
            rule_remediation=rule.remediation.strip(),
            rule_references=rule.references,
            routing=base_routing,
            effective_routing=effective_routing,
            rule_cwe=rule.cwe,
        )

    @staticmethod
    def _compute_effective_routing(
        base_routing: str,
        confidence: "Confidence",
        reachability: str,
    ) -> str:
        """
        Compute effective routing from the KB baseline + finding-level signals.

        Rules:
          - SELF_CONTAINED + (EXPERIMENTAL confidence OR unknown reachability)
            → NEEDS_CONTEXT: a low-confidence or ambiguous finding needs human
              review even when the rule normally self-describes.
          - All other combinations: keep the KB baseline.

        Note: constant reachability does NOT change routing here — it is
        handled at the exit-code level in analyzer.py so the finding is
        still reported but excluded from CI failure.
        """
        if base_routing == "SELF_CONTAINED" and (
            confidence == Confidence.EXPERIMENTAL
            or reachability == "unknown"
        ):
            return "NEEDS_CONTEXT"
        return base_routing
