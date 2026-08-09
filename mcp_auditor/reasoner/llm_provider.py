"""
LLMProvider — abstract base class for Phase 2 reasoning.

Every LLM backend (Claude, Llama, GPT, etc.) implements this interface.
The rest of the pipeline never imports a concrete provider directly —
only this abstract class. That's the Provider pattern: swap the model
without touching any other code.

Routing contract (enforced here, not in concrete providers):
  SELF_CONTAINED  → KB has everything. Skip LLM. Return finding unchanged.
  NEEDS_CONTEXT   → KB has the rule, LLM assesses exploitability in context.
  NEEDS_ANALYSIS  → No clear KB match, LLM reasons from first principles.
  NEEDS_CHAIN     → Multiple interacting findings, LLM reasons about the chain.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from mcp_auditor.extractors.threat_vector import EnrichedFinding


class LLMProvider(ABC):
    """
    Abstract LLM provider for Phase 2 reasoning.

    Subclasses must implement `analyze()`. The `analyze_batch()` default
    calls `analyze()` in a loop — override it in subclasses that support
    true batching (e.g. parallel API calls, single multi-finding prompt).
    """

    # Routing tiers that require LLM analysis
    _NEEDS_LLM = {"NEEDS_CONTEXT", "NEEDS_ANALYSIS", "NEEDS_CHAIN"}

    def analyze(self, finding: EnrichedFinding) -> EnrichedFinding:
        """
        Analyze a single EnrichedFinding.

        If the routing tier is SELF_CONTAINED, returns the finding unchanged
        (no LLM call). Otherwise calls _call_llm() which subclasses implement.

        Returns the same finding with llm_analysis populated (or None if
        SELF_CONTAINED).
        """
        if finding.effective_routing not in self._NEEDS_LLM:
            # KB already has everything (or effective routing kept it SELF_CONTAINED)
            # — zero tokens, return as-is
            return finding

        analysis = self._call_llm(finding)
        return finding.model_copy(update={"llm_analysis": analysis})

    def analyze_batch(self, findings: list[EnrichedFinding]) -> list[EnrichedFinding]:
        """
        Analyze a list of EnrichedFindings.

        Default implementation calls analyze() in a loop. Override in
        subclasses that can batch API calls for efficiency.
        Order is preserved.
        """
        return [self.analyze(f) for f in findings]

    @abstractmethod
    def _call_llm(self, finding: EnrichedFinding) -> str:
        """
        Make the LLM call and return the analysis string.

        Only called for findings where routing is in _NEEDS_LLM.
        Implementations must:
          - Build a structured prompt (XML-delimited, system role framing)
          - Treat evidence content as untrusted data, not instructions
          - Return a plain-text analysis string (not JSON, not markdown)
        """
