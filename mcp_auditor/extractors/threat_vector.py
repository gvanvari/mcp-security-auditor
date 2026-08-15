"""
ThreatVector — the canonical data contract for the entire pipeline.

Every extractor produces ThreatVectors.
The KB router consumes ThreatVectors.
The LLM provider receives ThreatVectors.
The report builder renders ThreatVectors.

Nothing bypasses this schema.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, List, Literal, Optional

from pydantic import BaseModel, Field, model_validator


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Confidence(str, Enum):
    # Confirmed: pattern validated against real known-vulnerable MCPs in corpus
    VERIFIED = "VERIFIED"
    # Probable: pattern matches known attack structure but not corpus-validated
    PROPOSED = "PROPOSED"
    # Speculative: heuristic match, needs human review
    EXPERIMENTAL = "EXPERIMENTAL"


class ThreatVectorType(str, Enum):
    # Tool description attacks (primary attack surface — all 3 corpus exploits)
    TOOL_POISONING = "tool_poisoning"          # Hidden instructions in docstring
    TOOL_SHADOWING = "tool_shadowing"          # Docstring overrides another tool's behavior
    RUG_PULL = "rug_pull"                      # Conditional __doc__ mutation after first run

    # Code-level attack surfaces
    CMD_INJECTION = "cmd_injection"            # subprocess, os.system, exec
    SSRF = "ssrf"                              # External HTTP calls to attacker-controlled URLs
    PATH_TRAVERSAL = "path_traversal"          # File access outside intended directory
    SECRET_EXPOSURE = "secret_exposure"        # Env vars or hardcoded credentials
    DESERIALIZATION = "deserialization"        # Unsafe pickle, yaml.load, eval
    SUPPLY_CHAIN = "supply_chain"              # Vulnerable or malicious dependency

    # Structural risk indicators
    EXCESSIVE_AGENCY = "excessive_agency"      # OWASP LLM08 — more capability than stated purpose
    PROMPT_INJECTION_SINK = "prompt_injection_sink"  # User input flows to LLM without sanitization


class ThreatVector(BaseModel):
    # Unique rule identifier — maps to KB entry (e.g. "MCP-TPA-001")
    rule_id: str

    # What category of threat this is
    type: ThreatVectorType

    # How bad is it
    severity: Severity

    # How confident are we that this is a real finding
    confidence: Confidence

    # Where in the source it was found — "function:add, docstring line 3"
    location: str

    # The exact text or code snippet that triggered the finding
    evidence: str

    # Human-readable description of what was found and why it matters
    description: str

    # OWASP LLM Top 10 reference if applicable — "LLM01", "LLM07", etc.
    owasp_llm: Optional[str] = None

    # How data flows through this vector — "env_var → external_call" if detectable
    data_flow: Optional[str] = None

    # Other tool names or threat vector IDs this interacts with
    interacts_with: List[str] = Field(default_factory=list)

    # Where this finding came from
    source: Literal["native", "semgrep", "bandit"] = "native"

    # Intra-procedural taint verdict (P1-1).
    # reachable  — sink argument traces back to an @mcp.tool() parameter
    # constant   — sink argument is a literal / config value with no param influence
    # unknown    — complex expression; conservative, treated like reachable for exit code
    reachability: Literal["reachable", "constant", "unknown"] = "unknown"


class ScanResult(BaseModel):
    """Complete output of Phase 1 extraction for a single file."""

    file_path: str
    findings: List[ThreatVector] = Field(default_factory=list)

    # Parse succeeded fully, partially, or failed
    parse_status: Literal["ok", "partial", "failed"] = "ok"
    parse_warning: Optional[str] = None

    # Summary counts — useful for the router and report header
    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    @property
    def total_count(self) -> int:
        return len(self.findings)


class EnrichedFinding(BaseModel):
    """
    A ThreatVector after KB lookup and optional LLM enrichment.

    Produced by: kb/router.py
    Consumed by: llm/provider.py (adds llm_analysis), reporters/

    The ThreatVector is never mutated — it is wrapped here alongside
    the KB rule content and the routing decision.
    """

    # The original finding from Phase 1 extraction — unchanged
    vector: ThreatVector

    # Full content of the matching YAML rule from kb/
    rule_title: str
    rule_description: str
    rule_remediation: str
    rule_references: List[str] = Field(default_factory=list)

    # CWE identifier from the KB rule (P1-4 / P2-5 SARIF taxa).
    # None for findings with no matching KB entry (fallback path).
    rule_cwe: Optional[str] = None

    # Routing decision from the KB (baseline per rule)
    routing: Literal["SELF_CONTAINED", "NEEDS_CONTEXT", "NEEDS_ANALYSIS", "NEEDS_CHAIN"]

    # Effective routing after applying confidence + reachability overrides (P1-3).
    # This is what the LLM provider and exit-code logic actually use.
    #
    # Rules:
    #   SELF_CONTAINED + (EXPERIMENTAL confidence OR unknown reachability)
    #       → escalated to NEEDS_CONTEXT (low-confidence finding needs human triage)
    #   constant reachability → routing unchanged, but finding excluded from exit-1
    #   Otherwise → equals routing (KB baseline)
    #
    # Defaults to `routing` when not explicitly provided so test fixtures that
    # only set `routing` still work correctly.
    effective_routing: Optional[Literal["SELF_CONTAINED", "NEEDS_CONTEXT", "NEEDS_ANALYSIS", "NEEDS_CHAIN"]] = None

    @model_validator(mode="after")
    def _default_effective_routing(self) -> "EnrichedFinding":
        if self.effective_routing is None:
            object.__setattr__(self, "effective_routing", self.routing)
        return self

    # Populated by the LLM provider (PR-6) — None until then
    llm_analysis: Optional[str] = None

    # Suppression (P2-2) — set by mcp_auditor.suppression, never dropped from
    # the result list. Suppressed findings stay visible in reports (marked)
    # but are excluded from CI-failure logic.
    suppressed: bool = False
    suppression_reason: Optional[Literal["inline-ignore", "baseline"]] = None
