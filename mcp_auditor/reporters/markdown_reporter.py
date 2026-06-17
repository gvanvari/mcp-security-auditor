"""
MarkdownReporter — Phase 4 output for human consumption.

Takes list[EnrichedFinding] and renders a structured Markdown report.
CRITICAL/HIGH findings first. SELF_CONTAINED uses KB remediation.
NEEDS_CONTEXT/NEEDS_ANALYSIS prepends LLM analysis.
"""

from __future__ import annotations

from typing import List

from mcp_auditor.extractors.threat_vector import EnrichedFinding, Severity

# Severity display order — highest risk first
_SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
}

_SEVERITY_BADGE = {
    Severity.CRITICAL: "🔴 CRITICAL",
    Severity.HIGH: "🟠 HIGH",
    Severity.MEDIUM: "🟡 MEDIUM",
    Severity.LOW: "🟢 LOW",
}


class MarkdownReporter:
    def generate(self, findings: List[EnrichedFinding], file_path: str = "") -> str:
        """Return a Markdown string for the given findings."""
        if not findings:
            return self._empty_report(file_path)

        sorted_findings = sorted(
            findings,
            key=lambda f: (_SEVERITY_ORDER[f.vector.severity], f.vector.rule_id),
        )

        lines: List[str] = []

        # Header
        lines.append("# MCP Security Audit Report")
        if file_path:
            lines.append(f"\n**File:** `{file_path}`\n")

        # Summary table
        lines.append(self._summary_table(findings))

        # Individual findings
        lines.append("\n---\n")
        lines.append("## Findings\n")
        for i, finding in enumerate(sorted_findings, 1):
            lines.append(self._render_finding(i, finding))

        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _summary_table(self, findings: List[EnrichedFinding]) -> str:
        counts = {s: 0 for s in Severity}
        for f in findings:
            counts[f.vector.severity] += 1

        rows = [
            "## Summary\n",
            "| Severity | Count |",
            "|----------|-------|",
        ]
        for severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]:
            rows.append(f"| {_SEVERITY_BADGE[severity]} | {counts[severity]} |")
        rows.append(f"| **Total** | **{len(findings)}** |")
        return "\n".join(rows)

    def _render_finding(self, index: int, finding: EnrichedFinding) -> str:
        v = finding.vector
        badge = _SEVERITY_BADGE[v.severity]
        lines = [
            f"### Finding {index}: {finding.rule_title}",
            "",
            f"**Severity:** {badge}  ",
            f"**Rule:** `{v.rule_id}`  ",
            f"**Type:** `{v.type.value}`  ",
            f"**Confidence:** `{v.confidence.value}`  ",
            f"**Location:** `{v.location}`  ",
            "",
            "**Evidence:**",
            f"```\n{v.evidence}\n```",
            "",
            f"**Description:** {v.description}",
            "",
        ]

        if v.owasp_llm:
            lines.append(f"**OWASP LLM Top 10:** {v.owasp_llm}  ")
            lines.append("")

        # LLM analysis for NEEDS_CONTEXT/NEEDS_ANALYSIS findings
        if finding.llm_analysis:
            lines.append("**LLM Analysis:**")
            lines.append(f"> {finding.llm_analysis.strip()}")
            lines.append("")

        # KB remediation always shown
        lines.append("**Remediation:**")
        lines.append(finding.rule_remediation)
        lines.append("")

        if finding.rule_references:
            lines.append("**References:**")
            for ref in finding.rule_references:
                lines.append(f"- {ref}")
            lines.append("")

        lines.append("---\n")
        return "\n".join(lines)

    def _empty_report(self, file_path: str) -> str:
        header = f"**File:** `{file_path}`\n\n" if file_path else ""
        return f"# MCP Security Audit Report\n\n{header}No findings detected. ✅\n"
