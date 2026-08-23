"""
AttackSurfaceReporter — P2-7 attack-surface map (code-KB bridge).

Reports are per-finding; this renders a per-package overview instead: for
each @mcp.tool() entry point, which sinks (from the P1-1 reachability graph)
it reaches, and a trust level derived from that. Same package walk as
scan_all (P2-1) — this is the entry-point / import-graph analogue for the
MCP tool-call attack surface rather than a general import graph.

Attribution is line-range containment: a finding's "file:line" location
falls inside an entry point's [lineno, end_lineno] span. Findings outside
every entry point's span (module-level code) are reported separately.
"""

from __future__ import annotations

from pathlib import Path
from typing import Dict, List

from mcp_auditor.extractors.entry_points import EntryPointExtractor, ToolEntryPoint
from mcp_auditor.extractors.threat_vector import EnrichedFinding, Severity

_TRUST_HIGH_RISK = "🔴 High-risk"
_TRUST_REVIEW = "🟡 Review"
_TRUST_TRUSTED = "🟢 Trusted"

_DANGEROUS_SEVERITIES = {Severity.CRITICAL, Severity.HIGH}


def _trust_level(findings: List[EnrichedFinding]) -> str:
    """
    🔴 High-risk — reaches a non-suppressed CRITICAL/HIGH sink with a
                   confirmed (reachable) data flow from a tool parameter.
    🟡 Review    — reaches a sink, but at lower severity or with an
                   unconfirmed (constant/unknown) data flow.
    🟢 Trusted   — reaches no sinks at all.
    """
    live = [f for f in findings if not f.suppressed]
    if not live:
        return _TRUST_TRUSTED
    if any(
        f.vector.reachability == "reachable" and f.vector.severity in _DANGEROUS_SEVERITIES
        for f in live
    ):
        return _TRUST_HIGH_RISK
    return _TRUST_REVIEW


def _finding_line(finding: EnrichedFinding) -> int:
    try:
        return int(finding.vector.location.rsplit(":", 1)[-1])
    except ValueError:
        return -1


class AttackSurfaceReporter:
    """
    Renders a Markdown attack-surface map from a package scan.

    Input mirrors scan_all's own accumulator:
      scan_results: {rel_path_str: [EnrichedFinding, ...]}
      root:         the resolved directory scan_all walked (rel_path is
                     relative to this — needed to re-parse each file for
                     its entry points)
    """

    def generate(self, scan_results: Dict[str, List[EnrichedFinding]], root: Path) -> str:
        extractor = EntryPointExtractor()
        lines: List[str] = ["# Attack Surface Map", ""]
        lines.append(
            "Every `@mcp.tool()` entry point in this package, the sinks it "
            "reaches (P1-1 reachability graph), and a trust level derived "
            "from the most dangerous confirmed flow."
        )
        lines.append("")

        total_entry_points = 0
        total_high_risk = 0

        for rel_path in sorted(scan_results.keys()):
            findings = scan_results[rel_path]
            entry_points = extractor.extract(str(root / rel_path))
            if not entry_points:
                continue

            lines.append(f"## `{rel_path}`")
            lines.append("")
            lines.append("| Tool | Parameters | Reachable Sinks | Trust Level |")
            lines.append("|------|------------|------------------|-------------|")

            attributed_lines: set[int] = set()

            for ep in sorted(entry_points, key=lambda e: e.lineno):
                ep_findings = [f for f in findings if ep.contains_line(_finding_line(f))]
                attributed_lines.update(_finding_line(f) for f in ep_findings)

                params = ", ".join(ep.params) if ep.params else "—"
                if ep_findings:
                    sinks = ", ".join(
                        f"`{f.vector.rule_id}`" + ("" if not f.suppressed else " (suppressed)")
                        for f in sorted(ep_findings, key=lambda f: f.vector.rule_id)
                    )
                else:
                    sinks = "—"

                trust = _trust_level(ep_findings)
                total_entry_points += 1
                if trust == _TRUST_HIGH_RISK:
                    total_high_risk += 1

                lines.append(f"| `{ep.name}` | {params} | {sinks} | {trust} |")

            lines.append("")

            # Findings that fall outside every entry point's line range —
            # module-level code, not reachable from a specific tool call.
            unattributed = [
                f for f in findings if _finding_line(f) not in attributed_lines
            ]
            if unattributed:
                lines.append(
                    "_Module-level findings (not attributable to a specific tool):_"
                )
                for f in sorted(unattributed, key=lambda f: f.vector.rule_id):
                    lines.append(f"- `{f.vector.rule_id}` at `{f.vector.location}`")
                lines.append("")

        lines.append("---")
        lines.append("")
        lines.append(
            f"**{total_entry_points}** entry point(s) mapped, "
            f"**{total_high_risk}** high-risk."
        )

        return "\n".join(lines)
