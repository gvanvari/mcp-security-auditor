"""
ComparisonReporter — shows patterns across multiple scanned MCPs.

Input: dict mapping mcp_name → list[EnrichedFinding]
Output: HTML dashboard showing:
  - Which MCPs had which severity levels
  - Which rules fired most often
  - Side-by-side comparison table
"""

from __future__ import annotations

import html
from collections import Counter
from typing import Dict, List

from mcp_auditor.extractors.threat_vector import EnrichedFinding, Severity

_SEVERITY_COLOR = {
    Severity.CRITICAL: "#dc2626",
    Severity.HIGH: "#ea580c",
    Severity.MEDIUM: "#ca8a04",
    Severity.LOW: "#16a34a",
}


class ComparisonReporter:
    def generate(self, scan_results: Dict[str, List[EnrichedFinding]]) -> str:
        """
        scan_results: {"cmd-injection": [findings...], "env-leak": [findings...], ...}
        Returns a self-contained HTML string.
        """
        mcp_names = sorted(scan_results.keys())

        # --- Build summary rows (one row per MCP)
        rows_html = ""
        for name in mcp_names:
            findings = scan_results[name]
            counts = {s: 0 for s in Severity}
            for f in findings:
                counts[f.vector.severity] += 1

            def cell(sev: Severity) -> str:
                n = counts[sev]
                if n == 0:
                    return '<td class="zero">—</td>'
                color = _SEVERITY_COLOR[sev]
                return f'<td style="color:{color};font-weight:700;">{n}</td>'

            rows_html += f"""
<tr>
  <td><code>{html.escape(name)}</code></td>
  {cell(Severity.CRITICAL)}
  {cell(Severity.HIGH)}
  {cell(Severity.MEDIUM)}
  {cell(Severity.LOW)}
  <td><strong>{len(findings)}</strong></td>
  <td>{"".join(self._rule_chips(findings))}</td>
</tr>"""

        # --- Top rules across all MCPs
        rule_counter: Counter = Counter()
        for findings in scan_results.values():
            for f in findings:
                rule_counter[f.vector.rule_id] += 1

        top_rules_html = ""
        for rule_id, count in rule_counter.most_common(10):
            pct = int(100 * count / max(len(scan_results), 1))
            color = "#2563eb"
            top_rules_html += f"""
<div class="rule-row">
  <code class="rule-id">{html.escape(rule_id)}</code>
  <div class="bar-wrap">
    <div class="bar" style="width:{pct}%;background:{color};"></div>
  </div>
  <span class="rule-count">{count} MCP{"s" if count != 1 else ""}</span>
</div>"""

        # --- Heatmap: MCPs × Rules
        all_rules = sorted({f.vector.rule_id for flist in scan_results.values() for f in flist})
        heatmap_header = "<tr><th>MCP</th>" + "".join(
            f"<th class='rule-th'>{html.escape(r)}</th>" for r in all_rules
        ) + "</tr>"
        heatmap_rows = ""
        for name in mcp_names:
            fired = {f.vector.rule_id for f in scan_results[name]}
            cells = ""
            for rule in all_rules:
                if rule in fired:
                    sev = next(
                        f.vector.severity
                        for f in scan_results[name]
                        if f.vector.rule_id == rule
                    )
                    bg = _SEVERITY_COLOR[sev]
                    cells += f'<td class="heat-cell" style="background:{bg};" title="{rule} in {name}">●</td>'
                else:
                    cells += '<td class="heat-cell heat-miss">·</td>'
            heatmap_rows += f"<tr><td><code>{html.escape(name)}</code></td>{cells}</tr>"

        total_mcps = len(scan_results)
        total_findings = sum(len(v) for v in scan_results.values())

        return _COMPARISON_TEMPLATE.format(
            total_mcps=total_mcps,
            total_findings=total_findings,
            rows=rows_html,
            top_rules=top_rules_html,
            heatmap_header=heatmap_header,
            heatmap_rows=heatmap_rows,
        )

    def _rule_chips(self, findings: List[EnrichedFinding]) -> List[str]:
        seen = {}
        for f in findings:
            if f.vector.rule_id not in seen:
                seen[f.vector.rule_id] = f.vector.severity
        chips = []
        for rule_id, sev in seen.items():
            color = _SEVERITY_COLOR[sev]
            chips.append(
                f'<span class="chip" style="background:{color}20;color:{color};border:1px solid {color}40;">'
                f"{html.escape(rule_id)}</span>"
            )
        return chips


_COMPARISON_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>MCP Security Audit — Comparison Report</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
         background: #f8fafc; color: #1e293b; line-height: 1.6; }}
  .container {{ max-width: 1000px; margin: 0 auto; padding: 2rem 1rem; }}
  h1 {{ font-size: 1.6rem; font-weight: 700; margin-bottom: 0.25rem; }}
  h2 {{ font-size: 1.1rem; font-weight: 600; margin: 2rem 0 0.75rem; color: #475569; }}
  .subtitle {{ color: #64748b; font-size: 0.9rem; margin-bottom: 2rem; }}
  .top-stats {{ display: flex; gap: 1rem; margin-bottom: 2rem; }}
  .stat {{ background: white; border-radius: 8px; padding: 1rem 1.5rem;
           border: 1px solid #e2e8f0; text-align: center; }}
  .stat-num {{ font-size: 2rem; font-weight: 700; color: #1e293b; }}
  .stat-label {{ font-size: 0.75rem; color: #64748b; text-transform: uppercase; }}
  table {{ width: 100%; background: white; border-radius: 8px; border: 1px solid #e2e8f0;
           border-collapse: collapse; overflow: hidden; font-size: 0.9rem; }}
  th {{ background: #f1f5f9; padding: 0.6rem 0.75rem; text-align: left;
        font-size: 0.8rem; color: #475569; border-bottom: 1px solid #e2e8f0; }}
  td {{ padding: 0.6rem 0.75rem; border-bottom: 1px solid #f1f5f9; vertical-align: middle; }}
  td.zero {{ color: #cbd5e1; }}
  tr:last-child td {{ border-bottom: none; }}
  .chip {{ display: inline-block; padding: 0.1rem 0.45rem; border-radius: 4px;
           font-size: 0.72rem; font-weight: 600; margin: 0.1rem; }}
  code {{ background: #f1f5f9; padding: 0.1rem 0.35rem; border-radius: 3px; font-size: 0.82rem; }}
  .rule-row {{ display: flex; align-items: center; gap: 0.75rem; margin-bottom: 0.5rem; }}
  .rule-id {{ min-width: 130px; }}
  .bar-wrap {{ flex: 1; background: #f1f5f9; border-radius: 4px; height: 14px; overflow: hidden; }}
  .bar {{ height: 100%; border-radius: 4px; transition: width 0.3s; }}
  .rule-count {{ font-size: 0.8rem; color: #64748b; min-width: 70px; text-align: right; }}
  .heat-cell {{ text-align: center; font-size: 1rem; }}
  .heat-miss {{ color: #e2e8f0; }}
  .rule-th {{ font-size: 0.7rem; writing-mode: vertical-rl; transform: rotate(180deg);
              padding: 0.5rem 0.25rem; white-space: nowrap; }}
  .section-box {{ background: white; border-radius: 8px; border: 1px solid #e2e8f0; padding: 1.25rem; margin-bottom: 1.5rem; }}
</style>
</head>
<body>
<div class="container">
  <h1>📊 MCP Security Comparison Report</h1>
  <p class="subtitle">Cross-MCP analysis — vulnerability patterns across scanned servers</p>

  <div class="top-stats">
    <div class="stat"><div class="stat-num">{total_mcps}</div><div class="stat-label">MCPs Scanned</div></div>
    <div class="stat"><div class="stat-num">{total_findings}</div><div class="stat-label">Total Findings</div></div>
  </div>

  <h2>Per-MCP Summary</h2>
  <table>
    <tr>
      <th>MCP</th>
      <th style="color:#dc2626;">🔴 Critical</th>
      <th style="color:#ea580c;">🟠 High</th>
      <th style="color:#ca8a04;">🟡 Medium</th>
      <th style="color:#16a34a;">🟢 Low</th>
      <th>Total</th>
      <th>Rules Fired</th>
    </tr>
    {rows}
  </table>

  <h2>Most Common Rules</h2>
  <div class="section-box">
    {top_rules}
  </div>

  <h2>Coverage Heatmap</h2>
  <p style="font-size:0.85rem;color:#64748b;margin-bottom:0.75rem;">
    Colored dot = rule fired (color = severity). · = not detected.
  </p>
  <div style="overflow-x:auto;">
    <table>
      {heatmap_header}
      {heatmap_rows}
    </table>
  </div>
</div>
</body>
</html>"""
