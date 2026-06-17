"""
HTMLReporter — Phase 4 output for interactive human review.

Renders a self-contained HTML file with:
- Severity-coloured finding cards
- Collapsible evidence / remediation sections
- Filter buttons by severity
- No external dependencies (all CSS/JS inline)
"""

from __future__ import annotations

import html
from typing import List

from mcp_auditor.extractors.threat_vector import EnrichedFinding, Severity

_SEVERITY_COLOR = {
    Severity.CRITICAL: "#dc2626",
    Severity.HIGH: "#ea580c",
    Severity.MEDIUM: "#ca8a04",
    Severity.LOW: "#16a34a",
}

_SEVERITY_BG = {
    Severity.CRITICAL: "#fef2f2",
    Severity.HIGH: "#fff7ed",
    Severity.MEDIUM: "#fefce8",
    Severity.LOW: "#f0fdf4",
}

_SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
}


class HTMLReporter:
    def generate(self, findings: List[EnrichedFinding], file_path: str = "") -> str:
        sorted_findings = sorted(
            findings,
            key=lambda f: (_SEVERITY_ORDER[f.vector.severity], f.vector.rule_id),
        )

        counts = {s: 0 for s in Severity}
        for f in findings:
            counts[f.vector.severity] += 1

        cards_html = "\n".join(
            self._finding_card(i + 1, f) for i, f in enumerate(sorted_findings)
        )

        empty_msg = (
            '<p class="empty">✅ No findings detected.</p>' if not findings else ""
        )

        return _HTML_TEMPLATE.format(
            file_path=html.escape(file_path),
            total=len(findings),
            critical=counts[Severity.CRITICAL],
            high=counts[Severity.HIGH],
            medium=counts[Severity.MEDIUM],
            low=counts[Severity.LOW],
            cards=cards_html,
            empty_msg=empty_msg,
        )

    # ------------------------------------------------------------------

    def _finding_card(self, index: int, finding: EnrichedFinding) -> str:
        v = finding.vector
        sev = v.severity
        color = _SEVERITY_COLOR[sev]
        bg = _SEVERITY_BG[sev]

        llm_block = ""
        if finding.llm_analysis:
            llm_block = f"""
            <div class="section">
              <strong>🤖 LLM Analysis</strong>
              <blockquote>{html.escape(finding.llm_analysis.strip())}</blockquote>
            </div>"""

        refs_html = ""
        if finding.rule_references:
            refs_items = "".join(
                f'<li><a href="{html.escape(r)}" target="_blank">{html.escape(r)}</a></li>'
                if r.startswith("http")
                else f"<li>{html.escape(r)}</li>"
                for r in finding.rule_references
            )
            refs_html = f"""
            <div class="section">
              <strong>📚 References</strong>
              <ul>{refs_items}</ul>
            </div>"""

        owasp_badge = ""
        if v.owasp_llm:
            owasp_badge = f'<span class="badge owasp">OWASP {html.escape(v.owasp_llm)}</span>'

        return f"""
<div class="card" data-severity="{sev.value}" style="border-left: 4px solid {color}; background: {bg};">
  <div class="card-header" onclick="toggle(this)">
    <span class="sev-badge" style="background:{color};">{sev.value}</span>
    <span class="card-title">Finding {index}: {html.escape(finding.rule_title)}</span>
    <span class="card-meta">
      <code>{html.escape(v.rule_id)}</code>
      {owasp_badge}
      <code class="loc">{html.escape(v.location)}</code>
    </span>
    <span class="toggle-icon">▼</span>
  </div>
  <div class="card-body">
    <div class="meta-grid">
      <div><strong>Type</strong><br><code>{html.escape(v.type.value)}</code></div>
      <div><strong>Confidence</strong><br><code>{html.escape(v.confidence.value)}</code></div>
      <div><strong>Routing</strong><br><code>{html.escape(finding.routing)}</code></div>
    </div>
    <div class="section">
      <strong>📝 Description</strong>
      <p>{html.escape(v.description)}</p>
    </div>
    <div class="section">
      <strong>🔍 Evidence</strong>
      <pre><code>{html.escape(v.evidence)}</code></pre>
    </div>
    <div class="section">
      <strong>🛠 Remediation</strong>
      <p>{html.escape(finding.rule_remediation)}</p>
    </div>
    {llm_block}
    {refs_html}
  </div>
</div>"""


_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>MCP Security Audit — {file_path}</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
         background: #f8fafc; color: #1e293b; line-height: 1.6; }}
  .container {{ max-width: 900px; margin: 0 auto; padding: 2rem 1rem; }}
  h1 {{ font-size: 1.6rem; font-weight: 700; margin-bottom: 0.25rem; }}
  .subtitle {{ color: #64748b; font-size: 0.9rem; margin-bottom: 2rem; }}
  .summary {{ display: flex; gap: 1rem; margin-bottom: 2rem; flex-wrap: wrap; }}
  .stat {{ background: white; border-radius: 8px; padding: 1rem 1.5rem;
           border: 1px solid #e2e8f0; text-align: center; min-width: 90px; }}
  .stat-num {{ font-size: 2rem; font-weight: 700; }}
  .stat-label {{ font-size: 0.75rem; color: #64748b; text-transform: uppercase; }}
  .stat.critical .stat-num {{ color: #dc2626; }}
  .stat.high .stat-num {{ color: #ea580c; }}
  .stat.medium .stat-num {{ color: #ca8a04; }}
  .stat.low .stat-num {{ color: #16a34a; }}
  .filters {{ margin-bottom: 1rem; display: flex; gap: 0.5rem; flex-wrap: wrap; }}
  .filter-btn {{ padding: 0.35rem 0.85rem; border-radius: 999px; border: 1px solid #cbd5e1;
                 background: white; cursor: pointer; font-size: 0.85rem; }}
  .filter-btn.active {{ background: #1e293b; color: white; border-color: #1e293b; }}
  .card {{ background: white; border-radius: 8px; margin-bottom: 1rem;
           border: 1px solid #e2e8f0; overflow: hidden; }}
  .card-header {{ display: flex; align-items: center; gap: 0.75rem; padding: 1rem;
                  cursor: pointer; user-select: none; flex-wrap: wrap; }}
  .card-header:hover {{ background: rgba(0,0,0,0.02); }}
  .sev-badge {{ color: white; padding: 0.2rem 0.6rem; border-radius: 4px;
                font-size: 0.75rem; font-weight: 700; white-space: nowrap; }}
  .card-title {{ font-weight: 600; flex: 1; }}
  .card-meta {{ display: flex; gap: 0.5rem; align-items: center; flex-wrap: wrap; }}
  .badge {{ padding: 0.15rem 0.5rem; border-radius: 4px; font-size: 0.75rem; font-weight: 600; }}
  .owasp {{ background: #dbeafe; color: #1d4ed8; }}
  .loc {{ color: #64748b; font-size: 0.8rem; }}
  .toggle-icon {{ color: #94a3b8; font-size: 0.8rem; margin-left: auto; }}
  .card-body {{ padding: 0 1.25rem 1.25rem; display: none; }}
  .card-body.open {{ display: block; }}
  .meta-grid {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 1rem;
                background: #f8fafc; border-radius: 6px; padding: 0.75rem; margin-bottom: 1rem; }}
  .meta-grid div {{ font-size: 0.85rem; }}
  .section {{ margin-bottom: 1rem; }}
  .section strong {{ display: block; margin-bottom: 0.25rem; font-size: 0.85rem; color: #475569; }}
  pre {{ background: #1e293b; color: #e2e8f0; padding: 0.75rem 1rem;
         border-radius: 6px; overflow-x: auto; font-size: 0.85rem; }}
  blockquote {{ border-left: 3px solid #94a3b8; padding: 0.5rem 1rem;
                background: #f8fafc; color: #475569; font-size: 0.9rem; border-radius: 0 4px 4px 0; }}
  ul {{ padding-left: 1.25rem; font-size: 0.9rem; }}
  a {{ color: #2563eb; }}
  p {{ font-size: 0.9rem; }}
  code {{ background: #f1f5f9; padding: 0.1rem 0.35rem; border-radius: 3px; font-size: 0.85rem; }}
  pre code {{ background: none; padding: 0; }}
  .empty {{ color: #16a34a; font-size: 1.1rem; padding: 2rem; text-align: center; }}
</style>
</head>
<body>
<div class="container">
  <h1>🔍 MCP Security Audit Report</h1>
  <p class="subtitle">File: <code>{file_path}</code></p>

  <div class="summary">
    <div class="stat"><div class="stat-num">{total}</div><div class="stat-label">Total</div></div>
    <div class="stat critical"><div class="stat-num">{critical}</div><div class="stat-label">Critical</div></div>
    <div class="stat high"><div class="stat-num">{high}</div><div class="stat-label">High</div></div>
    <div class="stat medium"><div class="stat-num">{medium}</div><div class="stat-label">Medium</div></div>
    <div class="stat low"><div class="stat-num">{low}</div><div class="stat-label">Low</div></div>
  </div>

  <div class="filters">
    <button class="filter-btn active" onclick="filter('ALL')">All ({total})</button>
    <button class="filter-btn" onclick="filter('CRITICAL')" style="color:#dc2626;">🔴 Critical ({critical})</button>
    <button class="filter-btn" onclick="filter('HIGH')" style="color:#ea580c;">🟠 High ({high})</button>
    <button class="filter-btn" onclick="filter('MEDIUM')" style="color:#ca8a04;">🟡 Medium ({medium})</button>
    <button class="filter-btn" onclick="filter('LOW')" style="color:#16a34a;">🟢 Low ({low})</button>
  </div>

  {empty_msg}
  {cards}
</div>

<script>
function toggle(header) {{
  const body = header.nextElementSibling;
  const icon = header.querySelector('.toggle-icon');
  body.classList.toggle('open');
  icon.textContent = body.classList.contains('open') ? '▲' : '▼';
}}

function filter(sev) {{
  document.querySelectorAll('.card').forEach(card => {{
    card.style.display = (sev === 'ALL' || card.dataset.severity === sev) ? '' : 'none';
  }});
  document.querySelectorAll('.filter-btn').forEach(btn => {{
    btn.classList.toggle('active', btn.textContent.startsWith(sev === 'ALL' ? 'All' : ''));
  }});
  // highlight active button
  document.querySelectorAll('.filter-btn').forEach(btn => btn.classList.remove('active'));
  event.target.classList.add('active');
}}
</script>
</body>
</html>"""
