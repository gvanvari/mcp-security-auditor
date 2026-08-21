"""
MetricsReporter — precision/recall validation dashboard.

Input:
  - scan_results: dict of mcp_name → list[EnrichedFinding] (tool output)
  - expected: dict of mcp_name → list[dict] (ground truth from EXPECTED.yaml)

Output: HTML validation report showing:
  - Per-file pass/fail/miss
  - Overall recall, precision, and false-positive rate
  - Per-rule precision/recall breakdown
  - False positive breakdown
  - Gap analysis narrative

Iterates over the UNION of expected.keys() and scan_results.keys(), not just
expected.keys() — a file scanned with no EXPECTED.yaml entry (or an empty
"[]" entry, i.e. a benign fixture) must still be checked for unexpected
findings, or false positives on clean files are invisible to this report
(P2-6 — this was the root cause of the unquantified "zero false positives"
claim: scan_all used to strip empty-list entries before calling here).
"""

from __future__ import annotations

import html
from typing import Any, Dict, List

from mcp_auditor.extractors.threat_vector import EnrichedFinding

_STATUS_COLOR = {
    "PASS": "#16a34a",
    "MISS": "#dc2626",
    "PARTIAL": "#ca8a04",
    "FP": "#7c3aed",
}


class MetricsReporter:
    def generate(
        self,
        scan_results: Dict[str, List[EnrichedFinding]],
        expected: Dict[str, List[Dict[str, Any]]],
    ) -> str:
        """
        scan_results: {"cmd-injection": [EnrichedFinding, ...], ...}
        expected: {"cmd-injection": [{"rule": "MCP-CMI-001", "line": 16, "severity": "HIGH"}, ...],
                   "clean-body": [], ...}   # "[]" = benign fixture, still checked for FPs
        """
        all_rows: List[Dict[str, Any]] = []
        tp = fp = fn = 0
        # rule_id -> {"tp": int, "fp": int, "fn": int}
        per_rule: Dict[str, Dict[str, int]] = {}

        def _bump(rule: str, key: str) -> None:
            per_rule.setdefault(rule, {"tp": 0, "fp": 0, "fn": 0})[key] += 1

        mcp_names = sorted(set(expected.keys()) | set(scan_results.keys()))
        benign_files = 0
        benign_files_with_fp = 0

        for mcp_name in mcp_names:
            expected_list = expected.get(mcp_name, [])
            findings = scan_results.get(mcp_name, [])
            found_rules = [f.vector.rule_id for f in findings]

            for exp in expected_list:
                rule = exp["rule"]
                matched = rule in found_rules
                if matched:
                    tp += 1
                    _bump(rule, "tp")
                    status = "PASS"
                else:
                    fn += 1
                    _bump(rule, "fn")
                    status = "MISS"

                all_rows.append({
                    "mcp": mcp_name,
                    "expected_rule": rule,
                    "expected_severity": exp.get("severity", "?"),
                    "status": status,
                    "note": exp.get("note", ""),
                })

            # False positives: rules fired that were NOT in expected
            expected_rules = {e["rule"] for e in expected_list}
            file_fp_count = 0
            for f in findings:
                if f.vector.rule_id not in expected_rules:
                    fp += 1
                    file_fp_count += 1
                    _bump(f.vector.rule_id, "fp")
                    all_rows.append({
                        "mcp": mcp_name,
                        "expected_rule": f"(unexpected) {f.vector.rule_id}",
                        "expected_severity": f.vector.severity.value,
                        "status": "FP",
                        "note": "Not in EXPECTED — may be false positive",
                    })

            if not expected_list:
                # A benign fixture — the file this tool is supposed to leave alone.
                benign_files += 1
                if file_fp_count:
                    benign_files_with_fp += 1

        total_expected = tp + fn
        recall = round(100 * tp / total_expected, 1) if total_expected else 0
        precision = round(100 * tp / (tp + fp), 1) if (tp + fp) else 0
        fp_rate = round(100 * benign_files_with_fp / benign_files, 1) if benign_files else 0

        per_rule_html = self._render_per_rule(per_rule)

        rows_html = ""
        for row in all_rows:
            color = _STATUS_COLOR.get(row["status"], "#64748b")
            rows_html += f"""
<tr>
  <td><code>{html.escape(row['mcp'])}</code></td>
  <td><code>{html.escape(row['expected_rule'])}</code></td>
  <td>{html.escape(row['expected_severity'])}</td>
  <td style="color:{color};font-weight:700;">{row['status']}</td>
  <td style="color:#64748b;font-size:0.85rem;">{html.escape(row['note'])}</td>
</tr>"""

        # Gap analysis: list all MISS rows
        misses = [r for r in all_rows if r["status"] == "MISS"]
        fps = [r for r in all_rows if r["status"] == "FP"]

        gaps_html = ""
        if misses:
            gaps_html += "<h3 style='color:#dc2626;margin-bottom:0.5rem;'>❌ Missed (False Negatives)</h3><ul>"
            for m in misses:
                gaps_html += f"<li><code>{html.escape(m['expected_rule'])}</code> in <code>{html.escape(m['mcp'])}</code> — {html.escape(m['note'] or 'Not detected')}</li>"
            gaps_html += "</ul>"

        if fps:
            gaps_html += "<h3 style='color:#7c3aed;margin:1rem 0 0.5rem;'>⚠️ False Positives</h3><ul>"
            for f in fps:
                gaps_html += f"<li><code>{html.escape(f['expected_rule'])}</code> in <code>{html.escape(f['mcp'])}</code> — {html.escape(f['note'])}</li>"
            gaps_html += "</ul>"

        if not gaps_html:
            gaps_html = "<p style='color:#16a34a;'>✅ No gaps or false positives detected.</p>"

        return _METRICS_TEMPLATE.format(
            tp=tp,
            fp=fp,
            fn=fn,
            recall=recall,
            precision=precision,
            fp_rate=fp_rate,
            benign_files=benign_files,
            benign_files_with_fp=benign_files_with_fp,
            total_expected=total_expected,
            per_rule=per_rule_html,
            rows=rows_html,
            gaps=gaps_html,
        )

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _render_per_rule(self, per_rule: Dict[str, Dict[str, int]]) -> str:
        if not per_rule:
            return "<p style='color:#64748b;'>No rules exercised.</p>"

        rows = ""
        for rule_id in sorted(per_rule.keys()):
            counts = per_rule[rule_id]
            rtp, rfp, rfn = counts["tp"], counts["fp"], counts["fn"]
            r_total_expected = rtp + rfn
            r_recall = round(100 * rtp / r_total_expected, 1) if r_total_expected else None
            r_precision = round(100 * rtp / (rtp + rfp), 1) if (rtp + rfp) else None
            recall_str = f"{r_recall}%" if r_recall is not None else "—"
            precision_str = f"{r_precision}%" if r_precision is not None else "—"
            rows += f"""
<tr>
  <td><code>{html.escape(rule_id)}</code></td>
  <td>{rtp}</td>
  <td>{rfp}</td>
  <td>{rfn}</td>
  <td>{precision_str}</td>
  <td>{recall_str}</td>
</tr>"""

        return f"""<table>
  <tr>
    <th>Rule</th>
    <th>TP</th>
    <th>FP</th>
    <th>FN</th>
    <th>Precision</th>
    <th>Recall</th>
  </tr>
  {rows}
</table>"""


_METRICS_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>MCP Security Audit — Validation Metrics</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
         background: #f8fafc; color: #1e293b; line-height: 1.6; }}
  .container {{ max-width: 950px; margin: 0 auto; padding: 2rem 1rem; }}
  h1 {{ font-size: 1.6rem; font-weight: 700; margin-bottom: 0.25rem; }}
  h2 {{ font-size: 1.1rem; font-weight: 600; margin: 2rem 0 0.75rem; color: #475569; }}
  h3 {{ font-size: 0.95rem; font-weight: 600; }}
  .subtitle {{ color: #64748b; font-size: 0.9rem; margin-bottom: 2rem; }}
  .metrics {{ display: flex; gap: 1rem; margin-bottom: 2rem; flex-wrap: wrap; }}
  .metric {{ background: white; border-radius: 8px; padding: 1rem 1.5rem;
             border: 1px solid #e2e8f0; text-align: center; min-width: 130px; }}
  .metric-num {{ font-size: 2rem; font-weight: 700; }}
  .metric-label {{ font-size: 0.75rem; color: #64748b; text-transform: uppercase; }}
  .metric-sub {{ font-size: 0.7rem; color: #94a3b8; margin-top: 0.15rem; }}
  .metric.recall .metric-num {{ color: #2563eb; }}
  .metric.precision .metric-num {{ color: #7c3aed; }}
  .metric.fprate .metric-num {{ color: #ea580c; }}
  .metric.tp .metric-num {{ color: #16a34a; }}
  .metric.fp .metric-num {{ color: #7c3aed; }}
  .metric.fn .metric-num {{ color: #dc2626; }}
  table {{ width: 100%; background: white; border-radius: 8px; border: 1px solid #e2e8f0;
           border-collapse: collapse; font-size: 0.88rem; overflow: hidden; }}
  th {{ background: #f1f5f9; padding: 0.6rem 0.75rem; text-align: left;
        font-size: 0.8rem; color: #475569; border-bottom: 1px solid #e2e8f0; }}
  td {{ padding: 0.55rem 0.75rem; border-bottom: 1px solid #f1f5f9; vertical-align: middle; }}
  tr:last-child td {{ border-bottom: none; }}
  code {{ background: #f1f5f9; padding: 0.1rem 0.35rem; border-radius: 3px; font-size: 0.82rem; }}
  .section-box {{ background: white; border-radius: 8px; border: 1px solid #e2e8f0;
                  padding: 1.25rem; margin-bottom: 1.5rem; }}
  ul {{ padding-left: 1.25rem; }}
  li {{ margin-bottom: 0.35rem; font-size: 0.9rem; }}
  .legend {{ display: flex; gap: 1rem; flex-wrap: wrap; margin-bottom: 1rem; font-size: 0.85rem; }}
  .legend-item {{ display: flex; align-items: center; gap: 0.35rem; }}
  .dot {{ width: 10px; height: 10px; border-radius: 50%; }}
</style>
</head>
<body>
<div class="container">
  <h1>📐 Validation Metrics Report</h1>
  <p class="subtitle">Ground truth comparison — how well does the auditor perform?</p>

  <div class="metrics">
    <div class="metric recall">
      <div class="metric-num">{recall}%</div>
      <div class="metric-label">Recall</div>
    </div>
    <div class="metric precision">
      <div class="metric-num">{precision}%</div>
      <div class="metric-label">Precision</div>
    </div>
    <div class="metric fprate">
      <div class="metric-num">{fp_rate}%</div>
      <div class="metric-label">FP rate</div>
      <div class="metric-sub">{benign_files_with_fp}/{benign_files} benign files flagged</div>
    </div>
    <div class="metric tp">
      <div class="metric-num">{tp}</div>
      <div class="metric-label">True Positives</div>
    </div>
    <div class="metric fp">
      <div class="metric-num">{fp}</div>
      <div class="metric-label">False Positives</div>
    </div>
    <div class="metric fn">
      <div class="metric-num">{fn}</div>
      <div class="metric-label">False Negatives</div>
    </div>
  </div>

  <h2>Per-Rule Breakdown</h2>
  {per_rule}

  <h2>Per-Finding Breakdown</h2>
  <div class="legend">
    <span class="legend-item"><span class="dot" style="background:#16a34a;"></span>PASS — correctly detected</span>
    <span class="legend-item"><span class="dot" style="background:#dc2626;"></span>MISS — not detected (false negative)</span>
    <span class="legend-item"><span class="dot" style="background:#7c3aed;"></span>FP — detected but not expected (false positive)</span>
  </div>
  <table>
    <tr>
      <th>MCP</th>
      <th>Expected Rule</th>
      <th>Severity</th>
      <th>Status</th>
      <th>Notes</th>
    </tr>
    {rows}
  </table>

  <h2>Gap Analysis</h2>
  <div class="section-box">
    {gaps}
  </div>
</div>
</body>
</html>"""
