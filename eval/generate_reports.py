#!/usr/bin/env python3
"""
Generate individual security audit reports for each corpus file.
Outputs:
  - tests/results/{mcp_name}-report.md (individual reports)
  - tests/results/INDEX.md (summary index)
  - tests/results/VALIDATION.csv (metrics)
"""

import csv
import sys
from pathlib import Path
from datetime import datetime
from mcp_auditor.analyzer import Analyzer
from mcp_auditor.reporters.markdown_reporter import MarkdownReporter

CORPUS_DIR = Path("eval/corpus")
RESULTS_DIR = Path("eval/results/corpus")
RESULTS_DIR.mkdir(exist_ok=True)

analyzer = Analyzer()
reporter = MarkdownReporter()

# Track for index
reports = []
csv_rows = []

print("[*] Generating reports for all corpus files...")
for corpus_file in sorted(CORPUS_DIR.glob("*.py")):
    print(f"  Scanning: {corpus_file.name}", file=sys.stderr)
    
    # Analyze
    findings = analyzer.analyze(str(corpus_file))
    
    # Generate report
    report_content = reporter.generate(findings, str(corpus_file))
    
    # Save individual report
    report_path = RESULTS_DIR / f"{corpus_file.stem}-report.md"
    report_path.write_text(report_content, encoding="utf-8")
    
    # Track for index
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        severity = f.vector.severity.value
        severity_counts[severity] += 1
    
    reports.append({
        "name": corpus_file.stem,
        "file": corpus_file.name,
        "total": len(findings),
        "critical": severity_counts["CRITICAL"],
        "high": severity_counts["HIGH"],
        "medium": severity_counts["MEDIUM"],
        "low": severity_counts["LOW"],
        "report": f"{corpus_file.stem}-report.md"
    })
    
    # CSV row
    csv_rows.append({
        "MCP": corpus_file.name,
        "Report": report_path.name,
        "Total Findings": len(findings),
        "🔴 CRITICAL": severity_counts["CRITICAL"],
        "🟠 HIGH": severity_counts["HIGH"],
        "🟡 MEDIUM": severity_counts["MEDIUM"],
        "🟢 LOW": severity_counts["LOW"],
    })

# Generate INDEX.md
index_content = f"""# MCP Security Audit Reports

**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## Summary

| MCP | 🔴 CRITICAL | 🟠 HIGH | 🟡 MEDIUM | 🟢 LOW | Total | Report |
|---|---|---|---|---|---|---|
"""

for r in reports:
    index_content += f"| `{r['name']}` | {r['critical']} | {r['high']} | {r['medium']} | {r['low']} | **{r['total']}** | [{r['report']}]({r['report']}) |\n"

index_content += f"""
---

## Individual Reports

"""

for r in reports:
    index_content += f"### [{r['name']}]({r['report']})\n\n"
    index_content += f"**File:** `{r['file']}`  \n"
    index_content += f"**Findings:** {r['total']} ({r['critical']} CRITICAL, {r['high']} HIGH, {r['medium']} MEDIUM, {r['low']} LOW)  \n"
    index_content += f"**Report:** [View full report →]({r['report']})\n\n"

# Save index
(RESULTS_DIR / "INDEX.md").write_text(index_content, encoding="utf-8")

# Save CSV
csv_path = RESULTS_DIR / "VALIDATION.csv"
if csv_rows:
    with csv_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=csv_rows[0].keys())
        writer.writeheader()
        writer.writerows(csv_rows)

# Summary
total_findings = sum(r["total"] for r in reports)
print(f"\n✅ Generated {len(reports)} reports")
print(f"📊 Total findings: {total_findings}")
print(f"📄 Index: {RESULTS_DIR / 'INDEX.md'}")
print(f"📋 CSV: {csv_path}")
