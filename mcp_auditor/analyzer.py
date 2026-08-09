"""
Analyzer — main orchestrator for the MCP Security Auditor pipeline.

Phase 1: AST extraction (ASTExtractor + ToolDescriptionAnalyzer) — zero LLM
Phase 2: KB routing (KBRouter) — enriches ThreatVectors with rule metadata
Phase 3: LLM reasoning (ClaudeProvider) — only for NEEDS_* findings
Phase 4: Reporting (MarkdownReporter / SARIFReporter)

Entry point: mcp-auditor CLI via click.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import List, Optional

import click
from rich.console import Console
from rich.panel import Panel

from mcp_auditor.kb.router import KBRouter
from mcp_auditor.extractors.ast_extractor import ASTExtractor
from mcp_auditor.extractors.threat_vector import EnrichedFinding, ScanResult
from mcp_auditor.extractors.tool_description_analyzer import ToolDescriptionAnalyzer
from mcp_auditor.reporters.markdown_reporter import MarkdownReporter
from mcp_auditor.reporters.sarif_reporter import SARIFReporter
from mcp_auditor.reporters.html_reporter import HTMLReporter
from mcp_auditor.reporters.comparison_reporter import ComparisonReporter
from mcp_auditor.reporters.metrics_reporter import MetricsReporter

console = Console(stderr=True)


class Analyzer:
    """
    Orchestrates all 4 phases for a single Python file.

    Constructed without an API key — the LLM phase is optional and
    only activated when api_key is provided to analyze().
    """

    def __init__(self, kb_dir: Optional[str] = None) -> None:
        _kb_dir = Path(kb_dir) if kb_dir else Path(__file__).parent / "kb"
        self._router = KBRouter(kb_dir=_kb_dir)
        self._ast_extractor = ASTExtractor()
        self._desc_analyzer = ToolDescriptionAnalyzer()

    def analyze(
        self,
        file_path: str,
        api_key: Optional[str] = None,
        model: str = "claude-haiku-4-5",
    ) -> List[EnrichedFinding]:
        """
        Run the full pipeline on a single Python file.

        Returns list[EnrichedFinding] sorted CRITICAL → LOW.
        LLM phase is skipped when api_key is None.
        """
        # Phase 1 — extraction (two extractors, results merged)
        ast_result: ScanResult = self._ast_extractor.analyze(file_path)
        desc_result: ScanResult = self._desc_analyzer.analyze(file_path)

        combined_vectors = ast_result.findings + desc_result.findings

        # Build a merged ScanResult for the router
        merged = ScanResult(
            file_path=file_path,
            findings=combined_vectors,
            parse_status=ast_result.parse_status,
        )

        # Phase 2 — KB routing
        enriched: List[EnrichedFinding] = self._router.route(merged)

        # Phase 3 — LLM reasoning (optional)
        if api_key:
            from mcp_auditor.reasoner.claude_provider import ClaudeProvider

            provider = ClaudeProvider(api_key=api_key, model=model)
            enriched = provider.analyze_batch(enriched)

        # Sort CRITICAL first
        _order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        enriched.sort(key=lambda f: _order.get(f.vector.severity.value, 9))

        return enriched


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


@click.command()
@click.argument("file", type=click.Path(exists=True, readable=True))
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["markdown", "sarif", "html", "both"], case_sensitive=False),
    default="markdown",
    show_default=True,
    help="Output format.",
)
@click.option(
    "--output",
    "-o",
    type=click.Path(),
    default=None,
    help="Write output to file instead of stdout.",
)
@click.option(
    "--llm/--no-llm",
    default=False,
    show_default=True,
    help="Enable LLM enrichment via ANTHROPIC_API_KEY.",
)
@click.option(
    "--model",
    default="claude-haiku-4-5",
    show_default=True,
    help="Claude model to use for LLM enrichment.",
)
def main(
    file: str,
    output_format: str,
    output: Optional[str],
    llm: bool,
    model: str,
) -> None:
    """Audit an MCP server Python file for security threats."""

    api_key: Optional[str] = None
    if llm:
        api_key = os.environ.get("ANTHROPIC_API_KEY")
        if not api_key:
            console.print(
                Panel(
                    "[red]ANTHROPIC_API_KEY not set.[/red] "
                    "Export it or run without --llm.",
                    title="Error",
                )
            )
            sys.exit(1)

    console.print(f"[bold]Scanning[/bold] {file}...", style="blue")

    analyzer = Analyzer()
    findings = analyzer.analyze(file, api_key=api_key, model=model)

    if not findings:
        console.print("[green]No findings detected.[/green]")
        if output:
            Path(output).write_text("No findings detected.\n", encoding="utf-8")
        return

    console.print(f"Found [bold red]{len(findings)}[/bold red] finding(s).")

    if output_format in ("markdown", "both"):
        md = MarkdownReporter().generate(findings, file_path=file)
        _write_or_print(md, output if output_format == "markdown" else None)

    if output_format == "html":
        report = HTMLReporter().generate(findings, file_path=file)
        _write_or_print(report, output)

    if output_format in ("sarif", "both"):
        sarif = SARIFReporter().generate(findings, file_path=file)
        sarif_out = output if output_format == "sarif" else (
            output.replace(".md", ".sarif") if output else None
        )
        _write_or_print(sarif, sarif_out)

    # Exit code 1 only for reachable-or-unknown CRITICAL/HIGH findings (P1-3).
    # constant-reachability findings are reported but excluded from CI failure —
    # they represent hardcoded sinks with no attacker-controlled input path.
    critical_or_high = any(
        f.vector.severity.value in ("CRITICAL", "HIGH")
        and f.vector.reachability in ("reachable", "unknown")
        for f in findings
    )
    if critical_or_high:
        sys.exit(1)


def _write_or_print(content: str, path: Optional[str]) -> None:
    if path:
        Path(path).write_text(content, encoding="utf-8")
        console.print(f"[dim]Written to {path}[/dim]")
    else:
        click.echo(content)


# Directories never part of an MCP server's own code — used by scan_all and tests.
_EXCLUDED_DIRS_SET: frozenset[str] = frozenset({
    ".venv", "venv", "env",
    "__pycache__", ".git",
    "node_modules",
    "tests", "test",
    "build", "dist",
    "site-packages",
})


@click.command()
@click.argument("directory", type=click.Path(exists=True, file_okay=False))
@click.option(
    "--output-dir", "-o",
    type=click.Path(),
    default="eval/results/corpus",
    show_default=True,
    help="Directory to write reports into.",
)
@click.option(
    "--llm/--no-llm",
    default=False,
    show_default=True,
    help="Enable LLM enrichment via ANTHROPIC_API_KEY.",
)
@click.option(
    "--model",
    default="claude-haiku-4-5",
    show_default=True,
    help="Claude model for LLM enrichment.",
)
def scan_all(
    directory: str,
    output_dir: str,
    llm: bool,
    model: str,
) -> None:
    """Scan all .py files in DIRECTORY (recursively) and produce individual + comparison reports.

    Excluded directories: .venv, venv, env, __pycache__, .git, node_modules,
    tests, test, build, dist, site-packages.

    Note: analysis is intra-file only — cross-file data flows are not tracked.
    """
    api_key: Optional[str] = None
    if llm:
        api_key = os.environ.get("ANTHROPIC_API_KEY")
        if not api_key:
            console.print("[red]ANTHROPIC_API_KEY not set.[/red]")
            sys.exit(1)

    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    root = Path(directory).resolve()

    def _is_excluded(path: Path) -> bool:
        """Return True if any path component is in the excluded set."""
        return any(part in _EXCLUDED_DIRS_SET for part in path.relative_to(root).parts)

    py_files = sorted(
        f for f in root.rglob("*.py") if not _is_excluded(f)
    )
    if not py_files:
        console.print(f"[yellow]No .py files found in {directory}[/yellow]")
        return

    analyzer = Analyzer()
    html_reporter = HTMLReporter()
    all_results: dict = {}

    for py_file in py_files:
        rel = py_file.relative_to(root)
        # Use relative path as key so subdirectory files are distinguishable
        result_key = str(rel)
        console.print(f"  Scanning [bold]{rel}[/bold]...", style="blue")
        findings = analyzer.analyze(str(py_file), api_key=api_key, model=model)
        all_results[result_key] = findings

        # Individual HTML report — mirror subdir structure under output_dir
        report_stem = str(rel).replace("/", "__").replace("\\", "__").replace(".py", "")
        report_path = out / f"{report_stem}-report.html"
        report_path.write_text(
            html_reporter.generate(findings, file_path=str(py_file)),
            encoding="utf-8",
        )
        console.print(f"    → {report_path} ({len(findings)} findings)", style="dim")

    # Comparison report across all MCPs
    comparison_path = out / "comparison-report.html"
    comparison_path.write_text(
        ComparisonReporter().generate(all_results),
        encoding="utf-8",
    )

    # Metrics / validation report — only if EXPECTED.yaml exists next to the scanned dir
    expected_yaml = root / "EXPECTED.yaml"
    if expected_yaml.exists():
        import yaml
        expected = yaml.safe_load(expected_yaml.read_text(encoding="utf-8")) or {}
        # Strip empty lists (files with no expected findings)
        expected = {k: v for k, v in expected.items() if v}
        metrics_path = out / "metrics-report.html"
        metrics_path.write_text(
            MetricsReporter().generate(all_results, expected),
            encoding="utf-8",
        )
        console.print(f"[dim]Metrics:    {metrics_path}[/dim]")

    total = sum(len(v) for v in all_results.values())
    console.print(
        f"\n[green]Done.[/green] Scanned {len(py_files)} file(s) across {root.name}/, "
        f"{total} total finding(s)."
    )
    console.print(f"[dim]Reports:    {out}/[/dim]")
    console.print(f"[dim]Comparison: {comparison_path}[/dim]")
    console.print(
        f"[dim]Note: analysis boundary is intra-file; "
        f"cross-file data flows are not tracked.[/dim]"
    )
