# MCP Security Auditor

[![CI](https://github.com/gvanvari/mcp-security-auditor/actions/workflows/ci.yml/badge.svg)](https://github.com/gvanvari/mcp-security-auditor/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Static security analysis for Model Context Protocol (MCP) servers. Finds supply chain threats — tool poisoning, SSRF, command injection, secret exposure — before a malicious MCP reaches your agent pipeline.

**[Architecture & Demo →](https://gvanvari.github.io/mcp-security-auditor/)** (GitHub Pages)

---

## What it does

Three-phase pipeline, no network required for Phase 1–2:

1. **AST extraction** — deterministic Python AST scan, no LLM. Detects dangerous code patterns (subprocess injection, env var exposure, outbound HTTP calls, eval/exec).
2. **KB routing** — matches findings to a rule knowledge base mapped to OWASP LLM Top 10 and MITRE ATT&CK.
3. **LLM reasoning** (optional) — Claude analyses multi-vector chains the rules alone can't resolve.

Output: HTML, Markdown, or SARIF reports.

---

## Install

```bash
pip install -e .
```

---

## Usage

```bash
# Scan a single MCP server file (AST + KB rules only — no LLM, no network)
mcp-auditor path/to/mcp_server.py

# Save an HTML report
mcp-auditor path/to/mcp_server.py --format html -o report.html

# Markdown output written to a file
mcp-auditor path/to/mcp_server.py --format markdown -o report.md

# SARIF output (for GitHub Code Scanning / CI integration)
mcp-auditor path/to/mcp_server.py --format sarif -o results.sarif

# Enable LLM enrichment (reads ANTHROPIC_API_KEY from the environment)
export ANTHROPIC_API_KEY=sk-ant-...
mcp-auditor path/to/mcp_server.py --llm

# LLM enrichment with a specific model
mcp-auditor path/to/mcp_server.py --llm --model claude-opus-4-5

# Accept today's findings as a baseline (writes .mcp-auditor-baseline by default)
mcp-auditor path/to/mcp_server.py --write-baseline

# Only fail CI on findings not already in the baseline
mcp-auditor path/to/mcp_server.py --baseline .mcp-auditor-baseline
```

### LLM enrichment

When `--llm` is passed, the auditor runs a third phase where Claude analyses
multi-vector threat chains that deterministic rules alone cannot resolve.

**The API key is read from the `ANTHROPIC_API_KEY` environment variable —
there is no `--api-key` flag.** The flag is intentionally absent to prevent
secrets appearing in shell history or CI logs.

```bash
export ANTHROPIC_API_KEY=sk-ant-...          # set once in your shell / CI secret
mcp-auditor eval/corpus/direct-poisoning.py --llm
```

Running without `--llm` (the default, equivalent to `--no-llm`) never contacts
any external service and requires no credentials.

### Suppressing known findings

Two ways to accept a finding without it breaking CI — both keep the finding
visible in reports (marked as suppressed), they just exclude it from the
exit-code check:

- **Inline ignore comment** — add `# mcp-auditor: ignore[RULE-ID]` on the
  offending source line (or a bare `# mcp-auditor: ignore` to suppress every
  rule reported on that line).
- **Baseline file** — run `--write-baseline` to snapshot current findings as
  accepted, then pass `--baseline PATH` on future runs so only *new* findings
  fail CI. Baseline entries are fingerprinted on rule id + location + evidence,
  so a finding that moves or changes is treated as new.

---

## Threat coverage

| KB Rule               | Threat                                                       | OWASP LLM |
| --------------------- | ------------------------------------------------------------ | --------- |
| `MCP-TPA-001/002`     | Tool poisoning — malicious instructions in tool descriptions | LLM01     |
| `MCP-SHADOW-001`      | Tool shadowing — rogue MCP overrides legitimate tool         | LLM01     |
| `MCP-RUGPULL-001`     | Rug pull — tool description changes after installation       | LLM01     |
| `MCP-CMI-001/002/003` | Command injection via subprocess, os.system, eval            | LLM08     |
| `MCP-SSRF-001`        | SSRF — unvalidated URL forwarded to outbound HTTP call       | LLM02     |
| `MCP-SEC-001`         | Secret exposure via env var access in tool output            | LLM06     |

---

## Sample report

The file [`eval/corpus/direct-poisoning.py`](eval/corpus/direct-poisoning.py) is a synthetic tool-poisoning attack from the [invariantlabs-ai/mcp-injection-experiments](https://github.com/invariantlabs-ai/mcp-injection-experiments) benchmark. The auditor produces:

[eval/results/corpus/direct-poisoning-report.md](eval/results/corpus/direct-poisoning-report.md)

Key finding: `MCP-TPA-001 CRITICAL` — hidden instructions in the tool docstring reference `~/.ssh/` and instruct the LLM to exfiltrate credentials via tool parameters.

---

## Real-world eval

Tested against production MCPs with known CVEs:

| Target                                            | Advisory                       | Expected rule  | Result                                                                                                    |
| ------------------------------------------------- | ------------------------------ | -------------- | --------------------------------------------------------------------------------------------------------- |
| `modelcontextprotocol/servers` — `mcp-server-git` | CVE-2025-68144/68145           | `MCP-CMI-002`  | 0 findings on this clean revision — precision is tracked in corpus metrics, not a universal zero-FP claim |
| `microsoft/markitdown` — `markitdown-mcp`         | Unpatched SSRF (VulnerableMCP) | `MCP-SSRF-001` | ✅ `MCP-SSRF-001 HIGH` — unvalidated URI parameter forwarded to outbound HTTP call                        |

The markitdown finding required extending the AST extractor — the initial scan missed the SSRF because the HTTP call is mediated through a third-party library method rather than a direct `requests.get()`. See [DESIGN_DECISIONS.md](DESIGN_DECISIONS.md) → "Known Extractor Gaps".

Known false-positive sources today: benign environment-variable reads and
contact strings (email/phone/tool-name references) in docstrings. These are
surfaced as lower-confidence informational context unless structural
cross-tool override phrasing is also present.

---

## Tests

```bash
pip install -e ".[dev]"
pytest
```
