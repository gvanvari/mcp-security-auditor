# MCP Security Auditor

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
# Scan a single MCP server file
mcp-auditor path/to/mcp_server.py

# Save an HTML report
mcp-auditor path/to/mcp_server.py --format html -o report.html

# Markdown output
mcp-auditor path/to/mcp_server.py --format markdown

# With LLM reasoning (requires Anthropic API key)
mcp-auditor path/to/mcp_server.py --api-key $ANTHROPIC_API_KEY
```

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

| Target                                            | Advisory                       | Expected rule  | Result                                                                             |
| ------------------------------------------------- | ------------------------------ | -------------- | ---------------------------------------------------------------------------------- |
| `modelcontextprotocol/servers` — `mcp-server-git` | CVE-2025-68144/68145           | `MCP-CMI-002`  | 0 findings — HEAD already patched; no false positives on clean code                |
| `microsoft/markitdown` — `markitdown-mcp`         | Unpatched SSRF (VulnerableMCP) | `MCP-SSRF-001` | ✅ `MCP-SSRF-001 HIGH` — unvalidated URI parameter forwarded to outbound HTTP call |

The markitdown finding required extending the AST extractor — the initial scan missed the SSRF because the HTTP call is mediated through a third-party library method rather than a direct `requests.get()`. See [DESIGN_DECISIONS.md](DESIGN_DECISIONS.md) → "Known Extractor Gaps".

---

## Tests

```bash
pip install -e ".[dev]"
pytest
```
