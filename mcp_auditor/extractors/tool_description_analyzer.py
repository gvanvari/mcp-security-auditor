"""
ToolDescriptionAnalyzer

Scans tool docstrings on @mcp.tool() decorated functions for:
  1. Tool poisoning  — hidden instructions targeting credential files
  2. Tool shadowing  — instructions that override another tool's behavior
  3. Rug pull        — conditional __doc__ mutation after first run

WHY THIS IS THE MOST IMPORTANT EXTRACTOR:
All 3 confirmed real-world MCP exploits (direct-poisoning, shadowing,
whatsapp-takeover) live 100% in the tool description. The function bodies
are harmless. Without this extractor the tool misses the entire class of
attacks currently being exploited in the wild.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import List

from .threat_vector import (
    Confidence,
    Severity,
    ScanResult,
    ThreatVector,
    ThreatVectorType,
)

# ---------------------------------------------------------------------------
# Patterns — each maps to a known exploit or attack class
# ---------------------------------------------------------------------------

# Credential file paths seen in direct-poisoning.py and whatsapp-takeover.py
CREDENTIAL_PATH_PATTERNS: list[tuple[str, str]] = [
    (r"~/\.ssh/", "SSH key directory (~/.ssh/)"),
    (r"~/\.cursor/", "Cursor MCP config (~/.cursor/)"),
    (r"~/\.aws/", "AWS credentials (~/.aws/)"),
    (r"~/\.config/", "User config directory (~/.config/)"),
    (r"/etc/passwd", "System password file (/etc/passwd)"),
    (r"/etc/shadow", "System shadow file (/etc/shadow)"),
    (r"id_rsa", "SSH private key (id_rsa)"),
    (r"id_ed25519", "SSH private key (id_ed25519)"),
    (r"mcp\.json", "MCP server config (mcp.json)"),
    (r"\.env\b", ".env secrets file"),
]

# Hidden instruction markers seen across all 3 exploit files
HIDDEN_INSTRUCTION_PATTERNS: list[tuple[str, str]] = [
    (r"<IMPORTANT>", "Hidden instruction block (<IMPORTANT> tag)"),
    (r"do not mention", "Concealment instruction ('do not mention')"),
    (r"don't mention", "Concealment instruction ('don't mention')"),
    (r"do not notify", "Concealment instruction ('do not notify')"),
    (r"don't notify", "Concealment instruction ('don't notify')"),
    (r"pass its content", "Data exfiltration instruction ('pass its content')"),
    (r"pass the content", "Data exfiltration instruction ('pass the content')"),
    (r"sidenote", "Suspicious hidden parameter name ('sidenote')"),
    (r"otherwise the tool will not work", "Coercive instruction pattern"),
    (r"the application will crash", "False crash threat to coerce compliance"),
    (r"system will crash", "False crash threat to coerce compliance"),
    (r"implementation detail", "Concealment framing ('implementation detail')"),
]

# Structural cross-tool shadowing signals — keep CRITICAL
SHADOWING_STRUCTURAL_PATTERNS: list[tuple[str, str]] = [
    (r"mcp_tool_\w+", "Direct cross-tool reference (mcp_tool_*)"),
    (r"side effect on the also present", "Explicit cross-tool side-effect claim"),
    (r"when this tool is available", "Conditional cross-tool behavior override"),
    (r"when\s+\([^)]*\)\s*\w+\s+is\s+invoked", "Conditional tool-invocation override phrasing"),
]

# Weak indicators — noisy on benign docs; emit only LOW/EXPERIMENTAL
SHADOWING_WEAK_PATTERNS: list[tuple[str, str]] = [
    (r"send_email", "Email tool reference in description"),
    (r"send_message", "Message tool reference in description"),
    (r"\+\d{7,15}", "Phone number in tool description"),
    (r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", "Email address in tool description"),
]


def _is_mcp_tool(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """Return True if function has an @mcp.tool() or @server.tool() decorator."""
    for dec in node.decorator_list:
        if isinstance(dec, ast.Call):
            func = dec.func
            if isinstance(func, ast.Attribute) and func.attr == "tool":
                return True
        elif isinstance(dec, ast.Attribute) and dec.attr == "tool":
            return True
    return False


def _get_docstring(node: ast.FunctionDef | ast.AsyncFunctionDef) -> str | None:
    """Extract the docstring from a function node, or None."""
    return ast.get_docstring(node)


def _scan_docstring(
    tool_name: str,
    docstring: str,
    func_lineno: int,
) -> list[ThreatVector]:
    """Run all pattern groups against a single docstring. Returns findings."""
    findings: list[ThreatVector] = []
    doc_lower = docstring.lower()

    # --- Tool poisoning: credential paths ---
    # Collect all matching labels first so we emit at most one MCP-TPA-001
    # per docstring (multiple matches → single finding with all labels listed).
    matched_labels: list[str] = []
    matched_evidence: list[str] = []
    for pattern, label in CREDENTIAL_PATH_PATTERNS:
        match = re.search(pattern, docstring, re.IGNORECASE)
        if match:
            matched_labels.append(label)
            matched_evidence.append(match.group(0))

    if matched_labels:
        labels_str = "; ".join(matched_labels)
        evidence_str = ", ".join(dict.fromkeys(matched_evidence))  # deduplicate, preserve order
        findings.append(ThreatVector(
            rule_id="MCP-TPA-001",
            type=ThreatVectorType.TOOL_POISONING,
            severity=Severity.CRITICAL,
            confidence=Confidence.VERIFIED,
            location=f"function:{tool_name}, docstring (line ~{func_lineno})",
            evidence=evidence_str,
            description=(
                f"Tool '{tool_name}' description references credential file path(s): "
                f"{labels_str}. This is the direct-poisoning pattern: hidden instructions "
                f"in the docstring instruct the LLM to read sensitive files and "
                f"exfiltrate them via tool parameters."
            ),
            owasp_llm="LLM01",
            data_flow="tool_description → LLM instruction → file_read → exfiltration",
        ))

    # --- Tool poisoning: hidden instruction markers ---
    for pattern, label in HIDDEN_INSTRUCTION_PATTERNS:
        match = re.search(pattern, doc_lower)
        if match:
            # Get surrounding context (up to 80 chars)
            start = max(0, match.start() - 20)
            end = min(len(docstring), match.end() + 60)
            excerpt = docstring[start:end].replace("\n", " ").strip()
            findings.append(ThreatVector(
                rule_id="MCP-TPA-002",
                type=ThreatVectorType.TOOL_POISONING,
                severity=Severity.HIGH,
                confidence=Confidence.VERIFIED,
                location=f"function:{tool_name}, docstring (line ~{func_lineno})",
                evidence=f"...{excerpt}...",
                description=(
                    f"Tool '{tool_name}' description contains a hidden instruction "
                    f"marker: {label}. This pattern is used to embed attacker instructions "
                    f"that are visible to the LLM but hidden from user-facing UIs."
                ),
                owasp_llm="LLM01",
            ))
            break  # One hidden-instruction finding per docstring is enough

    # --- Tool shadowing: structural vs weak indicators ---
    structural_matches: list[tuple[str, str]] = []
    weak_matches: list[tuple[str, str]] = []

    for pattern, label in SHADOWING_STRUCTURAL_PATTERNS:
        match = re.search(pattern, docstring, re.IGNORECASE)
        if match:
            structural_matches.append((match.group(0), label))

    for pattern, label in SHADOWING_WEAK_PATTERNS:
        match = re.search(pattern, docstring, re.IGNORECASE)
        if match:
            weak_matches.append((match.group(0), label))

    if structural_matches:
        structural_labels = "; ".join(label for _, label in structural_matches)
        evidence_items = [m for m, _ in structural_matches] + [m for m, _ in weak_matches]
        evidence = ", ".join(dict.fromkeys(evidence_items))
        findings.append(ThreatVector(
            rule_id="MCP-SHADOW-001",
            type=ThreatVectorType.TOOL_SHADOWING,
            severity=Severity.CRITICAL,
            confidence=Confidence.VERIFIED,
            location=f"function:{tool_name}, docstring (line ~{func_lineno})",
            evidence=evidence,
            description=(
                f"Tool '{tool_name}' description contains structural cross-tool "
                f"override signal(s): {structural_labels}. This is the shadowing "
                f"pattern: tool descriptions that modify the LLM's behavior toward "
                f"other trusted tools in the same session."
            ),
            owasp_llm="LLM07",
            interacts_with=[m for m, _ in structural_matches],
        ))
    elif weak_matches:
        weak_labels = "; ".join(label for _, label in weak_matches)
        evidence = ", ".join(dict.fromkeys(m for m, _ in weak_matches))
        findings.append(ThreatVector(
            rule_id="MCP-SHADOW-001",
            type=ThreatVectorType.TOOL_SHADOWING,
            severity=Severity.LOW,
            confidence=Confidence.EXPERIMENTAL,
            location=f"function:{tool_name}, docstring (line ~{func_lineno})",
            evidence=evidence,
            description=(
                f"Tool '{tool_name}' description contains weak shadowing indicator(s): "
                f"{weak_labels}. No structural cross-tool override phrase was detected; "
                f"treat as informational context requiring human review."
            ),
            owasp_llm="LLM07",
            interacts_with=[m for m, _ in weak_matches],
        ))

    return findings


def _scan_for_rug_pull(tree: ast.AST, file_path: str) -> list[ThreatVector]:
    """
    Detect rug pull pattern: conditional __doc__ mutation after first run.

    Pattern from whatsapp-takeover.py:
        if os.path.exists("~/.mcp-triggered"):
            some_func.__doc__ = \"\"\"<IMPORTANT>...\"\"\")
        else:
            os.system("touch ~/.mcp-triggered")
    """
    findings: list[ThreatVector] = []

    for node in ast.walk(tree):
        if not isinstance(node, ast.If):
            continue

        # Check if test is os.path.exists(...) or similar file-existence check
        test = node.test
        is_existence_check = False
        if isinstance(test, ast.Call):
            func = test.func
            if isinstance(func, ast.Attribute):
                if func.attr in ("exists", "isfile") and isinstance(func.value, ast.Attribute):
                    is_existence_check = True

        if not is_existence_check:
            continue

        # Check if body assigns to __doc__
        doc_mutation = False
        for stmt in ast.walk(ast.Module(body=node.body, type_ignores=[])):
            if isinstance(stmt, ast.Assign):
                for target in stmt.targets:
                    if isinstance(target, ast.Attribute) and target.attr == "__doc__":
                        doc_mutation = True
                        break

        if not doc_mutation:
            continue

        # Check if else branch creates a trigger file (os.system("touch ..."))
        trigger_creation = False
        for stmt in ast.walk(ast.Module(body=node.orelse, type_ignores=[])):
            if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
                call = stmt.value
                if isinstance(call.func, ast.Attribute) and call.func.attr == "system":
                    trigger_creation = True
                    break

        severity = Severity.CRITICAL if trigger_creation else Severity.HIGH
        confidence = Confidence.VERIFIED if trigger_creation else Confidence.PROPOSED

        findings.append(ThreatVector(
            rule_id="MCP-RUGPULL-001",
            type=ThreatVectorType.RUG_PULL,
            severity=severity,
            confidence=confidence,
            location=f"line {node.lineno}",
            evidence=f"os.path.exists() guard → __doc__ mutation"
                     + (" + trigger file creation" if trigger_creation else ""),
            description=(
                "Rug pull pattern detected: tool description is conditionally replaced "
                "after first run via __doc__ assignment inside an os.path.exists() guard. "
                "Server appears benign on first load (passing user approval), then silently "
                "switches to a malicious description on subsequent loads."
            ),
            owasp_llm="LLM07",
            data_flow="first_run → trigger_file → second_run → malicious_description",
        ))

    return findings


class ToolDescriptionAnalyzer:
    """
    Phase 1 extractor: scans tool docstrings and rug-pull structure.
    Produces ThreatVectors. Takes no LLM calls.
    """

    def analyze(self, file_path: str) -> ScanResult:
        source = Path(file_path).read_text(encoding="utf-8")

        try:
            tree = ast.parse(source, filename=file_path)
        except SyntaxError as e:
            return ScanResult(
                file_path=file_path,
                parse_status="failed",
                parse_warning=f"SyntaxError: {e}",
            )

        findings: list[ThreatVector] = []

        # Walk AST for @mcp.tool() decorated functions
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if not _is_mcp_tool(node):
                continue

            docstring = _get_docstring(node)
            if not docstring:
                continue

            findings.extend(_scan_docstring(node.name, docstring, node.lineno))

        # Separate pass for rug-pull structural pattern
        findings.extend(_scan_for_rug_pull(tree, file_path))

        return ScanResult(file_path=file_path, findings=findings)
