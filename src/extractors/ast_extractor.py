"""
ASTExtractor

Walks the AST of a Python file to detect dangerous code patterns in
MCP tool function bodies:

  1. Command injection  — os.system, os.popen, subprocess.* with shell=True
  2. Code execution     — eval(), exec()
  3. Secret exposure    — os.environ subscript, os.getenv()
  4. SSRF / exfiltration — requests.get/post/put/patch/delete

WHY SEPARATE FROM ToolDescriptionAnalyzer:
All 3 confirmed corpus exploits live in docstrings. But in the wild, MCP
servers also contain dangerous code patterns that can be exploited if the
LLM is tricked into calling them with attacker-controlled arguments.
This extractor covers the code-body attack surface.
"""

from __future__ import annotations

import ast
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
# Low-level AST helpers
# ---------------------------------------------------------------------------

def _is_attr_call(node: ast.Call, module: str, attr: str) -> bool:
    """Return True if node is module.attr(...)."""
    return (
        isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == module
        and node.func.attr == attr
    )


def _has_shell_true(node: ast.Call) -> bool:
    """Return True if the Call has a shell=True keyword argument."""
    for kw in node.keywords:
        if (
            kw.arg == "shell"
            and isinstance(kw.value, ast.Constant)
            and kw.value.value is True
        ):
            return True
    return False


def _is_bare_call(node: ast.Call, name: str) -> bool:
    """Return True if node is a bare builtin call like eval(...) or exec(...)."""
    return isinstance(node.func, ast.Name) and node.func.id == name


# ---------------------------------------------------------------------------
# Detectors — one per attack class, each returns list[ThreatVector]
# ---------------------------------------------------------------------------

def _detect_cmd_injection(tree: ast.Module, file_path: str) -> list[ThreatVector]:
    """
    Detect shell command execution patterns:
      - os.system / os.popen: always invoke /bin/sh, no flag needed
      - subprocess.run/call/check_call/check_output with shell=True: shell injection
      - subprocess.Popen: flag regardless — attacker-controlled argv is still dangerous
    """
    findings: list[ThreatVector] = []

    # os.* that always spawn a shell
    OS_SHELL_CALLS = {"system", "popen"}

    # subprocess.* that are dangerous with shell=True (or always for Popen)
    SUBPROCESS_CALLS = {"run", "call", "check_call", "check_output", "Popen"}

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue

        # os.system / os.popen
        for fn in OS_SHELL_CALLS:
            if _is_attr_call(node, "os", fn):
                findings.append(ThreatVector(
                    rule_id="MCP-CMI-001",
                    type=ThreatVectorType.CMD_INJECTION,
                    severity=Severity.HIGH,
                    confidence=Confidence.PROPOSED,
                    location=f"{file_path}:{node.lineno}",
                    evidence=f"os.{fn}(...)",
                    description=(
                        f"os.{fn}() always passes its argument to /bin/sh. "
                        f"If attacker-controlled input reaches this call, arbitrary "
                        f"shell commands execute on the host running the MCP server."
                    ),
                    owasp_llm="LLM08",
                ))

        # subprocess.*
        for fn in SUBPROCESS_CALLS:
            if _is_attr_call(node, "subprocess", fn):
                if _has_shell_true(node):
                    findings.append(ThreatVector(
                        rule_id="MCP-CMI-002",
                        type=ThreatVectorType.CMD_INJECTION,
                        severity=Severity.HIGH,
                        confidence=Confidence.PROPOSED,
                        location=f"{file_path}:{node.lineno}",
                        evidence=f"subprocess.{fn}(..., shell=True)",
                        description=(
                            f"subprocess.{fn}() called with shell=True passes the command "
                            f"string to /bin/sh. Shell metacharacters (;, |, &&, $()) become "
                            f"active if any part of the command is attacker-controlled."
                        ),
                        owasp_llm="LLM08",
                    ))
                elif fn == "Popen":
                    # Popen without shell=True still deserves a flag:
                    # attacker-controlled values in the argv list can inject
                    # into process arguments even without shell interpretation.
                    findings.append(ThreatVector(
                        rule_id="MCP-CMI-002",
                        type=ThreatVectorType.CMD_INJECTION,
                        severity=Severity.MEDIUM,
                        confidence=Confidence.EXPERIMENTAL,
                        location=f"{file_path}:{node.lineno}",
                        evidence="subprocess.Popen(...)",
                        description=(
                            "subprocess.Popen() without shell=True passes args directly to "
                            "execve(). This avoids shell metacharacter injection but "
                            "attacker-controlled values in the argument list can still "
                            "influence the spawned process. Verify all arguments are validated."
                        ),
                        owasp_llm="LLM08",
                    ))

    return findings


def _detect_eval_exec(tree: ast.Module, file_path: str) -> list[ThreatVector]:
    """
    Detect eval() and exec() calls.
    Both execute arbitrary Python code strings at runtime — if the argument
    contains attacker-controlled input, this is full code execution.
    """
    findings: list[ThreatVector] = []

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue

        for builtin in ("eval", "exec"):
            if _is_bare_call(node, builtin):
                findings.append(ThreatVector(
                    rule_id="MCP-CMI-003",
                    type=ThreatVectorType.DESERIALIZATION,
                    severity=Severity.CRITICAL,
                    confidence=Confidence.PROPOSED,
                    location=f"{file_path}:{node.lineno}",
                    evidence=f"{builtin}(...)",
                    description=(
                        f"{builtin}() executes an arbitrary Python code string at runtime. "
                        f"If attacker-controlled input reaches this call, the attacker achieves "
                        f"full code execution within the MCP server process — including file "
                        f"system access, network calls, and process spawning."
                    ),
                    owasp_llm="LLM08",
                ))

    return findings


def _detect_env_access(tree: ast.Module, file_path: str) -> list[ThreatVector]:
    """
    Detect environment variable access patterns:
      - os.getenv(key)          — Call node
      - os.environ[key]         — Subscript node
    Both expose process secrets (API keys, tokens) to tool output if the
    key is attacker-controlled.
    """
    findings: list[ThreatVector] = []

    for node in ast.walk(tree):
        # os.getenv(...)
        if isinstance(node, ast.Call) and _is_attr_call(node, "os", "getenv"):
            findings.append(ThreatVector(
                rule_id="MCP-SEC-001",
                type=ThreatVectorType.SECRET_EXPOSURE,
                severity=Severity.MEDIUM,
                confidence=Confidence.PROPOSED,
                location=f"{file_path}:{node.lineno}",
                evidence="os.getenv(...)",
                description=(
                    "os.getenv() reads a value from the process environment and returns it. "
                    "If the key name is attacker-controlled, any secret stored as an env var "
                    "(API keys, tokens, credentials) can be exfiltrated via tool output."
                ),
                owasp_llm="LLM06",
            ))

        # os.environ[key] — AST node type is Subscript, not Call
        if (
            isinstance(node, ast.Subscript)
            and isinstance(node.value, ast.Attribute)
            and isinstance(node.value.value, ast.Name)
            and node.value.value.id == "os"
            and node.value.attr == "environ"
        ):
            findings.append(ThreatVector(
                rule_id="MCP-SEC-001",
                type=ThreatVectorType.SECRET_EXPOSURE,
                severity=Severity.MEDIUM,
                confidence=Confidence.PROPOSED,
                location=f"{file_path}:{node.lineno}",
                evidence="os.environ[...]",
                description=(
                    "os.environ subscript reads a value from the process environment. "
                    "If the key name is attacker-controlled, any secret stored as an env var "
                    "(API keys, tokens, credentials) can be exfiltrated via tool output. "
                    "Unlike os.getenv(), this raises KeyError on missing keys."
                ),
                owasp_llm="LLM06",
            ))

    return findings


def _detect_http_calls(tree: ast.Module, file_path: str) -> list[ThreatVector]:
    """
    Detect outbound HTTP calls via the requests library.
    These are SSRF candidates: if the URL is attacker-controlled the tool
    can probe internal services, cloud metadata endpoints (169.254.169.254),
    or exfiltrate data to external hosts.
    """
    findings: list[ThreatVector] = []

    HTTP_METHODS = {"get", "post", "put", "patch", "delete", "request"}

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue

        for method in HTTP_METHODS:
            if _is_attr_call(node, "requests", method):
                findings.append(ThreatVector(
                    rule_id="MCP-SSRF-001",
                    type=ThreatVectorType.SSRF,
                    severity=Severity.HIGH,
                    confidence=Confidence.PROPOSED,
                    location=f"{file_path}:{node.lineno}",
                    evidence=f"requests.{method}(...)",
                    description=(
                        f"requests.{method}() makes an outbound HTTP call. If the URL is "
                        f"attacker-controlled this enables SSRF: the attacker can probe "
                        f"internal services, reach cloud metadata endpoints "
                        f"(169.254.169.254), or exfiltrate data to an external host."
                    ),
                    owasp_llm="LLM02",
                ))

    return findings


# ---------------------------------------------------------------------------
# Public interface
# ---------------------------------------------------------------------------

class ASTExtractor:
    """Runs all AST-based detectors against a Python source file."""

    def analyze(self, file_path: str) -> ScanResult:
        source = Path(file_path).read_text(encoding="utf-8")
        try:
            tree = ast.parse(source, filename=file_path)
        except SyntaxError as exc:
            return ScanResult(
                file_path=file_path,
                findings=[],
                parse_status="failed",
                parse_warning=f"SyntaxError: {exc}",
            )

        findings: list[ThreatVector] = []
        findings.extend(_detect_cmd_injection(tree, file_path))
        findings.extend(_detect_eval_exec(tree, file_path))
        findings.extend(_detect_env_access(tree, file_path))
        findings.extend(_detect_http_calls(tree, file_path))

        return ScanResult(
            file_path=file_path,
            findings=findings,
            parse_status="ok",
        )
