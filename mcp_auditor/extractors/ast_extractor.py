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
# P1-1 — Intra-procedural taint analysis
# ---------------------------------------------------------------------------

class _TaintContext:
    """
    Lightweight single-pass taint context scoped to one function body.

    Sources: parameters of the enclosing @mcp.tool() function.
    Propagation: direct use, simple single-assignment alias (x = param).
    Sinks: classified on demand by _classify_node().

    Scope documented boundary:
      - Intra-procedural only — no cross-function tracking.
      - Single-pass — only explicit `name = param` assignments tracked.
      - f-strings and binary concat that include a tainted name → reachable.
      - Anything more complex → unknown (conservative).
    """

    def __init__(self, func_node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        # All parameter names are taint sources
        self._tainted: set[str] = {arg.arg for arg in func_node.args.args}
        # Walk the body once to propagate simple assignments: x = param
        self._propagate(func_node)

    def _propagate(self, func_node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        """Single-pass: record `alias = tainted_name` assignments."""
        for node in ast.walk(func_node):
            if not isinstance(node, ast.Assign):
                continue
            # RHS must be a single tainted Name
            if not isinstance(node.value, ast.Name):
                continue
            if node.value.id not in self._tainted:
                continue
            # LHS: propagate to simple Name targets
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self._tainted.add(target.id)

    def _node_is_tainted(self, node: ast.expr) -> bool:
        """Return True if node contains any tainted name."""
        for child in ast.walk(node):
            if isinstance(child, ast.Name) and child.id in self._tainted:
                return True
        return False

    def classify(self, arg_node: ast.expr) -> str:
        """
        Classify one call argument AST node.

        Returns one of:
          "reachable"  — argument contains a tainted (parameter-derived) name
          "constant"   — argument is a literal constant with no tainted name
          "unknown"    — expression is complex; treated conservatively
        """
        # Pure constant literal
        if isinstance(arg_node, ast.Constant):
            return "constant"

        # Direct name reference
        if isinstance(arg_node, ast.Name):
            if arg_node.id in self._tainted:
                return "reachable"
            # Name is not a literal — it could be assigned from anything
            # (function call result, attribute, etc.); treat conservatively.
            return "unknown"

        # List literal (e.g. subprocess.Popen(["cmd", user_arg, ...]))
        # Common in subprocess.Popen argv — tainted if any element is tainted.
        if isinstance(arg_node, ast.List):
            if self._node_is_tainted(arg_node):
                return "reachable"
            if all(isinstance(elt, ast.Constant) for elt in arg_node.elts):
                return "constant"
            return "unknown"

        # f-string: tainted if any tainted name appears in its values
        if isinstance(arg_node, ast.JoinedStr):
            return "reachable" if self._node_is_tainted(arg_node) else "constant"

        # Binary concat (e.g. "prefix" + param): tainted if any node is
        if isinstance(arg_node, ast.BinOp) and isinstance(arg_node.op, ast.Add):
            return "reachable" if self._node_is_tainted(arg_node) else "constant"

        # Everything else (subscripts, call results, attribute chains, etc.)
        return "unknown"


def _adjust_for_reachability(
    severity: "Severity",
    confidence: "Confidence",
    reachability: str,
) -> "tuple[Severity, Confidence]":
    """
    Apply the standard severity/confidence adjustment based on reachability.

      reachable → keep severity; upgrade confidence to VERIFIED (if not already)
      constant  → downgrade severity one level; downgrade confidence to EXPERIMENTAL
      unknown   → keep severity and confidence unchanged (conservative)
    """
    from .threat_vector import Severity, Confidence  # local import avoids circular

    _SEV_ORDER = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]

    if reachability == "reachable":
        new_sev = severity
        # Raise confidence — we have a confirmed flow from source to sink
        conf_map = {
            Confidence.EXPERIMENTAL: Confidence.PROPOSED,
            Confidence.PROPOSED: Confidence.VERIFIED,
            Confidence.VERIFIED: Confidence.VERIFIED,
        }
        new_conf = conf_map.get(confidence, confidence)
    elif reachability == "constant":
        # Downgrade severity by one level
        idx = _SEV_ORDER.index(severity)
        new_sev = _SEV_ORDER[max(0, idx - 1)]
        new_conf = Confidence.EXPERIMENTAL
    else:  # unknown
        new_sev = severity
        new_conf = confidence

    return new_sev, new_conf


# ---------------------------------------------------------------------------
# Detectors — one per attack class, each returns list[ThreatVector]
# All detectors now accept an optional _TaintContext for reachability.
# ---------------------------------------------------------------------------

def _detect_cmd_injection(
    tree: ast.Module,
    file_path: str,
    taint: "_TaintContext | None" = None,
) -> list[ThreatVector]:
    """
    Detect shell command execution patterns:
      - os.system / os.popen: always invoke /bin/sh, no flag needed
      - subprocess.run/call/check_call/check_output with shell=True: shell injection
      - subprocess.Popen: flag regardless — attacker-controlled argv is still dangerous
    """
    findings: list[ThreatVector] = []

    OS_SHELL_CALLS = {"system", "popen"}
    SUBPROCESS_CALLS = {"run", "call", "check_call", "check_output", "Popen"}

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue

        # os.system / os.popen
        for fn in OS_SHELL_CALLS:
            if _is_attr_call(node, "os", fn):
                # Classify the first positional argument
                arg_node = node.args[0] if node.args else None
                reach = taint.classify(arg_node) if (taint and arg_node) else "unknown"
                sev, conf = _adjust_for_reachability(Severity.HIGH, Confidence.PROPOSED, reach)
                findings.append(ThreatVector(
                    rule_id="MCP-CMI-001",
                    type=ThreatVectorType.CMD_INJECTION,
                    severity=sev,
                    confidence=conf,
                    location=f"{file_path}:{node.lineno}",
                    evidence=f"os.{fn}(...)",
                    description=(
                        f"os.{fn}() always passes its argument to /bin/sh. "
                        f"If attacker-controlled input reaches this call, arbitrary "
                        f"shell commands execute on the host running the MCP server."
                    ),
                    owasp_llm="LLM08",
                    reachability=reach,
                ))

        # subprocess.*
        for fn in SUBPROCESS_CALLS:
            if _is_attr_call(node, "subprocess", fn):
                # First arg is the command — classify it
                arg_node = node.args[0] if node.args else None
                reach = taint.classify(arg_node) if (taint and arg_node) else "unknown"

                if _has_shell_true(node):
                    sev, conf = _adjust_for_reachability(Severity.HIGH, Confidence.PROPOSED, reach)
                    findings.append(ThreatVector(
                        rule_id="MCP-CMI-002",
                        type=ThreatVectorType.CMD_INJECTION,
                        severity=sev,
                        confidence=conf,
                        location=f"{file_path}:{node.lineno}",
                        evidence=f"subprocess.{fn}(..., shell=True)",
                        description=(
                            f"subprocess.{fn}() called with shell=True passes the command "
                            f"string to /bin/sh. Shell metacharacters (;, |, &&, $()) become "
                            f"active if any part of the command is attacker-controlled."
                        ),
                        owasp_llm="LLM08",
                        reachability=reach,
                    ))
                elif fn == "Popen":
                    sev, conf = _adjust_for_reachability(Severity.MEDIUM, Confidence.EXPERIMENTAL, reach)
                    findings.append(ThreatVector(
                        rule_id="MCP-CMI-002",
                        type=ThreatVectorType.CMD_INJECTION,
                        severity=sev,
                        confidence=conf,
                        location=f"{file_path}:{node.lineno}",
                        evidence="subprocess.Popen(...)",
                        description=(
                            "subprocess.Popen() without shell=True passes args directly to "
                            "execve(). This avoids shell metacharacter injection but "
                            "attacker-controlled values in the argument list can still "
                            "influence the spawned process. Verify all arguments are validated."
                        ),
                        owasp_llm="LLM08",
                        reachability=reach,
                    ))

    return findings


def _detect_eval_exec(
    tree: ast.Module,
    file_path: str,
    taint: "_TaintContext | None" = None,
) -> list[ThreatVector]:
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
                arg_node = node.args[0] if node.args else None
                reach = taint.classify(arg_node) if (taint and arg_node) else "unknown"
                sev, conf = _adjust_for_reachability(Severity.CRITICAL, Confidence.PROPOSED, reach)
                findings.append(ThreatVector(
                    rule_id="MCP-CMI-003",
                    type=ThreatVectorType.DESERIALIZATION,
                    severity=sev,
                    confidence=conf,
                    location=f"{file_path}:{node.lineno}",
                    evidence=f"{builtin}(...)",
                    description=(
                        f"{builtin}() executes an arbitrary Python code string at runtime. "
                        f"If attacker-controlled input reaches this call, the attacker achieves "
                        f"full code execution within the MCP server process — including file "
                        f"system access, network calls, and process spawning."
                    ),
                    owasp_llm="LLM08",
                    reachability=reach,
                ))

    return findings


def _detect_env_access(
    tree: ast.Module,
    file_path: str,
    taint: "_TaintContext | None" = None,
) -> list[ThreatVector]:
    """
    Detect environment variable access patterns:
      - os.getenv(key)          — Call node
      - os.environ[key]         — Subscript node

    Reachability here applies to the *key* argument, not the value returned.
    A constant key (os.getenv("PORT")) is informational; a tainted key
    allows the attacker to choose which secret is read.
    """
    findings: list[ThreatVector] = []

    for node in ast.walk(tree):
        # os.getenv(...)
        if isinstance(node, ast.Call) and _is_attr_call(node, "os", "getenv"):
            arg_node = node.args[0] if node.args else None
            reach = taint.classify(arg_node) if (taint and arg_node) else "unknown"
            sev, conf = _adjust_for_reachability(Severity.MEDIUM, Confidence.PROPOSED, reach)
            findings.append(ThreatVector(
                rule_id="MCP-SEC-001",
                type=ThreatVectorType.SECRET_EXPOSURE,
                severity=sev,
                confidence=conf,
                location=f"{file_path}:{node.lineno}",
                evidence="os.getenv(...)",
                description=(
                    "os.getenv() reads a value from the process environment and returns it. "
                    "If the key name is attacker-controlled, any secret stored as an env var "
                    "(API keys, tokens, credentials) can be exfiltrated via tool output."
                ),
                owasp_llm="LLM06",
                reachability=reach,
            ))

        # os.environ[key]
        if (
            isinstance(node, ast.Subscript)
            and isinstance(node.value, ast.Attribute)
            and isinstance(node.value.value, ast.Name)
            and node.value.value.id == "os"
            and node.value.attr == "environ"
        ):
            key_node = node.slice if isinstance(node.slice, ast.expr) else None
            reach = taint.classify(key_node) if (taint and key_node) else "unknown"
            sev, conf = _adjust_for_reachability(Severity.MEDIUM, Confidence.PROPOSED, reach)
            findings.append(ThreatVector(
                rule_id="MCP-SEC-001",
                type=ThreatVectorType.SECRET_EXPOSURE,
                severity=sev,
                confidence=conf,
                location=f"{file_path}:{node.lineno}",
                evidence="os.environ[...]",
                description=(
                    "os.environ subscript reads a value from the process environment. "
                    "If the key name is attacker-controlled, any secret stored as an env var "
                    "(API keys, tokens, credentials) can be exfiltrated via tool output. "
                    "Unlike os.getenv(), this raises KeyError on missing keys."
                ),
                owasp_llm="LLM06",
                reachability=reach,
            ))

    return findings


def _detect_http_calls(
    tree: ast.Module,
    file_path: str,
    taint: "_TaintContext | None" = None,
) -> list[ThreatVector]:
    """
    Detect outbound HTTP calls via the requests or httpx libraries.
    These are SSRF candidates: if the URL is attacker-controlled the tool
    can probe internal services, cloud metadata endpoints (169.254.169.254),
    or exfiltrate data to external hosts.
    """
    findings: list[ThreatVector] = []

    HTTP_METHODS = {"get", "post", "put", "patch", "delete", "request"}
    HTTP_MODULES = {"requests", "httpx"}

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue

        for module in HTTP_MODULES:
            for method in HTTP_METHODS:
                if _is_attr_call(node, module, method):
                    # First positional arg is the URL
                    arg_node = node.args[0] if node.args else None
                    reach = taint.classify(arg_node) if (taint and arg_node) else "unknown"
                    sev, conf = _adjust_for_reachability(Severity.HIGH, Confidence.PROPOSED, reach)
                    findings.append(ThreatVector(
                        rule_id="MCP-SSRF-001",
                        type=ThreatVectorType.SSRF,
                        severity=sev,
                        confidence=conf,
                        location=f"{file_path}:{node.lineno}",
                        evidence=f"{module}.{method}(...)",
                        description=(
                            f"{module}.{method}() makes an outbound HTTP call. If the URL is "
                            f"attacker-controlled this enables SSRF: the attacker can probe "
                            f"internal services, reach cloud metadata endpoints "
                            f"(169.254.169.254), or exfiltrate data to an external host."
                        ),
                        owasp_llm="LLM02",
                        reachability=reach,
                    ))

    return findings


def _detect_url_param_forwarding(tree: ast.Module, file_path: str) -> list[ThreatVector]:
    """
    Detect MCP tool parameters with URL-like names forwarded directly into
    third-party library method calls without validation.

    Pattern caught:
        async def convert_to_markdown(uri: str) -> str:
            return MarkItDown().convert_uri(uri).markdown

    Direct HTTP library calls (requests.*, httpx.*) are already caught by
    _detect_http_calls.  This rule catches library-mediated fetches where a
    url/uri argument is delegated to an opaque third-party object method.

    These are always reachable by definition (the pattern requires a param to
    be forwarded), so reachability is set to "reachable" unconditionally.
    """
    findings: list[ThreatVector] = []

    URL_LIKE_PARAMS = {"url", "uri", "href", "link", "endpoint"}
    KNOWN_HTTP_MODULES = {"requests", "httpx", "urllib"}

    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue

        url_params = {
            arg.arg for arg in node.args.args
            if arg.arg.lower() in URL_LIKE_PARAMS
        }
        if not url_params:
            continue

        for child in ast.walk(node):
            if not isinstance(child, ast.Call):
                continue
            if not isinstance(child.func, ast.Attribute):
                continue
            if (
                isinstance(child.func.value, ast.Name)
                and child.func.value.id in KNOWN_HTTP_MODULES
            ):
                continue

            for arg in child.args:
                if isinstance(arg, ast.Name) and arg.id in url_params:
                    findings.append(ThreatVector(
                        rule_id="MCP-SSRF-001",
                        type=ThreatVectorType.SSRF,
                        severity=Severity.HIGH,
                        confidence=Confidence.EXPERIMENTAL,
                        location=f"{file_path}:{child.lineno}",
                        evidence=f"{arg.id} forwarded into .{child.func.attr}(...)",
                        description=(
                            f"Tool parameter '{arg.id}' (a URL/URI) is forwarded directly "
                            f"into a third-party library method .{child.func.attr}(). "
                            f"If the library performs an outbound HTTP request, this is an "
                            f"unvalidated SSRF: the attacker can probe internal services, "
                            f"reach cloud metadata endpoints (169.254.169.254), or "
                            f"exfiltrate data to an external host."
                        ),
                        owasp_llm="LLM02",
                        reachability="reachable",
                    ))
                    break

            for kw in child.keywords:
                if isinstance(kw.value, ast.Name) and kw.value.id in url_params:
                    findings.append(ThreatVector(
                        rule_id="MCP-SSRF-001",
                        type=ThreatVectorType.SSRF,
                        severity=Severity.HIGH,
                        confidence=Confidence.EXPERIMENTAL,
                        location=f"{file_path}:{child.lineno}",
                        evidence=f"{kw.value.id} forwarded into .{child.func.attr}(...)",
                        description=(
                            f"Tool parameter '{kw.value.id}' (a URL/URI) is forwarded "
                            f"directly into a third-party library method "
                            f".{child.func.attr}(). "
                            f"If the library performs an outbound HTTP request, this is an "
                            f"unvalidated SSRF: the attacker can probe internal services, "
                            f"reach cloud metadata endpoints (169.254.169.254), or "
                            f"exfiltrate data to an external host."
                        ),
                        owasp_llm="LLM02",
                        reachability="reachable",
                    ))
                    break

    return findings


# ---------------------------------------------------------------------------
# Public interface
# ---------------------------------------------------------------------------

def _is_mcp_tool_func(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """Return True if function is decorated with @mcp.tool() or @server.tool()."""
    for dec in node.decorator_list:
        if isinstance(dec, ast.Call):
            func = dec.func
            if isinstance(func, ast.Attribute) and func.attr == "tool":
                return True
        elif isinstance(dec, ast.Attribute) and dec.attr == "tool":
            return True
    return False


class ASTExtractor:
    """
    Runs all AST-based detectors against a Python source file.

    For @mcp.tool() decorated functions, detectors run with a _TaintContext
    built from the function's parameters — each finding carries a reachability
    verdict (reachable / constant / unknown).

    For code outside @mcp.tool() functions, detectors run without taint context
    and all findings default to reachability="unknown".

    Scope: intra-procedural, single-pass assignment propagation only.
    Multi-hop and cross-function flows are not tracked (documented boundary).
    """

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

        # --- Per-function pass: taint-aware for @mcp.tool() functions ---
        # Track lines already covered so we don't double-emit from the
        # file-level pass below.
        covered_lines: set[int] = set()

        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if not _is_mcp_tool_func(node):
                continue

            # Build a taint context from this function's parameters
            taint = _TaintContext(node)

            # Run sinks-in-body detectors scoped to this function's subtree
            func_module = ast.Module(body=[node], type_ignores=[])
            func_findings: list[ThreatVector] = []
            func_findings.extend(_detect_cmd_injection(func_module, file_path, taint))  # type: ignore[arg-type]
            func_findings.extend(_detect_eval_exec(func_module, file_path, taint))      # type: ignore[arg-type]
            func_findings.extend(_detect_env_access(func_module, file_path, taint))     # type: ignore[arg-type]
            func_findings.extend(_detect_http_calls(func_module, file_path, taint))     # type: ignore[arg-type]

            for f in func_findings:
                findings.append(f)
                # Extract line number from "path:N" location string
                try:
                    covered_lines.add(int(f.location.rsplit(":", 1)[-1]))
                except ValueError:
                    pass

        # --- File-level pass: no taint context, skip already-covered lines ---
        # Catches dangerous calls outside @mcp.tool() scope.
        all_findings: list[ThreatVector] = []
        all_findings.extend(_detect_cmd_injection(tree, file_path))  # type: ignore[arg-type]
        all_findings.extend(_detect_eval_exec(tree, file_path))      # type: ignore[arg-type]
        all_findings.extend(_detect_env_access(tree, file_path))     # type: ignore[arg-type]
        all_findings.extend(_detect_http_calls(tree, file_path))     # type: ignore[arg-type]

        for f in all_findings:
            try:
                lineno = int(f.location.rsplit(":", 1)[-1])
            except ValueError:
                lineno = -1
            if lineno not in covered_lines:
                findings.append(f)

        # _detect_url_param_forwarding is always reachable by construction
        findings.extend(_detect_url_param_forwarding(tree, file_path))

        return ScanResult(
            file_path=file_path,
            findings=findings,
            parse_status="ok",
        )
