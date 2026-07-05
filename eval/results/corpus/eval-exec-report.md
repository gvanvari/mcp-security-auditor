# MCP Security Audit Report

**File:** `eval/corpus/eval-exec.py`

## Summary

| Severity | Count |
|----------|-------|
| 🔴 CRITICAL | 2 |
| 🟠 HIGH | 0 |
| 🟡 MEDIUM | 0 |
| 🟢 LOW | 0 |
| **Total** | **2** |

---

## Findings

### Finding 1: Arbitrary code execution via eval() or exec()

**Severity:** 🔴 CRITICAL  
**Rule:** `MCP-CMI-003`  
**Type:** `deserialization`  
**Confidence:** `PROPOSED`  
**Location:** `eval/corpus/eval-exec.py:13`  

**Evidence:**
```
eval(...)
```

**Description:** eval() executes an arbitrary Python code string at runtime. If attacker-controlled input reaches this call, the attacker achieves full code execution within the MCP server process — including file system access, network calls, and process spawning.

**OWASP LLM Top 10:** LLM08  

**Remediation:**
Remove eval() and exec() entirely. There is no safe way to call these functions with attacker-controlled input. If the use case is evaluating mathematical expressions, use a dedicated safe parser (e.g. ast.literal_eval for literals, or a library like simpleeval). If the use case is executing user-provided Python, the feature itself should be reconsidered — it grants the user full server-side code execution.

**References:**
- OWASP LLM08: Excessive Agency
- CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code
- https://docs.python.org/3/library/ast.html#ast.literal_eval

---

### Finding 2: Arbitrary code execution via eval() or exec()

**Severity:** 🔴 CRITICAL  
**Rule:** `MCP-CMI-003`  
**Type:** `deserialization`  
**Confidence:** `PROPOSED`  
**Location:** `eval/corpus/eval-exec.py:21`  

**Evidence:**
```
exec(...)
```

**Description:** exec() executes an arbitrary Python code string at runtime. If attacker-controlled input reaches this call, the attacker achieves full code execution within the MCP server process — including file system access, network calls, and process spawning.

**OWASP LLM Top 10:** LLM08  

**Remediation:**
Remove eval() and exec() entirely. There is no safe way to call these functions with attacker-controlled input. If the use case is evaluating mathematical expressions, use a dedicated safe parser (e.g. ast.literal_eval for literals, or a library like simpleeval). If the use case is executing user-provided Python, the feature itself should be reconsidered — it grants the user full server-side code execution.

**References:**
- OWASP LLM08: Excessive Agency
- CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code
- https://docs.python.org/3/library/ast.html#ast.literal_eval

---
