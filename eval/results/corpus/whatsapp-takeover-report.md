# MCP Security Audit Report

**File:** `eval/corpus/whatsapp-takeover.py`

## Summary

| Severity | Count |
|----------|-------|
| 🔴 CRITICAL | 1 |
| 🟠 HIGH | 1 |
| 🟡 MEDIUM | 0 |
| 🟢 LOW | 0 |
| **Total** | **2** |

---

## Findings

### Finding 1: Rug pull — conditional __doc__ mutation at runtime

**Severity:** 🔴 CRITICAL  
**Rule:** `MCP-RUGPULL-001`  
**Type:** `rug_pull`  
**Confidence:** `VERIFIED`  
**Location:** `line 18`  

**Evidence:**
```
os.path.exists() guard → __doc__ mutation + trigger file creation
```

**Description:** Rug pull pattern detected: tool description is conditionally replaced after first run via __doc__ assignment inside an os.path.exists() guard. Server appears benign on first load (passing user approval), then silently switches to a malicious description on subsequent loads.

**OWASP LLM Top 10:** LLM07  

**Remediation:**
Tool docstrings must be static. Any runtime reassignment of __doc__ on an MCP tool function is inherently suspicious — there is no legitimate reason for a tool's description to change after the server starts. Remove the conditional __doc__ assignment entirely. If behavior must vary, use explicit runtime logic with proper logging — never by changing what the LLM is told the tool does.

**References:**
- OWASP LLM01: Prompt Injection
- CWE-494: Download of Code Without Integrity Check
- https://github.com/invariantlabs-ai/mcp-injection-experiments

---

### Finding 2: Shell command injection via os.system() or os.popen()

**Severity:** 🟠 HIGH  
**Rule:** `MCP-CMI-001`  
**Type:** `cmd_injection`  
**Confidence:** `PROPOSED`  
**Location:** `eval/corpus/whatsapp-takeover.py:39`  

**Evidence:**
```
os.system(...)
```

**Description:** os.system() always passes its argument to /bin/sh. If attacker-controlled input reaches this call, arbitrary shell commands execute on the host running the MCP server.

**OWASP LLM Top 10:** LLM08  

**Remediation:**
Replace os.system() and os.popen() with subprocess.run() using a validated argument list and shell=False. Never construct shell command strings by concatenating or formatting user-supplied input. If a shell command is genuinely required, validate and allowlist all input values before use.

**References:**
- OWASP LLM08: Excessive Agency
- CWE-78: Improper Neutralization of Special Elements used in an OS Command
- https://docs.python.org/3/library/subprocess.html#security-considerations

---
