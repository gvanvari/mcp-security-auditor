# MCP Security Audit Report

**File:** `eval/corpus/cmd-injection.py`

## Summary

| Severity | Count |
|----------|-------|
| 🔴 CRITICAL | 0 |
| 🟠 HIGH | 2 |
| 🟡 MEDIUM | 1 |
| 🟢 LOW | 0 |
| **Total** | **3** |

---

## Findings

### Finding 1: Shell command injection via os.system() or os.popen()

**Severity:** 🟠 HIGH  
**Rule:** `MCP-CMI-001`  
**Type:** `cmd_injection`  
**Confidence:** `PROPOSED`  
**Location:** `eval/corpus/cmd-injection.py:16`  

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

### Finding 2: Shell command injection via subprocess with shell=True

**Severity:** 🟠 HIGH  
**Rule:** `MCP-CMI-002`  
**Type:** `cmd_injection`  
**Confidence:** `PROPOSED`  
**Location:** `eval/corpus/cmd-injection.py:19`  

**Evidence:**
```
subprocess.run(..., shell=True)
```

**Description:** subprocess.run() called with shell=True passes the command string to /bin/sh. Shell metacharacters (;, |, &&, $()) become active if any part of the command is attacker-controlled.

**OWASP LLM Top 10:** LLM08  

**Remediation:**
Remove shell=True and pass the command as a list of strings instead:
  subprocess.run(["cmd", arg1, arg2], shell=False)
This bypasses the shell entirely — arguments are passed directly to execve() and metacharacters are treated as literals. Validate all arguments against an allowlist before passing them to subprocess.

**References:**
- OWASP LLM08: Excessive Agency
- CWE-78: Improper Neutralization of Special Elements used in an OS Command
- https://docs.python.org/3/library/subprocess.html#security-considerations

---

### Finding 3: Shell command injection via subprocess with shell=True

**Severity:** 🟡 MEDIUM  
**Rule:** `MCP-CMI-002`  
**Type:** `cmd_injection`  
**Confidence:** `EXPERIMENTAL`  
**Location:** `eval/corpus/cmd-injection.py:27`  

**Evidence:**
```
subprocess.Popen(...)
```

**Description:** subprocess.Popen() without shell=True passes args directly to execve(). This avoids shell metacharacter injection but attacker-controlled values in the argument list can still influence the spawned process. Verify all arguments are validated.

**OWASP LLM Top 10:** LLM08  

**Remediation:**
Remove shell=True and pass the command as a list of strings instead:
  subprocess.run(["cmd", arg1, arg2], shell=False)
This bypasses the shell entirely — arguments are passed directly to execve() and metacharacters are treated as literals. Validate all arguments against an allowlist before passing them to subprocess.

**References:**
- OWASP LLM08: Excessive Agency
- CWE-78: Improper Neutralization of Special Elements used in an OS Command
- https://docs.python.org/3/library/subprocess.html#security-considerations

---
