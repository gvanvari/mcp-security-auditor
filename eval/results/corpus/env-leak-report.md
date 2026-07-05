# MCP Security Audit Report

**File:** `eval/corpus/env-leak.py`

## Summary

| Severity | Count |
|----------|-------|
| 🔴 CRITICAL | 0 |
| 🟠 HIGH | 0 |
| 🟡 MEDIUM | 2 |
| 🟢 LOW | 0 |
| **Total** | **2** |

---

## Findings

### Finding 1: Environment variable access — potential secret exposure

**Severity:** 🟡 MEDIUM  
**Rule:** `MCP-SEC-001`  
**Type:** `secret_exposure`  
**Confidence:** `PROPOSED`  
**Location:** `eval/corpus/env-leak.py:15`  

**Evidence:**
```
os.environ[...]
```

**Description:** os.environ subscript reads a value from the process environment. If the key name is attacker-controlled, any secret stored as an env var (API keys, tokens, credentials) can be exfiltrated via tool output. Unlike os.getenv(), this raises KeyError on missing keys.

**OWASP LLM Top 10:** LLM06  

**Remediation:**
Avoid returning environment variable values directly as tool output. If configuration values are needed, load them at server startup into typed configuration objects and pass only what each tool needs. Never accept environment variable key names as tool parameters. If secrets must be accessed, ensure the tool's return value does not include the raw secret.

**References:**
- OWASP LLM06: Sensitive Information Disclosure
- CWE-526: Cleartext Storage of Sensitive Information in an Environment Variable
- https://owasp.org/www-project-top-10-for-large-language-model-applications/

---

### Finding 2: Environment variable access — potential secret exposure

**Severity:** 🟡 MEDIUM  
**Rule:** `MCP-SEC-001`  
**Type:** `secret_exposure`  
**Confidence:** `PROPOSED`  
**Location:** `eval/corpus/env-leak.py:22`  

**Evidence:**
```
os.getenv(...)
```

**Description:** os.getenv() reads a value from the process environment and returns it. If the key name is attacker-controlled, any secret stored as an env var (API keys, tokens, credentials) can be exfiltrated via tool output.

**OWASP LLM Top 10:** LLM06  

**Remediation:**
Avoid returning environment variable values directly as tool output. If configuration values are needed, load them at server startup into typed configuration objects and pass only what each tool needs. Never accept environment variable key names as tool parameters. If secrets must be accessed, ensure the tool's return value does not include the raw secret.

**References:**
- OWASP LLM06: Sensitive Information Disclosure
- CWE-526: Cleartext Storage of Sensitive Information in an Environment Variable
- https://owasp.org/www-project-top-10-for-large-language-model-applications/

---
