# MCP Security Audit Report

**File:** `eval/corpus/http-exfil.py`

## Summary

| Severity | Count |
|----------|-------|
| 🔴 CRITICAL | 0 |
| 🟠 HIGH | 2 |
| 🟡 MEDIUM | 0 |
| 🟢 LOW | 0 |
| **Total** | **2** |

---

## Findings

### Finding 1: Server-Side Request Forgery (SSRF) via outbound HTTP call

**Severity:** 🟠 HIGH  
**Rule:** `MCP-SSRF-001`  
**Type:** `ssrf`  
**Confidence:** `PROPOSED`  
**Location:** `eval/corpus/http-exfil.py:15`  

**Evidence:**
```
requests.get(...)
```

**Description:** requests.get() makes an outbound HTTP call. If the URL is attacker-controlled this enables SSRF: the attacker can probe internal services, reach cloud metadata endpoints (169.254.169.254), or exfiltrate data to an external host.

**OWASP LLM Top 10:** LLM02  

**Remediation:**
Validate and restrict the URL before making outbound requests. Use an allowlist of permitted hostnames or URL prefixes. Block requests to private IP ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, 127.0.0.0/8) and cloud metadata endpoints. If the tool only needs to reach one specific endpoint, hardcode the base URL and only allow user input for path parameters after validation.

**References:**
- OWASP LLM02: Insecure Output Handling
- CWE-918: Server-Side Request Forgery
- https://owasp.org/www-project-top-10-for-large-language-model-applications/
- https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html

---

### Finding 2: Server-Side Request Forgery (SSRF) via outbound HTTP call

**Severity:** 🟠 HIGH  
**Rule:** `MCP-SSRF-001`  
**Type:** `ssrf`  
**Confidence:** `PROPOSED`  
**Location:** `eval/corpus/http-exfil.py:23`  

**Evidence:**
```
requests.post(...)
```

**Description:** requests.post() makes an outbound HTTP call. If the URL is attacker-controlled this enables SSRF: the attacker can probe internal services, reach cloud metadata endpoints (169.254.169.254), or exfiltrate data to an external host.

**OWASP LLM Top 10:** LLM02  

**Remediation:**
Validate and restrict the URL before making outbound requests. Use an allowlist of permitted hostnames or URL prefixes. Block requests to private IP ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, 127.0.0.0/8) and cloud metadata endpoints. If the tool only needs to reach one specific endpoint, hardcode the base URL and only allow user input for path parameters after validation.

**References:**
- OWASP LLM02: Insecure Output Handling
- CWE-918: Server-Side Request Forgery
- https://owasp.org/www-project-top-10-for-large-language-model-applications/
- https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html

---
