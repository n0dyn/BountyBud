---
id: "http-security-headers"
title: "HTTP Security Headers Reference"
type: "cheatsheet"
category: "web-application"
subcategory: "configuration"
tags: ["security-headers", "csp", "hsts", "x-frame-options", "cors", "configuration"]
platforms: ["linux", "macos", "windows"]
related: ["clickjacking", "xss", "cors-misconfiguration"]
difficulty: "beginner"
updated: "2026-04-14"
---

# HTTP Security Headers Reference

## Check All Headers
```bash
curl -sI https://target.com | grep -iE "x-frame|x-content|strict-transport|content-security|x-xss|referrer-policy|permissions-policy|cross-origin"
```

## Content-Security-Policy (CSP)
```
Missing → XSS risk, inline script execution
Weak: script-src 'unsafe-inline' 'unsafe-eval' → XSS via inline/eval
Weak: script-src * → load scripts from anywhere
Bypass: script-src with JSONP endpoint or Angular/React CDN
Check: https://csp-evaluator.withgoogle.com/
```

## X-Frame-Options
```
Missing → Clickjacking possible
DENY → Cannot be framed at all
SAMEORIGIN → Only same-origin framing
ALLOW-FROM → NOT supported in Chrome/Safari (still frameable!)
Superseded by: CSP frame-ancestors
```

## Strict-Transport-Security (HSTS)
```
Missing → SSL stripping attacks possible
Weak: max-age < 31536000 → Short HSTS lifetime
Missing: includeSubDomains → Subdomains vulnerable
Missing: preload → Not in browser preload list
Good: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
```

## X-Content-Type-Options
```
Missing → MIME sniffing attacks
Should be: X-Content-Type-Options: nosniff
Prevents: Browser treating uploaded files as executable HTML/JS
```

## Referrer-Policy
```
Missing → Tokens/URLs leak via Referer header to third parties
Weak: no-referrer-when-downgrade (default) → Leaks full URL on HTTPS→HTTPS
Good: strict-origin-when-cross-origin or no-referrer
```

## Permissions-Policy (formerly Feature-Policy)
```
Missing → All browser features available
Controls: camera, microphone, geolocation, payment, fullscreen, etc.
Good: Permissions-Policy: camera=(), microphone=(), geolocation=()
```

## Cross-Origin Headers
```
Cross-Origin-Opener-Policy: same-origin → Prevents window.opener attacks
Cross-Origin-Embedder-Policy: require-corp → Prevents cross-origin loads
Cross-Origin-Resource-Policy: same-origin → Prevents cross-origin reads
```

## Access-Control (CORS)
```
Access-Control-Allow-Origin: * → Open to all origins (check with credentials)
Reflects Origin header → Origin reflection vulnerability
Access-Control-Allow-Credentials: true + wildcard → Critical CORS misconfig
Check: curl -H "Origin: https://evil.com" -I URL
```

## Cookie Flags
```
Missing HttpOnly → Cookie accessible via JavaScript (XSS theft)
Missing Secure → Cookie sent over HTTP (interception)
Missing SameSite → CSRF possible
SameSite=None without Secure → Invalid, browser may reject
No __Host- prefix → Cookie tossing from subdomains
```

## Quick Audit Command
```bash
curl -sI https://target.com | grep -iE "^(x-frame|x-content|strict-transport|content-security|x-xss|referrer-policy|permissions-policy|cross-origin|set-cookie|access-control)" | sort
```
