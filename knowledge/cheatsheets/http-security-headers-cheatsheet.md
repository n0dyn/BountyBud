---
id: "http-security-headers-cheatsheet"
title: "HTTP Security Headers Reference"
type: "cheatsheet"
category: "web-application"
subcategory: "configuration"
tags: ["headers", "security", "hsts", "csp", "x-frame-options", "cors", "configuration", "misconfiguration"]
difficulty: "beginner"
platforms: ["linux", "macos", "windows"]
related: ["curl-api-testing-cheatsheet", "burp-suite-cheatsheet"]
updated: "2026-04-14"
---

## Quick Security Header Check

```bash
# Check all security headers at once
curl -sI https://target.com | grep -iE "(strict-transport|content-security|x-frame|x-content-type|referrer-policy|permissions-policy|x-xss|cross-origin|cache-control|clear-site-data|x-permitted)"

# Online scanner: https://securityheaders.com
# Mozilla Observatory: https://observatory.mozilla.org
```

## Strict-Transport-Security (HSTS)

**Purpose**: Forces HTTPS-only connections, prevents SSL stripping attacks.

```
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
```

| Directive | Description |
|-----------|-------------|
| `max-age=SECONDS` | Duration to remember HTTPS-only (31536000 = 1 year) |
| `includeSubDomains` | Apply to all subdomains |
| `preload` | Opt into browser preload list |

**Testing**:
```bash
# Check HSTS header
curl -sI https://target.com | grep -i strict-transport

# Missing HSTS = can intercept first HTTP request (SSL stripping)
# Low max-age = short protection window
# Missing includeSubDomains = subdomains vulnerable

# Test: access via HTTP, should redirect to HTTPS
curl -sI http://target.com
```

**Misconfigurations**:
- Missing entirely (no protection)
- max-age too low (< 31536000)
- Missing `includeSubDomains` (subdomains can be stripped)
- Set on HTTP response (ignored by browsers, only valid on HTTPS)

---

## Content-Security-Policy (CSP)

**Purpose**: Controls which resources can load, prevents XSS, clickjacking, data injection.

```
Content-Security-Policy: default-src 'self'; script-src 'self' https://cdn.example.com; style-src 'self' 'unsafe-inline'; img-src *; frame-ancestors 'none'; base-uri 'self'; form-action 'self'
```

| Directive | Controls | Example |
|-----------|----------|---------|
| `default-src` | Fallback for all types | `'self'` |
| `script-src` | JavaScript sources | `'self' 'nonce-abc123'` |
| `style-src` | CSS sources | `'self' 'unsafe-inline'` |
| `img-src` | Image sources | `'self' data: https:` |
| `font-src` | Font sources | `'self' https://fonts.gstatic.com` |
| `connect-src` | XHR/Fetch/WebSocket | `'self' https://api.target.com` |
| `media-src` | Audio/Video sources | `'self'` |
| `object-src` | Flash/Java plugins | `'none'` |
| `frame-src` | Iframe sources | `'none'` |
| `frame-ancestors` | Who can frame this page | `'none'` |
| `base-uri` | Restrict base element | `'self'` |
| `form-action` | Form submission targets | `'self'` |
| `worker-src` | Web Worker sources | `'self'` |
| `manifest-src` | Manifest file sources | `'self'` |
| `report-uri` | Report violations (deprecated) | `/csp-report` |
| `report-to` | Report violations (new) | `csp-endpoint` |

| Source Value | Description |
|-------------|-------------|
| `'self'` | Same origin |
| `'none'` | Block all |
| `'unsafe-inline'` | Allow inline scripts/styles (weakens CSP) |
| `'unsafe-eval'` | Allow eval() (weakens CSP significantly) |
| `'nonce-VALUE'` | Allow specific nonce |
| `'sha256-HASH'` | Allow specific hash |
| `'strict-dynamic'` | Trust scripts loaded by trusted scripts |
| `data:` | Allow data: URIs |
| `blob:` | Allow blob: URIs |
| `https:` | Any HTTPS source |
| `*.example.com` | Wildcard subdomain |

**Testing**:
```bash
# Check CSP header
curl -sI https://target.com | grep -i content-security-policy

# Check for report-only mode (not enforcing!)
curl -sI https://target.com | grep -i content-security-policy-report-only
```

**Common CSP Bypasses** (report as misconfiguration):
- `script-src 'unsafe-inline'` - Inline XSS still works
- `script-src 'unsafe-eval'` - eval-based XSS works
- `script-src *` or `script-src https:` - Load scripts from anywhere
- `script-src` with CDNs that host user content (e.g., cdnjs with JSONP)
- Missing `default-src` with missing specific directives
- `object-src` not set to `'none'` - Flash-based XSS
- Missing `base-uri` - base tag injection
- Missing `frame-ancestors` - clickjacking possible
- Report-Only mode (not enforced at all)
- `*.googleapis.com` in script-src (JSONP bypass via Google APIs)

---

## X-Frame-Options

**Purpose**: Prevents clickjacking by controlling who can embed the page in frames.

```
X-Frame-Options: DENY
X-Frame-Options: SAMEORIGIN
```

| Value | Description |
|-------|-------------|
| `DENY` | Cannot be framed by anyone |
| `SAMEORIGIN` | Can only be framed by same origin |
| `ALLOW-FROM uri` | Deprecated, use CSP frame-ancestors |

**Note**: Superseded by CSP `frame-ancestors` but still widely used as fallback.

**Testing**:
```bash
curl -sI https://target.com | grep -i x-frame-options

# Missing = clickjacking possible
# Test by embedding in iframe:
# <iframe src="https://target.com/sensitive-action"></iframe>
```

---

## X-Content-Type-Options

**Purpose**: Prevents MIME-type sniffing, forces browser to respect declared Content-Type.

```
X-Content-Type-Options: nosniff
```

**Testing**:
```bash
curl -sI https://target.com | grep -i x-content-type-options

# Missing = browser may interpret files as different MIME type
# Enables MIME confusion attacks
```

---

## Referrer-Policy

**Purpose**: Controls how much referrer information is included with requests.

```
Referrer-Policy: strict-origin-when-cross-origin
```

| Value | Description |
|-------|-------------|
| `no-referrer` | Never send referrer |
| `no-referrer-when-downgrade` | No referrer on HTTPS->HTTP |
| `origin` | Send only origin (no path) |
| `origin-when-cross-origin` | Full URL same-origin, origin only cross-origin |
| `same-origin` | Referrer only for same-origin |
| `strict-origin` | Origin only, no referrer on downgrade |
| `strict-origin-when-cross-origin` | Recommended default |
| `unsafe-url` | Full URL always (dangerous) |

**Testing**:
```bash
curl -sI https://target.com | grep -i referrer-policy

# Missing or unsafe-url = sensitive URL paths/tokens leaked in referrer
```

---

## Permissions-Policy (formerly Feature-Policy)

**Purpose**: Controls which browser features the page can use.

```
Permissions-Policy: geolocation=(), camera=(), microphone=(), payment=(), usb=(), magnetometer=(), gyroscope=(), accelerometer=()
```

| Feature | Description |
|---------|-------------|
| `geolocation` | GPS access |
| `camera` | Camera access |
| `microphone` | Microphone access |
| `payment` | Payment API |
| `usb` | USB device access |
| `fullscreen` | Fullscreen API |
| `autoplay` | Media autoplay |
| `display-capture` | Screen capture |

**Testing**:
```bash
curl -sI https://target.com | grep -i permissions-policy
```

---

## Cross-Origin Headers

### Cross-Origin-Opener-Policy (COOP)
```
Cross-Origin-Opener-Policy: same-origin
```
Isolates window from cross-origin popups.

### Cross-Origin-Embedder-Policy (COEP)
```
Cross-Origin-Embedder-Policy: require-corp
```
Prevents loading cross-origin resources without explicit permission.

### Cross-Origin-Resource-Policy (CORP)
```
Cross-Origin-Resource-Policy: same-origin
```
Controls who can load this resource.

---

## Access-Control Headers (CORS)

```
Access-Control-Allow-Origin: https://trusted.com
Access-Control-Allow-Methods: GET, POST, PUT
Access-Control-Allow-Headers: Content-Type, Authorization
Access-Control-Allow-Credentials: true
Access-Control-Max-Age: 86400
Access-Control-Expose-Headers: X-Custom-Header
```

**CORS Misconfigurations** (reportable):
```bash
# Test: reflected origin
curl -H "Origin: https://evil.com" -sI https://api.target.com/ | grep -i access-control

# Dangerous responses:
# Access-Control-Allow-Origin: https://evil.com  (reflects attacker origin)
# Access-Control-Allow-Origin: *                  (with credentials = blocked, but still bad)
# Access-Control-Allow-Credentials: true          (with reflected origin = critical)
# Access-Control-Allow-Origin: null               (can be exploited via sandboxed iframe)

# Test null origin
curl -H "Origin: null" -sI https://api.target.com/ | grep -i access-control

# Test subdomain
curl -H "Origin: https://evil.target.com" -sI https://api.target.com/ | grep -i access-control

# Test with credentials
curl -H "Origin: https://evil.com" -sI https://api.target.com/ | grep -i "access-control-allow-credentials"
```

---

## Cache-Control

**Purpose**: Controls caching behavior for sensitive pages.

```
Cache-Control: no-store, no-cache, must-revalidate, private
Pragma: no-cache
```

**Testing**:
```bash
curl -sI https://target.com/account | grep -iE "(cache-control|pragma|expires)"

# Missing on sensitive pages = cached credentials/data
# public = can be cached by CDNs/proxies
# no-store = never cache (most secure)
```

---

## Clear-Site-Data

**Purpose**: Clears browser data on logout.

```
Clear-Site-Data: "cache", "cookies", "storage"
```

---

## Set-Cookie Security Flags

```
Set-Cookie: session=abc123; Secure; HttpOnly; SameSite=Strict; Path=/; Domain=target.com
```

| Flag | Description |
|------|-------------|
| `Secure` | Only send over HTTPS |
| `HttpOnly` | Not accessible via JavaScript |
| `SameSite=Strict` | Never sent cross-site |
| `SameSite=Lax` | Sent on top-level navigations only |
| `SameSite=None` | Sent cross-site (requires Secure) |
| `Path=/` | Cookie scope |
| `Domain=` | Cookie domain scope |
| `Max-Age=N` | Cookie lifetime in seconds |
| `Expires=` | Cookie expiry date |

**Testing**:
```bash
curl -sI https://target.com/login -d "user=test&pass=test" | grep -i set-cookie

# Missing Secure = cookie sent over HTTP
# Missing HttpOnly = XSS can steal cookies
# SameSite=None = CSRF possible
# Missing SameSite = defaults to Lax in modern browsers
```

---

## Deprecated / Removed Headers

| Header | Status | Replacement |
|--------|--------|-------------|
| `X-XSS-Protection` | Deprecated | CSP |
| `X-Webkit-CSP` | Removed | CSP |
| `X-Content-Security-Policy` | Removed | CSP |
| `Feature-Policy` | Renamed | Permissions-Policy |
| `Expect-CT` | Deprecated | Built into browsers |
| `Public-Key-Pins` | Removed | Certificate Transparency |

**Note**: `X-XSS-Protection` should be set to `0` or omitted entirely. Setting `X-XSS-Protection: 1; mode=block` can introduce vulnerabilities in some browsers.

---

## Complete Security Headers Template

```
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'; object-src 'none'
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: geolocation=(), camera=(), microphone=(), payment=()
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Resource-Policy: same-origin
Cache-Control: no-store, no-cache, must-revalidate, private
```

## Nuclei Template for Header Checks

```bash
# Use nuclei's built-in security header templates
nuclei -u https://target.com -t misconfiguration/http-missing-security-headers.yaml
nuclei -u https://target.com -tags misconfig,headers
```

## Pro Tips

- Missing security headers are typically informational/low severity
- CORS misconfiguration with credential reflection is HIGH severity
- CSP bypass leading to XSS is HIGH severity
- Missing HSTS on sites handling sensitive data is MEDIUM
- Always check CSP for `unsafe-inline` and `unsafe-eval`
- `Content-Security-Policy-Report-Only` is NOT enforced
- Test CORS with your own origin, null origin, and subdomain variants
- Cookie flags are as important as headers - always check both
- Many headers only matter on HTML responses, not API endpoints
