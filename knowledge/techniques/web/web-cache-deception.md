---
id: "web-cache-deception"
title: "Advanced Web Cache Deception (WCD)"
type: "technique"
category: "web-application"
subcategory: "infrastructure"
tags: ["wcd", "caching", "cdn"]
difficulty: "advanced"
updated: "2026-04-16"
---

## Overview
Web Cache Deception (WCD) occurs when an attacker tricks a user into requesting a sensitive endpoint in a way that causes the CDN/Proxy to cache the response, making it accessible to the attacker.

## Advanced Attack Vectors

### 1. Wildcard Path Confusion
Exploiting "Cache Everything" rules on specific directories by using path traversal normalization differentials.
**Payload:** `https://target.com/static/..%2fapi/user/settings`
- **CDN:** Sees `/static/` and decides to cache it. Does not normalize `..%2f`.
- **Origin:** Normalizes `..%2f` and routes the request to `/api/user/settings`.
- **Result:** Sensitive settings cached at the `/static/` route.

### 2. Delimiter Fuzzing
Origins and CDNs disagree on what character ends a URL path.
- **Fuzzing Chars:** `;`, `%00`, `%09`, `%20`, `%23`, `%2e`
- **Example (Spring Boot Matrix Variables):** `https://target.com/api/profile;/.css`
  - Spring Boot stops at `;` and returns `/api/profile`.
  - CDN caches it because it ends in `.css`.

### 3. WCD via Request Smuggling
If you can perform HTTP Request Smuggling, you do not need the victim to click a link.
1. Attacker smuggles `GET /api/profile` and leaves it in the queue.
2. Victim browser naturally requests `GET /images/logo.png`.
3. Origin responds to the smuggled `/api/profile`.
4. CDN caches the profile under `/images/logo.png`.
5. Attacker retrieves `/images/logo.png`.

## Detection Strategy
Always test with a **Cache Buster** (e.g., `?cb=123123`) to prevent poisoning the cache for real users during validation. Look for `X-Cache: HIT` or `Age: [number]` headers.