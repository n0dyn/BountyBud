---
id: "mfa-bypass"
title: "MFA Bypass Techniques (2026 Edition)"
type: "technique"
category: "web-application"
subcategory: "authentication"
tags: ["mfa", "2fa", "totp", "sms", "push-notification", "fido2", "passkey", "auth-bypass", "deep-dig"]
platforms: ["linux", "macos", "windows"]
related: ["account-takeover", "oauth-jwt-saml-bypasses", "auth-bypass-payloads"]
difficulty: "advanced"
updated: "2026-04-14"
---

# MFA Bypass Techniques (2026 Edition)

## Why MFA Bypass Pays Big
MFA is the last wall before full account takeover. Bypassing it on a major platform is consistently $10k–$50k+. Programs assume MFA is bulletproof — prove them wrong.

## Attack Surface Map

### 1. Response Manipulation
The most common bypass. The server checks the code but the client decides what to do with the response.

```
# Intercept the MFA verification response
# Change {"success": false} → {"success": true}
# Change status code 403 → 200
# Remove error fields from JSON response

# Burp: Match and Replace rule
# Match: "mfa_verified":false
# Replace: "mfa_verified":true
```

### 2. Status Code Bypass
```
# Some apps check MFA status client-side
# Step 1: Submit wrong code, capture 403 response
# Step 2: Change response to 200, check if session is granted
# Step 3: Try accessing authenticated endpoints directly after wrong code
```

### 3. Direct Endpoint Access (Skip MFA Step)
```
# After username+password, you land on /mfa-verify
# Try accessing post-auth pages directly:
GET /dashboard HTTP/1.1
Cookie: session=<pre-mfa-session-token>

# Try POST to the final auth endpoint without MFA step:
POST /api/auth/complete
{"session_token": "<pre-mfa-token>", "skip_mfa": true}
```

### 4. Backup Code Attacks
```
# Backup codes are often:
# - 8 digit numeric (bruteforceable: 10^8 = 100M combinations)
# - Not rate limited separately from TOTP
# - Reusable (check if same code works twice)
# - Predictable (sequential or weak PRNG)

# Test: Submit backup code endpoint with common patterns
000000, 111111, 123456, 999999

# Test: Brute force if no rate limit
# ffuf with numeric wordlist against /api/mfa/backup-verify
ffuf -u https://target.com/api/mfa/verify-backup \
  -X POST -H "Content-Type: application/json" \
  -H "Cookie: session=TOKEN" \
  -d '{"code":"FUZZ"}' \
  -w /usr/share/seclists/Fuzzing/6-digits-000000-999999.txt \
  -fc 401,403
```

### 5. TOTP Window Manipulation
```
# TOTP codes are valid for 30-second windows
# Most implementations accept ±1 window (90 seconds total)
# Some accept ±2 or more windows

# Test: Use a code from 5 minutes ago
# Test: Use a code from 5 minutes in the future
# Test: Reuse the same valid code multiple times

# Race condition: Submit the same valid code in parallel
# to create multiple authenticated sessions
```

### 6. Push Notification Fatigue (MFA Bombing)
```
# For push-based MFA (Duo, Microsoft Authenticator, Okta Verify):
# - Repeatedly trigger push notifications
# - User gets fatigued, accidentally approves
# - Best during: late night, early morning, meeting times

# Automated: Script login attempts every 30 seconds
# The key is VOLUME + TIMING, not speed

# Detection: Check if there's a rate limit on push requests
# Some apps limit to 3 pushes per 5 minutes — test the limit
```

### 7. SIM Swap / SS7 for SMS-Based MFA
```
# If MFA is SMS-only:
# - SIM swap attack (social engineering carrier)
# - SS7 interception (requires network access)
# - Voicemail interception (some apps offer voice call option)

# Cheaper: Check if SMS code is in API response
# Some apps return the code in the verify request response
# or in a different API endpoint

# Test: Intercept the "send SMS" request, check response body
POST /api/mfa/send-sms
Response: {"status": "sent", "code": "123456"}  ← vulnerability!
```

### 8. OAuth/SSO MFA Bypass
```
# If the app supports OAuth login (Google, GitHub, etc.):
# - Login via OAuth may skip the app's own MFA entirely
# - The app trusts the OAuth provider's auth, doesn't add its own MFA

# Test: Enable MFA on the target app
# Then: Login via OAuth/SSO — check if MFA is prompted
# If not — you can bypass MFA by using the SSO path

# Also: Check if linking a new OAuth provider requires MFA
# If not: attacker with password can link their Google, then use SSO
```

### 9. Password Reset MFA Bypass
```
# Password reset flow often skips MFA:
# 1. Request password reset
# 2. Click reset link in email
# 3. Set new password → auto-logged in WITHOUT MFA

# Also check:
# - Does "forgot password" disable MFA?
# - Can you change MFA settings from password reset session?
# - Is the reset token session cookie valid for full access?
```

### 10. API Endpoint Without MFA
```
# Mobile apps and APIs often skip MFA:
# - Try the mobile API endpoint with just username+password
# - Check /api/v1/login vs /api/v2/login (older versions skip MFA)
# - GraphQL mutations may not enforce MFA

# Headers that might skip MFA:
X-Requested-With: com.target.mobile
User-Agent: TargetApp/3.0 (iPhone; iOS 17.0)
X-App-Version: 2.0.0
```

### 11. Session Token Persistence
```
# After successful MFA, check token lifetime:
# - Does the session survive password change?
# - Does the session survive MFA re-enrollment?
# - Can you use an old pre-MFA token after MFA is disabled+re-enabled?

# Cookie manipulation:
# - Remove "mfa_verified" cookie flag
# - Change "auth_level" from "partial" to "full"
# - Copy session token to another browser
```

### 12. FIDO2/WebAuthn Bypass
```
# Newer but not invulnerable:
# - Check if fallback to TOTP/SMS is available (downgrade attack)
# - Test if WebAuthn ceremony can be replayed
# - Check if authenticator attestation is actually verified
# - Test origin validation (subdomain confusion)
# - Check if credentialId is bound to user (swap credential between accounts)
```

## Deep Dig Prompts
```
Given this MFA implementation [describe the flow]:
1. Map every state transition from password auth to full session
2. Identify which steps can be skipped by direct endpoint access
3. Test if the pre-MFA session token grants any API access
4. Check for response manipulation, backup code brute force, and SSO bypass
5. Look for race conditions in MFA verification (parallel code submission)
```

## Tools
- Burp Suite (response manipulation, race conditions via Turbo Intruder)
- ffuf (backup code brute force)
- mitmproxy (push notification interception)
- Custom Python scripts for TOTP window testing

## Proven 2026 Wins
- Response manipulation on fintech app ($15k)
- OAuth SSO path bypassing app MFA ($8k)
- Password reset auto-login skipping MFA ($12k)
- Backup code brute force with no rate limit ($5k)
- API v1 endpoint with no MFA enforcement ($10k)
