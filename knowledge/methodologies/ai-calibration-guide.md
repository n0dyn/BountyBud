---
id: "ai-calibration-guide"
title: "AI Calibration Guide - Getting Accurate Results from LLM Assistants"
type: "methodology"
category: "reporting"
subcategory: "vulnerability-reports"
tags: ["ai", "llm", "calibration", "false-positive", "prompting", "accuracy", "methodology", "deep-dig"]
difficulty: "intermediate"
platforms: ["linux", "macos", "windows"]
related: ["false-positive-elimination", "smart-hunting-strategy", "attack-synthesis"]
updated: "2026-03-30"
---

## Overview

LLMs are powerful hunting partners but terrible validators. They'll confidently tell you a finding is critical when it's informational, hallucinate CVEs that don't exist, and generate payloads that look right but don't work. This guide teaches you to extract maximum value from AI while filtering out the noise. The goal: AI does the breadth, you do the depth.

## The 8 Ways AI Gets You False Positives

### 1. Hallucinated Vulnerabilities
```
AI SAYS:  "This endpoint is vulnerable to SQL injection because it uses
           string concatenation in the query"
REALITY:  AI inferred this from a parameter name. It never tested. The app
           uses parameterized queries.

FIX: Never accept "is vulnerable" from AI. Only accept "test this with
     [specific payload] and check for [specific indicator]"
```

### 2. Theoretical vs. Exploitable
```
AI SAYS:  "CRITICAL: The application uses HTTP instead of HTTPS on the
           internal health check endpoint"
REALITY:  It's an internal endpoint, not user-facing, behind a VPN.
           No attacker can reach it.

FIX: For every finding, ask: "Can an attacker actually reach and exploit
     this? What is the realistic attack scenario?"
```

### 3. Outdated CVE References
```
AI SAYS:  "This version of Apache is vulnerable to CVE-2021-XXXX"
REALITY:  The CVE was patched in a minor update. The actual running
           version has the fix. Or the CVE doesn't exist at all.

FIX: Verify every CVE number on nvd.nist.gov. Check the exact version
     with --version flags. Confirm the vulnerable code path is reachable.
```

### 4. Payload Generation Without Testing
```
AI SAYS:  "Use this payload: <svg onload=alert(1)>"
REALITY:  The application HTML-encodes all output. The payload is reflected
           as text, not rendered as HTML.

FIX: Every AI-generated payload must be tested in a real browser.
     Check the DOM (Inspect Element), not just the page rendering.
```

### 5. Missing Defense Context
```
AI SAYS:  "This open redirect can be used to steal OAuth tokens"
REALITY:  The OAuth implementation validates redirect_uri against a strict
           allowlist. The open redirect exists but can't reach the OAuth flow.

FIX: Always provide AI with: CSP headers, CORS config, OAuth settings,
     WAF info, and any error messages from failed attempts.
```

### 6. Severity Inflation
```
AI SAYS:  "CRITICAL: Reflected XSS in search parameter"
REALITY:  It's reflected XSS, yes, but it's self-XSS behind authentication
           with HttpOnly cookies and a strict CSP. Impact is minimal.

FIX: Ask AI to rate severity with full context: "Given these defenses
     [list CSP, cookie flags, auth requirements], what is the realistic
     maximum impact of this XSS?"
```

### 7. Scanner Output Parroting
```
AI SAYS:  "Nuclei found 47 vulnerabilities including 12 critical"
REALITY:  35 are informational (version disclosure), 10 are duplicates,
           and 2 of the "critical" findings are false positives from
           generic regex matches.

FIX: Never trust scanner output at face value. Manual verification of
     every finding rated Medium or above. Batch-dismiss informational.
```

### 8. Context Window Confusion
```
AI SAYS:  "Based on the code you showed me earlier, this function is
           vulnerable to..."
REALITY:  The code shown was from a different file/service. The AI
           confused contexts across a long conversation.

FIX: For each analysis, provide the complete relevant context in that
     message. Don't rely on AI remembering correctly from 50 messages ago.
```

## The Verification Protocol

Before you believe ANY finding (from AI or your own testing):

```
┌─────────────────────────────────────────────┐
│           THE 5-GATE VERIFICATION           │
├─────────────────────────────────────────────┤
│                                             │
│  GATE 1: REPRODUCIBLE                       │
│  Can you trigger it yourself, right now,    │
│  in a real browser or tool? (not just        │
│  theoretically)                              │
│  □ YES → continue  □ NO → not a finding     │
│                                             │
│  GATE 2: CROSSES A TRUST BOUNDARY           │
│  Does it let an attacker do something they  │
│  shouldn't be able to do?                    │
│  □ YES → continue  □ NO → not a vuln        │
│                                             │
│  GATE 3: SURVIVES DEFENSES                  │
│  Does the exploit work WITH the deployed    │
│  CSP, WAF, SameSite, HttpOnly, etc.?        │
│  □ YES → continue  □ NO → theoretical only  │
│                                             │
│  GATE 4: MEANINGFUL IMPACT                  │
│  Can you articulate what an attacker gains? │
│  (data theft, account access, RCE, etc.)    │
│  □ YES → continue  □ NO → informational     │
│                                             │
│  GATE 5: NOT A DUPLICATE / OUT OF SCOPE     │
│  Is this in scope? Not already reported?    │
│  □ YES → REPORT IT  □ NO → move on         │
│                                             │
└─────────────────────────────────────────────┘
```

## Validation Checklists by Vulnerability Type

### XSS Validation
```
□ Payload executes in browser (not just reflected in source)
□ Tested with actual JavaScript execution (alert/fetch), not just HTML injection
□ Works without user interaction (or interaction is realistic, like clicking a link)
□ HttpOnly cookies are NOT set (or you have alternative impact like keylogging)
□ CSP does not block inline scripts (or you have a CSP bypass)
□ Not self-XSS (attackable from a different user/session)
□ Tested in latest Chrome/Firefox (not just legacy browsers)
```

### SSRF Validation
```
□ You received a callback on YOUR server (Interactsh, Burp Collaborator)
□ The request came FROM the target server (check source IP)
□ You can reach internal services (not just DNS resolution)
□ Cloud metadata is actually readable (not just a connection attempt)
□ The response is returned to you OR you have blind confirmation
□ It's not just an open redirect being followed client-side
```

### SQLi Validation
```
□ Different responses for TRUE vs FALSE conditions (boolean blind)
□ OR measurable time difference (time blind)
□ OR actual data extracted (union/error based)
□ It's not just an error message containing your input
□ The error is from the DATABASE, not the application layer
□ You can extract data beyond what you already have access to
```

### RCE Validation
```
□ Command output is returned in the response
□ OR you received a callback (DNS/HTTP) from command execution
□ OR you can demonstrate file creation/modification
□ The command runs as the SERVER process, not in your browser
□ It's not just code interpretation (e.g., template rendering without system access)
□ You can demonstrate impact beyond just 'id' or 'whoami'
```

### IDOR Validation
```
□ You accessed data belonging to a DIFFERENT user
□ You used a DIFFERENT authenticated session (not the data owner's)
□ The data is actually sensitive (not public information)
□ It's not designed behavior (e.g., public profiles)
□ Tested with at least 2 different accounts
```

## Prompting AI for Accurate Analysis

### The Context-First Template
```
ALWAYS provide this context before asking AI to analyze:

TARGET: [exact URL/endpoint]
METHOD: [GET/POST/etc]
TECH STACK: [server, framework, language — from headers/fingerprinting]
DEFENSES: [WAF, CSP header, cookie flags, CORS policy]
AUTH: [how you're authenticated, session type]
REQUEST: [full HTTP request]
RESPONSE: [full HTTP response including headers]
OBSERVATION: [what you noticed that seems interesting]

QUESTION: [specific question — not "is this vulnerable?"]
```

### Good vs Bad AI Questions
```
BAD:  "Is this website vulnerable?"
GOOD: "I sent <script>alert(1)</script> in the search parameter. It appears
       in the page source inside a <div>, but the page doesn't show an alert.
       Here's the response [paste]. Why isn't it executing and what should I
       try next?"

BAD:  "Find bugs in this code"
GOOD: "This Express.js route handler takes req.body and passes it to
       MongoDB. Is it vulnerable to NoSQL operator injection? What specific
       request body would confirm it?"

BAD:  "What's the severity of this finding?"
GOOD: "I found reflected XSS in the search parameter. The app has CSP:
       script-src 'self' https://cdn.example.com; cookies are HttpOnly and
       SameSite=Lax. What's the realistic maximum impact given these
       defenses?"
```

### Force AI to Show Its Work
```
After AI claims a finding, always follow up with:

"Walk me through exactly:
1. What request would an attacker send?
2. What response would confirm exploitation?
3. What defenses need to be absent for this to work?
4. What's the concrete impact to a real user?
5. How confident are you (1-10) and what would lower your confidence?"
```

## The "Prove It" Methodology

For every finding, write a single sentence in this format before reporting:

```
"An unauthenticated attacker can [ACTION] by [METHOD] which results in
[IMPACT] to [AFFECTED USERS] because [ROOT CAUSE]."

EXAMPLES:
GOOD: "An unauthenticated attacker can steal any user's session token by
       sending a crafted URL that triggers reflected XSS in the search
       parameter, which results in full account takeover of any user who
       clicks the link, because user input is inserted into the DOM via
       innerHTML without sanitization."

BAD:  "The search parameter reflects user input which could potentially be
       used for XSS attacks."
       (Who can do it? What's the impact? Is it confirmed or theoretical?)
```

If you can't complete that sentence with specifics, the finding isn't ready to report.

## Deep Dig Prompts

```
I think I found [vulnerability type] at [endpoint]. Here's my evidence:
[paste full request, response, and observations]

1. Apply the 5-Gate Verification. Does this pass all 5 gates?
2. What specific defenses could prevent exploitation that I might be missing?
3. What additional test would definitively confirm or deny this finding?
4. If it's real, write the one-sentence "Prove It" statement.
5. Rate confidence 1-10 and explain what uncertainties remain.
6. If confidence is below 7, what test would raise it above 8?
```

```
I'm reviewing scanner output that flagged these [N] findings:
[paste scanner results]

1. Which findings are almost certainly false positives and why?
2. Which findings need manual verification?
3. For each finding needing verification, what single test confirms it?
4. Rank the remaining findings by likelihood of being real × impact.
5. How long should I spend verifying each one?
```
