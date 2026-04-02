---
id: "attack-synthesis"
title: "Attack Synthesis - Crafting Novel Exploit Chains"
type: "methodology"
category: "web-application"
subcategory: "business-logic"
tags: ["methodology", "attack-chain", "exploit-chain", "novel", "creative", "synthesis", "deep-dig"]
difficulty: "expert"
platforms: ["linux", "macos", "windows"]
related: ["dig-deep-asset-classes", "business-logic-flaws", "account-takeover"]
updated: "2026-03-30"
---

## Overview

Finding known vulnerabilities is table stakes. The highest payouts come from novel attack chains — combining low-severity findings into critical exploits that nobody has seen before. This methodology teaches you to think like an exploit developer, not a scanner operator. Use this framework with AI assistance to systematically discover attack chains unique to your target.

## The Chain Thinking Framework

Every high-payout bug is a chain. Individual links are often low severity. The chain is critical.

```
LOW: Open redirect on target.com
LOW: CORS trusts *.target.com
LOW: Subdomain with XSS on blog.target.com
= CRITICAL: Open redirect → subdomain XSS → CORS bypass → read admin API → account takeover
```

### Chain Categories (by payout tier)

```
$50-$500:    Single finding, limited impact
$500-$2k:    Two-step chain, clear impact
$2k-$10k:    Multi-step chain, account takeover or data breach
$10k-$50k:   Novel technique, critical infrastructure impact
$50k-$200k:  Zero-click RCE, authentication bypass at scale, novel class
```

## Step 1: Map the Attack Surface Deeply

Don't just find endpoints. Understand the relationships.

```
For each feature:
- What data flows between components?
- What assumptions does the developer make?
- Where does trust transition happen (client→server, service→service)?
- What happens at the boundaries between systems?
- What state changes occur and in what order?
```

### Deep Dig Prompt — Surface Mapping
```
Given this application [describe architecture, features, tech stack]:
1. Map every trust boundary (user→app, app→database, app→API, app→cache, app→queue).
2. For each boundary, list what is validated vs assumed.
3. Identify all state machines (auth flow, checkout, approval workflows).
4. Find every point where user input influences system behavior indirectly.
5. List all third-party integrations and their trust relationships.
```

## Step 2: Identify Primitive Building Blocks

Catalog every "primitive" you discover — even minor ones:

```
PRIMITIVES TO COLLECT:
- URL control (open redirect, parameter injection)
- Header injection (CRLF, Host, X-Forwarded-*)
- HTML injection (even without JS execution)
- CSS injection
- CORS misconfiguration (even limited)
- Cookie setting (subdomain, CRLF)
- DOM control (DOM clobbering, prototype pollution)
- Timing differences (race conditions, oracle)
- Error message information leakage
- Parameter reflection
- Cache behavior (unkeyed inputs, path confusion)
- File write (any location, any content)
- SSRF (even blind, even limited)
- Token predictability (even slight)
```

### Deep Dig Prompt — Primitive Discovery
```
I've discovered these primitives on [target]:
[list each finding with its constraints]

For each primitive:
1. What additional capability would make it critical?
2. Which other primitives could it chain with?
3. What is the "missing link" that would complete an exploit chain?
4. Are there any well-known chains (James Kettle, Orange Tsai, etc.) that use similar primitives?
```

## Step 3: Chain Synthesis — The Combination Matrix

Cross every primitive against every target for chain opportunities:

```
                    TARGETS:
                    Auth Token  User Data  Admin Access  RCE  Cache
PRIMITIVES:
Open Redirect       OAuth ATO   -          -             -    CSP bypass
CRLF Injection      Cookie set  -          -             -    Cache poison
SSRF (blind)        -           -          Internal API  -    -
XSS (self)          -           -          -             -    -
Race Condition       -           -          Privesc       -    -
Param Pollution     -           IDOR       Mass assign   -    -

CHAIN: Open Redirect + CRLF + Cache Poison = Stored XSS for all users
CHAIN: SSRF + Cloud metadata + IAM role = Full cloud account compromise
CHAIN: Race condition + Business logic = Infinite credit/money
```

### Deep Dig Prompt — Chain Synthesis
```
I have these findings on [target]:
Finding 1: [describe with constraints]
Finding 2: [describe with constraints]
Finding 3: [describe with constraints]

1. Generate ALL possible combinations of these findings.
2. For each combination, describe the resulting attack chain and its impact.
3. Rank chains by severity (CVSS) and novelty.
4. For the top 3 chains, provide exact reproduction steps.
5. Identify what "missing primitive" would unlock the most powerful chain.
6. Suggest where to hunt for that missing primitive.
```

## Step 4: Analogy-Based Discovery

Study published research and map techniques to your target:

```
PATTERN: "X worked on Y, does a variant work on Z?"

Examples:
- James Kettle's request smuggling on Apache → does it work on your target's Nginx?
- Orange Tsai's path confusion on IIS → does similar confusion exist in your CDN?
- Gareth Heyes' mXSS in DOMPurify → does the same namespace confusion affect your sanitizer?
- Alex Birsan's dependency confusion on npm → does your target use internal packages?
```

### Deep Dig Prompt — Analogy Search
```
This target uses [technology stack].
1. List the top 10 published security research papers/talks from 2024-2026 relevant to this stack.
2. For each, describe the core technique and how it could apply to this target.
3. Identify any published CVEs for the exact versions in use.
4. Suggest novel combinations of published techniques that haven't been tried together.
```

## Step 5: Assumption Violation

The most creative bugs come from violating developer assumptions.

```
ASSUMPTIONS TO VIOLATE:
- "This parameter is always a string" → send object, array, null, number
- "This request only comes from our frontend" → send from CLI, different origin
- "Users can't access this internal API" → SSRF, path confusion
- "This runs synchronously" → race condition
- "This value can't be negative" → send -1
- "Unicode is handled correctly" → send right-to-left override, null bytes
- "The cache key matches the request" → find unkeyed inputs
- "Our CDN normalizes paths" → path confusion
- "HTTP/2 headers can't contain CRLF" → some proxies downgrade incorrectly
- "File uploads are validated" → polyglot files, race between upload and check
- "AI follows instructions" → prompt injection
```

### Deep Dig Prompt — Assumption Breaking
```
Given this feature [describe in detail]:
1. List every assumption the developer likely made about inputs, state, timing, and trust.
2. For each assumption, suggest a specific test that violates it.
3. Predict what would happen if the assumption is wrong.
4. Which violations could chain with other findings for critical impact?
```

## Step 6: Report Crafting for Maximum Impact

A novel chain needs a novel report to get the payout it deserves.

```
REPORT STRUCTURE FOR CHAINS:
1. Executive summary — one sentence describing the full impact
2. Attack narrative — tell the story, step by step, from attacker's perspective
3. Video PoC — show the full chain executing
4. Impact analysis — what data/access/actions are compromised
5. Affected users — how many, which roles
6. Remediation — fix each link in the chain
7. Novelty statement — explain why this is a new technique
```

## Meta-Prompt: The Universal Attack Synthesizer

```
You are an elite bug bounty hunter analyzing [target].

CONTEXT:
- Technology: [stack]
- Scope: [domains, APIs, apps]
- Defenses: [WAF, CSP, auth mechanisms]
- Discovered primitives: [list everything found so far]

TASK:
1. What is the highest-impact attack chain possible with the current primitives?
2. What is the most NOVEL attack possible (something never published before)?
3. What single additional primitive would unlock a critical chain?
4. Where should I look next to find that primitive?
5. Generate 3 attack chains ranked by: impact × novelty × feasibility.
6. For the #1 chain, write the exact step-by-step reproduction.
```

## Reference: Famous Novel Chains

| Researcher | Chain | Impact |
|-----------|-------|--------|
| James Kettle | Request smuggling → cache poisoning → stored XSS | $200k in 2 weeks |
| Orange Tsai | Path confusion + cache deception | Multiple $10k+ |
| Alex Birsan | Dependency confusion (npm/pip/gems) | $130k from one technique |
| Gareth Heyes | mXSS via MathML namespace | Bypasses every sanitizer |
| Frans Rosén | Subdomain takeover → OAuth token theft | Account takeover at scale |
| Sam Curry | Chained IDOR + info disclosure → full admin | $50k from vehicle companies |
| Corben Leo | DNS rebinding → SSRF → RCE | Internal infrastructure |
