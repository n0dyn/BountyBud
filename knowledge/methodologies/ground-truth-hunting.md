---
id: "ground-truth-hunting"
title: "BountyBud Foundation: Ground Truth Hunting"
type: "methodology"
category: "foundational"
tags: ["ground-truth", "evidence", "real-bugs", "anti-hallucination"]
difficulty: "advanced"
updated: "2026-04-18"
---

# BountyBud Foundation: Ground Truth Hunting

## The Core Mandate: Real Bugs Only
Theoretical vulnerabilities, missing best practices, and code-level flaws that exist only in a vacuum are **rejected**. BountyBud is an engineering tool designed to identify **empirical vulnerabilities**—flaws that result in verifiable data loss, state modification, or financial damage.

---

## The "Evidence Chain" Requirement
Every finding must satisfy the **Evidence Chain**:
1.  **Controlled Input:** A specific, reproducible request sent by the agent.
2.  **Verifiable Output:** A response containing actual sensitive data or indicating a state change.
3.  **Impact Proof:** A step-by-step trace of how this result harms the target infrastructure or user base.

---

## Common "Theoretical Noise" to Ignore

### 1. Theoretical Auth Bypasses
- **The Noise:** Minting a JWT with `sub: null`.
- **The Truth:** If the token cannot access or modify any object due to server-side RLS, there is no bug. **Ignore it.**

### 2. Browser-Side Theory (RFC 6265)
- **The Noise:** Reflecting `X-Forwarded-Host` into a cookie domain.
- **The Truth:** If modern browsers (Chrome/Firefox) reject the cookie based on the Public Suffix List or domain-suffix rules, no hijacking occurs. **Ignore it.**

### 3. Isolated Subdomain XSS
- **The Noise:** XSS on `user-content.target.com`.
- **The Truth:** If the origin is sandboxed and holds no session data or access to the primary app, it is a non-impact finding. **Ignore it.**

### 4. Mock/Gatekeeper 200 OKs
- **The Noise:** Unauth `DELETE` request returning `200 OK`.
- **The Truth:** If the resource is still there and un-modified, the API gateway is just mocking the response. **Ignore it.**

### 5. Third-Party vs. Core Source Code (Scope Traps)
- **The Noise:** Finding a 0-day in a generic 3rd-party library used by the target.
- **The Truth:** Unless the company explicitly lists the repository as a `SOURCE_CODE` asset in their scope, vulnerabilities in 3rd-party vendor code are out-of-scope for the target program.
- **The Exception:** If the target manages the project (e.g., Spotify and Backstage), and the repo is in-scope, local static analysis findings are valid even if not currently exploitable on the live production URL.

### 6. The "Long Tail" Logic (Guidance Update)
- **The Noise:** Hunting for bugs in heavily tested, well-known components (e.g., Backstage TechDocs). This is a high-collision area full of duplicates.
- **The Truth:** Prioritize **Obscure Integrations** and the "Long Tail." Focus on core components that are boring, complex, and less "famous" (e.g., `@backstage/plugin-events-node` or `@backstage/plugin-signals-node`). These are exactly where Critical RCEs sit unreported for years.

---

## Anti-Hallucination Guidelines
When reasoning, the AI team must never say *"An attacker could potentially..."* without following it up with *"We have proven this by..."*
- If the PoC fails to retrieve data: **The finding is dead.**
- If the Strategist finds a browser-side block: **The finding is dead.**
- If the impact is only a 'Best Practice' violation: **The finding is dead.**
