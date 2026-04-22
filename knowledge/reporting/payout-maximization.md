---
id: "payout-maximization-impact"
title: "BountyBud Guidance: Proving ACTUAL Impact"
type: "reporting"
category: "strategy"
tags: ["triaging", "impact", "bounties", "false-positives"]
difficulty: "advanced"
updated: "2026-04-18"
---

# BountyBud Guidance: Proving ACTUAL Impact

## The "So What?" Rule
Triagers do not care about theoretical vulnerabilities, missing best practices, or code-level bugs that execute in a vacuum. A finding is only a vulnerability if it has **proven, undeniable business impact**. Before flagging a finding or writing a report, you must answer: *"If an attacker abuses this, what is the exact financial, reputational, or data-loss damage to the company?"*

---

## False Positives & Traps to Avoid

### 1. The "Null Subject" Auth Bypass
*   **The Trap:** You bypass an authentication check (e.g., forcing a server to mint a JWT) but the resulting token has no privileges (e.g., `sub: null`).
*   **Why it's invalid:** If the backend relies on Row Level Security (RLS) or object-level checks (`user_id == auth.uid()`), your "bypassed" token cannot read, write, or modify any sensitive data.
*   **Required Impact:** You must prove the bypassed token can extract sensitive PII, modify other users' data, or escalate privileges to an admin level.

### 2. The Browser-Blocked Payload (e.g., Cookie Scoping ATO)
*   **The Trap:** The server reflects an attacker-controlled header (like `X-Forwarded-Host`) into a `Set-Cookie` domain attribute.
*   **Why it's invalid:** Modern browsers (following RFC 6265) silently reject and drop cookies if the domain attribute does not match the requested host's suffix. The session is never hijacked.
*   **Required Impact:** You must prove the attack works in a modern, standard browser without warnings or security exceptions.

### 3. The "Empty Sandbox" XSS
*   **The Trap:** You achieve Cross-Site Scripting (XSS), but it executes on an isolated, sandboxed subdomain (e.g., a CDN or user-content storage domain).
*   **Why it's invalid:** Sandboxed domains have no authentication cookies, no `localStorage` tokens, and cannot interact with the main application due to the Same-Origin Policy (SOP) and the Public Suffix List (PSL).
*   **Required Impact:** XSS must execute in the context of a sensitive session, allowing token theft, session hijacking, or unauthorized actions on behalf of the victim.

### 4. The "No-Op" Broken Access Control (BAC)
*   **The Trap:** An endpoint (like a `DELETE` request) returns a `200 OK` without authentication.
*   **Why it's invalid:** API Gateways or mock endpoints often return `200 OK` for requests that do absolutely nothing. If the resource isn't actually deleted or modified, there is no BAC.
*   **Required Impact:** You must demonstrate state change. Create a test resource, send the unauthenticated request, and prove the resource was actually deleted/modified.

### 5. Low-Impact Assets (e.g., The Marketing Blog)
*   **The Trap:** Finding a minor flaw (like a CORS misconfiguration or WP-JSON user enumeration) on a non-core marketing blog.
*   **Why it's invalid (or low value):** Triagers prioritize core applications. Stealing a list of public PR authors from a WordPress blog does not expose customer data or threaten infrastructure.
*   **Required Impact:** Target core assets. If attacking a non-core asset, the exploit must lead to Remote Code Execution (RCE) or a pivot into the internal corporate network.

---

## How to Prove Impact
To be bounty-worthy, your report MUST include:
1.  **Clear Victimology:** Who is harmed? (e.g., "Any user who clicks this link," "All enterprise customers.")
2.  **Data Extraction:** Actual, sensitive data dumped from the target (with PII redacted).
3.  **State Modification:** Proof that an attacker can alter the system (e.g., changing a victim's password, deleting a project).
4.  **Financial Damage:** Proof that the flaw bypasses payment gateways, inflates billing metrics, or steals premium features.
