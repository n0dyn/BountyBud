---
id: "business-logic-hunting"
title: "Business Logic Hunting - Finding Bugs Tools Can't"
type: "methodology"
category: "web-application"
subcategory: "business-logic"
tags: ["business-logic", "idor", "auth-bypass", "race-condition", "manual-testing", "proxy", "mitmproxy", "methodology", "deep-dig"]
difficulty: "advanced"
platforms: ["linux", "macos", "windows"]
related: ["smart-hunting-strategy", "vulnerability-priority-matrix", "auth-bypass-payloads", "race-condition-payloads", "smart-tool-execution"]
updated: "2026-04-04"
---

## Overview

Automated scanners find 5% of bounties. The other 95% come from understanding how an application works and breaking its assumptions. Business logic bugs are the highest-paying, least-competed vulnerability class because they require human reasoning — no template can detect them. This guide teaches an AI assistant how to hunt like a manual tester using mitmproxy as the interception layer.

## Step 0: Stop Scanning, Start Using

Before running a single tool, **use the application as a real user for 20 minutes**:

```
1. Create an account (free tier is fine)
2. Complete the core workflow:
   - E-commerce? Browse → add to cart → checkout
   - SaaS? Create project → invite user → share data
   - Social? Create post → comment → like → follow
   - API? Read docs → get API key → make test requests
3. Note every request in mitmproxy — what IDs appear, what changes state
4. Ask: "What would be bad if someone else could do this as me?"
```

This gives you something no scanner has: **context**.

## Mapping Trust Boundaries

Every application has boundaries where trust changes. Bugs live at these boundaries.

### Identify the Boundaries

```
USER ROLES
  └── Unauthenticated → Authenticated → Premium → Admin → Super Admin
  Ask: Can I access role X's features with role Y's session?

OWNERSHIP
  └── My data → Other user's data → Other org's data
  Ask: Can I reference another user's object IDs?

STATE TRANSITIONS
  └── Draft → Submitted → Approved → Published
  Ask: Can I skip steps? Revert to a previous state? Modify after approval?

PAYMENT BOUNDARIES
  └── Free → Trial → Paid → Enterprise
  Ask: Can I access paid features without paying? Modify pricing?

API vs WEB
  └── Web UI enforces rules → Does the API enforce the same rules?
  Ask: If the UI prevents an action, does the API also prevent it?
```

### Map Boundaries with Proxy

Using mitmproxy to systematically map:

```
1. Perform action as ADMIN — capture the request
2. Replay the SAME request using a REGULAR USER session
3. Does it work? → IDOR / privilege escalation
4. Replay with NO session → unauthorized access

For every endpoint captured in mitmproxy:
  - What HTTP method does it use?
  - What IDs/references are in the URL, body, or headers?
  - What role/permission is needed?
  - What happens if you change the ID?
  - What happens if you remove the auth header?
```

## The 7 Business Logic Bug Classes

### 1. IDOR / Broken Object-Level Authorization (BOLA)

The #1 most common bounty-paying bug class.

```
WHAT: User A can access/modify User B's resources by changing an ID.

HOW TO FIND:
1. In mitmproxy, filter for requests containing numeric IDs or UUIDs
2. Create two accounts (Account A and Account B)
3. As Account A, perform actions — note all IDs in requests
4. Replay those requests using Account B's session cookie
5. Check: Can B see/modify A's data?

WHAT TO TEST:
  GET /api/users/123/profile          → Change 123 to 124
  GET /api/orders/abc-uuid/receipt     → Use another user's order UUID
  PUT /api/settings/123               → Modify another user's settings
  DELETE /api/posts/456               → Delete another user's post
  GET /api/invoices/2024-001.pdf      → Sequential invoice IDs

COMMON PATTERNS:
  - Numeric sequential IDs (easiest to exploit)
  - UUIDs leaked in other responses (check public profiles, shared links)
  - Encoded IDs (base64 decode, check if sequential underneath)
  - Composite keys (/org/5/user/3 — change org ID)

ESCALATION:
  - Read-only IDOR → Medium ($500-2k)
  - Write IDOR (modify data) → High ($2k-10k)
  - Delete IDOR → High ($2k-10k)
  - IDOR + PII exposure → Critical ($5k-20k)
```

### 2. Broken Function-Level Authorization (BFLA)

```
WHAT: Regular user can access admin-only endpoints.

HOW TO FIND:
1. Map all endpoints visible to admin (or find them via JS analysis, API docs)
2. Try accessing those endpoints with a regular user session
3. Also try: changing HTTP method (GET → POST → PUT → DELETE)

WHAT TO TEST:
  POST /api/admin/users                → Create user as non-admin
  PUT /api/admin/settings              → Modify app settings
  DELETE /api/admin/users/123          → Delete user as non-admin
  GET /api/admin/reports               → View admin reports
  POST /api/internal/debug             → Internal endpoints exposed

DISCOVERY TIPS:
  - Check JavaScript bundles for admin route definitions
  - Look for /admin/, /internal/, /management/ paths
  - API docs (Swagger/OpenAPI) often list all endpoints including admin
  - GraphQL introspection reveals all mutations including privileged ones
```

### 3. Workflow/State Bypass

```
WHAT: Skipping steps in a multi-step process or reverting state transitions.

HOW TO FIND:
1. Complete a multi-step workflow normally while capturing all requests
2. Replay the FINAL step without completing earlier steps
3. Try going backwards (approved → draft)
4. Try repeating steps that should be one-time

EXAMPLES:
  - Skip email verification → access account immediately
  - Skip payment step → get premium features
  - Submit form without completing CAPTCHA
  - Revert "cancelled" order back to "active"
  - Skip KYC/identity verification
  - Complete checkout without adding payment method

PROXY TECHNIQUE:
  1. Start the workflow, capture step 1 request
  2. Note what tokens/state params are passed between steps
  3. Jump directly to step 3 — does it check that step 2 happened?
  4. Modify state params to skip validation
```

### 4. Price/Quantity Manipulation

```
WHAT: Modifying prices, quantities, discounts, or financial values.

HOW TO FIND:
1. Add item to cart, proceed to checkout
2. Intercept the checkout/payment request in mitmproxy
3. Modify: price, quantity, discount code, currency, tax

WHAT TO TEST:
  {"quantity": -1}                    → Negative quantity (credit?)
  {"price": 0.01}                    → Modified price
  {"discount": 100}                  → 100% discount
  {"currency": "IDR"}                → Cheapest currency
  {"coupon": "SAVE50", "coupon": "SAVE50"}  → Apply coupon twice (HPP)
  Remove tax/shipping fields entirely → Free shipping?

ALSO CHECK:
  - Modify subscription tier in upgrade request
  - Change billing cycle (monthly → yearly price at monthly rate)
  - Transfer credits/points with modified amounts
  - Referral bonus — claim multiple times
```

### 5. Race Conditions

```
WHAT: Exploiting time-of-check-to-time-of-use gaps.

HOW TO FIND:
1. Identify operations that should be atomic:
   - Coupon redemption, money transfer, vote/like, invitation claim
2. Send 20-50 identical requests simultaneously
3. Check if the operation executed more times than allowed

HIGH-VALUE TARGETS:
  - Redeem single-use coupon → send 30 concurrent requests
  - Transfer $100 from $100 balance → send 20 concurrent requests
  - Like/vote → send 100 concurrent requests
  - Claim referral bonus → send 30 concurrent requests
  - Follow/unfollow rapidly → inconsistent follower counts

USE TURBO INTRUDER or Python threading (see race-condition-payloads doc)
```

### 6. Mass Assignment / Parameter Pollution

```
WHAT: Adding extra parameters that modify server-side fields.

HOW TO FIND:
1. Capture a normal POST/PUT request (e.g., profile update)
2. Add extra fields the API might accept:
   {"name": "test", "role": "admin"}
   {"name": "test", "is_admin": true}
   {"name": "test", "plan": "enterprise"}
   {"name": "test", "verified": true}
   {"name": "test", "balance": 99999}

DISCOVERY:
  - Check API docs for all fields on the model
  - GraphQL introspection shows all fields
  - Try common field names: role, admin, is_admin, type, plan, 
    tier, verified, active, approved, permissions, group, org_id

ALSO TEST HTTP Parameter Pollution:
  ?user_id=attacker&user_id=victim  → Which one wins?
  POST body vs URL param conflict
```

### 7. Authentication/Session Logic

```
WHAT: Flaws in how the app handles identity and sessions.

PASSWORD RESET:
  - Reset email uses Host header for link → inject your domain
  - Token in response body → steal directly
  - Token is predictable (timestamp-based, sequential)
  - Token doesn't expire after use
  - IDOR in reset: change user_id param to victim's ID

OAUTH:
  - redirect_uri allows open redirect → steal token
  - State parameter missing → CSRF on OAuth flow
  - Token leakage via Referer header after redirect

SESSION:
  - Session doesn't rotate after login → session fixation
  - Session doesn't invalidate after password change
  - Concurrent session limit bypass
  - JWT claim manipulation (see auth-bypass-payloads)

MFA:
  - Response manipulation (change 403 → 200)
  - Direct access to authenticated endpoint (skip MFA page)
  - Brute-force backup codes (rate limiting?)
  - MFA not enforced on API, only web UI
```

## The Proxy-Driven Hunting Loop

```
FOR EACH FEATURE:
  1. USE IT NORMALLY — capture all requests in mitmproxy
  2. IDENTIFY — what IDs, tokens, state params appear?
  3. QUESTION — what assumptions is the server making?
     - "It assumes the user owns this object ID"
     - "It assumes step 1 was completed before step 3"
     - "It assumes the price hasn't been modified"
     - "It assumes only one request will arrive"
  4. BREAK THE ASSUMPTION — replay/modify the request
  5. VERIFY — did the server actually check?
  6. ESCALATE — what's the maximum impact?
  7. DOCUMENT — screenshot the request/response pair
```

## Target Feature Prioritization

Spend time on features most likely to have logic bugs:

```
HIGHEST PRIORITY (test these first):
  □ User registration and profile management
  □ Password reset / account recovery
  □ Payment / checkout / subscription management
  □ File upload / download / sharing
  □ API key / token management
  □ Team/org management (invite, remove, role change)
  □ Data export / import functionality
  □ Search with filters (SQLi, but also access control)

MEDIUM PRIORITY:
  □ Notification/email preferences (IDOR in notification endpoints)
  □ Public/private toggle on content
  □ Reporting / flagging system
  □ Webhook / integration management
  □ Settings pages (both user and org level)

LOWER PRIORITY (but still worth checking):
  □ Commenting / messaging
  □ Following / connections
  □ Content creation (posts, projects, etc.)
```

## Deep Dig Prompts

```
I'm testing {application_name} which is a {app_type} (e.g., SaaS, e-commerce).
I have mitmproxy capturing traffic and I've mapped these features:
{feature_list}

1. Which 3 features are most likely to have business logic bugs?
2. For each, what specific requests should I intercept and modify?
3. What parameter manipulation should I try?
4. What trust boundary violations should I test?
5. Design a 10-step manual testing plan focused on IDOR and auth bypass.
```

```
I intercepted this request in mitmproxy:
{http_request}

And got this response:
{http_response}

1. What assumptions is the server making about this request?
2. What parameters should I modify to test for IDOR?
3. Could this endpoint have a race condition?
4. What role/permission bypasses should I try?
5. Is there a mass assignment opportunity in the request body?
```
