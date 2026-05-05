---
id: "idor-10-patterns-2026"
title: "IDOR Hunting: 10 Advanced Patterns, UUID Bypass & Systematic Testing 2026"
type: "technique"
category: "web-application"
subcategory: "idor"
tags: ["idor", "bola", "authorization", "uuid", "graphql", "webhooks", "batch", "export", "state-changing"]
difficulty: "advanced"
platforms: ["linux", "macos", "windows"]
related: ["idor-bola", "bfla-authorization-testing", "business-logic-flaws"]
updated: "2026-05-04"
---

## Overview
IDOR/BOLA is the most exploited class since 2021. Beyond simple "change ID in URL", 10 distinct patterns exist in modern apps (REST, GraphQL, webhooks, exports). UUIDs add obscurity but not security. Systematic 2-account testing + manual review beats scanners. High payouts for write-IDORs and bulk access.

## The 10 Patterns
1. **Direct ID** (URL/path param): `/api/user/123`
2. **Body Parameters**: POST with `user_id` in JSON/form.
3. **File/Path References**: `/download?file=../user/456/report.pdf`
4. **GraphQL Queries**: `user(id: "456") { email }` or nested.
5. **Indirect References**: Slug, username, email as ID (predictable or enumerable).
6. **Batch/Bulk Endpoints**: `/api/batch?ids=1,2,3` or array in body.
7. **State-Changing Operations**: Update/delete other user's resources (write IDOR > read).
8. **Webhooks & Callbacks**: Attacker-registered webhook receives other users' events.
9. **API Versioning**: `/v1/users/123` vs `/v2/` with different auth.
10. **Export/Report Functions**: `/export?user_id=456` leaks bulk data.

## UUID Bypass Techniques
- UUIDs leak in API responses, emails, WebSockets, HTML source, logs.
- Predictable UUIDs (time-based, sequential).
- IDOR via related objects: change `order_id` to access `user_id` data.
- Enumeration: Brute-force short UUID prefixes or use timing.

## Systematic Testing Methodology (2-Account)
**Phase 1: Recon**
- Map all endpoints (Burp, Katana, Param Miner).
- Create User A (attacker), User B (victim).
- Document all resource IDs (int, UUID, slug).

**Phase 2: Matrix**
For every ID-accepting endpoint:
- Own resource → 200
- Other user's → 200? = IDOR
- Non-existent → 404 (good) or 200 (enum)
- No auth → 401/200?
- Low-priv → admin resource?

**Phase 3: Advanced**
- Use Autorize Burp extension for automated.
- ffuf for ID fuzzing.
- GraphQL: Introspection + batch queries for rate limit bypass + IDOR.
- Webhooks: Register attacker URL, trigger victim action.

**Phase 4: Write vs Read**
Prioritize state changes: cancel other orders, promote users, delete data.

## Deep Dig Prompts
```
From recon data (endpoints, roles, sample IDs/UUIDs), generate:
1. Complete testing matrix script (Python + requests, 2 accounts).
2. Specific payloads for all 10 patterns (GraphQL example, webhook, export).
3. UUID bypass enumeration strategy.
4. Impact chains: "Read all user PII → ATO via password reset → full org takeover".
5. Report template with severity (Critical for write/bulk).
6. Prevention: ORM query scoping by authenticated user ID.
Prioritize bulk and state-changing for max payout.
```

## Remediation
- ORM-level: Always scope queries by `current_user.id`.
- Never trust client-supplied IDs for ownership.
- Use indirect refs + server-side mapping.
- Rate limit + monitor anomalous access patterns.
- UUIDs + ACLs, not UUIDs alone.

## References
- SecureCodeReviews 2026 IDOR guide, Autorize extension, real HackerOne/Bugcrowd reports.
---
