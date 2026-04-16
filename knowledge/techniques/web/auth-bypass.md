---
id: "auth-bypass-techniques"
title: "Advanced Authentication Bypass"
type: "technique"
category: "web-application"
subcategory: "authentication"
tags: ["auth-bypass", "logic-flaw", "session-puzzling"]
difficulty: "advanced"
updated: "2026-04-16"
---

## Techniques

### 1. Session Puzzling
Mismatched or confusing session identifiers can bypass auth checks.
- Try removing the `session_id` cookie but keeping the URL parameter (or vice-versa).
- Swap session tokens between two different accounts of different privilege levels.

### 2. Parameter Pollution (HPP)
Exploit how the backend handles multiple parameters with the same name.
- `GET /profile?user_id=victim&user_id=attacker`
- Backend might use `victim` for the database query but `attacker` for the permission check.

### 3. Header Mangling
Inject headers that trick the app into thinking you are authenticated or internal.
- `X-Custom-IP-Authorization: 127.0.0.1`
- `X-Remote-User: admin`
- `X-Forwarded-For: 127.0.0.1`

## Payloads
- Refer to `knowledge/payloads/auth-bypass-payloads.md` for specific implementation.
