---
id: "idor-bola"
title: "IDOR & BOLA Hunting Masterclass (2026 Edition)"
type: "technique"
category: "web-application"
subcategory: "idor"
tags: ["idor", "bola", "uuid", "snowflake", "multi-tenant", "authorization", "api", "deep-dig"]
platforms: ["linux", "macos", "windows"]
related: ["graphql-grpc", "business-logic-flaws"]
difficulty: "intermediate"
updated: "2026-03-30"
---

# IDOR & BOLA Hunting Masterclass (2026 Edition)

## Introduction
Insecure Direct Object Reference (IDOR) and Broken Object Level Authorization (BOLA) remain the top vulnerabilities in modern APIs. In 2026, the shift is toward UUID/Snowflake ID exploitation and cross-tenant data exfiltration.

## Modern Attack Patterns
1. **UUID/Snowflake Guessing**: Predicting next-gen IDs through leakage in other endpoints or time-based generation.
2. **Method Switching**: Changing `GET` to `POST/PUT/DELETE` on objects you shouldn't own.
3. **Parameter Pollution**: Adding `&user_id=target` to a request that usually only takes `?id=mine`.
4. **Cross-Tenant Leakage**: Accessing organization-level resources by switching `org_id`.

## Deep Dig Prompts
```
Given these requests [paste Burp/Network history]: 
1. Identify all parameters that represent object IDs (user_id, account_id, doc_id, uuid).
2. Suggest 10 variations to test for IDOR, including method swapping and wrapping IDs in JSON arrays/objects.
3. Draft a script to iterate through suspected Snowflake ID ranges or UUID v4/v7 patterns.
```

```
Analyze this multi-tenant API structure: 
How can I leak data from Tenant B while authenticated as Tenant A? Look for shared resources, global search endpoints, or invite-user flows that expose PII.
```

## Tools
- Burp Suite: Autorize, AuthMatrix, AutoRepeater
- Custom Python scripts for ID incrementing/brute-forcing
- UUID version detectors

## High-Value Targets
- `/api/v1/billing/settings`
- `/api/v1/users/me/export`
- `/api/v1/admin/debug/user/{id}`
