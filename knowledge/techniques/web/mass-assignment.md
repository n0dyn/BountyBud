---
id: "mass-assignment-vulnerabilities"
title: "Mass Assignment & Overposting"
type: "technique"
category: "web-application"
subcategory: "api-security"
tags: ["mass-assignment", "overposting", "api"]
difficulty: "medium"
updated: "2026-04-16"
---

## Overview
Mass Assignment occurs when an application automatically maps user-provided input fields to internal data models without a strict allowlist.

## Discovery
1. Perform a `GET` on a resource (e.g., `/api/user/me`).
2. Identify fields not present in the `POST` profile update (e.g., `is_admin`, `role`, `balance`).
3. Try to `POST`/`PUT` those fields back to the server.

## Payloads
- `{"role": "admin"}`
- `{"is_verified": true}`
- `{"account_balance": 999999}`
- `{"user[is_admin]": true}` (Nested object syntax)
