---
id: "cache-poisoning-advanced"
title: "Web Cache Poisoning"
type: "technique"
category: "web-application"
subcategory: "infrastructure"
tags: ["cache-poisoning", "unkeyed-headers", "cdn"]
difficulty: "expert"
updated: "2026-04-16"
---

## Overview
Cache poisoning tricks a CDN or server-side cache into storing a malicious response and serving it to other users.

## Methodology
1. Find an "Unkeyed Header" (a header that affects the response but isn't part of the cache key).
2. Inject a malicious payload into that header (e.g., a path to an attacker-controlled JS file).
3. Confirm the response is cached (`X-Cache: HIT`).

## Stealth Testing
Always use a **Cache Buster** query parameter (e.g., `?cb=789`) during testing to prevent affecting real users.

## Payloads
```http
X-Forwarded-Host: attacker.com
X-Original-URL: /admin
X-Rewrite-URL: /api/v1/users
```
