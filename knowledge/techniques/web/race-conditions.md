---
id: "race-conditions"
title: "Race Conditions & TOCTOU Masterclass (2026)"
type: "technique"
category: "web-application"
subcategory: "race-conditions"
tags: ["race-condition", "toctou", "turbo-intruder", "parallel-requests", "state-desync", "deep-dig"]
platforms: ["linux", "macos", "windows"]
related: ["business-logic-flaws"]
difficulty: "advanced"
updated: "2026-03-30"
---

# Race Conditions & TOCTOU Masterclass (Turbo Intruder 2026)

## Introduction
Race conditions and Time-of-Check-Time-of-Use (TOCTOU) flaws pay $15k–$100k+ because they beat every WAF and auth control.

## Core Patterns
- Duplicate actions (coupon, transfer, signup)
- Limit bypass via parallel requests
- State desync (inventory, balance, approval)

## Deep Dig Prompts
```
Analyze this multi-step flow [paste requests/steps]: 
Map the exact state machine. Identify every TOCTOU window and suggest Turbo Intruder race scripts (10 concurrent threads, 500ms delay variations) to force invalid states.
```

## Tools & Scripts
- Burp Turbo Intruder (built-in race templates)
- Custom Python with asyncio + httpx
- 2 accounts + different proxies

## Proven 2026 Wins
- Parallel premium feature activation
- Negative balance creation
- Token reuse across sessions
