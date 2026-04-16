---
id: "stealth-hunting-strategy"
title: "Stealth Hunting Strategy: Low and Slow"
type: "methodology"
category: "reconnaissance"
tags: ["stealth", "waf", "rate-limiting", "opsec"]
difficulty: "advanced"
updated: "2026-04-16"
---

## Overview
The "Low and Slow" methodology is designed to bypass modern WAFs and rate-limiters by mimicking legitimate user behavior and avoiding aggressive scanning patterns that trigger IP bans or security alerts.

## Core Principles
1. **Pacing:** Never exceed 1 request every 3-5 seconds on a single endpoint.
2. **Feedback Awareness:** Actively monitor `X-RateLimit` headers and stop *before* hitting a 429.
3. **Footprint Distribution:** Randomize User-Agents, headers, and even the order of parameter testing.
4. **Behavioral Mimicry:** If an endpoint expects a specific token (like an embed token), reuse it carefully rather than rotating many tokens.

## Rate Limit Monitoring
Always check for these headers in the response:
- `X-RateLimit-Limit`: The total allowed requests.
- `X-RateLimit-Remaining`: How many you have left. Stop if this is < 10.
- `X-RateLimit-Reset`: When the counter resets.

## Stealth Profiles

### CONSERVATIVE
- **Delay:** 1.0s - 2.5s jitter.
- **Concurrent:** 1-2 threads max.
- **Goal:** Avoid standard rate-limiting on sensitive endpoints (Login, Reset Password).

### STEALTH
- **Delay:** 5.0s - 10.0s jitter.
- **Concurrent:** 1 thread.
- **Headers:** Randomize `User-Agent`, `Accept-Language`, and `Referer`.
- **IP Spoofing:** Add rotating `X-Forwarded-For` and `X-Real-IP` headers.

## Deep Dig Prompts
- "Analyze this target's rate-limiting headers. Suggest a delay interval that keeps X-RateLimit-Remaining above 50%."
- "Craft a stealth profile for this specific API using the observed header behavior."
