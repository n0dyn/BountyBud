---
id: "race-condition-logic"
title: "Race Conditions & State Manipulation"
type: "technique"
category: "web-application"
subcategory: "business-logic"
tags: ["race-condition", "turbo-intruder", "concurrency"]
difficulty: "advanced"
updated: "2026-04-16"
---

## Overview
Race conditions occur when a system's behavior depends on the sequence or timing of uncontrollable events. In web apps, this usually involves concurrent requests manipulating the same data.

## Attack Vectors
1. **Redeem Limit Bypass:** Redeeming a single-use coupon multiple times in the same millisecond.
2. **Double Withdrawal:** Withdrawing funds twice before the balance is updated.
3. **Multi-Factor Bypass:** Entering many OTP guesses simultaneously to beat a rate-limiter.

## Verification
Use **Burp Suite Turbo Intruder** with a single-packet attack (HTTP/2) to ensure all requests arrive at the server at the exact same time.

## Deep Dig Prompts
- "Identify stateful operations in this app (withdrawals, redemptions, voting). Suggest a race condition test for the /redeem endpoint."
