---
id: "business-logic-flaws"
title: "Business Logic Flaws Playbook (2026 Edition)"
type: "technique"
category: "web-application"
subcategory: "business-logic"
tags: ["business-logic", "price-manipulation", "workflow-bypass", "state-machine", "rounding-errors", "deep-dig"]
platforms: ["linux", "macos", "windows"]
related: ["race-conditions", "idor-bola"]
difficulty: "advanced"
updated: "2026-03-30"
---

# Business Logic Flaws Playbook (2026 Edition)

## Introduction
Business logic flaws are the "logic bugs" of the application. They aren't about code syntax but about how the application's rules can be subverted. These are often the highest-paying bugs because they directly impact revenue or user trust.

## Core 2026 Logic Vectors
1. **Price & Quantity Manipulation**: Changing values in requests that the server assumes are immutable.
2. **Step Skipping/Workflow Bypass**: Navigating directly to `/success` or `/admin/provision` without completing prerequisite steps (e.g., payment, 2FA).
3. **State Machine Abuse**: Forcing an object (order, user account) into an invalid state by repeating or reversing actions.
4. **Rounding Errors & Currency Conversion**: Exploiting floating-point math or inconsistent exchange rates to gain credit.

## Deep Dig Prompts
```
Analyze this multi-step checkout flow [describe]: 
1. Identify where price, discount, and inventory checks occur. 
2. Suggest ways to skip the payment step or reuse a one-time discount code across multiple sessions.
3. Test for "negative quantity" or "fractional quantity" inputs in the cart.
```

```
In this user registration/onboarding process: 
Can a user gain "premium" status by interrupting the flow after payment is initiated but before it's confirmed? What happens if the callback from the payment provider is spoofed or replayed?
```

## Tools
- Burp Suite: Repeater, Match and Replace
- Proxy logs analysis for parameter consistency
- "Mind mapping" tools to visualize state transitions

## High-Impact Findings
- Free subscription via cancellation flow abuse
- Unlimited trial period via email aliasing + script
- Unauthorized access to private "beta" features
