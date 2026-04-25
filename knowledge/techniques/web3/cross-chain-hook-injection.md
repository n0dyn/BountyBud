---
id: "cross-chain-hook-injection"
title: "Cross-Chain Message Hook Injection"
type: "technique"
category: "bridge"
subcategory: "interoperability"
tags: ["bridge", "hook", "arbitrary-call", "delegatecall", "2026"]
difficulty: "expert"
updated: "2026-04-18"
---

## Overview
Cross-chain protocols allow users to embed arbitrary "hook" data to be executed on the destination chain. Injection occurs when this data is passed to low-level calls without validation.

## Vulnerability Patterns
The destination bridge contract takes `hookData` and uses it to call an untrusted target address.

### Vulnerability Signature (Solidity)
```solidity
// VULNERABLE: Direct call using untrusted user hook data
(bool success, ) = target.call(hookData);
```

## How BountyBud Hunts It
1. **Recon:** Search for message receiving handlers (`receiveMessage`, `executeHook`) that accept arbitrary bytes.
2. **Audit:** Trace the `hookData` or `messageBody` flow on the destination chain.
3. **Signature Hunt:** Find `.call()` or `.delegatecall()` usages that consume this user data without atomicity or gas limits.
4. **Impact Proof:** Embed a payload that forces the bridge to call its own `mint()` or `withdraw()` functions, or liquidates an external protocol.

## Deep Dig Prompts
- "Trace the flow of hookData from the Relayer to the Execution unit. Is there a restricted allowlist of target addresses?"
- "Generate a payload that uses hookData to trigger a reentrancy attack on the destination bridge."
