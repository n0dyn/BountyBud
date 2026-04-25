---
id: "asset-scaling-precision-mismatch"
title: "Native vs. Wrapped Asset Scaling Mismatch"
type: "technique"
category: "smart-contract"
subcategory: "protocol-logic"
tags: ["blockchain", "decimals", "precision", "dos", "2026"]
difficulty: "expert"
updated: "2026-04-18"
---

## Overview
A critical logic flaw occurring when a network uses a token with low decimal precision (e.g., USDC with 6 decimals) as a native gas or utility token in an environment that expects high precision (e.g., EVM with 18 decimals).

## The Vulnerability Pattern
The underlying execution environment's ledger expects increments in $10^{18}$ units, but the bridging/wrapping contract applies increments in $10^{6}$ units without a scaling factor.

### Vulnerability Signature (Solidity/Rust)
Look for balance updates that lack a multiplier:
```rust
// VULNERABLE: Direct application of 6-decimal amount to 18-decimal ledger
let native_amount = wrapped_token_amount; 
ledger.credit(user, native_amount);
```

## How BountyBud Hunts It
1. **Recon:** Identify the specific contract responsible for wrapping/unwrapping the native gas token.
2. **Audit:** Trace the `deposit` or `mint` functions into the system's precompiles or core ledger.
3. **Signature Hunt:** Search for balance increment/decrement functions that fail to apply a scaling factor (e.g., `amount * 10^12`).
4. **Impact Proof:** Demonstrate that 1 standard token unit credits only $10^{-12}$ units of native gas, permanently bricking the account with an "Insufficient Funds" DoS.

## Deep Dig Prompts
- "Analyze the precision scaling in this bridge contract. Does the credit function account for the 10^12 difference between USDC and the native gas ledger?"
- "Simulate a gas price oracle check against a low-precision credited account. Prove account bricking."
