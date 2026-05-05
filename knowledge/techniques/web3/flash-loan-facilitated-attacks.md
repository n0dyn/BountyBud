---
id: "flash-loan-facilitated-attacks"
title: "Flash Loan Facilitated Attacks 2026 - Oracle Manipulation, Rounding, Donation & Compositional Exploits"
type: "technique"
category: "web3"
subcategory: "smart-contract"
tags: ["flash-loan", "defi", "oracle-manipulation", "rounding-error", "donation-attack", "compositional", "aave", "uniswap", "2026"]
difficulty: "expert"
platforms: ["linux", "macos", "windows"]
related: ["reentrancy-attacks-2026", "web3-smart-contract-vulnerabilities", "defi-business-logic", "oracle-manipulation"]
updated: "2026-05-04"
---

## Overview
Flash loans (Aave, dYdX, Uniswap V3, etc.) provide uncollateralized capital in one tx. Not a vuln themselves, but amplify any logic/oracle/arithmetic flaw into protocol drains ($10M-$200M incidents). OWASP SC04 2026. Common in lending, AMMs, vaults, governance. Bug bounties reward novel flash-loan chains highly.

## Core Attack Flow
1. Flash-borrow massive capital (e.g., 3M USDT).
2. Manipulate state/price/accounting in same tx (oracle skew, rounding abuse, donation to inflate shares).
3. Extract profit (under-collateralized loan, drain liquidity, skew votes).
4. Repay flash loan + keep profit. Tx reverts on failure.

## High-Impact Variants 2026
### 1. Oracle Manipulation (Spot Price Skew)
Flash large swap to move Uniswap V2 spot price → protocol using spot (not TWAP/Chainlink) sees inflated price → liquidate or borrow cheaply.
- **Bypass TWAP**: Target thin-liquidity pools or short windows; combine with MEV sandwich.
- **Examples**: YieldBlox ($7M), older Cream Finance.

### 2. Rounding / Precision Attacks
Repeated micro-ops exploit truncation (e.g., integer division down).
- **Bunni (Sep 2025, $8.4M)**: 44 tiny withdrawals exploiting 28 wei imbalance after flash-driven price push.
- **zkLend ($9.5M)**: mint() rounding + repeated deposit/withdraw cycle.
- **Balancer v2 ($128M)**: 65 compounding rounding errors across modules.

### 3. Donation Attacks / Share Inflation
Donate tokens to vault/pool to inflate share price or trigger bad accounting mid-calc.
- Common in yield vaults, reward distributors.

### 4. Compositional / Cross-Protocol
Chain multiple protocols (flash mint on A → Curve convert → Yearn deposit → donation on B). Euler Finance ($197M) example.

### 5. Governance / Voting Weight
Flash large balance → vote on proposal → repay. Or manipulate liquidation thresholds.

## Hunting & Analysis Techniques
1. **Assume Flash Loans**: Model every sensitive func (mint/burn/borrow/liquidate) with arbitrary capital available same-tx.
2. **Fuzz + Invariant**: Foundry fuzz + invariant tests for rounding, slippage, oracle staleness.
3. **Simulation**: Tenderly or Foundry fork mainnet + flash loan contracts; test extreme slippage, stale oracles, donation.
4. **On-Chain Signals**: Monitor large flash loan + state change patterns (use Dune, Nansen, or custom).
5. **Source Review**: Look for:
   - Raw spot DEX prices as oracles.
   - Share math without snapshots or safe math.
   - No per-block caps, no max slippage, no circuit breakers.
   - External calls without reentrancy guards in accounting paths.

## Prevention (2026 Best Practices)
- **Oracle Hygiene**: Centralize reads; use TWAP + Chainlink + staleness/deviation checks + fallback + emergency mode.
- **Accounting Safety**: Internal ledgers (not raw balances); snapshot before external influence; handle fee-on-transfer tokens explicitly.
- **Rate Limits & Caps**: Per-block mint/borrow caps, dynamic fees on high volume, max position size, max slippage.
- **Circuit Breakers / Safe Mode**: Pause risky ops on anomaly (e.g., sudden liquidity drop).
- **Invariant + Fuzz Testing**: 95%+ coverage + adversarial fuzz (MEV sandwich simulation).
- **CEI + ReentrancyGuard** on all stateful paths.
- **Audit + Continuous**: Multiple audits + bug bounty + on-chain monitoring.

## Deep Dig Prompts
```
For target DeFi protocol (lending/AMM/vault source):
1. Identify all oracle usages and flash-loan integration points.
2. Generate Foundry flash-loan harness + adversarial test cases for rounding, donation, oracle skew.
3. List invariants that must hold (e.g., total assets == sum user shares * price).
4. Recommend fixes: TWAP migration, per-block limits, safe-mode circuit breaker.
5. Impact quantification: "Flash-loan amplified rounding error drains $X liquidity in one tx."
6. Cross-reference recent incidents (Bunni, zkLend, Balancer, Euler).
Output PoC code, test commands, and bounty report structure.
```

## References
- OWASP SC04 2026, Bunni/zkLend/Balancer/Euler post-mortems, Aave flash loan docs, Foundry best practices, Chainalysis 2025 crypto crime report.
---
