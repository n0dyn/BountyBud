---
id: "reentrancy-attacks-2026"
title: "Reentrancy Attacks 2026 - Classic, Read-Only, Cross-Function, Cross-Contract & DeFi Variants"
type: "technique"
category: "web3"
subcategory: "smart-contract"
tags: ["reentrancy", "smart-contract", "defi", "checks-effects-interactions", "reentrancyguard", "cross-function", "read-only-reentrancy", "flash-loan", "2026"]
difficulty: "expert"
platforms: ["linux", "macos", "windows"]
related: ["web3-smart-contract-vulnerabilities", "cross-chain-hook-injection", "flash-loan-facilitated-attacks", "defi-business-logic"]
updated: "2026-05-04"
---

## Overview
Reentrancy remains a top OWASP Smart Contract Top 10 2026 (SC08) despite mitigations. Classic withdraw-before-update is rare in audited code, but variants (read-only, cross-function, cross-contract, hook-based) still drain millions (GMX V1 $42M). Affects DeFi, NFTs, DAOs, bridges. Payouts $10k-$500k+ on bug bounties for novel variants.

## Variants & Exploitation

### 1. Classic (Withdraw-Before-Update)
```solidity
function withdraw(uint amount) external {
    require(balances[msg.sender] >= amount);
    (bool ok) = msg.sender.call{value: amount}(""); // external call before update
    require(ok);
    balances[msg.sender] -= amount; // too late
}
```
Bypass: Malicious receiver re-enters withdraw during call.

### 2. Read-Only Reentrancy
View functions or oracles read inconsistent state during callback (e.g., during flash loan or hook). No state change needed for profit.

### 3. Cross-Function Reentrancy
Re-enter a different function before state sync (e.g., deposit calls internal withdraw logic).

### 4. Cross-Contract / Multi-Module
Vault → Strategy → DEX flows where reentrancy spans contracts. Common in composable DeFi.

### 5. Hook-Based (ERC777, ERC721/1155, ERC4626, Flash Loan Callbacks)
Malicious token/receiver hooks trigger re-entry on transfer.

**Real 2025-2026 Examples**:
- GMX V1: Cross-contract reentrancy in executeDecreaseOrder via refund callback.
- Curve Vyper compiler bug broke ReentrancyGuard.

## Detection & Hunting Methodology
1. **Static**: Slither `reentrancy` detectors, Mythril, MythX.
2. **Dynamic/Fuzz**: Foundry fuzz (10k+ inputs on stateful funcs), Echidna invariants.
3. **Manual**:
   - Identify all external calls (`call`, `transfer`, `send`, `delegatecall`).
   - Check if state updates AFTER external call (violate CEI: Checks-Effects-Interactions).
   - Test with malicious contracts that re-enter on fallback/receive/hook.
   - For read-only: Call view funcs mid-transaction via proxy or flash loan.
4. **Tools**: Hardhat/Foundry test harnesses, Tenderly simulations, on-chain monitoring (e.g., for large flash loans + reentrant patterns).

## Prevention (Best Practices 2026)
- **CEI Pattern**: Checks → Effects (state updates) → Interactions (external calls). Always.
- **ReentrancyGuard** (OpenZeppelin) on every balance-modifying + external-call function. Use nonReentrant modifier.
- **Pull over Push**: Don't push funds; let users pull (reduces callback surface).
- **Checks-Effects-Interactions + Mutex** for complex flows.
- **Invariant Testing**: Core properties (e.g., totalSupply == sum balances) must hold post-tx.
- **Timelocks / Pauses** for high-impact functions.
- **Audit + Bounty + Monitoring**: Multiple independent audits + active bug bounty + on-chain anomaly detection.

## Deep Dig Prompts (RAG-Optimized for Agents)
```
Analyze target smart contract (Solidity/Vyper source or verified on Etherscan) for reentrancy:
1. List all external calls and state variables modified after them.
2. Generate Foundry test contract for classic + cross-function + read-only reentrancy PoC.
3. Check for hook interfaces (ERC777, receiver callbacks) and flash loan integrations.
4. Recommend fixes: CEI refactor + ReentrancyGuard placement.
5. Impact: "Drain of X ETH via reentrancy in withdraw path, bypassing ReentrancyGuard due to cross-contract call."
6. Cross-check against 2026 OWASP SC08 and recent incidents (GMX, Curve).
Output structured report with code snippets, test commands, and severity.
```

## References
- OWASP Smart Contract Top 10 2026 SC08, OpenZeppelin docs, GMX/Curve post-mortems, Slither/Foundry best practices.
---
