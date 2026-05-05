---
id: "proxy-upgrade-vulnerabilities"
title: "Proxy & Upgradeability Vulnerabilities 2026 - UUPS, Transparent, Storage Collisions, Initialization & Selector Clashes"
type: "technique"
category: "web3"
subcategory: "smart-contract"
tags: ["proxy", "upgradeability", "uups", "transparent-proxy", "storage-collision", "initialization", "selector-clash", "delegatecall", "2026"]
difficulty: "expert"
platforms: ["linux", "macos", "windows"]
related: ["web3-smart-contract-vulnerabilities", "reentrancy-attacks-2026", "access-control"]
updated: "2026-05-04"
---

## Overview
Upgradeable proxies (UUPS, Transparent, Beacon) dominate 2026 DeFi/NFT/bridges but introduce new classes: uninitialized proxies, storage layout collisions, function selector clashes, and delegatecall pitfalls. OWASP SC10 (new). Wormhole $10M bounty for uninitialized UUPS. High payouts for ownership takeover or logic hijack.

## Key Vulnerabilities
### 1. Uninitialized Proxies
Implementation contract can be `initialize()`'d directly by attacker if not called on proxy deploy or if initializer not protected.
- **Example**: Wormhole bridge - attacker calls initialize on impl → takes ownership.
- **Bypass**: No `initializer` modifier or missing `onlyProxy` checks.

### 2. Storage Layout Collisions
Proxy and implementation share storage slot 0+; new vars in impl overwrite proxy admin/owner slots.
- Classic in UUPS/Transparent if slots not reserved (e.g., via `__gap` or inheritance ordering).

### 3. Function Selector Clashes
`delegatecall` routes by 4-byte selector; clash between proxy admin funcs and impl funcs allows hijack.
- E.g., `upgradeTo` selector matches malicious func in impl.

### 4. Delegatecall to Untrusted / Selfdestruct
Impl contains `delegatecall` to user-controlled address or `selfdestruct` → permanent bricking or takeover.

### 5. Missing Access Control on Upgrade
Anyone can call `upgradeTo` if not gated by `onlyOwner` + timelock.

## Hunting Methodology
1. **Source + Verified Code**: Check Etherscan for proxy (EIP-1967 slots for admin/implementation).
2. **Static**: Slither `proxy` / `delegatecall` detectors; manual slot analysis.
3. **Dynamic**: Foundry fork + deploy malicious impl that collides slots or clashes selectors; test `initialize` on impl directly.
4. **On-Chain**: Look for recent upgrades, large `delegatecall` patterns, unverified impls.
5. **Tools**: OpenZeppelin Upgrades plugins, Hardhat upgrades, storage layout visualizers.

## Prevention (2026)
- **UUPS**: Use OpenZeppelin UUPSUpgradeable + `onlyProxy` + `__UUPS_init` with initializer guard.
- **Transparent**: Separate admin contract; never call impl directly.
- **Storage**: Always reserve `__gap[50]` or use structured inheritance; verify layout with `forge inspect`.
- **Selectors**: Avoid common names; use unique or proxy-only functions.
- **Init**: `initializer` modifier + `onlyProxy` check on all init funcs.
- **Upgrades**: Timelock + multi-sig + on-chain proposal.
- **Testing**: Full upgrade simulation in CI; invariant tests post-upgrade.

## Deep Dig Prompts
```
For target proxy contract (UUPS/Transparent):
1. Extract storage layout (slots 0-50) and identify collisions risk.
2. Check initializer protection and direct impl calls.
3. Generate Foundry test for uninit proxy takeover + selector clash PoC.
4. Recommend fixes: UUPS + gap + onlyProxy + timelock.
5. Impact: "Arbitrary upgrade / ownership takeover via uninitialized proxy leading to full protocol drain."
6. Reference Wormhole incident and OWASP SC10.
Output code, test commands, and high-severity report template.
```

## References
- OWASP SC10 2026, OpenZeppelin Upgrades docs, Wormhole bounty report, EIP-1967, Slither proxy rules.
---
