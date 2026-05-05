---
id: "http3-quic-attacks"
title: "HTTP/3 & QUIC Attacks 2026 - Stream Manipulation, 0-RTT Replay, Migration Abuse & Protocol Downgrade"
type: "technique"
category: "web-application"
subcategory: "http2-attacks"
tags: ["http3", "quic", "0-rtt", "stream", "migration", "downgrade", "protocol", "2026"]
difficulty: "expert"
platforms: ["linux", "macos", "windows"]
related: ["http2-attacks", "http-request-smuggling", "cache-poisoning"]
updated: "2026-05-04"
---

## Overview
HTTP/3 (QUIC over UDP) adoption in 2026 introduces new surfaces: 0-RTT replay, stream ID manipulation, connection migration abuse, and downgrade to HTTP/2/1.1. Fewer tools support it, giving edge to prepared hunters.

## Key Attack Vectors
### 1. 0-RTT Replay
Early data in first flight can be replayed if not idempotent-protected.
- **Test**: Capture 0-RTT handshake, replay POSTs (e.g., payment, login).

### 2. Stream & Frame Manipulation
- Reset streams mid-transfer, inject frames, abuse flow control.
- **Test**: Custom QUIC client (quiche, quic-go, or Burp + extensions).

### 3. Connection Migration Abuse
- Spoof migration to redirect or DoS connections.
- **Test**: MITM on UDP or use tooling to force migration.

### 4. Protocol Downgrade
- Force fallback to HTTP/2 smuggling or 1.1 issues.
- **Test**: Block UDP 443 or manipulate ALPN.

### 5. Cache Poisoning via QUIC
- 0-RTT + cache key differences between protocols.

## Hunting
1. Check `Alt-Svc: h3=":443"` header.
2. Use tools: `curl --http3`, `quiche-client`, custom scripts.
3. Burp Suite HTTP/3 support or external proxy.
4. Fuzz streams, test replay on state-changing endpoints.

## Deep Dig Prompts
```
For target with HTTP/3 support:
1. Confirm QUIC/HTTP3 endpoints and 0-RTT usage.
2. Generate replay attack PoC for non-idempotent endpoints.
3. Stream manipulation test cases.
4. Downgrade chain to known HTTP/2 smuggling.
5. Impact: "0-RTT replay bypasses auth leading to duplicate payment/order."
Output commands and mitigation (idempotency keys, anti-replay).
```

## References
- IETF QUIC RFCs, 2026 protocol security research, real-world HTTP/3 bug reports.
---
