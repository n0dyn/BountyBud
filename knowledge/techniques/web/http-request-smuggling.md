---
id: "http-request-smuggling"
title: "Advanced HTTP Request Smuggling (2025)"
type: "technique"
category: "web-application"
subcategory: "infrastructure"
tags: ["hrs", "desync", "http2", "clte", "tecl"]
difficulty: "expert"
updated: "2026-04-16"
---

## Overview
Modern HTTP Request Smuggling (HRS) focuses on parser differentials between CDNs/Proxies and backend origin servers, primarily exploiting HTTP/2 downgrading, zero-length body parsing, and chunk extension smuggling.

## Advanced Attack Vectors

### 1. HTTP/2 Downgrading (H2.CL / H2.TE)
When a front-end server receives HTTP/2 but downgrades it to HTTP/1.1 to talk to the backend, it must translate H2 frames into HTTP/1.1 format.
- **H2.CL**: You inject a `Content-Length` header via pseudo-headers. The backend uses the injected CL instead of the actual frame length.
- **H2.TE**: You inject a `Transfer-Encoding: chunked` header. The backend parses chunks while the front-end parsed frames.

### 2. Zero-Length Smuggling
- **0.CL (Zero Content-Length):** The front-end sees `Content-Length: 0` and stops parsing. The backend ignores `0` and parses the next request as the body of the first.
- **TE.0 (Transfer-Encoding Zero):** The front-end uses `Transfer-Encoding: chunked`, but the backend ignores it and assumes `Content-Length: 0`.

### 3. Chunk Extension Smuggling
Injecting newline characters (`\n`, `\r`) into HTTP chunk extensions.
```http
0;key=value\n\nGET /smuggled HTTP/1.1
```
If the backend parser evaluates the newline inside the extension, it splits the request.

## Detection Methodology (Response Queue Poisoning)
To confidently confirm desync without relying solely on timeouts:
1. Send a smuggled request designed to trigger a specific response (e.g., a 404 to a non-existent endpoint).
2. Immediately send a normal request (e.g., to `/`).
3. If the normal request returns the 404 intended for the smuggled request, you have successfully poisoned the socket connection.

## Exploitation Chains
1. **Smuggling + Cache Deception:** Smuggle a request for sensitive data just as a victim requests a static file (`/js/app.js`). The CDN caches the sensitive data under the static file path.
2. **Internal API Routing:** Smuggle requests to internal IP headers or non-public paths (e.g., `/admin`).

## Deep Dig Prompts
- "Analyze this target's CDN/Backend combo. If it's Cloudflare + Spring Boot, suggest an H2.TE downgrade payload."
- "Given these smuggled responses, build a Response Queue Poisoning chain."