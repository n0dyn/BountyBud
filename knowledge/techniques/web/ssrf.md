---
id: "ssrf-techniques"
title: "SSRF Modern Techniques & Bypasses (2026 Edition)"
type: "technique"
category: "web-application"
subcategory: "ssrf"
tags: ["ssrf", "dns-rebinding", "imdsv2", "cloud-metadata", "gopher", "parser-differential", "deep-dig"]
platforms: ["linux", "macos", "windows"]
related: ["cloud-misconfigurations", "oauth-jwt-saml-bypasses"]
difficulty: "advanced"
updated: "2026-03-30"
---

# SSRF Modern Techniques & Bypasses (2026 Edition)

## Why SSRF is Still King
Server-Side Request Forgery (SSRF) has evolved. With the hardening of IMDSv2, attackers now focus on DNS rebinding, URL parser inconsistencies, and internal service mesh exploitation.

## 2026 Attack Vectors
1. **IMDSv2 Bypasses**: Exploiting proxy headers or misconfigured internal gateways to reach `169.254.169.254`.
2. **DNS Rebinding**: Using services like `rbndr.us` to bypass IP blacklists/whitelists.
3. **Parser Differential**: Exploiting how different libraries (e.g., Python `requests` vs. Go `net/http`) interpret `http://user@target.com:80@internal.local`.
4. **PDF/Image Renderers**: Forcing headless browsers to fetch internal metadata.

## Deep Dig Prompts
```
Given this URL-accepting endpoint [describe]: 
1. Provide 15 bypass payloads for a "localhost" or "169.254" filter (e.g., decimal IPs, hex, CIDR tricks, @ syntax).
2. Suggest a DNS rebinding strategy using a 1s TTL to flip from a safe IP to the internal metadata IP.
3. If this uses a PDF generator, craft a `<link>` or `<iframe>` tag to leak the AWS/GCP metadata token.
```

## Internal Services to Target
- Redis (via gopher://)
- Memcached
- Internal K8s API
- Docker Socket
- Cloud Metadata (AWS, GCP, Azure, DigitalOcean)

## Tools
- SSRFmap, Gopherus
- Interactsh / Burp Collaborator
- DNS rebinding servers (Abalone, Singularity)
