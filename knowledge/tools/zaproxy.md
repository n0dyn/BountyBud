---
id: "zaproxy"
title: "OWASP ZAP - Web Application Security Scanner"
type: "tool"
category: "web-application"
subcategory: "xss"
tags: ["webapp", "zaproxy", "opensource", "automated-scanning", "manual-testing", "api-support"]
difficulty: "beginner"
platforms: ["linux", "macos"]
source_url: "https://www.zaproxy.org/"
related: []
updated: "2026-03-30"
---

## Overview

Free and open-source web application security scanner with automated and manual testing capabilities.

## Command Reference

```bash
zap-baseline.py -t https://{domain} -J {domain}_zap_baseline.json
echo "[+] ZAP: Baseline security scan completed"
```

## Features

- Automated scanning
- Manual testing
- API support

## Documentation

- [Official Documentation](https://www.zaproxy.org/)

## Effectiveness Scores

| Target Type | Score |
|-------------|-------|
| Web         | 0.85  |
| API         | 0.80  |
| Network     | 0.30  |
| Cloud       | 0.50  |
| CMS         | 0.80  |

## Fallback Alternatives

nuclei → nikto → Burp Suite

## Context-Aware Parameters

```bash
# Quick scan (baseline)
zap-baseline.py -t https://{domain} -J {domain}_zap_baseline.json

# Full scan
zap-full-scan.py -t https://{domain} -J {domain}_zap_full.json

# API scan
zap-api-scan.py -t https://{domain}/openapi.json -f openapi -J {domain}_zap_api.json

# Spider only
zap-baseline.py -t https://{domain} -s -J {domain}_zap_spider.json

# Active scan with policy
zap-full-scan.py -t https://{domain} -p /path/to/policy.policy -J {domain}_zap_policy.json
```
