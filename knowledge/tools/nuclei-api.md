---
id: "nuclei-api"
title: "Nuclei API Templates"
type: "tool"
category: "api-security"
subcategory: "rest"
tags: ["api", "nuclei-api"]
difficulty: "beginner"
platforms: ["linux", "macos"]
related: []
updated: "2026-03-30"
---

## Overview

API-specific vulnerability scanning using Nuclei.

## Command Reference

```bash
nuclei -u https://{domain} -t http/misconfiguration/,http/vulnerabilities/ -rate-limit 50 -o {domain}_api_scan.txt
echo "API scan results saved to {domain}_api_scan.txt"
```

## Effectiveness Scores

| Category   | Score |
|------------|-------|
| Web App    | 0.5   |
| API        | 0.9   |
| Network    | 0.1   |
| Cloud      | 0.3   |
| CMS        | 0.3   |

## Fallback Alternatives

- **zaproxy** - Full API scanning with OpenAPI support
- **burpsuite** - Manual and automated API testing
- **ffuf-api** - API endpoint discovery via fuzzing

## Context-Aware Parameters

**Standard API vulnerability scan**
```bash
nuclei -u https://{domain} -t http/misconfiguration/,http/vulnerabilities/ -rate-limit 50 -o {domain}_api_scan.txt
```

**Scan with API-specific templates only**
```bash
nuclei -u https://{domain}/api/ -t http/ -tags api -rate-limit 30 -o {domain}_api_focused.txt
```

**Scan list of discovered API endpoints**
```bash
nuclei -l {domain}_api_endpoints.txt -t http/misconfiguration/,http/vulnerabilities/ -rate-limit 50 -o {domain}_api_bulk.txt
```

**Scan with severity filtering**
```bash
nuclei -u https://{domain} -t http/ -tags api -severity high,critical -rate-limit 50 -o {domain}_api_critical.txt
```
