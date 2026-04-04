---
id: "nuclei-services"
title: "Nuclei Service Detection"
type: "tool"
category: "network"
subcategory: "service-enumeration"
tags: ["service", "nuclei-services"]
difficulty: "beginner"
platforms: ["linux", "macos"]
related: []
updated: "2026-03-30"
---

## Overview

Service-specific vulnerability scanning using Nuclei.

## Command Reference

```bash
nuclei -u https://{domain} -t technologies/ -rate-limit 50 -o {domain}_service_detection.txt
echo "Service detection results saved to {domain}_service_detection.txt"
```

## Effectiveness Scores

| Category   | Score |
|------------|-------|
| Web App    | 0.5   |
| API        | 0.4   |
| Network    | 0.7   |
| Cloud      | 0.4   |
| CMS        | 0.5   |

## Fallback Alternatives

- **nmap-scripts** - NSE scripts for deeper service enumeration
- **nuclei-full** - Full scan includes service detection plus more
- **whatweb** - Web technology fingerprinting

## Context-Aware Parameters

**Standard service/technology detection**
```bash
nuclei -u https://{domain} -t technologies/ -rate-limit 50 -o {domain}_service_detection.txt
```

**Network service scanning with host list**
```bash
nuclei -l {domain}_live_hosts.txt -t network/ -rate-limit 30 -o {domain}_network_services.txt
```

**Combined technology and misconfiguration scan**
```bash
nuclei -u https://{domain} -t technologies/,misconfiguration/ -rate-limit 50 -o {domain}_tech_misconfig.txt
```
