---
id: "corsy"
title: "Corsy CORS Scanner"
type: "tool"
category: "web-application"
subcategory: "cors"
tags: ["cors", "corsy", "misconfiguration", "cors-testing", "misconfiguration-detection", "multi-threaded"]
difficulty: "beginner"
platforms: ["linux", "macos"]
source_url: "https://github.com/s0md3v/Corsy"
related: []
updated: "2026-03-30"
---

## Overview

CORS misconfiguration scanner.

## Command Reference

```bash
python3 /opt/tools/Corsy/corsy.py -u https://{domain} -t 20 -o {domain}_cors_results.txt
echo "[+] Corsy: CORS scan completed"
```

## Features

- CORS testing
- Misconfiguration detection
- Multi-threaded

## Documentation

- [Official Documentation](https://github.com/s0md3v/Corsy)

## Effectiveness Scores

| Category   | Score |
|------------|-------|
| Web App    | 0.7   |
| API        | 0.8   |
| Network    | 0.0   |
| Cloud      | 0.3   |
| CMS        | 0.4   |

## Fallback Alternatives

- **nuclei** - CORS misconfiguration templates available
- **burpsuite** - Manual CORS testing via repeater
- **curl** - Manual Origin header testing with custom requests

## Context-Aware Parameters

**Standard CORS scan**
```bash
python3 /opt/tools/Corsy/corsy.py -u https://{domain} -t 20 -o {domain}_cors_results.txt
```

**Scan multiple URLs from file**
```bash
python3 /opt/tools/Corsy/corsy.py -i {domain}_live_hosts.txt -t 10 -o {domain}_cors_bulk.txt
```

**Scan with custom headers**
```bash
python3 /opt/tools/Corsy/corsy.py -u https://{domain} -t 20 --headers "Cookie: session=abc" -o {domain}_cors_auth.txt
```
