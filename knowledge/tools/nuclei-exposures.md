---
id: "nuclei-exposures"
title: "Nuclei Exposure Detection"
type: "tool"
category: "reconnaissance"
subcategory: "sensitive-data-discovery"
tags: ["sensitive", "nuclei-exposures", "detection", "exposure-detection", "template-based", "fast-scanning"]
difficulty: "beginner"
platforms: ["linux", "macos"]
source_url: "https://github.com/projectdiscovery/nuclei"
related: []
updated: "2026-03-30"
---

## Overview

Scan for exposed sensitive files and configurations using Nuclei.

## Command Reference

```bash
nuclei -u https://{domain} -t exposures/ -rate-limit 50 -o {domain}_exposures.txt
echo "[+] Nuclei: Exposure scan completed"
```

## Features

- Exposure detection
- Template-based
- Fast scanning

## Documentation

- [Official Documentation](https://github.com/projectdiscovery/nuclei)

## Effectiveness Scores

| Category   | Score |
|------------|-------|
| Web App    | 0.8   |
| API        | 0.6   |
| Network    | 0.2   |
| Cloud      | 0.6   |
| CMS        | 0.7   |

## Fallback Alternatives

- **nuclei-full** - Full scan includes exposures plus more
- **nikto** - Detects common misconfigurations and exposed files
- **ffuf** - Manual fuzzing for backup files, configs, etc.

## Context-Aware Parameters

**Standard exposure scan**
```bash
nuclei -u https://{domain} -t exposures/ -rate-limit 50 -o {domain}_exposures.txt
```

**Focus on config and backup file exposure**
```bash
nuclei -u https://{domain} -t exposures/configs/,exposures/backups/ -rate-limit 50 -o {domain}_config_exposures.txt
```

**Bulk exposure scan across subdomains**
```bash
nuclei -l {domain}_live_hosts.txt -t exposures/ -rate-limit 30 -c 5 -o {domain}_bulk_exposures.txt
```

**High severity exposures only**
```bash
nuclei -u https://{domain} -t exposures/ -severity high,critical -rate-limit 50 -o {domain}_critical_exposures.txt
```
