---
id: "spiderfoot"
title: "SpiderFoot - Automated OSINT"
type: "tool"
category: "reconnaissance"
subcategory: "osint"
tags: ["osint", "spiderfoot", "automated", "200-modules", "web-interface", "correlation-analysis"]
difficulty: "beginner"
platforms: ["linux", "macos"]
source_url: "https://github.com/smicallef/spiderfoot"
related: []
updated: "2026-03-30"
---

## Overview

Automated OSINT collection with 200+ modules for footprinting and intelligence gathering.

## Command Reference

```bash
python3 /opt/spiderfoot/sf.py -s {domain} -t DOMAIN_NAME -q -o csv:{domain}_spiderfoot.csv
echo "[+] SpiderFoot: Automated OSINT scan initiated"
```

## Features

- 200+ modules
- Web interface
- Correlation analysis

## Documentation

- [Official Documentation](https://github.com/smicallef/spiderfoot)

## Effectiveness Scores

| Category   | Score |
|------------|-------|
| Web App    | 0.5   |
| API        | 0.3   |
| Network    | 0.5   |
| Cloud      | 0.4   |
| CMS        | 0.3   |

## Fallback Alternatives

- **theHarvester** - Lighter OSINT tool for emails and subdomains
- **amass** - More focused subdomain and network enumeration
- **sherlock** - Specialized social media username OSINT

## Context-Aware Parameters

**Standard OSINT scan**
```bash
python3 /opt/spiderfoot/sf.py -s {domain} -t DOMAIN_NAME -q -o csv:{domain}_spiderfoot.csv
```

**All module types scan (comprehensive)**
```bash
python3 /opt/spiderfoot/sf.py -s {domain} -t DOMAIN_NAME,INTERNET_NAME,IP_ADDRESS -q -o csv:{domain}_spiderfoot_full.csv
```

**Web UI mode for interactive investigation**
```bash
python3 /opt/spiderfoot/sf.py -l 127.0.0.1:5001
```

**Email-focused OSINT**
```bash
python3 /opt/spiderfoot/sf.py -s {domain} -t EMAILADDR -q -o csv:{domain}_spiderfoot_emails.csv
```
