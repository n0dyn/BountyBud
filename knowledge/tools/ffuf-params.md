---
id: "ffuf-params"
title: "FFUF Parameter Fuzzing"
type: "tool"
category: "reconnaissance"
subcategory: "parameter-discovery"
tags: ["parameter", "ffuf-params"]
difficulty: "beginner"
platforms: ["linux", "macos"]
related: []
updated: "2026-03-30"
---

## Overview

Parameter fuzzing using FFUF with common parameter wordlists.

## Command Reference

```bash
ffuf -u 'https://{domain}/?FUZZ=test' -w /opt/wordlists/parameters.txt -t 20 -rate 100 -mc 200 -o {domain}_param_fuzz.json
echo "Parameter fuzzing results saved to {domain}_param_fuzz.json"
```

## Effectiveness Scores

| Category   | Score |
|------------|-------|
| Web App    | 0.8   |
| API        | 0.7   |
| Network    | 0.0   |
| Cloud      | 0.1   |
| CMS        | 0.5   |

## Fallback Alternatives

- **arjun** - Dedicated parameter discovery tool
- **wfuzz** - Multi-point fuzzing for parameter testing
- **burpsuite** - Param Miner extension for automated discovery

## Context-Aware Parameters

**Standard GET parameter fuzzing**
```bash
ffuf -u 'https://{domain}/?FUZZ=test' -w /opt/wordlists/parameters.txt -t 20 -rate 100 -mc 200 -o {domain}_param_fuzz.json
```

**POST parameter fuzzing**
```bash
ffuf -u 'https://{domain}/login' -X POST -d 'FUZZ=test' -w /opt/wordlists/parameters.txt -t 20 -rate 100 -mc 200 -o {domain}_param_post.json
```

**Parameter value fuzzing (known param)**
```bash
ffuf -u 'https://{domain}/?id=FUZZ' -w /opt/wordlists/idor_values.txt -t 20 -rate 100 -mc 200 -o {domain}_param_values.json
```

**Header-based parameter discovery**
```bash
ffuf -u 'https://{domain}/' -H 'FUZZ: test' -w /opt/wordlists/headers.txt -t 20 -rate 100 -mc 200 -o {domain}_header_fuzz.json
```
