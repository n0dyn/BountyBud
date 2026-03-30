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
