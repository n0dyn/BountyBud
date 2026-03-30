---
id: "ffuf"
title: "FFUF - Fast Web Fuzzer"
type: "tool"
category: "reconnaissance"
subcategory: "directory-discovery"
tags: ["directory", "ffuf", "fuzzing", "advanced-filtering", "json-output", "rate-limiting"]
difficulty: "beginner"
platforms: ["linux", "macos"]
source_url: "https://github.com/ffuf/ffuf"
related: []
updated: "2026-03-30"
---

## Overview

Lightning-fast web fuzzer with advanced filtering and output options.

## Command Reference

```bash
ffuf -u https://{domain}/FUZZ -w /usr/share/seclists/Discovery/Web-Content/big.txt -t 40 -rate 200 -fc 404,403 -o {domain}_ffuf.json
echo "[+] FFUF: Fuzzing completed, check JSON output"
```

## Features

- Advanced filtering
- JSON output
- Rate limiting

## Documentation

- [Official Documentation](https://github.com/ffuf/ffuf)
