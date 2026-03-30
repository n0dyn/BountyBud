---
id: "httpx-probe"
title: "HTTPx - Live Host Verification"
type: "tool"
category: "reconnaissance"
subcategory: "subdomain-enumeration"
tags: ["subdomain", "httpx-probe", "active", "http-probing", "technology-detection", "status-code-analysis"]
difficulty: "beginner"
platforms: ["linux", "macos"]
source_url: "https://github.com/projectdiscovery/httpx"
related: []
updated: "2026-03-30"
---

## Overview

Probes HTTP/HTTPS services on discovered subdomains with technology detection.

## Command Reference

```bash
httpx -l {domain}_subfinder.txt -threads 50 -rate-limit 150 -timeout 10 -title -tech-detect -status-code -o {domain}_live_hosts.txt
echo "[+] HTTPx: $(wc -l < {domain}_live_hosts.txt) live hosts found"
```

## Features

- HTTP probing
- Technology detection
- Status code analysis

## Documentation

- [Official Documentation](https://github.com/projectdiscovery/httpx)
