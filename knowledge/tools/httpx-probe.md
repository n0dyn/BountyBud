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

## Effectiveness Scores

| Target Type | Score | Notes |
|-------------|-------|-------|
| Web App | 0.95 | Essential for identifying live web services |
| API | 0.95 | Detects API services and their technologies |
| Network | 0.60 | Limited to HTTP services only |
| Cloud | 0.85 | Good cloud service identification |
| CMS | 0.95 | Identifies CMS platforms via tech detection |

## Fallback Alternatives

If httpx is unavailable: `httprobe` → `curl` scripting → `wget` scripting

## Context-Aware Parameters

```bash
# Quick probe (live/dead only)
httpx -l subs.txt -silent -o live.txt

# Full reconnaissance probe
httpx -l subs.txt -sc -cl -title -tech-detect -server -method -websocket -ip -cname -cdn -follow-redirects -threads 50 -o full_probe.txt

# JSON output for automation
httpx -l subs.txt -sc -title -tech-detect -json -o probe.json

# Screenshot capture
httpx -l subs.txt -screenshot -system-chrome -o screenshots/

# Filter by status code
httpx -l subs.txt -mc 200,301,302,403 -o interesting.txt
```
