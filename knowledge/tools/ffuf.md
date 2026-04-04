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

## Effectiveness Scores

| Target Type | Score | Notes |
|-------------|-------|-------|
| Web App | 0.95 | Best-in-class web fuzzer |
| API | 0.90 | Excellent API endpoint discovery |
| Network | 0.30 | Not designed for network scanning |
| Cloud | 0.70 | Good for finding cloud-hosted paths |
| CMS | 0.90 | Strong content discovery |

## Fallback Alternatives

If ffuf is unavailable: `feroxbuster` → `dirsearch` → `gobuster` → `dirb` → `wfuzz`

## Context-Aware Parameters

```bash
# Directory discovery
ffuf -u https://{domain}/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -mc 200,301,302,403 -recursion -recursion-depth 2

# Parameter fuzzing
ffuf -u https://{domain}/page?FUZZ=test -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -fs {baseline_size}

# Virtual host discovery
ffuf -u https://{domain} -H "Host: FUZZ.{domain}" -w subdomains.txt -fs {baseline_size}

# POST parameter fuzzing
ffuf -u https://{domain}/login -X POST -d "username=admin&FUZZ=test" -w params.txt -fc 401

# API endpoint discovery
ffuf -u https://{domain}/api/FUZZ -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt -mc 200,201,204,301,401,403,405

# With rate limiting (conservative)
ffuf -u https://{domain}/FUZZ -w wordlist.txt -rate 50 -t 10 -mc 200,301,302,403

# Recursive with depth
ffuf -u https://{domain}/FUZZ -w wordlist.txt -recursion -recursion-depth 3 -recursion-strategy greedy -mc 200,301,302
```
