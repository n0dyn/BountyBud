---
id: "wfuzz"
title: "Wfuzz - Advanced Web Fuzzer"
type: "tool"
category: "reconnaissance"
subcategory: "directory-discovery"
tags: ["directory", "wfuzz", "advanced", "plugin-system", "multiple-injection", "advanced-filtering"]
difficulty: "beginner"
platforms: ["linux", "macos"]
source_url: "https://github.com/xmendez/wfuzz"
related: []
updated: "2026-03-30"
---

## Overview

Powerful web application fuzzer with plugins and multiple injection points.

## Command Reference

```bash
wfuzz -c -z file,/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt --hc 404,403 http://{domain}/FUZZ > {domain}_wfuzz.txt
echo "[+] Wfuzz: Advanced fuzzing completed"
```

## Features

- Plugin system
- Multiple injection
- Advanced filtering

## Documentation

- [Official Documentation](https://github.com/xmendez/wfuzz)

## Effectiveness Scores

| Category   | Score |
|------------|-------|
| Web App    | 0.8   |
| API        | 0.7   |
| Network    | 0.1   |
| Cloud      | 0.2   |
| CMS        | 0.6   |

## Fallback Alternatives

- **ffuf** - Faster Go-based fuzzer with similar features
- **gobuster** - Simpler directory brute-forcing
- **feroxbuster** - Recursive content discovery in Rust

## Context-Aware Parameters

**Standard directory fuzzing**
```bash
wfuzz -c -z file,/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt --hc 404,403 http://{domain}/FUZZ
```

**Parameter value fuzzing**
```bash
wfuzz -c -z file,/opt/wordlists/sqli_payloads.txt --hc 404 -d "param=FUZZ" http://{domain}/login
```

**Header fuzzing (Host header injection)**
```bash
wfuzz -c -z file,/opt/wordlists/vhosts.txt -H "Host: FUZZ.{domain}" --hc 404 --hl 0 http://{domain}/
```

**Multi-point injection**
```bash
wfuzz -c -z file,/opt/wordlists/users.txt -z file,/opt/wordlists/passwords.txt --hc 403 -d "user=FUZZ&pass=FUZ2Z" http://{domain}/login
```
