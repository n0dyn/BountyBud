---
id: "dirb"
title: "DIRB - Classic Directory Bruteforcer"
type: "tool"
category: "reconnaissance"
subcategory: "directory-discovery"
tags: ["directory", "dirb", "classic", "built-in-wordlists", "authentication", "recursive-mode"]
difficulty: "beginner"
platforms: ["linux", "macos"]
source_url: "http://dirb.sourceforge.net/"
related: []
updated: "2026-03-30"
---

## Overview

Traditional directory bruteforcer with built-in wordlists and authentication support.

## Command Reference

```bash
dirb https://{domain} /usr/share/dirb/wordlists/big.txt -r -S -w -o {domain}_dirb.txt
echo "[+] DIRB: Classic directory scan completed"
```

## Features

- Built-in wordlists
- Authentication
- Recursive mode

## Documentation

- [Official Documentation](http://dirb.sourceforge.net/)

## Effectiveness Scores

| Category   | Score |
|------------|-------|
| Web App    | 0.7   |
| API        | 0.4   |
| Network    | 0.0   |
| Cloud      | 0.1   |
| CMS        | 0.5   |

## Fallback Alternatives

- **ffuf** - Much faster, more flexible fuzzer
- **gobuster** - Go-based, faster than DIRB
- **feroxbuster** - Recursive discovery with better performance

## Context-Aware Parameters

**Standard directory scan**
```bash
dirb https://{domain} /usr/share/dirb/wordlists/big.txt -r -S -w -o {domain}_dirb.txt
```

**Authenticated scan with cookies**
```bash
dirb https://{domain} /usr/share/dirb/wordlists/big.txt -c "PHPSESSID=abc123" -r -S -o {domain}_dirb_auth.txt
```

**Scan with custom extensions**
```bash
dirb https://{domain} /usr/share/dirb/wordlists/common.txt -X ".php,.bak,.old,.conf" -r -o {domain}_dirb_ext.txt
```

**Quick scan with small wordlist**
```bash
dirb https://{domain} /usr/share/dirb/wordlists/small.txt -S -o {domain}_dirb_quick.txt
```
