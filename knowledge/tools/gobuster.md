---
id: "gobuster"
title: "Gobuster - High-Speed Directory Brute Force"
type: "tool"
category: "reconnaissance"
subcategory: "directory-discovery"
tags: ["directory", "gobuster", "brute-force", "high-speed", "extension-support", "stealth-mode"]
difficulty: "beginner"
platforms: ["linux", "macos"]
source_url: "https://github.com/OJ/gobuster"
related: []
updated: "2026-03-30"
---

## Overview

Ultra-fast directory and file brute-forcer with support for multiple wordlists and extensions.

## Command Reference

```bash
gobuster dir -u https://{domain} -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt -t 50 -x php,html,txt,js,json -q -o {domain}_gobuster.txt
echo "[+] Gobuster: $(wc -l < {domain}_gobuster.txt) paths discovered"
```

## Features

- High speed
- Extension support
- Stealth mode

## Documentation

- [Official Documentation](https://github.com/OJ/gobuster)

## Effectiveness Scores

| Target Type | Score |
|-------------|-------|
| Web         | 0.85  |
| API         | 0.80  |
| Network     | 0.25  |
| Cloud       | 0.60  |
| CMS         | 0.85  |

## Fallback Alternatives

ffuf → feroxbuster → dirsearch → dirb

## Context-Aware Parameters

```bash
# Dir mode
gobuster dir -u https://{domain} -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt -t 50 -o {domain}_gobuster_dir.txt

# DNS mode
gobuster dns -d {domain} -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -t 50 -o {domain}_gobuster_dns.txt

# Vhost mode
gobuster vhost -u https://{domain} -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -t 50 -o {domain}_gobuster_vhost.txt

# With status codes filter
gobuster dir -u https://{domain} -w /usr/share/wordlists/dirb/common.txt -s 200,301,302 -o {domain}_gobuster_status.txt

# With extensions
gobuster dir -u https://{domain} -w /usr/share/wordlists/dirb/common.txt -x php,html,txt,js,json,bak -o {domain}_gobuster_ext.txt
```
