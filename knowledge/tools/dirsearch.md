---
id: "dirsearch"
title: "Dirsearch - Web Path Scanner"
type: "tool"
category: "reconnaissance"
subcategory: "directory-discovery"
tags: ["directory", "dirsearch", "comprehensive", "smart-detection", "multiple-extensions", "random-agents"]
difficulty: "beginner"
platforms: ["linux", "macos"]
source_url: "https://github.com/maurosoria/dirsearch"
related: []
updated: "2026-03-30"
---

## Overview

Advanced web path scanner with smart detection and comprehensive wordlists.

## Command Reference

```bash
dirsearch -u https://{domain} -e php,asp,aspx,jsp,html,js -t 30 --random-agent -o {domain}_dirsearch.txt
echo "[+] Dirsearch: $(grep -c "200" {domain}_dirsearch.txt 2>/dev/null || echo 0) paths found"
```

## Features

- Smart detection
- Multiple extensions
- Random agents

## Documentation

- [Official Documentation](https://github.com/maurosoria/dirsearch)

## Effectiveness Scores

| Target Type | Score |
|-------------|-------|
| Web         | 0.80  |
| API         | 0.75  |
| Network     | 0.20  |
| Cloud       | 0.55  |
| CMS         | 0.80  |

## Fallback Alternatives

ffuf → feroxbuster → gobuster → dirb

## Context-Aware Parameters

```bash
# With extensions
dirsearch -u https://{domain} -e php,asp,aspx,jsp,html,js,json -o {domain}_dirsearch_ext.txt

# Recursive scan
dirsearch -u https://{domain} -r -R 3 -o {domain}_dirsearch_recursive.txt

# With custom wordlist
dirsearch -u https://{domain} -w /usr/share/seclists/Discovery/Web-Content/raft-large-files.txt -o {domain}_dirsearch_custom.txt

# Rate limited
dirsearch -u https://{domain} --delay=0.5 -t 20 -o {domain}_dirsearch_slow.txt
```
