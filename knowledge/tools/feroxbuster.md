---
id: "feroxbuster"
title: "Feroxbuster - Recursive Content Discovery"
type: "tool"
category: "reconnaissance"
subcategory: "directory-discovery"
tags: ["directory", "feroxbuster", "recursive", "auto-tuning", "wildcard-detection", "smart-filtering"]
difficulty: "beginner"
platforms: ["linux", "macos"]
source_url: "https://github.com/epi052/feroxbuster"
related: []
updated: "2026-03-30"
---

## Overview

Intelligent recursive content discovery with auto-filtering and wildcard detection.

## Command Reference

```bash
feroxbuster -u https://{domain} -w /usr/share/seclists/Discovery/Web-Content/raft-large-files.txt -t 30 -C 404,403 -x js,php,txt,json --auto-tune -o {domain}_ferox.txt
echo "[+] Feroxbuster: Recursive scan completed"
```

## Features

- Auto-tuning
- Wildcard detection
- Smart filtering

## Documentation

- [Official Documentation](https://github.com/epi052/feroxbuster)

## Effectiveness Scores

| Target Type | Score |
|-------------|-------|
| Web         | 0.90  |
| API         | 0.85  |
| Network     | 0.25  |
| Cloud       | 0.65  |
| CMS         | 0.85  |

## Fallback Alternatives

ffuf → dirsearch → gobuster → dirb

## Context-Aware Parameters

```bash
# Recursive scan
feroxbuster -u https://{domain} -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt --depth 3 -o {domain}_ferox_recursive.txt

# With extensions
feroxbuster -u https://{domain} -x php,html,js,json,txt,bak -o {domain}_ferox_ext.txt

# Rate limited
feroxbuster -u https://{domain} --rate-limit 100 --threads 10 -o {domain}_ferox_ratelimit.txt

# Resume from state file
feroxbuster --resume-from {domain}_ferox_state.json
```
