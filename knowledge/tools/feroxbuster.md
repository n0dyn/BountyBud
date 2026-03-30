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
