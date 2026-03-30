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
