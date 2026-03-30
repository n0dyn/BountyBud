---
id: "gospider"
title: "GoSpider - Fast Web Spider"
type: "tool"
category: "reconnaissance"
subcategory: "url-collection"
tags: ["url", "gospider", "active", "high-performance", "multiple-formats", "subdomain-inclusion"]
difficulty: "beginner"
platforms: ["linux", "macos"]
source_url: "https://github.com/jaeles-project/gospider"
related: []
updated: "2026-03-30"
---

## Overview

High-performance web spider written in Go with support for multiple output formats.

## Command Reference

```bash
gospider -s https://{domain} -d 2 -c 10 -t 20 --other-source --include-subs -o {domain}_spider
echo "[+] GoSpider: Crawling completed, check {domain}_spider/ directory"
```

## Features

- High performance
- Multiple formats
- Subdomain inclusion

## Documentation

- [Official Documentation](https://github.com/jaeles-project/gospider)
