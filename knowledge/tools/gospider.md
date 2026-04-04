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

## Effectiveness Scores

| Category   | Score |
|------------|-------|
| Web App    | 0.8   |
| API        | 0.5   |
| Network    | 0.1   |
| Cloud      | 0.2   |
| CMS        | 0.6   |

## Fallback Alternatives

- **katana** - ProjectDiscovery crawler with headless browser support
- **hakrawler** - Lightweight alternative for quick crawling
- **burpsuite** - Full-featured proxy with active crawling

## Context-Aware Parameters

**Standard crawl with subdomain inclusion**
```bash
gospider -s https://{domain} -d 2 -c 10 -t 20 --other-source --include-subs -o {domain}_spider
```

**Deep crawl for hidden endpoints**
```bash
gospider -s https://{domain} -d 5 -c 5 -t 10 --js --sitemap --robots -o {domain}_spider_deep
```

**Quick surface-level scan**
```bash
gospider -s https://{domain} -d 1 -c 20 -t 30 --no-redirect -o {domain}_spider_quick
```

**Crawl with custom headers (authenticated)**
```bash
gospider -s https://{domain} -d 3 -c 10 -H "Authorization: Bearer TOKEN" -H "Cookie: session=abc" -o {domain}_spider_auth
```
