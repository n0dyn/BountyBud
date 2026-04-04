---
id: "gauplus"
title: "GauPlus - Enhanced Archive Mining"
type: "tool"
category: "reconnaissance"
subcategory: "url-collection"
tags: ["url", "gauplus", "archive", "enhanced-providers", "content-filtering", "subdomain-support"]
difficulty: "beginner"
platforms: ["linux", "macos"]
source_url: "https://github.com/bp0lr/gauplus"
related: []
updated: "2026-03-30"
---

## Overview

Enhanced version of GAU with additional providers and filtering capabilities.

## Command Reference

```bash
gauplus -subs {domain} -b png,jpg,gif,jpeg,swf,woff,svg,pdf -o {domain}_gauplus.txt
echo "[+] GauPlus: $(wc -l < {domain}_gauplus.txt) filtered URLs collected"
```

## Features

- Enhanced providers
- Content filtering
- Subdomain support

## Documentation

- [Official Documentation](https://github.com/bp0lr/gauplus)

## Effectiveness Scores

| Category   | Score |
|------------|-------|
| Web App    | 0.7   |
| API        | 0.6   |
| Network    | 0.1   |
| Cloud      | 0.2   |
| CMS        | 0.5   |

## Fallback Alternatives

- **gau** - Original tool, fewer providers but more stable
- **waybackurls** - Wayback Machine focused URL collection
- **katana** - Active crawling instead of archive mining

## Context-Aware Parameters

**Broad URL collection (default)**
```bash
gauplus -subs {domain} -b png,jpg,gif,jpeg,swf,woff,svg,pdf -o {domain}_gauplus.txt
```

**API endpoint discovery**
```bash
gauplus -subs {domain} -b png,jpg,gif,jpeg,swf,woff,svg,pdf,css | grep -iE '/api/|/v[0-9]/' > {domain}_gauplus_api.txt
```

**Parameter mining for injection testing**
```bash
gauplus -subs {domain} | grep '=' | sort -u > {domain}_gauplus_params.txt
```
