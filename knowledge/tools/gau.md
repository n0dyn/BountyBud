---
id: "gau"
title: "GetAllUrls (GAU) - Archive Mining"
type: "tool"
category: "reconnaissance"
subcategory: "url-collection"
tags: ["url", "gau", "archive", "archive-mining", "multiple-sources", "historical-data"]
difficulty: "beginner"
platforms: ["linux", "macos"]
source_url: "https://github.com/lc/gau"
related: []
updated: "2026-03-30"
---

## Overview

Fetches known URLs from Wayback Machine, Common Crawl, and AlienVault OTX for comprehensive historical coverage.

## Command Reference

```bash
gau {domain} | head -15000 | sort -u > {domain}_gau_urls.txt
echo "[+] GAU: $(wc -l < {domain}_gau_urls.txt) unique URLs discovered"
```

## Features

- Archive mining
- Multiple sources
- Historical data

## Documentation

- [Official Documentation](https://github.com/lc/gau)

## Effectiveness Scores

| Target Type | Score |
|-------------|-------|
| Web         | 0.85  |
| API         | 0.75  |
| Network     | 0.30  |
| Cloud       | 0.70  |
| CMS         | 0.85  |

## Fallback Alternatives

waybackurls → gauplus → waymore

## Context-Aware Parameters

```bash
# With subdomains included
gau --subs {domain} | sort -u > {domain}_gau_subs.txt

# Specific providers only
gau --providers wayback,commoncrawl {domain} > {domain}_gau_providers.txt

# Date filter
gau --from 202301 --to 202312 {domain} > {domain}_gau_dated.txt

# Output with dedup
gau {domain} | sort -u | tee {domain}_gau_dedup.txt
```
