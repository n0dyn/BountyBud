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
