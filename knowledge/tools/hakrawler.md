---
id: "hakrawler"
title: "Hakrawler - Live Web Crawling"
type: "tool"
category: "reconnaissance"
subcategory: "url-collection"
tags: ["url", "hakrawler", "active", "live-crawling", "form-discovery", "js-file-extraction"]
difficulty: "beginner"
platforms: ["linux", "macos"]
source_url: "https://github.com/hakluke/hakrawler"
related: []
updated: "2026-03-30"
---

## Overview

Fast web crawler that discovers URLs, forms, and JavaScript files by actively crawling live sites.

## Command Reference

```bash
echo https://{domain} | hakrawler -depth 3 -plain -usewayback -insecure > {domain}_crawled.txt
echo "[+] Hakrawler: $(wc -l < {domain}_crawled.txt) URLs crawled"
```

## Features

- Live crawling
- Form discovery
- JS file extraction

## Documentation

- [Official Documentation](https://github.com/hakluke/hakrawler)
