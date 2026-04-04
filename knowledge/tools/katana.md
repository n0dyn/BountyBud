---
id: "katana"
title: "Katana - Next-Gen Web Crawler"
type: "tool"
category: "reconnaissance"
subcategory: "url-collection"
tags: ["url", "katana", "modern", "js-rendering", "scope-control", "form-parsing"]
difficulty: "beginner"
platforms: ["linux", "macos"]
source_url: "https://github.com/projectdiscovery/katana"
related: []
updated: "2026-03-30"
---

## Overview

Modern web crawler with JavaScript rendering, form parsing, and scope control.

## Command Reference

```bash
katana -u https://{domain} -d 5 -ps -pss waybackarchive,commoncrawl -f qurl -o {domain}_katana.txt
echo "[+] Katana: $(wc -l < {domain}_katana.txt) URLs discovered"
```

## Features

- JS rendering
- Scope control
- Form parsing

## Documentation

- [Official Documentation](https://github.com/projectdiscovery/katana)

## Effectiveness Scores

| Target Type | Score | Notes |
|-------------|-------|-------|
| Web App | 0.95 | Best modern web crawler with JS support |
| API | 0.80 | Good API endpoint discovery via crawling |
| Network | 0.20 | Not designed for network targets |
| Cloud | 0.60 | Limited to web-accessible cloud resources |
| CMS | 0.90 | Thorough CMS content crawling |

## Fallback Alternatives

If katana is unavailable: `hakrawler` → `gospider` → `crawley` → `wget --spider`

## Context-Aware Parameters

```bash
# Standard crawl
katana -u https://{domain} -d 5 -jc -o crawl.txt

# Deep crawl with passive sources
katana -u https://{domain} -d 5 -ps -pss waybackarchive,commoncrawl -f qurl -o deep_crawl.txt

# JavaScript-heavy SPA crawling
katana -u https://{domain} -d 3 -jc -hl -system-chrome -o spa_crawl.txt

# Crawl from list of hosts
katana -list live_hosts.txt -d 3 -jc -o all_urls.txt

# Extract forms and parameters
katana -u https://{domain} -d 3 -f qurl -ef css,png,jpg,gif,svg,woff -o parameterized.txt

# Scope-controlled crawling
katana -u https://{domain} -d 5 -cs {domain} -o scoped_crawl.txt

# With rate limiting
katana -u https://{domain} -d 3 -rl 50 -c 10 -o rate_limited.txt
```
