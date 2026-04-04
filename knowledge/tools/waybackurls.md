---
id: "waybackurls"
title: "Wayback URLs - Internet Archive"
type: "tool"
category: "reconnaissance"
subcategory: "url-collection"
tags: ["url", "waybackurls", "archive", "wayback-machine", "date-filtering", "clean-output"]
difficulty: "beginner"
platforms: ["linux", "macos"]
source_url: "https://github.com/tomnomnom/waybackurls"
related: []
updated: "2026-03-30"
---

## Overview

Specialized tool for extracting URLs from the Wayback Machine with date filtering capabilities.

## Command Reference

```bash
waybackurls {domain} | head -10000 | sort -u > {domain}_wayback.txt
echo "[+] Wayback: $(wc -l < {domain}_wayback.txt) historical URLs found"
```

## Features

- Wayback Machine
- Date filtering
- Clean output

## Documentation

- [Official Documentation](https://github.com/tomnomnom/waybackurls)

## Effectiveness Scores

| Target Type | Score |
|-------------|-------|
| Web         | 0.80  |
| API         | 0.70  |
| Network     | 0.25  |
| Cloud       | 0.65  |
| CMS         | 0.80  |

## Fallback Alternatives

gau → gauplus → waymore

## Context-Aware Parameters

```bash
# With dates
waybackurls -dates {domain} > {domain}_wayback_dates.txt

# No subdomains
waybackurls -no-subs {domain} > {domain}_wayback_nosubs.txt

# Piped to grep for interesting extensions
waybackurls {domain} | grep -iE "\.(php|asp|aspx|jsp|json|xml|config|env|bak|sql|log)$" > {domain}_wayback_interesting.txt
```
