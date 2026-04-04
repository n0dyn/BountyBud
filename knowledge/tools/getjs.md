---
id: "getjs"
title: "GetJS"
type: "tool"
category: "reconnaissance"
subcategory: "javascript-analysis"
tags: ["javascript", "getjs"]
difficulty: "beginner"
platforms: ["linux", "macos"]
related: []
updated: "2026-03-30"
---

## Overview

Tool to extract all JavaScript files from a domain.

## Command Reference

```bash
getjs --url https://{domain} --output {domain}_js_files.txt
echo "JavaScript files saved to {domain}_js_files.txt"
```

## Effectiveness Scores

| Category   | Score |
|------------|-------|
| Web App    | 0.7   |
| API        | 0.6   |
| Network    | 0.0   |
| Cloud      | 0.1   |
| CMS        | 0.5   |

## Fallback Alternatives

- **linkfinder** - Finds endpoints within JS files (complementary)
- **katana** - Crawler that can extract JS URLs during crawling
- **gospider** - Web spider with JS file extraction

## Context-Aware Parameters

**Standard JS extraction**
```bash
getjs --url https://{domain} --output {domain}_js_files.txt
```

**Complete JS extraction with subdomains**
```bash
getjs --url https://{domain} --complete --output {domain}_js_complete.txt
```

**Pipeline from subdomain list**
```bash
cat {domain}_live_hosts.txt | getjs --input - --complete --output {domain}_all_js.txt
```
