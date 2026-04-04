---
id: "subfinder"
title: "Subfinder - Fast Passive Discovery"
type: "tool"
category: "reconnaissance"
subcategory: "subdomain-enumeration"
tags: ["subdomain", "subfinder", "passive", "passive-enumeration", "multiple-sources", "fast-execution"]
difficulty: "beginner"
platforms: ["linux", "macos"]
source_url: "https://github.com/projectdiscovery/subfinder"
related: []
updated: "2026-03-30"
---

## Overview

Discovers subdomains using passive sources with high-speed enumeration and multiple data sources.

## Command Reference

```bash
subfinder -d {domain} -all -recursive -t 50 -o {domain}_subfinder.txt
echo "[+] Subfinder: $(wc -l < {domain}_subfinder.txt) subdomains found"
```

## Features

- Passive enumeration
- Multiple sources
- Fast execution

## Documentation

- [Official Documentation](https://github.com/projectdiscovery/subfinder)

## Effectiveness Scores

| Target Type | Score | Notes |
|-------------|-------|-------|
| Web App | 0.95 | Excellent passive subdomain discovery |
| API | 0.90 | Good for finding API subdomains |
| Network | 0.70 | Limited to DNS-based discovery |
| Cloud | 0.85 | Good coverage of cloud-hosted assets |
| CMS | 0.95 | Full subdomain coverage |

## Fallback Alternatives

If subfinder is unavailable: `amass enum -passive` → `assetfinder` → `findomain` → `chaos`

## Context-Aware Parameters

```bash
# Quick scan (speed priority)
subfinder -d {domain} -silent -o subs.txt

# Deep scan (thoroughness priority)
subfinder -d {domain} -all -recursive -t 100 -o subs.txt

# With specific sources only
subfinder -d {domain} -s crtsh,virustotal,shodan -o subs.txt

# Output for piping to httpx
subfinder -d {domain} -all -silent | httpx -silent -sc -title
```
