---
id: "theHarvester"
title: "theHarvester - Email & Domain Intelligence"
type: "tool"
category: "reconnaissance"
subcategory: "osint"
tags: ["osint", "theHarvester", "intelligence", "email-harvesting", "social-media-intel", "multiple-sources"]
difficulty: "beginner"
platforms: ["linux", "macos"]
source_url: "https://github.com/laramies/theHarvester"
related: []
updated: "2026-03-30"
---

## Overview

Comprehensive OSINT tool for gathering emails, names, subdomains, IPs, and URLs from public sources.

## Command Reference

```bash
theHarvester -d {domain} -l 500 -b google,bing,yahoo,duckduckgo,linkedin,twitter -f {domain}_harvest
echo "[+] theHarvester: Intelligence gathering completed"
```

## Features

- Email harvesting
- Social media intel
- Multiple sources

## Documentation

- [Official Documentation](https://github.com/laramies/theHarvester)

## Effectiveness Scores

| Target Type | Score |
|-------------|-------|
| Web         | 0.80  |
| API         | 0.70  |
| Network     | 0.75  |
| Cloud       | 0.80  |
| CMS         | 0.80  |

## Fallback Alternatives

amass → spiderfoot → recon-ng

## Context-Aware Parameters

```bash
# All sources
theHarvester -d {domain} -l 500 -b all -f {domain}_harvest_all

# Specific sources
theHarvester -d {domain} -b google,bing,linkedin -f {domain}_harvest_specific

# With DNS brute force
theHarvester -d {domain} -b all -c -f {domain}_harvest_dns

# With screenshots
theHarvester -d {domain} -b all --screenshot {domain}_screenshots -f {domain}_harvest_screenshots
```
