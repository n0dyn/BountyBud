---
id: "assetfinder"
title: "Assetfinder - Rapid Asset Discovery"
type: "tool"
category: "reconnaissance"
subcategory: "subdomain-enumeration"
tags: ["subdomain", "assetfinder", "passive", "minimal-setup", "fast-execution", "certificate-transparency"]
difficulty: "beginner"
platforms: ["linux", "macos"]
source_url: "https://github.com/tomnomnom/assetfinder"
related: []
updated: "2026-03-30"
---

## Overview

Lightweight subdomain discovery tool that focuses on speed and minimal configuration.

## Command Reference

```bash
assetfinder --subs-only {domain} > {domain}_assetfinder.txt
echo "[+] Assetfinder: $(wc -l < {domain}_assetfinder.txt) assets discovered"
```

## Features

- Minimal setup
- Fast execution
- Certificate transparency

## Documentation

- [Official Documentation](https://github.com/tomnomnom/assetfinder)

## Effectiveness Scores

| Target Type | Score |
|-------------|-------|
| Web         | 0.80  |
| API         | 0.75  |
| Network     | 0.60  |
| Cloud       | 0.70  |
| CMS         | 0.80  |

## Fallback Alternatives

subfinder → amass → findomain

## Context-Aware Parameters

```bash
# Subdomains only
assetfinder --subs-only {domain} > {domain}_subs.txt

# With related domains
assetfinder {domain} > {domain}_all_assets.txt

# Piped to httpx for live validation
assetfinder --subs-only {domain} | httpx -silent -o {domain}_live.txt
```
