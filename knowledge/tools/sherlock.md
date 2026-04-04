---
id: "sherlock"
title: "Sherlock - Social Media Username Search"
type: "tool"
category: "reconnaissance"
subcategory: "osint"
tags: ["osint", "sherlock", "social", "400-networks", "username-hunting", "csv-export"]
difficulty: "beginner"
platforms: ["linux", "macos"]
source_url: "https://github.com/sherlock-project/sherlock"
related: []
updated: "2026-03-30"
---

## Overview

Hunt down social media accounts by username across 400+ social networks. Note: Requires username input.

## Command Reference

```bash
echo "Enter username to search: "
read username
sherlock $username --output {domain}_${username}_sherlock.txt --csv
echo "[+] Sherlock: Social media search completed for $username"
```

## Features

- 400+ networks
- Username hunting
- CSV export

## Documentation

- [Official Documentation](https://github.com/sherlock-project/sherlock)

## Effectiveness Scores

| Category   | Score |
|------------|-------|
| Web App    | 0.2   |
| API        | 0.1   |
| Network    | 0.0   |
| Cloud      | 0.1   |
| CMS        | 0.1   |

## Fallback Alternatives

- **spiderfoot** - Broader OSINT with social media modules
- **theHarvester** - Email and name harvesting from public sources
- **whatbreach** - Username breach checking alternative

## Context-Aware Parameters

**Standard username search with CSV export**
```bash
sherlock $username --output {domain}_${username}_sherlock.txt --csv
```

**Quick scan on popular sites only**
```bash
sherlock $username --site twitter --site github --site instagram --site linkedin --output {domain}_${username}_quick.txt
```

**Verbose scan with timeout control**
```bash
sherlock $username --timeout 10 --print-found --csv --output {domain}_${username}_full.txt
```

**Multiple username search**
```bash
sherlock user1 user2 user3 --csv --output {domain}_multi_sherlock.txt
```
