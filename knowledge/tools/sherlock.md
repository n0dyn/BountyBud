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
