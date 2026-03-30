---
id: "chaos"
title: "Chaos - ProjectDiscovery Dataset"
type: "tool"
category: "reconnaissance"
subcategory: "subdomain-enumeration"
tags: ["subdomain", "chaos", "passive", "curated-dataset", "high-quality-results", "api-based"]
difficulty: "beginner"
platforms: ["linux", "macos"]
source_url: "https://github.com/projectdiscovery/chaos-client"
related: []
updated: "2026-03-30"
---

## Overview

Queries ProjectDiscovery's Chaos dataset for previously discovered subdomains.

## Command Reference

```bash
chaos -d {domain} -key YOUR_CHAOS_API_KEY -o {domain}_chaos.txt
echo "[+] Chaos: $(wc -l < {domain}_chaos.txt) subdomains from dataset"
```

## Features

- Curated dataset
- High-quality results
- API-based

## Documentation

- [Official Documentation](https://github.com/projectdiscovery/chaos-client)
