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
