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
