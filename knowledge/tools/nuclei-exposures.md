---
id: "nuclei-exposures"
title: "Nuclei Exposure Detection"
type: "tool"
category: "reconnaissance"
subcategory: "sensitive-data-discovery"
tags: ["sensitive", "nuclei-exposures", "detection", "exposure-detection", "template-based", "fast-scanning"]
difficulty: "beginner"
platforms: ["linux", "macos"]
source_url: "https://github.com/projectdiscovery/nuclei"
related: []
updated: "2026-03-30"
---

## Overview

Scan for exposed sensitive files and configurations using Nuclei.

## Command Reference

```bash
nuclei -u https://{domain} -t exposures/ -rate-limit 50 -o {domain}_exposures.txt
echo "[+] Nuclei: Exposure scan completed"
```

## Features

- Exposure detection
- Template-based
- Fast scanning

## Documentation

- [Official Documentation](https://github.com/projectdiscovery/nuclei)
