---
id: "nuclei-full"
title: "Nuclei - Comprehensive Vulnerability Scanner"
type: "tool"
category: "web-application"
subcategory: "xss"
tags: ["vuln", "nuclei-full", "comprehensive", "7000-templates", "cve-detection", "misconfiguration-scanning"]
difficulty: "beginner"
platforms: ["linux", "macos"]
source_url: "https://github.com/projectdiscovery/nuclei"
related: []
updated: "2026-03-30"
---

## Overview

Next-generation vulnerability scanner with 7000+ templates covering CVEs, misconfigurations, and exposures.

## Command Reference

```bash
nuclei -u https://{domain} -t cves/,vulnerabilities/,misconfiguration/,exposures/ -rate-limit 100 -c 50 -silent -o {domain}_nuclei_scan.txt
echo "[+] Nuclei: $(wc -l < {domain}_nuclei_scan.txt) vulnerabilities found"
```

## Features

- 7000+ templates
- CVE detection
- Misconfiguration scanning

## Documentation

- [Official Documentation](https://github.com/projectdiscovery/nuclei)
