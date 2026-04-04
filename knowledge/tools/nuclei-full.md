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

## Effectiveness Scores

| Target Type | Score | Notes |
|-------------|-------|-------|
| Web App | 0.95 | Comprehensive vuln scanning with 7000+ templates |
| API | 0.90 | Strong API-specific template coverage |
| Network | 0.80 | Network service templates available |
| Cloud | 0.85 | Cloud misconfiguration detection |
| CMS | 0.95 | Extensive CMS-specific templates |

## Fallback Alternatives

If nuclei is unavailable: `nikto` → `zaproxy` (active scan) → manual testing

## Context-Aware Parameters

```bash
# Quick critical-only scan
nuclei -l targets.txt -severity critical,high -rate-limit 150 -es info,low

# Full comprehensive scan
nuclei -l targets.txt -severity critical,high,medium -rate-limit 100 -bulk-size 25 -o results.txt

# Technology-specific scanning
nuclei -l targets.txt -tags wordpress          # WordPress
nuclei -l targets.txt -tags aws,s3,cloud       # Cloud/AWS
nuclei -l targets.txt -tags api,graphql        # API
nuclei -l targets.txt -tags network,service    # Network services
nuclei -l targets.txt -tags auth,jwt,oauth     # Authentication

# Bug bounty focused (high-impact only)
nuclei -l targets.txt -severity critical -tags rce,sqli,ssrf,lfi,xxe,ssti -es info,low

# Exposure and secrets scanning
nuclei -l targets.txt -tags exposure,token,secret,config

# With custom templates
nuclei -l targets.txt -t ~/nuclei-templates/custom/ -severity critical,high

# Conservative rate (WAF-aware)
nuclei -l targets.txt -rate-limit 30 -bulk-size 5 -c 5
```
