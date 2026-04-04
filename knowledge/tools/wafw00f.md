---
id: "wafw00f"
title: "WAFW00F - Web Application Firewall Detection"
type: "tool"
category: "web-application"
subcategory: "xss"
tags: ["webapp", "wafw00f", "reconnaissance", "waf-detection", "fingerprinting", "evasion-planning"]
difficulty: "beginner"
platforms: ["linux", "macos"]
source_url: "https://github.com/EnableSecurity/wafw00f"
related: []
updated: "2026-03-30"
---

## Overview

Identifies and fingerprints Web Application Firewall (WAF) products protecting a website.

## Command Reference

```bash
wafw00f https://{domain} -a -o {domain}_waf_detection.txt
echo "[+] WAFW00F: WAF detection completed"
```

## Features

- WAF detection
- Fingerprinting
- Evasion planning

## Documentation

- [Official Documentation](https://github.com/EnableSecurity/wafw00f)

## Effectiveness Scores

| Target Type | Score |
|-------------|-------|
| Web         | 0.85  |
| API         | 0.80  |
| Network     | 0.20  |
| Cloud       | 0.70  |
| CMS         | 0.85  |

## Fallback Alternatives

whatweb → manual header inspection

## Context-Aware Parameters

```bash
# Single URL
wafw00f https://{domain}

# List of URLs
wafw00f -i urls.txt -o {domain}_waf_results.txt

# Verbose output
wafw00f https://{domain} -v -o {domain}_waf_verbose.txt

# All WAFs check (test against all WAF signatures)
wafw00f https://{domain} -a -o {domain}_waf_all.txt
```
