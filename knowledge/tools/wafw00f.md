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
