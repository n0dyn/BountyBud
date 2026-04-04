---
id: "nikto"
title: "Nikto - Web Server Scanner"
type: "tool"
category: "web-application"
subcategory: "xss"
tags: ["vuln", "nikto", "classic", "server-fingerprinting", "cgi-scanning", "ssl-testing"]
difficulty: "beginner"
platforms: ["linux", "macos"]
source_url: "https://cirt.net/Nikto2"
related: []
updated: "2026-03-30"
---

## Overview

Classic web server scanner that identifies dangerous files, misconfigurations, and vulnerabilities.

## Command Reference

```bash
nikto -h https://{domain} -Format txt -output {domain}_nikto.txt -Tuning 9
echo "[+] Nikto: Web server scan completed"
```

## Features

- Server fingerprinting
- CGI scanning
- SSL testing

## Documentation

- [Official Documentation](https://cirt.net/Nikto2)

## Effectiveness Scores

| Target Type | Score |
|-------------|-------|
| Web         | 0.70  |
| API         | 0.50  |
| Network     | 0.30  |
| Cloud       | 0.40  |
| CMS         | 0.75  |

## Fallback Alternatives

nuclei → zaproxy

## Context-Aware Parameters

```bash
# Standard scan
nikto -h https://{domain} -output {domain}_nikto.txt

# With SSL
nikto -h https://{domain} -ssl -output {domain}_nikto_ssl.txt

# With tuning options (1=files, 2=misconfig, 3=info, 4=XSS, 9=SQL injection)
nikto -h https://{domain} -Tuning 1234 -output {domain}_nikto_tuned.txt

# Output formats
nikto -h https://{domain} -Format htm -output {domain}_nikto.html
nikto -h https://{domain} -Format xml -output {domain}_nikto.xml
```
