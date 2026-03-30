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
