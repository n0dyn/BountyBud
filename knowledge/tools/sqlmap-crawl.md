---
id: "sqlmap-crawl"
title: "SQLMap - Automated SQL Injection Testing"
type: "tool"
category: "web-application"
subcategory: "xss"
tags: ["vuln", "sqlmap-crawl", "injection", "database-detection", "injection-testing", "data-extraction"]
difficulty: "beginner"
platforms: ["linux", "macos"]
source_url: "https://sqlmap.org/"
related: []
updated: "2026-03-30"
---

## Overview

Advanced SQL injection detection and exploitation tool with database fingerprinting.

## Command Reference

```bash
sqlmap -u https://{domain} --crawl=2 --batch --random-agent --level=2 --risk=2 --output-dir={domain}_sqlmap_results
echo "[+] SQLMap: SQL injection testing completed"
```

## Features

- Database detection
- Injection testing
- Data extraction

## Documentation

- [Official Documentation](https://sqlmap.org/)
