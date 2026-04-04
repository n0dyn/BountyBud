---
id: "nuclei-wordpress"
title: "Nuclei WordPress Templates"
type: "tool"
category: "cms"
subcategory: "wordpress"
tags: ["wordpress", "nuclei-wordpress"]
difficulty: "beginner"
platforms: ["linux", "macos"]
related: []
updated: "2026-03-30"
---

## Overview

WordPress-specific vulnerability scanning using Nuclei.

## Command Reference

```bash
nuclei -u https://{domain} -t wordpress/ -rate-limit 50 -o {domain}_wp_nuclei.txt
echo "WordPress Nuclei scan results saved to {domain}_wp_nuclei.txt"
```

## Effectiveness Scores

| Category   | Score |
|------------|-------|
| Web App    | 0.4   |
| API        | 0.2   |
| Network    | 0.0   |
| Cloud      | 0.1   |
| CMS        | 0.9   |

## Fallback Alternatives

- **wpscan** - Dedicated WordPress scanner with vulnerability database
- **nuclei-full** - Full template scan covers WordPress plus more
- **nikto** - General web scanner that detects some WP issues

## Context-Aware Parameters

**Standard WordPress template scan**
```bash
nuclei -u https://{domain} -t wordpress/ -rate-limit 50 -o {domain}_wp_nuclei.txt
```

**WordPress plugin vulnerability focus**
```bash
nuclei -u https://{domain} -t wordpress/ -tags wp-plugin -severity high,critical -o {domain}_wp_plugins.txt
```

**Bulk WordPress site scanning**
```bash
nuclei -l {domain}_wp_sites.txt -t wordpress/ -rate-limit 30 -c 5 -o {domain}_wp_bulk.txt
```
