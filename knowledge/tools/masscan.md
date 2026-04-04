---
id: "masscan"
title: "Masscan Fast Port Scan"
type: "tool"
category: "network"
subcategory: "port-scanning"
tags: ["network", "masscan"]
difficulty: "beginner"
platforms: ["linux", "macos"]
related: []
updated: "2026-03-30"
---

## Overview

Ultra-fast port scanner for large-scale scanning.

## Command Reference

```bash
dig +short {domain} | grep -E '^[0-9.]+' > {domain}_ips.txt
masscan -p1-65535 -iL {domain}_ips.txt --rate=1000 -oX {domain}_masscan.xml
echo "[+] Masscan: High-speed port scan completed"
```

## Effectiveness Scores

| Target Type | Score |
|-------------|-------|
| Web         | 0.50  |
| API         | 0.45  |
| Network     | 0.90  |
| Cloud       | 0.70  |
| CMS         | 0.50  |

## Fallback Alternatives

nmap → rustscan → zmap

## Context-Aware Parameters

```bash
# Top ports
masscan -iL {domain}_ips.txt --top-ports 1000 --rate=1000 -oX {domain}_masscan_top.xml

# All ports
masscan -iL {domain}_ips.txt -p0-65535 --rate=1000 -oX {domain}_masscan_all.xml

# Specific ports
masscan -iL {domain}_ips.txt -p80,443,8080,8443,3000,5000 --rate=1000 -oX {domain}_masscan_specific.xml

# Rate limited
masscan -iL {domain}_ips.txt -p1-65535 --rate=100 -oX {domain}_masscan_slow.xml

# With banners
masscan -iL {domain}_ips.txt -p1-65535 --rate=1000 --banners -oX {domain}_masscan_banners.xml
```
