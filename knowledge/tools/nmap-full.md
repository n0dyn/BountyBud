---
id: "nmap-full"
title: "Nmap Full Port Scan"
type: "tool"
category: "network"
subcategory: "port-scanning"
tags: ["network", "nmap-full"]
difficulty: "beginner"
platforms: ["linux", "macos"]
related: []
updated: "2026-03-30"
---

## Overview

Comprehensive scan of all 65535 ports.

## Command Reference

```bash
nmap -p- -T4 {domain} -oA {domain}_nmap_full
echo "Nmap full port scan results saved to {domain}_nmap_full.*"
```

## Effectiveness Scores

| Target Type | Score | Notes |
|-------------|-------|-------|
| Web App | 0.70 | Useful for port/service discovery |
| API | 0.65 | Identifies API service ports |
| Network | 0.95 | Gold standard for network scanning |
| Cloud | 0.80 | Effective for cloud host enumeration |
| CMS | 0.70 | Finds web server ports |

## Fallback Alternatives

If nmap is unavailable: `rustscan` → `masscan` → `zmap`

## Context-Aware Parameters

```bash
# Web application target
nmap -sV -sC -p 80,443,8080,8443,3000,5000,8000,9090 {target} -oA web_scan

# Full network assessment
nmap -sS -sV -sC -O --top-ports 1000 -T4 {target} -oA network_scan

# All ports (comprehensive)
nmap -p- -T4 {target} -oA full_port_scan

# Stealth scan (IDS evasion)
nmap -sS -T2 -f --data-length 24 -D RND:5 {target} -oA stealth_scan

# Service-specific scripts
nmap --script http-* -p 80,443 {target}         # Web
nmap --script smb-* -p 445 {target}              # SMB
nmap --script ssh-* -p 22 {target}               # SSH
nmap --script ftp-* -p 21 {target}               # FTP
nmap --script mysql-* -p 3306 {target}           # MySQL

# UDP scan
nmap -sU --top-ports 100 -T4 {target} -oA udp_scan

# Vulnerability scripts
nmap --script vuln -p- {target} -oA vuln_scan
```
