---
id: "nmap-basic"
title: "Nmap Basic Port Scan"
type: "tool"
category: "network"
subcategory: "port-scanning"
tags: ["network", "nmap-basic"]
difficulty: "beginner"
platforms: ["linux", "macos"]
related: []
updated: "2026-03-30"
---

## Overview

Basic port scan with service detection and common scripts.

## Command Reference

```bash
nmap -sV -sC -T4 {domain} -oA {domain}_nmap_basic
echo "Nmap basic scan results saved to {domain}_nmap_basic.*"
```

## Effectiveness Scores

| Category   | Score |
|------------|-------|
| Web App    | 0.3   |
| API        | 0.2   |
| Network    | 0.8   |
| Cloud      | 0.2   |
| CMS        | 0.2   |

## Fallback Alternatives

- **nmap-full** - Comprehensive all-port scan with more detail
- **masscan** - Faster port scanning for large IP ranges
- **nmap-scripts** - NSE-focused scanning for deeper enumeration

## Context-Aware Parameters

**Standard basic scan**
```bash
nmap -sV -sC -T4 {domain} -oA {domain}_nmap_basic
```

**Quick top ports scan**
```bash
nmap -sV --top-ports 100 -T4 {domain} -oA {domain}_nmap_quick
```

**Basic scan with OS detection**
```bash
nmap -sV -sC -O -T4 {domain} -oA {domain}_nmap_os
```

**UDP service discovery**
```bash
nmap -sU --top-ports 50 -T4 {domain} -oA {domain}_nmap_udp
```
